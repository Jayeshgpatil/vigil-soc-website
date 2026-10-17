/**
 * Live SOC console: KPIs, charts, the streaming alert queue and the
 * triage drawer (status, assignment, notes, escalation to an incident).
 */
(function () {
  'use strict';

  var V = window.VGIL;
  var C = window.VGCharts;
  var $ = window.VG.$;
  var $$ = window.VG.$$;
  var el = window.VG.el;

  if (!V.session.isAuthed()) return; // main.js already redirected

  var SEV_COLOR = {
    critical: C.PALETTE.critical,
    high: C.PALETTE.high,
    medium: C.PALETTE.medium,
    low: C.PALETTE.low,
    info: C.PALETTE.info
  };

  var me = V.session.user() || {};
  var state = {
    page: 1,
    limit: 25,
    severity: '',
    status: '',
    q: '',
    sort: 'ts',
    quick: '',
    streaming: true,
    newSinceLoad: 0,
    pages: 1
  };

  /* ------------------------------------------------------------ identity */

  (function showUser() {
    var email = $('[data-user-email]');
    if (email) email.textContent = me.email || '—';
    var role = $('[data-user-role]');
    if (role) role.textContent = me.title || me.role || '—';
    var org = $('[data-user-org]');
    if (org) org.textContent = me.org || '—';
  })();

  // Confirm the token is still valid; main.js only checks that one exists.
  V.api.me().catch(function (err) {
    if (err.status === 401) {
      window.VG.toast('Session expired', 'Please sign in again.', 'crit');
      setTimeout(function () {
        location.href = '/login.html?next=/dashboard.html';
      }, 1200);
    }
  });

  /* --------------------------------------------------------------- stats */

  var stats = null;

  /** Writes a KPI and flashes it only when the number actually moved. */
  function setKpi(name, value) {
    var node = $('[data-kpi="' + name + '"]');
    if (!node || node.textContent === value) return;

    var hadValue = node.textContent !== '—';
    node.textContent = value;

    if (hadValue) {
      node.classList.remove('flash');
      void node.offsetWidth; // restart the animation
      node.classList.add('flash');
    }
  }

  function renderStats() {
    if (!stats) return;
    var t = stats.totals;

    setKpi('alerts24h', window.VG.num(t.alerts24h));
    setKpi('critical24h', window.VG.num(t.critical24h));
    setKpi('openIncidents', window.VG.num(t.openIncidents));
    setKpi('mttr', window.VG.duration(stats.performance.mttrMinutes));

    $('[data-kpi-sub="alerts"]').textContent =
      t.assetsMonitored + ' assets · ' + t.liveViewers + ' analyst(s) connected';
    $('[data-kpi-sub="incidents"]').textContent = t.totalIncidents + ' total this period';

    C.area($('#dash-volume'), stats.timeline, { height: 210 });

    var slices = Object.keys(stats.bySeverity)
      .filter(function (k) {
        return stats.bySeverity[k] > 0;
      })
      .map(function (k) {
        return { label: k, value: stats.bySeverity[k], color: SEV_COLOR[k] };
      });

    C.donut($('#dash-donut'), slices, { height: 200, caption: 'ALERTS' });

    var legend = $('#dash-donut-legend');
    if (legend) {
      legend.innerHTML = '';
      slices.forEach(function (s) {
        var span = el('span');
        var i = el('i');
        i.style.background = s.color;
        span.appendChild(i);
        span.appendChild(document.createTextNode(s.label + ' · ' + s.value));
        legend.appendChild(span);
      });
    }

    C.bars(
      $('#dash-sources'),
      Object.keys(stats.bySource)
        .map(function (k) {
          return { label: k, value: stats.bySource[k], color: C.PALETTE.accent2 };
        })
        .sort(function (a, b) {
          return b.value - a.value;
        }),
      { barHeight: 17, labelWidth: 110 }
    );

    C.bars(
      $('#dash-tactics'),
      Object.keys(stats.byTactic)
        .map(function (k) {
          return { label: k, value: stats.byTactic[k], color: C.PALETTE.accent };
        })
        .sort(function (a, b) {
          return b.value - a.value;
        })
        .slice(0, 8),
      { barHeight: 17, labelWidth: 110 }
    );

    var perf = $('#dash-perf');
    if (perf) {
      perf.innerHTML = '';
      var p = stats.performance;
      [
        ['Mean time to acknowledge', window.VG.duration(p.mttaMinutes)],
        ['Mean time to respond', window.VG.duration(p.mttrMinutes)],
        ['Detection coverage', p.detectionCoverage + '%'],
        ['False positive rate', p.falsePositiveRate + '%'],
        ['Automation rate', p.automationRate + '%'],
        ['Platform uptime', p.uptime + '%']
      ].forEach(function (pair) {
        var row = el('div', 'metric-row');
        row.appendChild(el('span', null, pair[0]));
        row.appendChild(el('span', 'v', pair[1]));
        perf.appendChild(row);
      });

      // Only on the first build — this panel is rebuilt on every 30s poll.
      if (!perf.__vgDealt && window.VGFx) {
        perf.__vgDealt = true;
        window.VGFx.cascade(perf.children, { step: 60, side: true });
      }
    }
  }

  function loadStats() {
    return V.api
      .stats()
      .then(function (res) {
        stats = res.data;
        renderStats();
      })
      .catch(function () {});
  }

  loadStats();
  setInterval(loadStats, 30000);

  /* --------------------------------------------------------- alert queue */

  var tbody = $('#alert-rows');
  var alertCache = {};

  function severityCell(sev) {
    var td = el('td');
    td.appendChild(el('span', 'badge badge-dot sev-' + sev, sev));
    return td;
  }

  function riskCell(risk) {
    var td = el('td', 'cell-mono');
    var color = risk >= 85 ? 'var(--crit)' : risk >= 65 ? 'var(--high)' : 'var(--muted)';
    var span = el('span', null, String(risk));
    span.style.color = color;
    span.style.fontWeight = '700';
    td.appendChild(span);
    return td;
  }

  function buildRow(a, fresh) {
    alertCache[a.id] = a;

    var tr = el('tr', 'row-click' + (fresh ? ' fresh' : ''));
    tr.dataset.id = a.id;

    var t = el('td', 'cell-mono');
    t.textContent = window.VG.clock(a.ts);
    t.title = window.VG.fullTime(a.ts);
    tr.appendChild(t);

    tr.appendChild(severityCell(a.severity));
    tr.appendChild(riskCell(a.risk));
    tr.appendChild(el('td', 'strong', a.rule));

    var tech = el('td', 'cell-mono');
    tech.textContent = a.technique;
    tech.style.color = 'var(--accent-2)';
    tech.title = a.techniqueName;
    tr.appendChild(tech);

    var asset = el('td', 'cell-mono');
    asset.textContent = a.host;
    asset.title = a.assetType + ' · ' + a.zone + ' · ' + a.criticality;
    tr.appendChild(asset);

    tr.appendChild(el('td', 'cell-mono', a.sourceIp));

    var status = el('td');
    status.appendChild(
      el('span', 'badge' + (a.status === 'new' ? ' sev-medium' : ''), a.status)
    );
    tr.appendChild(status);

    tr.addEventListener('click', function () {
      openAlert(a.id);
    });
    return tr;
  }

  function renderAlerts(res) {
    tbody.innerHTML = '';

    if (!res.data.length) {
      var tr = el('tr');
      var td = el('td', 'empty', 'No alerts match the current filters.');
      td.colSpan = 8;
      tr.appendChild(td);
      tbody.appendChild(tr);
    } else {
      res.data.forEach(function (a) {
        tbody.appendChild(buildRow(a, false));
      });
      // Deal the queue in on load and on every filter or page change.
      if (window.VGFx) window.VGFx.cascade(tbody.children, { step: 22 });
    }

    var p = res.pagination;
    state.pages = p.pages;
    $('#page-info').textContent =
      'Page ' + p.page + ' of ' + p.pages + ' · ' + window.VG.num(p.total) + ' alerts';
    $('#prev-page').disabled = !p.hasPrev;
    $('#next-page').disabled = !p.hasNext;
  }

  function queryParams() {
    var params = {
      page: state.page,
      limit: state.limit,
      sort: state.sort,
      q: state.q
    };

    // Quick filters are shortcuts over the same API parameters.
    if (state.quick === 'critical') params.severity = 'critical';
    else if (state.quick === 'untriaged') params.status = 'new';
    else {
      if (state.severity) params.severity = state.severity;
      if (state.status) params.status = state.status;
    }

    return params;
  }

  function loadAlerts() {
    return V.api
      .alerts(queryParams())
      .then(function (res) {
        // "Assigned to me" has no server-side filter; narrow the page client-side.
        if (state.quick === 'mine') {
          res = {
            data: res.data.filter(function (a) {
              return a.assignee === me.email;
            }),
            pagination: res.pagination
          };
        }
        renderAlerts(res);
      })
      .catch(function (err) {
        tbody.replaceChildren(
          window.VG.errorCell(8, 'Could not load alerts: ' + err.message)
        );
      });
  }

  loadAlerts();

  /* ------------------------------------------------------------ filters */

  var searchTimer;
  $('#f-search').addEventListener('input', function (e) {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function () {
      state.q = e.target.value.trim();
      state.page = 1;
      loadAlerts();
    }, 260);
  });

  ['f-severity', 'f-status', 'f-sort'].forEach(function (id) {
    $('#' + id).addEventListener('change', function (e) {
      var key = id.split('-')[1];
      state[key === 'sort' ? 'sort' : key] = e.target.value;
      state.page = 1;
      // An explicit dropdown choice overrides an active quick filter.
      if (key !== 'sort') {
        state.quick = '';
        $$('#quick-filters .chip').forEach(function (c) {
          c.classList.toggle('on', c.dataset.quick === '');
        });
      }
      loadAlerts();
    });
  });

  $$('#quick-filters .chip').forEach(function (chip) {
    chip.addEventListener('click', function () {
      state.quick = chip.dataset.quick;
      state.page = 1;
      $$('#quick-filters .chip').forEach(function (c) {
        c.classList.toggle('on', c === chip);
      });
      loadAlerts();
    });
  });

  $('#prev-page').addEventListener('click', function () {
    if (state.page > 1) {
      state.page -= 1;
      loadAlerts();
    }
  });

  $('#next-page').addEventListener('click', function () {
    if (state.page < state.pages) {
      state.page += 1;
      loadAlerts();
    }
  });

  /* ------------------------------------------------------------- stream */

  var liveCount = $('[data-live-count]');

  function badge(text, cls) {
    var b = $('[data-stream-badge]');
    if (b) {
      b.textContent = text;
      b.className = 'badge badge-dot ' + cls;
    }
  }

  V.stream({
    connected: function () {
      badge('LIVE', 'sev-ok');
    },
    alert: function (a) {
      // The map runs regardless of whether the queue is paused: pausing stops
      // rows moving under the analyst's cursor, not the world.
      if (window.VGMap) window.VGMap.attack(a.severity);

      if (!state.streaming) return;

      state.newSinceLoad += 1;
      if (liveCount) liveCount.textContent = '+' + state.newSinceLoad;

      // Only prepend when the viewer is on page 1 of an unfiltered newest-first
      // view — otherwise a live row would break the sort or the filter.
      var plainView =
        state.page === 1 &&
        state.sort === 'ts' &&
        !state.q &&
        !state.severity &&
        !state.status &&
        (state.quick === '' || (state.quick === 'critical' && a.severity === 'critical') ||
          (state.quick === 'untriaged' && a.status === 'new'));

      if (plainView) {
        if (tbody.querySelector('.empty')) tbody.innerHTML = '';
        tbody.insertBefore(buildRow(a, true), tbody.firstChild);
        while (tbody.children.length > state.limit) {
          tbody.removeChild(tbody.lastChild);
        }
      }

      if (a.severity === 'critical') {
        window.VG.toast('Critical detection', a.rule + ' on ' + a.host, 'crit');
        // Pull the operator back when they are on another tab.
        if (window.VGFx) window.VGFx.flashTitle('CRITICAL DETECTION');
      }
    },
    'alert-updated': function (a) {
      alertCache[a.id] = a;
      var row = tbody.querySelector('tr[data-id="' + a.id + '"]');
      if (row) row.replaceWith(buildRow(a, false));
    },
    incident: function (i) {
      window.VG.toast('Incident opened', i.id + ' · ' + i.title, 'warn');
      loadStats();
    },
    error: function () {
      badge('RECONNECTING', 'sev-medium');
    }
  });

  $('#toggle-stream').addEventListener('click', function () {
    state.streaming = !state.streaming;
    this.textContent = state.streaming ? 'Pause stream' : 'Resume stream';
    badge(state.streaming ? 'LIVE' : 'PAUSED', state.streaming ? 'sev-ok' : 'sev-info');
    if (state.streaming) loadAlerts();
  });

  /* ------------------------------------------------------------- assets */

  V.api
    .assets()
    .then(function (res) {
      var body = $('#asset-rows');
      body.innerHTML = '';
      $('#asset-count').textContent = res.total + ' assets';

      res.data.forEach(function (a) {
        var tr = el('tr');
        tr.appendChild(el('td', 'strong cell-mono', a.host));
        tr.appendChild(el('td', 'cell-mono', a.ip));
        tr.appendChild(el('td', null, a.type));
        tr.appendChild(el('td', null, a.zone));

        var crit = el('td');
        crit.appendChild(
          el(
            'span',
            'badge sev-' + (a.criticality === 'critical' ? 'critical' : a.criticality === 'high' ? 'high' : 'info'),
            a.criticality
          )
        );
        tr.appendChild(crit);

        tr.appendChild(el('td', null, a.owner));

        var count = el('td', 'cell-mono');
        count.textContent = String(a.alerts24h);
        if (a.alerts24h > 20) count.style.color = 'var(--crit)';
        tr.appendChild(count);

        var agent = el('td', 'cell-mono');
        agent.textContent = a.agentVersion || '—';
        if (a.status === 'degraded') {
          agent.appendChild(document.createTextNode(' '));
          agent.appendChild(el('span', 'badge sev-medium', 'degraded'));
        }
        tr.appendChild(agent);

        body.appendChild(tr);
      });

      if (window.VGFx) window.VGFx.cascadeOnView(body, body.children, { step: 30 });
    })
    .catch(function () {
      $('#asset-rows').innerHTML =
        '<tr><td colspan="8" class="empty">Inventory unavailable.</td></tr>';
    });

  /* ------------------------------------------------------ triage drawer */

  var drawer = $('[data-drawer]');
  var backdrop = $('[data-drawer-backdrop]');
  var currentId = null;

  function closeDrawer() {
    drawer.classList.remove('open');
    backdrop.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    currentId = null;
  }

  function openAlert(id) {
    currentId = id;
    var cached = alertCache[id];

    drawer.classList.add('open');
    backdrop.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');

    if (cached) renderDrawer(cached);
    V.api
      .alert(id)
      .then(function (res) {
        if (currentId === id) renderDrawer(res.data);
      })
      .catch(function () {});
  }

  function renderDrawer(a) {
    $('[data-drawer-id]').textContent = a.id + ' · ' + a.ruleId;
    $('[data-drawer-title]').textContent = a.rule;

    var body = $('[data-drawer-body]');
    body.innerHTML = '';

    // ---- severity + risk header
    var head = el('div', 'flex gap-sm wrap-flex mb-2');
    head.appendChild(el('span', 'badge badge-dot sev-' + a.severity, a.severity));
    head.appendChild(el('span', 'badge', 'risk ' + a.risk + '/100'));
    head.appendChild(el('span', 'badge', 'confidence ' + a.confidence + '%'));
    head.appendChild(el('span', 'badge', a.status));
    body.appendChild(head);

    var meter = el('div', 'meter ' + (a.risk >= 85 ? 'crit' : a.risk >= 65 ? 'high' : 'low'));
    var fill = el('span');
    fill.style.width = a.risk + '%';
    meter.appendChild(fill);
    meter.style.marginBottom = '1.4rem';
    body.appendChild(meter);

    // ---- detail table
    var dl = el('dl', 'kv');
    var rows = [
      ['Detected', window.VG.fullTime(a.ts) + ' (' + window.VG.timeAgo(a.ts) + ')'],
      ['Technique', a.technique + ' — ' + a.techniqueName],
      ['Tactic', a.tactic],
      ['Telemetry', a.source],
      ['Asset', a.host + ' (' + a.ip + ')'],
      ['Asset class', a.assetType + ' · ' + a.criticality + ' criticality'],
      ['Zone / owner', a.zone + ' · ' + a.owner],
      ['Principal', a.user],
      ['Source address', a.sourceIp + ' → port ' + a.destPort],
      ['Assignee', a.assignee || 'unassigned']
    ];
    if (a.indicator) rows.push(['Indicator', a.indicator + ' (' + a.indicatorType + ')']);
    if (a.actor) rows.push(['Attributed actor', a.actor]);
    if (a.incidentId) rows.push(['Incident', a.incidentId]);

    rows.forEach(function (pair) {
      dl.appendChild(el('dt', null, pair[0]));
      dl.appendChild(el('dd', null, pair[1]));
    });
    body.appendChild(dl);

    body.appendChild(el('div', 'stat-label', 'What fired'));
    var desc = el('p');
    desc.textContent = a.description;
    desc.style.marginBottom = '1.2rem';
    body.appendChild(desc);

    body.appendChild(el('div', 'stat-label', 'Recommended response'));
    var rec = el('p');
    rec.textContent = a.recommendation;
    rec.style.marginBottom = '1.4rem';
    body.appendChild(rec);

    // ---- notes
    if (a.notes && a.notes.length) {
      body.appendChild(el('div', 'stat-label', 'Analyst notes'));
      var ul = el('ul', 'timeline');
      ul.style.marginTop = '.75rem';
      a.notes
        .slice()
        .reverse()
        .forEach(function (n) {
          var li = el('li');
          li.appendChild(el('span', 'ts', window.VG.fullTime(n.ts)));
          li.appendChild(el('span', 'who', n.author));
          li.appendChild(el('p', null, n.text));
          ul.appendChild(li);
        });
      body.appendChild(ul);
    }

    // ---- triage actions
    var actions = el('div');
    actions.style.borderTop = '1px solid var(--line)';
    actions.style.paddingTop = '1.25rem';
    actions.style.marginTop = '1.25rem';
    actions.appendChild(el('div', 'stat-label', 'Triage actions'));

    var statusRow = el('div', 'chip-row mt-1');
    ['triaged', 'investigating', 'contained', 'closed'].forEach(function (s) {
      var chip = el('button', 'chip' + (a.status === s ? ' on' : ''), s);
      chip.type = 'button';
      chip.addEventListener('click', function () {
        setStatus(a.id, s);
      });
      statusRow.appendChild(chip);
    });
    actions.appendChild(statusRow);

    var noteField = el('div', 'field mt-2');
    var label = el('label', null, 'Add an analyst note');
    label.setAttribute('for', 'note-input');
    noteField.appendChild(label);
    var ta = el('textarea', 'textarea');
    ta.id = 'note-input';
    ta.rows = 3;
    ta.placeholder = 'What did you find? What did you do?';
    ta.style.minHeight = '80px';
    noteField.appendChild(ta);
    actions.appendChild(noteField);

    var btns = el('div', 'btn-row');

    var saveNote = el('button', 'btn btn-ghost btn-sm', 'Save note');
    saveNote.type = 'button';
    saveNote.addEventListener('click', function () {
      var text = ta.value.trim();
      if (!text) {
        window.VG.toast('Note is empty', 'Write something before saving.', 'warn');
        return;
      }
      saveNote.disabled = true;
      V.api
        .updateAlert(a.id, { note: text, assignee: me.email })
        .then(function (res) {
          window.VG.toast('Note saved', 'Alert ' + a.id + ' updated.');
          renderDrawer(res.data);
          loadAlerts();
        })
        .catch(function (err) {
          window.VG.toast('Could not save', err.message, 'crit');
          saveNote.disabled = false;
        });
    });
    btns.appendChild(saveNote);

    var claim = el('button', 'btn btn-ghost btn-sm', 'Assign to me');
    claim.type = 'button';
    claim.addEventListener('click', function () {
      V.api
        .updateAlert(a.id, { assignee: me.email, status: 'investigating' })
        .then(function (res) {
          window.VG.toast('Alert claimed', a.id + ' assigned to you.');
          renderDrawer(res.data);
          loadAlerts();
        })
        .catch(function (err) {
          window.VG.toast('Could not assign', err.message, 'crit');
        });
    });
    btns.appendChild(claim);

    if (!a.incidentId) {
      var esc = el('button', 'btn btn-danger btn-sm', 'Escalate to incident');
      esc.type = 'button';
      esc.addEventListener('click', function () {
        esc.disabled = true;
        V.api
          .escalate(a.id)
          .then(function (res) {
            window.VG.toast('Incident opened', res.data.id + ' created from ' + a.id);
            closeDrawer();
            loadAlerts();
            loadStats();
          })
          .catch(function (err) {
            window.VG.toast('Escalation failed', err.message, 'crit');
            esc.disabled = false;
          });
      });
      btns.appendChild(esc);
    } else {
      var view = el('a', 'btn btn-ghost btn-sm', 'View ' + a.incidentId);
      view.href = '/incidents.html?id=' + encodeURIComponent(a.incidentId);
      btns.appendChild(view);
    }

    // Marking a detection wrong is the input the tuning report is built from,
    // so it sits alongside the other actions rather than buried in a menu.
    if (a.falsePositive) {
      var restore = el('button', 'btn btn-ghost btn-sm', 'Not a false positive');
      restore.type = 'button';
      restore.addEventListener('click', function () {
        restore.disabled = true;
        V.request('/alerts/' + encodeURIComponent(a.id) + '/true-positive', { method: 'POST' })
          .then(function (res) {
            window.VG.toast('Mark removed', a.id + ' reopened for investigation.', 'ok');
            renderDrawer(res.data);
            loadAlerts();
          })
          .catch(function (err) {
            window.VG.toast('Could not update', err.message, 'crit');
            restore.disabled = false;
          });
      });
      btns.appendChild(restore);
    } else {
      var fp = el('button', 'btn btn-ghost btn-sm', 'False positive');
      fp.type = 'button';
      fp.addEventListener('click', function () { openFalsePositive(a); });
      btns.appendChild(fp);
    }

    actions.appendChild(btns);

    if (a.falsePositive) {
      var mark = el('div', 'notice notice-warn mt-2');
      mark.style.fontSize = '.82rem';
      mark.textContent =
        'Marked false positive by ' + a.fpMarkedBy + ' — ' + (a.fpReason || '') +
        (a.fpCategory && FP_CATEGORIES[a.fpCategory] ? ' (' + FP_CATEGORIES[a.fpCategory] + ')' : '');
      body.appendChild(mark);
    }

    body.appendChild(actions);
  }

  /* ------------------------------------------------- false positives */

  var FP_CATEGORIES = {};

  if (V.session.isAuthed()) {
    V.request('/soc/tuning')
      .then(function (res) { FP_CATEGORIES = res.categories || {}; })
      .catch(function () {
        // The labels are only needed to mark something, which needs a session
        // anyway; failing quietly leaves the rest of the console working.
      });
  }

  /** Asks why before recording, because the category drives the advice. */
  // Built once: prompt() needs real line breaks, and escaping them inline
  // has already been mangled once by a shell heredoc.
  var BREAK = String.fromCharCode(10);

  function openFalsePositive(alert) {
    var keys = Object.keys(FP_CATEGORIES);
    if (!keys.length) {
      window.VG.toast('Unavailable', 'Sign in to mark false positives.', 'warn');
      return;
    }

    var menu = keys.map(function (key, index) {
      return '  ' + (index + 1) + '. ' + FP_CATEGORIES[key];
    }).join(String.fromCharCode(10));

    var choice = prompt('Why did this detection fire on something benign?' + BREAK + BREAK + menu + BREAK + BREAK + 'Enter a number:');
    if (choice === null) return;

    var category = keys[Number(choice) - 1];
    if (!category) {
      window.VG.toast('Not recognised', 'Enter one of the listed numbers.', 'warn');
      return;
    }

    var reason = prompt('Briefly, what made it benign? (at least 8 characters)');
    if (reason === null) return;
    if (reason.trim().length < 8) {
      window.VG.toast('Reason too short', 'Say what made it benign in at least 8 characters.', 'warn');
      return;
    }

    V.request('/alerts/' + encodeURIComponent(alert.id) + '/false-positive', {
      method: 'POST',
      body: { category: category, reason: reason.trim() }
    })
      .then(function (res) {
        // Show the effect on the rule rather than letting the mark vanish
        // into a report nobody opens.
        window.VG.toast('Recorded', res.message, 'ok');
        renderDrawer(res.data);
        loadAlerts();
        loadSocStatus();
      })
      .catch(function (err) {
        window.VG.toast('Could not record', err.message, 'crit');
      });
  }

  function setStatus(id, status) {
    V.api
      .updateAlert(id, { status: status })
      .then(function (res) {
        window.VG.toast('Status updated', id + ' → ' + status);
        renderDrawer(res.data);
        loadAlerts();
      })
      .catch(function (err) {
        window.VG.toast('Update failed', err.message, 'crit');
      });
  }

  backdrop.addEventListener('click', closeDrawer);
  $$('[data-drawer-close]').forEach(function (b) {
    b.addEventListener('click', closeDrawer);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeDrawer();
  });

  /* ---------------------------------------------------------- export */

  var alertExport = $('#a-export');
  if (alertExport) {
    alertExport.addEventListener('click', function () {
      var token = V.session.token();
      if (!token) {
        window.VG.toast('Sign in required', 'Exports need an active session.', 'warn');
        return;
      }

      // Export what the analyst is actually looking at, filters and all.
      var params = new URLSearchParams();
      if (state.q) params.set('q', state.q);
      if (state.severity) params.set('severity', state.severity);
      if (state.status) params.set('status', state.status);
      if (state.sort) params.set('sort', state.sort);

      alertExport.disabled = true;
      alertExport.textContent = 'Exporting…';

      fetch('/api/export/alerts' + (params.toString() ? '?' + params : ''), {
        headers: { Authorization: 'Bearer ' + token }
      })
        .then(function (res) {
          if (!res.ok) throw new Error('Export failed (' + res.status + ')');
          return res.blob();
        })
        .then(function (blob) {
          var href = URL.createObjectURL(blob);
          var anchor = document.createElement('a');
          anchor.href = href;
          anchor.download = 'vgil-alerts-' + new Date().toISOString().slice(0, 10) + '.csv';
          document.body.appendChild(anchor);
          anchor.click();
          document.body.removeChild(anchor);
          setTimeout(function () { URL.revokeObjectURL(href); }, 1000);
          window.VG.toast('Exported', 'CSV downloaded.', 'ok');
        })
        .catch(function (err) {
          window.VG.toast('Export failed', err.message, 'crit');
        })
        .then(function () {
          alertExport.disabled = false;
          alertExport.textContent = 'Export CSV';
        });
    });
  }

  /* ==================================================================
     FOLLOW-THE-SUN CONSOLE
     ==================================================================
     Every figure here comes from the rota and the alert rows. Where there
     is nothing to measure it shows a dash rather than a number, because a
     dashboard that cannot distinguish "no data" from "instant" stops being
     worth reading.
     ================================================================== */

  function renderSocStatus(state, metrics) {
    var onDuty = $('#soc-onduty');
    var onDutySub = $('#soc-onduty-sub');

    if (state.onDuty.length) {
      onDuty.textContent = state.onDuty.map(function (shift) { return shift.region; }).join(' + ');
      onDutySub.textContent = state.onDuty
        .map(function (shift) {
          return shift.label + (shift.pod ? ' · ' + shift.pod.name : '');
        })
        .join(', ');
    } else {
      onDuty.textContent = 'Nobody';
      onDuty.style.color = 'var(--crit)';
      onDutySub.textContent = 'No active shift covers ' +
        String(state.utcHour).padStart(2, '0') + ':00 UTC';
    }

    var next = $('#soc-next');
    var nextSub = $('#soc-next-sub');
    if (state.nextHandover) {
      next.textContent = 'in ' + state.nextHandover.inHours + 'h';
      nextSub.textContent = state.nextHandover.incoming.length
        ? 'to ' + state.nextHandover.incoming.map(function (s) { return s.region; }).join(' + ')
        : 'console goes unstaffed';
    } else {
      next.textContent = '—';
      nextSub.textContent = 'single shift covers the whole day';
    }

    var coverage = $('#soc-coverage');
    coverage.textContent = state.coverage
      ? state.coverage.complete
        ? '24/24 COVERED'
        : state.coverage.coveredHours + '/24 COVERED'
      : 'NO ROTA';
    coverage.className = 'badge mono ' +
      (state.coverage && state.coverage.complete ? 'is-ok' : 'is-crit');

    var claim = $('#soc-claim');
    claim.textContent = state.claim;
    claim.className = 'notice mt-2 ' +
      (state.coverage && state.coverage.complete ? 'notice-ok' : 'notice-err');

    var escalations = $('#soc-escalations');
    escalations.textContent = state.openEscalations;
    if (state.openEscalations > 0) escalations.style.color = 'var(--high)';

    if (metrics) {
      $('#soc-triage').textContent = metrics.triage.medianLabel;
      $('#soc-triage-sub').textContent = metrics.triage.sampleSize
        ? 'median of ' + metrics.triage.sampleSize + ' triaged · p90 ' + metrics.triage.p90Label
        : 'nothing triaged in this window yet';

      if (metrics.escalation.sampleSize) {
        $('#soc-escalations-sub').textContent =
          'median ' + metrics.escalation.medianLabel + ' to the bridge';
      }
    }
  }

  function loadSocStatus() {
    return Promise.all([
      V.request('/soc/status', { auth: false }).catch(function () { return null; }),
      V.request('/soc/metrics', { auth: false }).catch(function () { return null; })
    ]).then(function (results) {
      if (results[0]) renderSocStatus(results[0], results[1]);

      var handover = $('#soc-handover');
      if (handover) handover.hidden = !V.session.isAuthed();
    });
  }

  var handoverBtn = $('#soc-handover');
  if (handoverBtn) {
    handoverBtn.addEventListener('click', function () {
      var notes = prompt(
        'Handover note for the incoming shift.\n\n' +
        'The open incident queue is snapshotted automatically — describe what the next ' +
        'analyst needs to know. "Nothing to report" is a valid note.'
      );
      if (notes === null) return;
      if (notes.trim().length < 10) {
        window.VG.toast('Note too short', 'Write at least 10 characters.', 'warn');
        return;
      }

      V.request('/soc/handovers', { method: 'POST', body: { notes: notes.trim() } })
        .then(function (res) {
          window.VG.toast(
            'Handover recorded',
            res.data.openCount + ' open incident(s) passed to the next shift.',
            'ok'
          );
          loadSocStatus();
        })
        .catch(function (err) {
          window.VG.toast('Could not record handover', err.message, 'crit');
        });
    });
  }

  loadSocStatus();
  // The rota changes on the hour, so a slow refresh keeps "on console now"
  // honest without polling hard.
  setInterval(loadSocStatus, 120000);
})();
