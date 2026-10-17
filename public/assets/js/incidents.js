/**
 * Incident queue: list, filters, detail drawer with response timeline,
 * and (when authenticated) status transitions and timeline entries.
 */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;
  var $$ = window.VG.$$;
  var el = window.VG.el;

  var authed = V.session.isAuthed();
  var me = V.session.user() || {};

  var state = { page: 1, limit: 20, status: '', severity: '', q: '', pages: 1 };

  var tbody = $('#incident-rows');

  /* ------------------------------------------------------------ helpers */

  /** Wall-clock duration of an incident, open or closed. */
  function lifespan(inc) {
    var end = inc.closedAt ? new Date(inc.closedAt) : new Date();
    var mins = Math.round((end - new Date(inc.openedAt)) / 60000);
    return window.VG.duration(mins) + (inc.closedAt ? '' : ' (open)');
  }

  function statusBadge(status) {
    var cls =
      status === 'closed'
        ? 'sev-ok'
        : status === 'contained'
        ? 'sev-low'
        : status === 'investigating'
        ? 'sev-high'
        : status === 'triaged'
        ? 'sev-medium'
        : 'sev-critical';
    return el('span', 'badge badge-dot ' + cls, status);
  }

  /* --------------------------------------------------------------- list */

  function render(res) {
    tbody.innerHTML = '';

    var s = res.summary;
    $('[data-sum="open"]').textContent = s.open;
    $('[data-sum="critical"]').textContent = s.critical;
    $('[data-sum="closed"]').textContent = s.closed;
    $('[data-sum="total"]').textContent = s.total;

    if (!res.data.length) {
      tbody.innerHTML = '<tr><td colspan="10" class="empty">No incidents match those filters.</td></tr>';
    } else {
      res.data.forEach(function (inc) {
        var tr = el('tr', 'row-click');
        tr.dataset.id = inc.id;

        tr.appendChild(el('td', 'cell-mono strong', inc.id));

        var pri = el('td');
        pri.appendChild(
          el(
            'span',
            'badge ' + (inc.priority === 'P1' ? 'sev-critical' : inc.priority === 'P2' ? 'sev-high' : 'sev-info'),
            inc.priority
          )
        );
        tr.appendChild(pri);

        var sev = el('td');
        sev.appendChild(el('span', 'badge badge-dot sev-' + inc.severity, inc.severity));
        tr.appendChild(sev);

        tr.appendChild(el('td', 'strong', inc.title));
        tr.appendChild(el('td', 'cell-mono', inc.host || '—'));
        tr.appendChild(el('td', 'cell-mono', inc.analyst || '—'));

        var st = el('td');
        st.appendChild(statusBadge(inc.status));
        tr.appendChild(st);

        var opened = el('td', 'cell-mono');
        opened.textContent = window.VG.timeAgo(inc.openedAt);
        opened.title = window.VG.fullTime(inc.openedAt);
        tr.appendChild(opened);

        tr.appendChild(el('td', 'cell-mono', lifespan(inc)));

        tr.addEventListener('click', function () {
          open(inc.id);
        });
        tbody.appendChild(tr);
      });

      if (window.VGFx) window.VGFx.cascade(tbody.children, { step: 40 });
    }

    decorateRowsWithSelection();

    var p = res.pagination;
    state.pages = p.pages;
    $('#i-page-info').textContent =
      'Page ' + p.page + ' of ' + p.pages + ' · ' + p.total + ' incidents';
    $('#i-prev').disabled = !p.hasPrev;
    $('#i-next').disabled = !p.hasNext;
  }

  function load() {
    return V.api
      .incidents({
        page: state.page,
        limit: state.limit,
        status: state.status,
        severity: state.severity,
        q: state.q
      })
      .then(render)
      .catch(function (err) {
        tbody.replaceChildren(
          window.VG.errorCell(9, 'Could not load incidents: ' + err.message)
        );
      });
  }

  load();

  /* ------------------------------------------------------------ filters */

  var timer;
  $('#i-search').addEventListener('input', function (e) {
    clearTimeout(timer);
    timer = setTimeout(function () {
      state.q = e.target.value.trim();
      state.page = 1;
      load();
    }, 260);
  });

  $('#i-status').addEventListener('change', function (e) {
    state.status = e.target.value;
    state.page = 1;
    load();
  });

  $('#i-severity').addEventListener('change', function (e) {
    state.severity = e.target.value;
    state.page = 1;
    load();
  });

  $('#i-prev').addEventListener('click', function () {
    if (state.page > 1) {
      state.page -= 1;
      load();
    }
  });

  $('#i-next').addEventListener('click', function () {
    if (state.page < state.pages) {
      state.page += 1;
      load();
    }
  });

  /* ------------------------------------------------------------- drawer */

  var drawer = $('[data-drawer]');
  var backdrop = $('[data-drawer-backdrop]');
  var currentId = null;

  function close() {
    drawer.classList.remove('open');
    backdrop.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    currentId = null;

    // Keep the URL clean when a deep-linked incident is dismissed.
    if (location.search.indexOf('id=') !== -1) {
      history.replaceState(null, '', location.pathname);
    }
  }

  function open(id) {
    currentId = id;
    drawer.classList.add('open');
    backdrop.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');

    var body = $('[data-drawer-body]');
    body.innerHTML = '<div class="skeleton" style="height:300px"></div>';

    V.api
      .incident(id)
      .then(function (res) {
        if (currentId === id) renderDrawer(res.data, res.relatedAlerts);
      })
      .catch(function (err) {
        body.replaceChildren(window.VG.errorBox(err.message));
      });
  }

  function renderDrawer(inc, related) {
    $('[data-drawer-id]').textContent = inc.id + ' · ' + inc.priority;
    $('[data-drawer-title]').textContent = inc.title;

    var body = $('[data-drawer-body]');
    body.innerHTML = '';

    var head = el('div', 'flex gap-sm wrap-flex mb-2');
    head.appendChild(el('span', 'badge badge-dot sev-' + inc.severity, inc.severity));
    head.appendChild(statusBadge(inc.status));
    head.appendChild(el('span', 'badge', lifespan(inc)));
    body.appendChild(head);

    var dl = el('dl', 'kv');
    var rows = [
      ['Opened', window.VG.fullTime(inc.openedAt)],
      ['Acknowledged', inc.acknowledgedAt ? window.VG.fullTime(inc.acknowledgedAt) : 'pending'],
      ['Closed', inc.closedAt ? window.VG.fullTime(inc.closedAt) : '—'],
      ['Lead analyst', inc.analyst || 'unassigned'],
      ['Affected asset', (inc.host || '—') + ' · ' + (inc.zone || '—')],
      ['Asset owner', inc.owner || '—'],
      ['Detection', inc.rule ? inc.rule + ' (' + inc.ruleId + ')' : '—'],
      ['ATT&CK', inc.technique ? inc.technique + ' · ' + inc.tactic : '—']
    ];
    if (inc.sourceAlertId) rows.push(['Source alert', inc.sourceAlertId]);

    rows.forEach(function (p) {
      dl.appendChild(el('dt', null, p[0]));
      dl.appendChild(el('dd', null, p[1]));
    });
    body.appendChild(dl);

    body.appendChild(el('div', 'stat-label', 'Summary'));
    var sum = el('p');
    sum.textContent = inc.summary;
    sum.style.marginBottom = '1.5rem';
    body.appendChild(sum);

    body.appendChild(el('div', 'stat-label', 'Response timeline'));
    var ul = el('ul', 'timeline');
    ul.style.marginTop = '.85rem';
    inc.timeline
      .slice()
      .reverse()
      .forEach(function (t) {
        var li = el('li');
        li.appendChild(el('span', 'ts', window.VG.fullTime(t.ts)));
        li.appendChild(el('span', 'who', t.actor));
        li.appendChild(el('p', null, t.entry));
        ul.appendChild(li);
      });
    body.appendChild(ul);

    // The response history plays back newest to oldest as the drawer settles.
    if (window.VGFx) {
      window.VGFx.cascade(dl.children, { step: 26, lead: 140 });
      window.VGFx.cascade(ul.children, { step: 90, lead: 260, side: true });
    }

    if (related && related.length) {
      body.appendChild(el('div', 'stat-label mt-2', 'Linked detections (' + related.length + ')'));
      related.forEach(function (a) {
        var row = el('div', 'metric-row');
        var left = el('div');
        left.appendChild(el('div', null, a.rule));
        var meta = el('div', 'mono');
        meta.textContent = a.id + ' · ' + a.host;
        meta.style.fontSize = '.72rem';
        meta.style.color = 'var(--dim)';
        left.appendChild(meta);
        row.appendChild(left);
        row.appendChild(el('span', 'badge badge-dot sev-' + a.severity, a.severity));
        body.appendChild(row);
      });
    }

    if (!authed) {
      var hint = el('p', 'form-note');
      hint.textContent = 'Sign in to update this incident or add a timeline entry.';
      body.appendChild(hint);
      return;
    }

    /* ---- authenticated actions */

    var actions = el('div');
    actions.style.borderTop = '1px solid var(--line)';
    actions.style.paddingTop = '1.25rem';
    actions.style.marginTop = '1.5rem';
    actions.appendChild(el('div', 'stat-label', 'Update incident'));

    var chips = el('div', 'chip-row mt-1');
    ['triaged', 'investigating', 'contained', 'closed'].forEach(function (s) {
      var chip = el('button', 'chip' + (inc.status === s ? ' on' : ''), s);
      chip.type = 'button';
      chip.addEventListener('click', function () {
        V.api
          .updateIncident(inc.id, { status: s })
          .then(function (res) {
            window.VG.toast('Incident updated', inc.id + ' → ' + s);
            V.api.incident(inc.id).then(function (full) {
              renderDrawer(full.data, full.relatedAlerts);
            });
            load();
            return res;
          })
          .catch(function (err) {
            window.VG.toast('Update failed', err.message, 'crit');
          });
      });
      chips.appendChild(chip);
    });
    actions.appendChild(chips);

    var field = el('div', 'field mt-2');
    field.appendChild(el('label', null, 'Add a timeline entry'));
    var ta = el('textarea', 'textarea');
    ta.rows = 3;
    ta.style.minHeight = '80px';
    ta.placeholder = 'e.g. Host rebuilt from gold image and returned to service.';
    field.appendChild(ta);
    actions.appendChild(field);

    var save = el('button', 'btn btn-primary btn-sm', 'Add entry');
    save.type = 'button';
    save.addEventListener('click', function () {
      var text = ta.value.trim();
      if (!text) {
        window.VG.toast('Entry is empty', 'Write something first.', 'warn');
        return;
      }
      save.disabled = true;
      V.api
        .updateIncident(inc.id, { note: text })
        .then(function () {
          window.VG.toast('Timeline updated', inc.id);
          return V.api.incident(inc.id).then(function (full) {
            renderDrawer(full.data, full.relatedAlerts);
          });
        })
        .catch(function (err) {
          window.VG.toast('Could not add entry', err.message, 'crit');
          save.disabled = false;
        });
    });
    actions.appendChild(save);

    body.appendChild(actions);

    // Appended asynchronously so a slow fetch never delays the rest of the
    // drawer.
    V.request('/soc/escalations?limit=50')
      .then(function (res) {
        if (currentId !== inc.id) return;
        var mine = (res.data || []).filter(function (row) { return row.incidentId === inc.id; });
        body.appendChild(escalationSection(inc, mine));
      })
      .catch(function () {
        /* the drawer is still useful without it */
      });

    loadContainmentActions().then(function () {
      V.request('/containment/incident/' + encodeURIComponent(inc.id))
        .then(function (res) {
          if (currentId !== inc.id) return;
          body.appendChild(containmentSection(inc.id, res.data || []));
        })
        .catch(function () {
          /* the drawer is still useful without it */
        });
    });
  }

  backdrop.addEventListener('click', close);
  $$('[data-drawer-close]').forEach(function (b) {
    b.addEventListener('click', close);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') close();
  });

  /* -------------------------------------------------- authed extras */

  if (authed) {
    var hint = $('#auth-hint');
    if (hint) hint.hidden = true;

    var newBtn = $('#new-incident');
    if (newBtn) {
      newBtn.hidden = false;
      newBtn.addEventListener('click', openCreateForm);
    }
  }

  function openCreateForm() {
    drawer.classList.add('open');
    backdrop.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
    currentId = null;

    $('[data-drawer-id]').textContent = 'NEW · ' + me.email;
    $('[data-drawer-title]').textContent = 'Open an incident';

    var body = $('[data-drawer-body]');
    body.innerHTML = '';

    var form = el('form');
    form.noValidate = true;

    var notice = el('div', 'notice notice-err mb-2');
    notice.setAttribute('data-notice', '');
    notice.hidden = true;
    form.appendChild(notice);

    function field(name, label, control, hint) {
      var wrap = el('div', 'field');
      var l = el('label', null, label);
      l.setAttribute('for', 'nf-' + name);
      wrap.appendChild(l);
      control.id = 'nf-' + name;
      control.name = name;
      wrap.appendChild(control);
      if (hint) wrap.appendChild(el('div', 'hint', hint));
      var err = el('div', 'err');
      err.setAttribute('data-err', name);
      wrap.appendChild(err);
      form.appendChild(wrap);
    }

    var title = el('input', 'input');
    title.type = 'text';
    title.placeholder = 'Short description of what happened';
    field('title', 'Incident title', title, 'Minimum 6 characters.');

    var sev = el('select', 'select');
    ['critical', 'high', 'medium', 'low'].forEach(function (s) {
      var o = el('option', null, s);
      o.value = s;
      sev.appendChild(o);
    });
    sev.value = 'high';
    field('severity', 'Severity', sev);

    var host = el('input', 'input mono');
    host.type = 'text';
    host.placeholder = 'sql-fin-prod';
    field('host', 'Affected host', host, 'Optional.');

    var summary = el('textarea', 'textarea');
    summary.rows = 4;
    summary.placeholder = 'What is known so far, and what has already been done.';
    field('summary', 'Summary', summary, 'Minimum 10 characters.');

    var submit = el('button', 'btn btn-primary btn-block', 'Open incident');
    submit.type = 'submit';
    form.appendChild(submit);

    body.appendChild(form);

    window.VG.bindForm(
      form,
      function (values) {
        return V.api.createIncident(values);
      },
      {
        busyText: 'Opening…',
        onSuccess: function (res) {
          window.VG.toast('Incident opened', res.data.id + ' created.');
          load();
          open(res.data.id);
        }
      }
    );
  }

  /* ---------------------------------------------------- deep linking */

  var wanted = new URLSearchParams(location.search).get('id');
  if (wanted) open(wanted);

  /* ==================================================================
     BULK SELECTION AND EXPORT
     ==================================================================
     Selection survives re-renders (the live stream repaints the table) by
     living in a Set of ids rather than in the checkbox elements themselves.
     ================================================================== */

  var selected = new Set();

  function bulkBar() { return $('#i-bulk'); }

  function syncBulkBar() {
    var bar = bulkBar();
    if (!bar) return;

    bar.hidden = selected.size === 0;

    var count = $('#i-bulk-count');
    if (count) {
      count.textContent = selected.size + (selected.size === 1 ? ' selected' : ' selected');
    }

    // Header checkbox reflects the page, not the whole result set.
    var all = $('#i-select-all');
    if (all) {
      var boxes = $$('#incident-rows input[type="checkbox"]');
      var ticked = boxes.filter(function (b) { return b.checked; }).length;
      all.checked = boxes.length > 0 && ticked === boxes.length;
      all.indeterminate = ticked > 0 && ticked < boxes.length;
    }
  }

  /** Called by render() after it rebuilds the tbody. */
  function decorateRowsWithSelection() {
    $$('#incident-rows tr').forEach(function (tr) {
      var id = tr.dataset.id;
      if (!id) return;

      var cell = document.createElement('td');
      cell.className = 'col-select';

      var box = document.createElement('input');
      box.type = 'checkbox';
      box.checked = selected.has(id);
      box.setAttribute('aria-label', 'Select ' + id);

      // Without this the row's own click handler opens the drawer whenever
      // somebody aims for the checkbox.
      box.addEventListener('click', function (event) {
        event.stopPropagation();
      });

      box.addEventListener('change', function () {
        if (box.checked) selected.add(id);
        else selected.delete(id);
        tr.classList.toggle('is-selected', box.checked);
        syncBulkBar();
      });

      cell.addEventListener('click', function (event) {
        event.stopPropagation();
      });

      cell.appendChild(box);
      tr.insertBefore(cell, tr.firstChild);
      tr.classList.toggle('is-selected', selected.has(id));
    });

    syncBulkBar();
  }

  var selectAll = $('#i-select-all');
  if (selectAll) {
    selectAll.addEventListener('change', function () {
      $$('#incident-rows input[type="checkbox"]').forEach(function (box) {
        box.checked = selectAll.checked;
        var tr = box.closest('tr');
        if (!tr || !tr.dataset.id) return;
        if (selectAll.checked) selected.add(tr.dataset.id);
        else selected.delete(tr.dataset.id);
        tr.classList.toggle('is-selected', selectAll.checked);
      });
      syncBulkBar();
    });
  }

  var bulkClear = $('#i-bulk-clear');
  if (bulkClear) {
    bulkClear.addEventListener('click', function () {
      selected.clear();
      $$('#incident-rows input[type="checkbox"]').forEach(function (box) {
        box.checked = false;
        var tr = box.closest('tr');
        if (tr) tr.classList.remove('is-selected');
      });
      syncBulkBar();
    });
  }

  /**
   * Applies one PATCH per selected incident.
   *
   * There is no bulk endpoint on purpose: each change has to write its own
   * timeline entry, and a partial failure must leave the successful ones
   * applied rather than rolling back work an analyst has already decided on.
   */
  function applyBulk(patch, label) {
    if (!selected.size) return;

    var ids = Array.from(selected);
    var buttons = $$('#i-bulk button');
    buttons.forEach(function (b) { b.disabled = true; });

    Promise.all(
      ids.map(function (id) {
        return V.request('/incidents/' + encodeURIComponent(id), {
          method: 'PATCH',
          body: patch
        })
          .then(function () { return { id: id, ok: true }; })
          .catch(function (err) { return { id: id, ok: false, error: err.message }; });
      })
    ).then(function (results) {
      var failed = results.filter(function (r) { return !r.ok; });
      var done = results.length - failed.length;

      if (!failed.length) {
        window.VG.toast(label, done + ' incident' + (done === 1 ? '' : 's') + ' updated.', 'ok');
      } else {
        window.VG.toast(
          'Partly applied',
          done + ' updated, ' + failed.length + ' failed: ' + failed[0].error,
          'warn'
        );
      }

      // Keep anything that failed selected so it can be retried.
      selected = new Set(failed.map(function (r) { return r.id; }));
      buttons.forEach(function (b) { b.disabled = false; });
      load();
    });
  }

  var bulkAssign = $('#i-bulk-assign');
  if (bulkAssign) {
    bulkAssign.addEventListener('click', function () {
      var user = V.session.user();
      if (!user) return;
      applyBulk({ analyst: user.email }, 'Assigned');
    });
  }

  var bulkTriage = $('#i-bulk-triage');
  if (bulkTriage) {
    bulkTriage.addEventListener('click', function () {
      applyBulk({ status: 'triaged', note: 'Bulk triaged from the incident queue.' }, 'Triaged');
    });
  }

  var bulkClose = $('#i-bulk-close');
  if (bulkClose) {
    bulkClose.addEventListener('click', function () {
      if (!confirm('Close ' + selected.size + ' incident(s)?')) return;
      applyBulk({ status: 'closed', note: 'Bulk closed from the incident queue.' }, 'Closed');
    });
  }

  /* ---------------------------------------------------------- export */

  var exportBtn = $('#i-export');
  if (exportBtn) {
    exportBtn.addEventListener('click', function () {
      var token = V.session.token();
      if (!token) {
        window.VG.toast('Sign in required', 'Exports need an active session.', 'warn');
        return;
      }

      // Export exactly what the analyst is looking at, filters included.
      var params = new URLSearchParams();
      if (state.q) params.set('q', state.q);
      if (state.status) params.set('status', state.status);
      if (state.severity) params.set('severity', state.severity);

      var url = '/api/export/incidents' + (params.toString() ? '?' + params : '');

      exportBtn.disabled = true;
      exportBtn.textContent = 'Exporting…';

      fetch(url, { headers: { Authorization: 'Bearer ' + token } })
        .then(function (res) {
          if (!res.ok) throw new Error('Export failed (' + res.status + ')');
          return res.blob();
        })
        .then(function (blob) {
          var href = URL.createObjectURL(blob);
          var anchor = document.createElement('a');
          anchor.href = href;
          anchor.download = 'vgil-incidents-' + new Date().toISOString().slice(0, 10) + '.csv';
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
          exportBtn.disabled = false;
          exportBtn.textContent = 'Export CSV';
        });
    });
  }

  /* ------------------------------------------------- printable report */

  var printBtn = $('#i-print');
  if (printBtn) {
    printBtn.addEventListener('click', function () {
      // A class on <html> rather than a separate window: the drawer is
      // already populated, and re-rendering it into a popup would duplicate
      // the whole timeline renderer just to lose the stylesheet.
      document.documentElement.classList.add('printing-incident');

      var restore = function () {
        document.documentElement.classList.remove('printing-incident');
        window.removeEventListener('afterprint', restore);
      };
      window.addEventListener('afterprint', restore);

      window.print();

      // Safari does not always fire afterprint, so this is belt and braces.
      setTimeout(restore, 2000);
    });
  }

  /* ==================================================================
     CONTAINMENT RECORDS
     ==================================================================
     These document what an analyst did. Nothing here reaches a machine —
     the platform has no agents, so a control claiming to have isolated a
     host would be asserting something it cannot know. What an incident
     needs afterwards is the defensible account, which is what this is.
     ================================================================== */

  var containmentActions = [];

  function loadContainmentActions() {
    if (!authed || containmentActions.length) return Promise.resolve(containmentActions);
    return V.request('/containment/actions')
      .then(function (res) {
        containmentActions = res.data || [];
        return containmentActions;
      })
      .catch(function () {
        return [];
      });
  }

  /** Builds the containment block appended to the incident drawer. */
  function containmentSection(incidentId, records) {
    var section = el('div', 'drawer-section');
    section.appendChild(el('h4', null, 'Containment record'));

    var note = el('p', 'text-muted');
    note.style.cssText = 'font-size:.8rem;margin:.3rem 0 .8rem';
    note.textContent =
      'A log of containment decisions and when they were lifted. Recording an action documents it — it does not execute anything.';
    section.appendChild(note);

    if (!records.length) {
      section.appendChild(el('p', 'text-muted', 'Nothing contained yet.'));
    } else {
      var list = el('div', 'timeline');

      records.forEach(function (record) {
        var item = el('div', 'timeline-item');

        var head = el('div', 'flex gap-sm items-center wrap-flex');
        head.appendChild(
          el('span', 'badge ' + (record.active ? 'is-high' : ''), record.active ? 'Active' : 'Lifted')
        );

        var label = el('strong', null, actionLabel(record.action));
        head.appendChild(label);
        item.appendChild(head);

        var target = el('div', 'mono');
        target.style.cssText = 'font-size:.82rem;margin-top:.25rem';
        target.textContent = record.target + (record.scope ? ' · ' + record.scope : '');
        item.appendChild(target);

        var why = el('div', 'text-muted');
        why.style.cssText = 'font-size:.82rem;margin-top:.25rem';
        why.textContent = record.reason;
        item.appendChild(why);

        var meta = el('div', 'text-muted');
        meta.style.cssText = 'font-size:.75rem;margin-top:.3rem';
        meta.textContent =
          record.performedBy +
          ' · ' +
          window.VG.timeAgo(record.performedAt) +
          (record.authorisedBy && record.authorisedBy !== record.performedBy
            ? ' · authorised by ' + record.authorisedBy
            : '');
        item.appendChild(meta);

        if (!record.active) {
          var lifted = el('div', 'text-muted');
          lifted.style.cssText = 'font-size:.75rem;margin-top:.2rem';
          lifted.textContent =
            'Lifted ' + window.VG.timeAgo(record.revertedAt) + ' by ' + record.revertedBy +
            (record.revertReason ? ' — ' + record.revertReason : '');
          item.appendChild(lifted);
        } else if (authed) {
          var lift = el('button', 'btn btn-ghost btn-sm', 'Record as lifted');
          lift.type = 'button';
          lift.style.marginTop = '.5rem';
          lift.addEventListener('click', function () {
            var reason = prompt('Why is this containment being lifted?');
            if (!reason || reason.trim().length < 8) {
              if (reason !== null) {
                window.VG.toast('Reason too short', 'Say why in at least 8 characters.', 'warn');
              }
              return;
            }
            V.request('/containment/' + encodeURIComponent(record.id) + '/revert', {
              method: 'POST',
              body: { reason: reason.trim() }
            })
              .then(function () {
                window.VG.toast('Containment lifted', record.target, 'ok');
                open(incidentId);
              })
              .catch(function (err) {
                window.VG.toast('Could not update', err.message, 'crit');
              });
          });
          item.appendChild(lift);
        }

        list.appendChild(item);
      });

      section.appendChild(list);
    }

    if (authed) section.appendChild(containmentForm(incidentId));
    return section;
  }

  function actionLabel(id) {
    var match = containmentActions.filter(function (a) { return a.id === id; })[0];
    return match ? match.label : id;
  }

  function containmentForm(incidentId) {
    var wrap = el('div');
    wrap.style.marginTop = '1rem';

    var toggle = el('button', 'btn btn-ghost btn-sm', '+ Record containment');
    toggle.type = 'button';
    wrap.appendChild(toggle);

    var form = el('form');
    form.hidden = true;
    form.style.marginTop = '.75rem';
    form.noValidate = true;

    var notice = el('div', 'notice notice-err mb-2');
    notice.hidden = true;
    notice.setAttribute('data-notice', '');
    form.appendChild(notice);

    // Action
    var actionField = el('div', 'field');
    actionField.appendChild(el('label', null, 'Action taken'));
    var actionSelect = el('select', 'select');
    actionSelect.name = 'action';
    containmentActions.forEach(function (action) {
      var option = el('option', null, action.label);
      option.value = action.id;
      actionSelect.appendChild(option);
    });
    actionField.appendChild(actionSelect);
    form.appendChild(actionField);

    // Target
    var targetField = el('div', 'field');
    var targetLabel = el('label', null, 'Target');
    targetField.appendChild(targetLabel);
    var targetInput = el('input', 'input mono');
    targetInput.type = 'text';
    targetInput.name = 'target';
    targetInput.maxLength = 120;
    targetField.appendChild(targetInput);
    targetField.appendChild(errSlot('target'));
    form.appendChild(targetField);

    // The target label follows the chosen action, so it asks for a hostname
    // when isolating and an account when revoking.
    function syncTargetLabel() {
      var match = containmentActions.filter(function (a) { return a.id === actionSelect.value; })[0];
      targetLabel.textContent = match ? match.targetLabel : 'Target';
      targetInput.placeholder = match ? match.detail : '';
    }
    actionSelect.addEventListener('change', syncTargetLabel);
    syncTargetLabel();

    // Scope
    var scopeField = el('div', 'field');
    scopeField.appendChild(el('label', null, 'Scope (optional)'));
    var scopeInput = el('input', 'input');
    scopeInput.type = 'text';
    scopeInput.name = 'scope';
    scopeInput.maxLength = 200;
    scopeInput.placeholder = 'Management VLAN only';
    scopeField.appendChild(scopeInput);
    form.appendChild(scopeField);

    // Reason
    var reasonField = el('div', 'field');
    reasonField.appendChild(el('label', null, 'Why'));
    var reasonInput = el('textarea', 'input');
    reasonInput.name = 'reason';
    reasonInput.rows = 2;
    reasonInput.maxLength = 400;
    reasonInput.placeholder = 'Confirmed beaconing to a known C2 address; isolating pending forensics.';
    reasonField.appendChild(reasonInput);
    reasonField.appendChild(errSlot('reason'));
    form.appendChild(reasonField);

    // Authorised by
    var authField = el('div', 'field');
    authField.appendChild(el('label', null, 'Authorised by (optional)'));
    var authInput = el('input', 'input');
    authInput.type = 'text';
    authInput.name = 'authorisedBy';
    authInput.maxLength = 120;
    authInput.placeholder = 'duty-manager@vgil.io';
    authField.appendChild(authInput);
    form.appendChild(authField);

    var submit = el('button', 'btn btn-primary btn-sm', 'Record');
    submit.type = 'submit';
    form.appendChild(submit);

    var caveat = el('p', 'text-muted');
    caveat.style.cssText = 'font-size:.75rem;margin-top:.5rem';
    caveat.textContent = 'This writes to the incident timeline and the audit log. It does not perform the action.';
    form.appendChild(caveat);

    toggle.addEventListener('click', function () {
      form.hidden = !form.hidden;
      toggle.textContent = form.hidden ? '+ Record containment' : 'Cancel';
      if (!form.hidden) targetInput.focus();
    });

    window.VG.bindForm(
      form,
      function (values) {
        return V.request('/containment', {
          method: 'POST',
          body: {
            incidentId: incidentId,
            action: values.action,
            target: values.target,
            scope: values.scope || undefined,
            reason: values.reason,
            authorisedBy: values.authorisedBy || undefined
          }
        });
      },
      {
        busyText: 'Recording…',
        onSuccess: function () {
          window.VG.toast('Containment recorded', 'Added to the incident timeline.', 'ok');
          open(incidentId);
          load();
        }
      }
    );

    wrap.appendChild(form);
    return wrap;
  }

  function errSlot(name) {
    var slot = el('div', 'err');
    slot.setAttribute('data-err', name);
    return slot;
  }

  /* ==================================================================
     P1 ESCALATION BRIDGE
     ==================================================================
     The "no ticket queue for P1" path. Raising notifies subscribers
     immediately, bypassing digest and quiet-hours settings, and the gap
     between raising and acknowledgement is the number the claim rests on.
     ================================================================== */

  function formatSeconds(seconds) {
    if (seconds === null || seconds === undefined) return '—';
    if (seconds < 60) return seconds + 's';
    var minutes = Math.floor(seconds / 60);
    return minutes < 60
      ? minutes + 'm ' + (seconds % 60) + 's'
      : Math.floor(minutes / 60) + 'h ' + (minutes % 60) + 'm';
  }

  function escalationSection(inc, records) {
    var section = el('div', 'drawer-section');
    section.appendChild(el('h4', null, 'Escalation'));

    if (!records.length) {
      var none = el('p', 'text-muted');
      none.style.cssText = 'font-size:.82rem;margin:.3rem 0 .8rem';
      none.textContent = 'Not escalated.';
      section.appendChild(none);
    } else {
      records.forEach(function (record) {
        var item = el('div', 'timeline-item');

        var head = el('div', 'flex gap-sm items-center wrap-flex');
        head.appendChild(
          el('span', 'badge ' + (record.priority === 'P1' ? 'is-crit' : 'is-high'), record.priority)
        );
        head.appendChild(
          el(
            'span',
            'badge ' + (record.acknowledgedAt ? 'is-ok' : ''),
            record.acknowledgedAt ? 'Acknowledged' : 'Awaiting response'
          )
        );
        if (record.resolvedAt) head.appendChild(el('span', 'badge', 'Resolved'));
        item.appendChild(head);

        var why = el('div', 'text-muted');
        why.style.cssText = 'font-size:.82rem;margin-top:.3rem';
        why.textContent = record.reason;
        item.appendChild(why);

        var meta = el('div', 'text-muted');
        meta.style.cssText = 'font-size:.75rem;margin-top:.3rem';
        meta.textContent =
          'Raised by ' + record.raisedBy + ' ' + window.VG.timeAgo(record.raisedAt) +
          (record.acknowledgedAt
            ? ' · taken by ' + record.acknowledgedBy + ' after ' + formatSeconds(record.acknowledgeSeconds)
            : '') +
          (record.bridgeRef ? ' · bridge ' + record.bridgeRef : '');
        item.appendChild(meta);

        if (authed && !record.acknowledgedAt) {
          var ack = el('button', 'btn btn-primary btn-sm', 'Acknowledge — I have the bridge');
          ack.type = 'button';
          ack.style.marginTop = '.5rem';
          ack.addEventListener('click', function () {
            ack.disabled = true;
            V.request('/soc/escalations/' + encodeURIComponent(record.id) + '/acknowledge', {
              method: 'POST'
            })
              .then(function (res) {
                window.VG.toast(
                  'Bridge taken',
                  'Acknowledged after ' + formatSeconds(res.data.acknowledgeSeconds) + '.',
                  'ok'
                );
                open(inc.id);
              })
              .catch(function (err) {
                window.VG.toast('Could not acknowledge', err.message, 'crit');
                ack.disabled = false;
              });
          });
          item.appendChild(ack);
        } else if (authed && !record.resolvedAt) {
          var close = el('button', 'btn btn-ghost btn-sm', 'Resolve escalation');
          close.type = 'button';
          close.style.marginTop = '.5rem';
          close.addEventListener('click', function () {
            var resolution = prompt('How was it resolved? (at least 10 characters)');
            if (resolution === null) return;
            if (resolution.trim().length < 10) {
              window.VG.toast('Too short', 'Say how it was resolved in at least 10 characters.', 'warn');
              return;
            }
            V.request('/soc/escalations/' + encodeURIComponent(record.id) + '/resolve', {
              method: 'POST',
              body: { resolution: resolution.trim() }
            })
              .then(function () {
                window.VG.toast('Escalation resolved', inc.id, 'ok');
                open(inc.id);
              })
              .catch(function (err) {
                window.VG.toast('Could not resolve', err.message, 'crit');
              });
          });
          item.appendChild(close);
        }

        section.appendChild(item);
      });
    }

    if (authed && inc.status !== 'closed') {
      var raise = el('button', 'btn btn-danger btn-sm', 'Escalate to the bridge');
      raise.type = 'button';
      raise.addEventListener('click', function () { openEscalation(inc); });
      section.appendChild(raise);

      var caveat = el('p', 'text-muted');
      caveat.style.cssText = 'font-size:.75rem;margin-top:.5rem';
      caveat.textContent =
        'A P1 notifies subscribers immediately, ignoring digest and quiet-hours settings.';
      section.appendChild(caveat);
    }

    return section;
  }

  function openEscalation(inc) {
    var priority = prompt('Priority — P1, P2 or P3?', 'P1');
    if (priority === null) return;
    priority = String(priority).toUpperCase().trim();

    if (['P1', 'P2', 'P3'].indexOf(priority) === -1) {
      window.VG.toast('Not recognised', 'Use P1, P2 or P3.', 'warn');
      return;
    }

    var reason = prompt('Why does this need the bridge? (at least 10 characters)');
    if (reason === null) return;
    if (reason.trim().length < 10) {
      window.VG.toast('Reason too short', 'Say why in at least 10 characters.', 'warn');
      return;
    }

    var bridgeRef = prompt('Bridge reference, if one is open (optional):') || '';

    V.request('/soc/escalations', {
      method: 'POST',
      body: {
        incidentId: inc.id,
        priority: priority,
        reason: reason.trim(),
        bridgeRef: bridgeRef.trim() || undefined
      }
    })
      .then(function (res) {
        var onDuty = (res.onDuty || []).map(function (shift) { return shift.region; }).join(', ');
        window.VG.toast(
          priority + ' raised',
          // Worth saying when nobody is on the rota for this hour: the whole
          // point of the bridge is that somebody picks it up.
          onDuty ? 'On console now: ' + onDuty + '.' : 'Warning: no shift is currently on console.',
          priority === 'P1' ? 'crit' : 'warn'
        );
        open(inc.id);
        load();
      })
      .catch(function (err) {
        window.VG.toast('Could not escalate', err.message, 'crit');
      });
  }
})();
