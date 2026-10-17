/**
 * Threat intelligence centre: indicator lookup, posture assessment,
 * actor profiles, IOC feed, vulnerabilities and attack geography.
 */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;
  var $$ = window.VG.$$;
  var el = window.VG.el;

  /* ------------------------------------------------- indicator lookup */

  var lookupResult = $('#lookup-result');

  function renderLookup(res) {
    var d = res.data;
    lookupResult.innerHTML = '';

    var VERDICT = {
      malicious: { cls: 'sev-critical', label: 'MALICIOUS' },
      suspicious: { cls: 'sev-medium', label: 'SUSPICIOUS' },
      clean: { cls: 'sev-ok', label: 'NO KNOWN THREAT' }
    };
    var v = VERDICT[d.verdict] || VERDICT.clean;

    var box = el('div', 'panel');
    box.style.background = 'var(--bg-1)';

    var head = el('div', 'panel-head');
    var ind = el('span', 'mono strong');
    ind.textContent = d.indicator;
    ind.style.fontSize = '.85rem';
    ind.style.color = 'var(--text)';
    ind.style.wordBreak = 'break-all';
    head.appendChild(ind);
    head.appendChild(el('span', 'badge badge-dot ' + v.cls, v.label));
    box.appendChild(head);

    var body = el('div', 'panel-body');

    var dl = el('dl', 'kv');
    dl.style.marginBottom = '.75rem';
    var pairs = [
      ['Type', d.type],
      ['Confidence', d.confidence + '%'],
      ['Severity', d.severity]
    ];
    if (d.actor) pairs.push(['Attributed to', d.actor]);
    if (d.firstSeen) pairs.push(['First seen', d.firstSeen]);
    pairs.push(['Sources', d.sources.join(', ')]);

    pairs.forEach(function (p) {
      dl.appendChild(el('dt', null, p[0]));
      dl.appendChild(el('dd', null, p[1]));
    });
    body.appendChild(dl);

    var meter = el(
      'div',
      'meter ' + (d.verdict === 'malicious' ? 'crit' : d.verdict === 'suspicious' ? 'med' : '')
    );
    var fill = el('span');
    fill.style.width = d.confidence + '%';
    meter.appendChild(fill);
    body.appendChild(meter);

    var desc = el('p', 'mt-1');
    desc.textContent = d.description;
    desc.style.fontSize = '.87rem';
    body.appendChild(desc);

    if (d.tags && d.tags.length) {
      var tags = el('div', 'tag-list mt-1');
      d.tags.forEach(function (t) {
        tags.appendChild(el('span', 'tag', t));
      });
      body.appendChild(tags);
    }

    if (d.relatedDetections && d.relatedDetections.length) {
      body.appendChild(el('div', 'stat-label mt-2', 'Related detection rules'));
      d.relatedDetections.forEach(function (r) {
        var row = el('div', 'metric-row');
        row.appendChild(el('span', null, r.name));
        row.appendChild(el('span', 'v', r.id));
        body.appendChild(row);
      });
    }

    var checked = el('p', 'form-note');
    checked.textContent = 'Checked ' + window.VG.fullTime(res.checkedAt);
    body.appendChild(checked);

    box.appendChild(body);
    lookupResult.appendChild(box);

    if (window.VGFx) {
      window.VGFx.cascade([box], { step: 0 });
      window.VGFx.cascade(dl.children, { step: 34, lead: 140 });
    }
  }

  var lookupForm = $('#lookup-form');
  if (lookupForm) {
    window.VG.bindForm(
      lookupForm,
      function (values) {
        return V.api.lookup(values.indicator);
      },
      { busyText: 'Querying threat graph…', onSuccess: renderLookup }
    );

    $$('[data-sample]').forEach(function (chip) {
      chip.addEventListener('click', function () {
        $('#indicator').value = chip.dataset.sample;
        lookupForm.requestSubmit
          ? lookupForm.requestSubmit()
          : lookupForm.dispatchEvent(new Event('submit', { cancelable: true }));
      });
    });
  }

  /* ---------------------------------------------------- posture scan */

  var scanResult = $('#scan-result');

  function renderScan(res) {
    var d = res.data;
    scanResult.innerHTML = '';

    var box = el('div', 'panel');
    box.style.background = 'var(--bg-1)';

    var body = el('div', 'panel-body');

    var top = el('div', 'scan-result');

    // Score dial: the arc sweeps round to the measured score. 283 is the
    // circumference of the r=45 circle in the SVG's own coordinate space.
    var dial = el('div', 'grade-wrap g-' + d.grade);
    dial.style.setProperty('--arc', 283 - (283 * d.score) / 100);
    dial.innerHTML =
      '<svg class="grade-ring" viewBox="0 0 100 100" aria-hidden="true">' +
      '<circle class="grade-track"></circle><circle class="grade-arc"></circle></svg>';

    var grade = el('div', 'grade', d.grade);
    grade.setAttribute('role', 'img');
    grade.setAttribute('aria-label', 'Grade ' + d.grade + ', score ' + d.score + ' out of 100');
    dial.appendChild(grade);
    top.appendChild(dial);

    var summary = el('div');
    var host = el('div', 'mono strong');
    host.textContent = d.domain;
    host.style.color = 'var(--text)';
    host.style.wordBreak = 'break-all';
    summary.appendChild(host);

    var score = el('div', 'stat-value');
    score.textContent = d.score + '/100';
    score.style.fontSize = '1.5rem';
    score.style.marginTop = '.3rem';
    summary.appendChild(score);

    var counts = el('div', 'flex gap-sm mt-1 wrap-flex');
    counts.appendChild(el('span', 'badge sev-ok', d.passed + ' passed'));
    if (d.failed) counts.appendChild(el('span', 'badge sev-critical', d.failed + ' failed'));
    summary.appendChild(counts);

    top.appendChild(summary);
    body.appendChild(top);

    var list = el('ul', 'check-list');
    d.checks.forEach(function (c) {
      var li = el('li', c.pass ? 'pass' : 'fail');
      li.appendChild(el('span', 'mark', c.pass ? '✓' : '✕'));
      li.appendChild(el('span', 'cname', c.name));
      li.appendChild(el('span', 'cdetail', c.detail));
      list.appendChild(li);
    });
    body.appendChild(list);

    var note = el('p', 'form-note');
    note.textContent = d.disclaimer;
    body.appendChild(note);

    box.appendChild(body);
    scanResult.appendChild(box);

    // Checks tick down the list while the dial is still sweeping.
    if (window.VGFx) window.VGFx.cascade(list.children, { step: 60, lead: 450, side: true });
  }

  var scanForm = $('#scan-form');
  if (scanForm) {
    window.VG.bindForm(
      scanForm,
      function (values) {
        return V.api.postureScan(values.domain);
      },
      { busyText: 'Assessing…', onSuccess: renderScan }
    );
  }

  /* --------------------------------------------------------- actors */

  var actorGrid = $('#actor-grid');
  var TREND = {
    rising: { cls: 'sev-critical', label: '▲ rising' },
    steady: { cls: 'sev-medium', label: '▬ steady' },
    falling: { cls: 'sev-ok', label: '▼ declining' }
  };

  function renderActors(rows) {
    actorGrid.innerHTML = '';

    if (!rows.length) {
      actorGrid.innerHTML = '<div class="empty">No actors match that filter.</div>';
      return;
    }

    rows.forEach(function (a, i) {
      var card = el('div', 'card card-hover');
      card.style.cursor = 'pointer';

      var head = el('div', 'flex between items-center');
      var name = el('h3', 'mono', a.name);
      name.style.fontSize = '1.05rem';
      head.appendChild(name);
      var t = TREND[a.trend] || TREND.steady;
      head.appendChild(el('span', 'badge ' + t.cls, t.label));
      card.appendChild(head);

      var meta = el('div', 'mono text-dim');
      meta.textContent = a.id + ' · ' + a.motivation + ' · ' + a.origin;
      meta.style.fontSize = '.73rem';
      meta.style.marginTop = '.25rem';
      card.appendChild(meta);

      var sum = el('p', 'mt-1');
      sum.textContent = a.summary;
      sum.style.fontSize = '.86rem';
      card.appendChild(sum);

      card.appendChild(el('div', 'stat-label mt-2', 'Targets'));
      var tags = el('div', 'tag-list');
      a.targets.forEach(function (t2) {
        tags.appendChild(el('span', 'tag', t2));
      });
      card.appendChild(tags);

      card.appendChild(el('div', 'stat-label mt-2', 'Techniques'));
      var techs = el('div', 'tag-list');
      a.techniques.forEach(function (t3) {
        var tag = el('span', 'tag', t3);
        tag.style.color = 'var(--accent-2)';
        techs.appendChild(tag);
      });
      card.appendChild(techs);

      card.addEventListener('click', function () {
        openActor(a.id);
      });

      actorGrid.appendChild(card);
      setTimeout(function () {
        card.classList.add('in');
      }, i * 50);
    });
  }

  function loadActors(trend) {
    V.api
      .actors(trend ? { trend: trend } : {})
      .then(function (res) {
        renderActors(res.data);
      })
      .catch(function () {
        actorGrid.innerHTML = '<div class="empty">Actor profiles unavailable.</div>';
      });
  }

  loadActors('');

  $$('#actor-filters .chip').forEach(function (chip) {
    chip.addEventListener('click', function () {
      $$('#actor-filters .chip').forEach(function (c) {
        c.classList.toggle('on', c === chip);
      });
      loadActors(chip.dataset.trend);
    });
  });

  /* --------------------------------------------------- actor drawer */

  var drawer = $('[data-drawer]');
  var backdrop = $('[data-drawer-backdrop]');

  function closeDrawer() {
    drawer.classList.remove('open');
    backdrop.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
  }

  function openActor(id) {
    drawer.classList.add('open');
    backdrop.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');

    var body = $('[data-drawer-body]');
    body.innerHTML = '<div class="skeleton" style="height:260px"></div>';

    V.api
      .actor(id)
      .then(function (res) {
        var a = res.data;
        $('[data-drawer-id]').textContent = a.id + ' · ' + a.sophistication + ' sophistication';
        $('[data-drawer-title]').textContent = a.name;

        body.innerHTML = '';

        var dl = el('dl', 'kv');
        [
          ['Aliases', a.aliases.join(', ')],
          ['Motivation', a.motivation],
          ['Assessed origin', a.origin],
          ['First observed', a.firstSeen],
          ['Sophistication', a.sophistication],
          ['Activity trend', a.trend],
          ['Target sectors', a.targets.join(', ')]
        ].forEach(function (p) {
          dl.appendChild(el('dt', null, p[0]));
          dl.appendChild(el('dd', null, p[1]));
        });
        body.appendChild(dl);

        body.appendChild(el('div', 'stat-label', 'Assessment'));
        var sum = el('p');
        sum.textContent = a.summary;
        sum.style.marginBottom = '1.4rem';
        body.appendChild(sum);

        if (res.indicators.length) {
          body.appendChild(
            el('div', 'stat-label', 'Attributed indicators (' + res.indicators.length + ')')
          );
          res.indicators.forEach(function (i) {
            var row = el('div', 'metric-row');
            var left = el('div');
            var ind = el('div', 'mono');
            ind.textContent = i.indicator;
            ind.style.fontSize = '.78rem';
            ind.style.color = 'var(--text)';
            ind.style.wordBreak = 'break-all';
            left.appendChild(ind);
            var desc = el('div');
            desc.textContent = i.description;
            desc.style.fontSize = '.74rem';
            desc.style.color = 'var(--dim)';
            left.appendChild(desc);
            row.appendChild(left);
            row.appendChild(el('span', 'badge badge-dot sev-' + i.severity, String(i.confidence)));
            body.appendChild(row);
          });
        }

        if (res.detections.length) {
          body.appendChild(
            el('div', 'stat-label mt-2', 'Detection coverage (' + res.detections.length + ' rules)')
          );
          res.detections.forEach(function (r) {
            var row = el('div', 'metric-row');
            row.appendChild(el('span', null, r.name));
            var right = el('span', 'v');
            right.textContent = r.id;
            right.style.color = 'var(--accent)';
            row.appendChild(right);
            body.appendChild(row);
          });
        } else {
          var gap = el('p', 'form-note');
          gap.textContent =
            'No published rule maps directly to this actor’s techniques — behavioural models cover it instead.';
          body.appendChild(gap);
        }

        if (window.VGFx) {
          window.VGFx.cascade(dl.children, { step: 26, lead: 130 });
          window.VGFx.cascade(body.querySelectorAll('.metric-row'), {
            step: 45,
            lead: 300,
            side: true
          });
        }
      })
      .catch(function (err) {
        body.replaceChildren(window.VG.errorBox(err.message));
      });
  }

  if (backdrop) backdrop.addEventListener('click', closeDrawer);
  $$('[data-drawer-close]').forEach(function (b) {
    b.addEventListener('click', closeDrawer);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeDrawer();
  });

  /* ----------------------------------------------------------- IOCs */

  var iocBody = $('#ioc-rows');
  var iocSearch = $('#ioc-search');
  var iocType = $('#ioc-type');
  var iocTimer;

  function loadIocs() {
    var params = {};
    if (iocSearch.value.trim()) params.q = iocSearch.value.trim();
    if (iocType.value) params.type = iocType.value;

    V.api
      .iocs(params)
      .then(function (res) {
        iocBody.innerHTML = '';
        $('#ioc-count').textContent = res.data.length + ' indicators';

        if (!res.data.length) {
          iocBody.innerHTML = '<tr><td colspan="7" class="empty">No indicators match.</td></tr>';
          return;
        }

        res.data.forEach(function (i) {
          var tr = el('tr');

          var ind = el('td', 'cell-mono strong');
          ind.textContent =
            i.indicator.length > 30 ? i.indicator.slice(0, 28) + '…' : i.indicator;
          ind.title = i.indicator + ' — ' + i.description;
          tr.appendChild(ind);

          tr.appendChild(el('td', 'cell-mono', i.type));

          var sev = el('td');
          sev.appendChild(el('span', 'badge badge-dot sev-' + i.severity, i.severity));
          tr.appendChild(sev);

          var conf = el('td');
          var meter = el('div', 'meter ' + (i.confidence > 85 ? 'crit' : 'med'));
          meter.style.width = '70px';
          meter.style.display = 'inline-block';
          meter.style.verticalAlign = 'middle';
          var fill = el('span');
          fill.style.width = i.confidence + '%';
          meter.appendChild(fill);
          conf.appendChild(meter);
          var pct = el('span', 'cell-mono', ' ' + i.confidence + '%');
          pct.style.marginLeft = '.5rem';
          conf.appendChild(pct);
          tr.appendChild(conf);

          tr.appendChild(el('td', 'cell-mono', i.actor));

          var tags = el('td');
          var list = el('div', 'tag-list');
          i.tags.forEach(function (t) {
            list.appendChild(el('span', 'tag', t));
          });
          tags.appendChild(list);
          tr.appendChild(tags);

          tr.appendChild(el('td', 'cell-mono', i.firstSeen));
          iocBody.appendChild(tr);
        });

        if (window.VGFx) window.VGFx.cascade(iocBody.children, { step: 28 });
      })
      .catch(function () {
        iocBody.innerHTML = '<tr><td colspan="7" class="empty">Feed unavailable.</td></tr>';
      });
  }

  loadIocs();

  if (iocSearch) {
    iocSearch.addEventListener('input', function () {
      clearTimeout(iocTimer);
      iocTimer = setTimeout(loadIocs, 250);
    });
  }
  if (iocType) iocType.addEventListener('change', loadIocs);

  /* -------------------------------------------------- vulnerabilities */

  V.api
    .vulnerabilities()
    .then(function (res) {
      var body = $('#vuln-rows');
      body.innerHTML = '';

      $('#kev-count').textContent = res.summary.kev + ' KEV';
      $('#vuln-summary').textContent =
        res.summary.affectedAssets + ' affected assets across ' + res.summary.total + ' CVEs';

      res.data.forEach(function (v) {
        var tr = el('tr');

        var cve = el('td', 'cell-mono strong');
        cve.textContent = v.cve;
        cve.title = v.summary;
        tr.appendChild(cve);

        tr.appendChild(el('td', null, v.product));

        var cvss = el('td', 'cell-mono');
        var score = el('span', null, v.cvss.toFixed(1));
        score.style.color = v.cvss >= 9 ? 'var(--crit)' : v.cvss >= 7 ? 'var(--high)' : 'var(--med)';
        score.style.fontWeight = '700';
        cvss.appendChild(score);
        tr.appendChild(cvss);

        tr.appendChild(el('td', 'cell-mono', Math.round(v.epss * 100) + '%'));

        var status = el('td');
        status.appendChild(
          el('span', 'badge ' + (v.kev ? 'sev-critical' : 'sev-info'), v.status)
        );
        tr.appendChild(status);

        tr.appendChild(el('td', 'cell-mono', String(v.affected)));
        body.appendChild(tr);
      });

      if (window.VGFx) window.VGFx.cascadeOnView(body, body.children, { step: 45 });
    })
    .catch(function () {
      $('#vuln-rows').innerHTML =
        '<tr><td colspan="6" class="empty">Vulnerability data unavailable.</td></tr>';
    });

  /* ------------------------------------------------------------- geo */

  V.api
    .geo()
    .then(function (res) {
      // Animated scope above the ranked list. "Other" is a bucket, not a
      // place, so it is excluded from the plot but kept in the list.
      var map = $('#attack-map');
      if (map && window.VGCharts.attackMap) {
        window.VGCharts.attackMap(
          map,
          res.data.filter(function (g) {
            return g.code !== 'XX';
          }),
          { height: 300 }
        );
      }

      var host = $('#geo-list');
      host.innerHTML = '';

      res.data.forEach(function (g) {
        var row = el('div', 'geo-row');
        row.appendChild(el('span', 'geo-code', g.code));
        row.appendChild(el('span', 'geo-name', g.country));

        var bar = el('div', 'geo-bar');
        var meter = el('div', 'meter');
        var fill = el('span');
        fill.style.width = Math.min(g.share * 4, 100) + '%';
        meter.appendChild(fill);
        bar.appendChild(meter);
        row.appendChild(bar);

        row.appendChild(el('span', 'geo-val', g.share.toFixed(1) + '%'));
        host.appendChild(row);
      });

      var total = el('p', 'form-note');
      total.textContent =
        window.VG.num(res.totalEvents) + ' attack events observed in the ' + res.window + '.';
      host.appendChild(total);

      if (window.VGFx) {
        window.VGFx.cascadeOnView(host, host.querySelectorAll('.geo-row'), {
          step: 55,
          side: true
        });
      }
    })
    .catch(function () {
      $('#geo-list').innerHTML = '<div class="empty">Geography data unavailable.</div>';
    });
})();
