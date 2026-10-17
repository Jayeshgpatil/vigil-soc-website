/** Homepage: live console, headline metrics, mini charts and intel panels. */
(function () {
  'use strict';

  var V = window.VGIL;
  var C = window.VGCharts;
  var $ = window.VG.$;
  var el = window.VG.el;

  var SEV_COLOR = {
    critical: C.PALETTE.critical,
    high: C.PALETTE.high,
    medium: C.PALETTE.medium,
    low: C.PALETTE.low,
    info: C.PALETTE.info
  };

  /* ------------------------------------------------------- live console */

  var consoleBody = $('#hero-console');
  var recentBody = $('#recent-alerts');
  var MAX_LINES = 60;

  function consoleLine(alert) {
    if (!consoleBody) return;

    var line = el('div', 'console-line');
    line.appendChild(el('span', 't', window.VG.clock(alert.ts)));
    line.appendChild(el('span', 'lv lv-' + alert.severity, alert.severity.toUpperCase()));

    var msg = el('span', 'm');
    msg.textContent =
      alert.technique + ' ' + alert.rule + ' → ' + alert.host + ' (' + alert.sourceIp + ')';
    line.appendChild(msg);

    consoleBody.appendChild(line);
    while (consoleBody.children.length > MAX_LINES) {
      consoleBody.removeChild(consoleBody.firstChild);
    }
    consoleBody.scrollTop = consoleBody.scrollHeight;
  }

  function recentRow(alert, fresh) {
    if (!recentBody) return;

    if (recentBody.querySelector('.empty')) recentBody.innerHTML = '';

    var tr = el('tr', fresh ? 'fresh' : '');

    var t = el('td', 'cell-mono', window.VG.clock(alert.ts));
    tr.appendChild(t);

    var sev = el('td');
    sev.appendChild(el('span', 'badge badge-dot sev-' + alert.severity, alert.severity));
    tr.appendChild(sev);

    var rule = el('td', 'strong');
    rule.textContent = alert.rule;
    tr.appendChild(rule);

    tr.appendChild(el('td', 'cell-mono', alert.host));

    recentBody.insertBefore(tr, recentBody.firstChild);
    while (recentBody.children.length > 6) {
      recentBody.removeChild(recentBody.lastChild);
    }
  }

  V.stream({
    connected: function () {
      var badge = $('[data-stream-badge]');
      if (badge) {
        badge.textContent = 'LIVE';
        badge.className = 'badge badge-dot sev-ok';
      }
    },
    alert: function (alert) {
      consoleLine(alert);
      recentRow(alert, true);
    },
    error: function () {
      var badge = $('[data-stream-badge]');
      if (badge) {
        badge.textContent = 'RECONNECTING';
        badge.className = 'badge badge-dot sev-medium';
      }
    }
  });

  /* -------------------------------------------------------------- stats */

  var statsCache = null;

  V.api
    .stats()
    .then(function (res) {
      statsCache = res.data;
      var t = res.data.totals;

      var events = $('[data-metric="events"]');
      // Each detection represents a much larger volume of raw analysed events.
      if (events) window.VG.countTo(events, t.alerts24h * 1470, '');

      var crit = $('[data-metric="critical"]');
      if (crit) window.VG.countTo(crit, t.critical24h, '');

      var total = $('[data-metric="alerts-total"]');
      if (total) total.textContent = window.VG.num(t.alerts24h) + ' alerts';

      C.register(function () {
        var canvas = $('#volume-chart');
        if (canvas && statsCache) C.area(canvas, statsCache.timeline, { height: 190 });
      });

      C.register(function () {
        var canvas = $('#sev-donut');
        if (!canvas || !statsCache) return;
        var slices = Object.keys(statsCache.bySeverity)
          .filter(function (k) {
            return statsCache.bySeverity[k] > 0;
          })
          .map(function (k) {
            return { label: k, value: statsCache.bySeverity[k], color: SEV_COLOR[k] };
          });
        C.donut(canvas, slices, { height: 170, caption: 'ALERTS' });

        var legend = $('#sev-legend');
        if (legend) {
          legend.innerHTML = '';
          slices.forEach(function (s) {
            var span = el('span');
            var i = el('i');
            i.style.background = s.color;
            span.appendChild(i);
            span.appendChild(document.createTextNode(s.label + ' ' + s.value));
            legend.appendChild(span);
          });
        }
      });

      C.register(function () {
        var canvas = $('#tactic-bars');
        if (!canvas || !statsCache) return;
        var rows = Object.keys(statsCache.byTactic)
          .map(function (k) {
            return { label: k, value: statsCache.byTactic[k], color: C.PALETTE.accent };
          })
          .sort(function (a, b) {
            return b.value - a.value;
          })
          .slice(0, 5);
        C.bars(canvas, rows, { barHeight: 18, labelWidth: 104 });
      });
    })
    .catch(function () {
      var total = $('[data-metric="alerts-total"]');
      if (total) total.textContent = 'offline';
    });

  /* ----------------------------------------------------------- services */

  var SERVICE_ICONS = {
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 12l7-4"/>',
    shield: '<path d="M12 2 4 5v6c0 5 3.4 8.5 8 10 4.6-1.5 8-5 8-10V5l-8-3Z"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18Z"/>',
    siren: '<path d="M5 20h14M7 20v-6a5 5 0 0 1 10 0v6M12 3v2M4.5 7 6 8.5M19.5 7 18 8.5"/>',
    bug: '<path d="M8 6a4 4 0 0 1 8 0M6 10h12v4a6 6 0 0 1-12 0v-4ZM3 12h3M18 12h3M4.5 7 7 9M19.5 7 17 9M4.5 17 7 15M19.5 17 17 15"/>',
    clipboard: '<rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3h6v1M9 10h6M9 14h6M9 18h3"/>'
  };

  V.api
    .services()
    .then(function (res) {
      var grid = $('#services-grid');
      if (!grid) return;
      grid.innerHTML = '';

      res.data.forEach(function (svc, i) {
        var card = el('div', 'card card-hover reveal');
        card.dataset.delay = String(i * 70);

        var icon = el('div', 'card-icon');
        icon.innerHTML =
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" ' +
          'stroke-linecap="round" stroke-linejoin="round">' +
          (SERVICE_ICONS[svc.icon] || SERVICE_ICONS.shield) +
          '</svg>';
        card.appendChild(icon);

        card.appendChild(el('h3', null, svc.name));
        card.appendChild(el('p', 'mono text-accent', svc.tagline));
        card.appendChild(el('p', 'mt-1', svc.description));

        var metrics = el('div', 'flex gap-sm mt-2 wrap-flex');
        svc.metrics.forEach(function (m) {
          metrics.appendChild(el('span', 'badge', m.label + ' ' + m.value));
        });
        card.appendChild(metrics);

        var link = el('a', 'link-arrow', 'Learn more');
        link.href = '/vigil-soc-website/services.html#' + svc.id;
        link.style.marginTop = '1rem';
        link.style.display = 'inline-flex';
        card.appendChild(link);

        grid.appendChild(card);
      });

      // These cards were inserted after the reveal observer was set up, so
      // stagger them in directly rather than waiting for an intersection.
      window.VG.$$('.reveal', grid).forEach(function (node, i) {
        setTimeout(function () {
          node.classList.add('in');
        }, i * 70);
      });
    })
    .catch(function () {
      var grid = $('#services-grid');
      if (grid) grid.innerHTML = '<div class="empty">Service catalog unavailable.</div>';
    });

  /* ------------------------------------------------------- intel panels */

  V.api
    .actors({ trend: 'rising' })
    .then(function (res) {
      var host = $('#home-actors');
      if (!host) return;
      host.innerHTML = '';

      res.data.slice(0, 3).forEach(function (a) {
        var row = el('div');
        row.style.padding = '.6rem 0';
        row.style.borderBottom = '1px solid var(--line)';

        var top = el('div', 'flex between items-center');
        var name = el('strong', 'mono');
        name.textContent = a.name;
        name.style.fontSize = '.88rem';
        top.appendChild(name);
        top.appendChild(el('span', 'badge sev-high', a.motivation));
        row.appendChild(top);

        var meta = el('p');
        meta.style.fontSize = '.78rem';
        meta.style.marginTop = '.25rem';
        meta.textContent = a.targets.join(' · ');
        row.appendChild(meta);

        host.appendChild(row);
      });

      var link = el('a', 'link-arrow mt-2', 'All tracked actors');
      link.href = '/vigil-soc-website/threat-intel.html';
      link.style.display = 'inline-flex';
      host.appendChild(link);
    })
    .catch(function () {});

  V.api
    .vulnerabilities()
    .then(function (res) {
      var host = $('#home-vulns');
      if (!host) return;
      host.innerHTML = '';

      res.data.slice(0, 4).forEach(function (v) {
        var row = el('div', 'metric-row');
        var left = el('div');
        var cve = el('div', 'mono');
        cve.textContent = v.cve;
        cve.style.fontSize = '.82rem';
        cve.style.color = 'var(--text)';
        left.appendChild(cve);
        var prod = el('div');
        prod.textContent = v.product;
        prod.style.fontSize = '.75rem';
        prod.style.color = 'var(--dim)';
        left.appendChild(prod);
        row.appendChild(left);

        var right = el('div', 'flex gap-sm items-center');
        if (v.kev) right.appendChild(el('span', 'badge sev-critical', 'KEV'));
        var score = el('span', 'v');
        score.textContent = v.cvss.toFixed(1);
        score.style.color = v.cvss >= 9 ? 'var(--crit)' : 'var(--high)';
        right.appendChild(score);
        row.appendChild(right);

        host.appendChild(row);
      });
    })
    .catch(function () {});

  V.api
    .geo()
    .then(function (res) {
      var host = $('#home-geo');
      if (!host) return;
      host.innerHTML = '';

      res.data.slice(0, 6).forEach(function (g) {
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
    })
    .catch(function () {});
})();
