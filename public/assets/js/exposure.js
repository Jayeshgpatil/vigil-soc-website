/**
 * Exposure management console.
 *
 * Every row here is a real finding — one vulnerability on one of your assets —
 * ranked by the exposure score rather than CVSS. The drawer shows the factors
 * that produced the score, because a ranking nobody can interrogate is a
 * ranking engineers work around.
 *
 * Nodes are built with textContent throughout: CVE summaries, product strings
 * and hostnames all come from data rather than from this file.
 */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;
  var el = window.VG.el;

  var authed = V.session.isAuthed();
  var state = { status: 'open', surface: '' };
  var current = null;

  /* ------------------------------------------------------------ helpers */

  function scoreCell(score, scoreBand) {
    var cell = el('td');
    var badge = el('span', 'badge badge-dot sev-' +
      (scoreBand === 'critical' ? 'critical' : scoreBand === 'high' ? 'high' : scoreBand === 'medium' ? 'medium' : 'low'),
      String(score));
    cell.appendChild(badge);
    return cell;
  }

  function percent(value) {
    return Math.round((Number(value) || 0) * 100) + '%';
  }

  function dueLabel(finding) {
    if (!finding.dueAt) return '—';
    var due = new Date(finding.dueAt);
    var days = Math.round((due - new Date()) / 86400000);
    if (finding.status === 'resolved') return 'closed';
    if (days < 0) return Math.abs(days) + 'd overdue';
    return 'in ' + days + 'd';
  }

  /* -------------------------------------------------------------- queue */

  function renderRows(findings) {
    var body = $('#exp-rows');
    body.textContent = '';

    if (!findings.length) {
      body.appendChild(window.VG.errorCell(9, 'No findings match that filter.'));
      $('#exp-count').textContent = '0 findings';
      return;
    }

    findings.forEach(function (finding) {
      var row = el('tr', 'row-click');
      row.dataset.id = finding.id;

      row.appendChild(scoreCell(finding.exposureScore, finding.band));

      var cve = el('td', 'cell-mono strong');
      cve.textContent = finding.cve;
      if (finding.vulnerability.kev) {
        var kev = el('span', 'badge is-crit', 'KEV');
        kev.style.marginLeft = '.4rem';
        cve.appendChild(kev);
      }
      row.appendChild(cve);

      row.appendChild(el('td', 'cell-mono', finding.asset.host));

      var surface = el('td');
      surface.appendChild(
        el('span', 'badge ' + (finding.surface === 'external' ? 'is-high' : ''), finding.surface)
      );
      row.appendChild(surface);

      var epss = el('td', 'cell-mono', percent(finding.vulnerability.epss));
      epss.style.color = 'var(--accent-2)';
      row.appendChild(epss);

      // Muted on purpose: it is the least important column on this page.
      var cvss = el('td', 'cell-mono', String(finding.vulnerability.cvss));
      cvss.style.color = 'var(--dim)';
      row.appendChild(cvss);

      row.appendChild(el('td', 'cell-mono', finding.blastRadius + ' asset' + (finding.blastRadius === 1 ? '' : 's')));

      var due = el('td', 'cell-mono', dueLabel(finding));
      if (finding.overdue) due.style.color = 'var(--crit)';
      row.appendChild(due);

      var status = el('td');
      status.appendChild(
        el('span', 'badge ' +
          (finding.status === 'resolved' ? 'is-ok' : finding.status === 'accepted' ? '' : 'is-info'),
          finding.status === 'accepted' ? 'risk accepted' : finding.status)
      );
      row.appendChild(status);

      row.addEventListener('click', function () { openFinding(finding); });
      body.appendChild(row);
    });

    if (window.VGFx) window.VGFx.cascade(body.children, { step: 26 });
    $('#exp-count').textContent = findings.length + ' finding' + (findings.length === 1 ? '' : 's');
  }

  function renderSummary(summary) {
    $('[data-exp="open"]').textContent = summary.open;
    $('[data-exp="openSub"]').textContent =
      summary.total + ' total · ' + summary.resolved + ' resolved · ' + summary.accepted + ' accepted';
    $('[data-exp="kev"]').textContent = summary.kevOpen;
    $('[data-exp="overdue"]').textContent = summary.overdue;
    $('[data-exp="external"]').textContent = summary.externalOpen;
  }

  function load() {
    var params = new URLSearchParams({ status: state.status, limit: '100' });
    if (state.surface) params.set('surface', state.surface);

    return V.request('/exposure?' + params.toString(), { auth: false })
      .then(function (res) {
        renderRows(res.data);
        renderSummary(res.summary);
      })
      .catch(function (err) {
        var body = $('#exp-rows');
        body.textContent = '';
        body.appendChild(window.VG.errorCell(9, 'Could not load findings: ' + err.message));
      });
  }

  /* --------------------------------------------------------- comparison */

  function renderRanking(res) {
    function fill(id, rows) {
      var body = $(id);
      body.textContent = '';
      rows.forEach(function (row) {
        var tr = el('tr');
        tr.appendChild(el('td', 'cell-mono', String(row.rank)));

        var cve = el('td', 'cell-mono');
        cve.textContent = row.cve;
        if (row.kev) {
          var kev = el('span', 'badge is-crit', 'KEV');
          kev.style.marginLeft = '.35rem';
          cve.appendChild(kev);
        }
        tr.appendChild(cve);

        tr.appendChild(el('td', 'cell-mono', row.host));
        tr.appendChild(el('td', 'cell-mono strong', String(row.exposureScore)));

        var cvss = el('td', 'cell-mono', String(row.cvss));
        cvss.style.color = 'var(--dim)';
        tr.appendChild(cvss);

        body.appendChild(tr);
      });
    }

    fill('#rank-exposure', res.byExposure);
    fill('#rank-cvss', res.byCvss);

    $('#ranking-diff').textContent = res.differing + ' OF ' + res.limit + ' DIFFER';
    $('#ranking-diff').className = 'badge mono ' + (res.differing ? 'is-high' : '');
    $('#ranking-explanation').textContent = res.explanation;
  }

  function loadRanking() {
    return V.request('/exposure/ranking?limit=5', { auth: false })
      .then(renderRanking)
      .catch(function () {
        $('#ranking-explanation').textContent = 'Ranking comparison unavailable.';
      });
  }

  function loadScans() {
    return V.request('/exposure/scans?limit=10', { auth: false })
      .then(function (res) {
        var body = $('#exp-scans');
        body.textContent = '';

        if (!res.data.length) {
          body.appendChild(window.VG.errorCell(4, 'No scans yet.'));
          return;
        }

        res.data.forEach(function (scan) {
          var row = el('tr');
          var when = el('td', 'cell-mono', window.VG.timeAgo(scan.startedAt));
          when.title = window.VG.fullTime(scan.startedAt);
          row.appendChild(when);
          row.appendChild(el('td', null, scan.kind));
          row.appendChild(el('td', 'cell-mono', scan.target || '—'));
          row.appendChild(el('td', 'cell-mono', String(scan.findingsNew)));
          body.appendChild(row);
        });
      })
      .catch(function () {});
  }

  /* ------------------------------------------------------------- drawer */

  var drawer = $('[data-drawer]');
  var backdrop = $('[data-drawer-backdrop]');

  function closeDrawer() {
    if (!drawer) return;
    drawer.classList.remove('open');
    if (backdrop) backdrop.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    current = null;
  }

  function openFinding(finding) {
    if (!drawer) return;
    current = finding.id;

    drawer.classList.add('open');
    if (backdrop) backdrop.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');

    $('[data-drawer-id]').textContent = finding.cve + ' · ' + finding.asset.host;
    $('[data-drawer-title]').textContent = finding.vulnerability.title;

    var body = $('[data-drawer-body]');
    body.textContent = '';

    /* --- the score, and where it came from --- */
    var scoreBlock = el('div', 'drawer-section');
    scoreBlock.appendChild(el('h4', null, 'Exposure ' + finding.exposureScore + '/100'));

    var basis = el('p', 'text-muted');
    basis.style.cssText = 'font-size:.8rem;margin:.2rem 0 .7rem';
    basis.textContent = 'Every point is attributable. CVSS is the smallest term on purpose.';
    scoreBlock.appendChild(basis);

    finding.factors.forEach(function (factor) {
      var line = el('div');
      line.style.cssText = 'display:flex;gap:.6rem;align-items:baseline;padding:.3rem 0;border-bottom:1px solid var(--line)';

      var points = el('span', 'mono strong', '+' + factor.points);
      points.style.cssText = 'min-width:2.6rem;color:' +
        (factor.factor === 'cvss' ? 'var(--dim)' : 'var(--accent)');
      line.appendChild(points);

      var detail = el('span');
      detail.style.fontSize = '.84rem';
      detail.textContent = factor.detail;
      line.appendChild(detail);

      scoreBlock.appendChild(line);
    });
    body.appendChild(scoreBlock);

    /* --- the vulnerability --- */
    var vulnBlock = el('div', 'drawer-section');
    vulnBlock.appendChild(el('h4', null, 'Vulnerability'));

    [
      ['Product', finding.vulnerability.product],
      ['Summary', finding.vulnerability.summary],
      ['Fixed in', finding.vulnerability.fixVersion || 'no fix published'],
      ['Published', finding.vulnerability.published || '—'],
      ['Blast radius', finding.blastRadius + ' asset(s) in this estate'],
      ['Surface', finding.surface],
      ['Due', finding.dueAt ? window.VG.fullTime(finding.dueAt) : '—']
    ].forEach(function (pair) {
      var row = el('div');
      row.style.cssText = 'display:flex;gap:.6rem;padding:.25rem 0;font-size:.84rem';
      var label = el('span', 'text-muted', pair[0]);
      label.style.minWidth = '7rem';
      row.appendChild(label);
      row.appendChild(el('span', null, String(pair[1])));
      vulnBlock.appendChild(row);
    });
    body.appendChild(vulnBlock);

    if (finding.status === 'accepted') {
      var accepted = el('div', 'notice notice-warn');
      accepted.style.marginTop = '1rem';
      accepted.textContent =
        'Risk accepted by ' + finding.acceptedBy + ' until ' +
        String(finding.acceptedUntil).slice(0, 10) + ' — ' + finding.acceptedReason;
      body.appendChild(accepted);
    }

    if (authed) body.appendChild(actionsFor(finding));
  }

  function actionsFor(finding) {
    var section = el('div', 'drawer-section');
    section.appendChild(el('h4', null, 'Remediation'));

    var row = el('div', 'flex gap-sm wrap-flex');
    row.style.marginTop = '.5rem';

    if (finding.status === 'open') {
      var start = el('button', 'btn btn-primary btn-sm', 'Start remediation');
      start.type = 'button';
      start.addEventListener('click', function () {
        patch(finding.id, { status: 'remediating', assignedTo: '' }, 'Assigned to you.');
      });
      row.appendChild(start);
    }

    if (finding.status === 'open' || finding.status === 'remediating') {
      var verify = el('button', 'btn btn-ghost btn-sm', 'Run verification rescan');
      verify.type = 'button';
      verify.addEventListener('click', function () {
        verify.disabled = true;
        V.request('/exposure/' + encodeURIComponent(finding.id) + '/verify', {
          method: 'POST',
          body: { stillPresent: false }
        })
          .then(function (res) {
            window.VG.toast(
              res.verified ? 'Verified resolved' : 'Still present',
              res.message,
              res.verified ? 'ok' : 'warn'
            );
            closeDrawer();
            refresh();
          })
          .catch(function (err) {
            window.VG.toast('Verification failed', err.message, 'crit');
            verify.disabled = false;
          });
      });
      row.appendChild(verify);

      // Recording that a patch did not take is the honest outcome, so it is a
      // first-class action rather than something to hide.
      var failed = el('button', 'btn btn-ghost btn-sm', 'Rescan: still present');
      failed.type = 'button';
      failed.addEventListener('click', function () {
        V.request('/exposure/' + encodeURIComponent(finding.id) + '/verify', {
          method: 'POST',
          body: { stillPresent: true }
        })
          .then(function (res) {
            window.VG.toast('Reopened', res.message, 'warn');
            closeDrawer();
            refresh();
          })
          .catch(function (err) {
            window.VG.toast('Could not record', err.message, 'crit');
          });
      });
      row.appendChild(failed);

      var accept = el('button', 'btn btn-ghost btn-sm', 'Accept risk');
      accept.type = 'button';
      accept.addEventListener('click', function () { acceptRisk(finding); });
      row.appendChild(accept);

      var escalate = el('button', 'btn btn-danger btn-sm', 'Open an incident');
      escalate.type = 'button';
      escalate.addEventListener('click', function () {
        escalate.disabled = true;
        V.request('/exposure/' + encodeURIComponent(finding.id) + '/escalate', { method: 'POST' })
          .then(function (res) {
            window.VG.toast('Incident opened', res.incident.id + ' created from ' + finding.cve, 'ok');
            closeDrawer();
            refresh();
          })
          .catch(function (err) {
            window.VG.toast('Could not escalate', err.message, 'crit');
            escalate.disabled = false;
          });
      });
      row.appendChild(escalate);
    }

    if (finding.status === 'accepted') {
      var withdraw = el('button', 'btn btn-ghost btn-sm', 'Withdraw acceptance');
      withdraw.type = 'button';
      withdraw.addEventListener('click', function () {
        V.request('/exposure/' + encodeURIComponent(finding.id) + '/withdraw-acceptance', { method: 'POST' })
          .then(function () {
            window.VG.toast('Back in the queue', finding.cve, 'ok');
            closeDrawer();
            refresh();
          })
          .catch(function (err) {
            window.VG.toast('Could not withdraw', err.message, 'crit');
          });
      });
      row.appendChild(withdraw);
    }

    section.appendChild(row);

    var note = el('p', 'text-muted');
    note.style.cssText = 'font-size:.75rem;margin-top:.6rem';
    note.textContent =
      'A finding is only resolved once a verification rescan confirms it is gone. ' +
      'Marking it fixed by hand is not an option.';
    section.appendChild(note);

    return section;
  }

  function acceptRisk(finding) {
    var reason = prompt(
      'Why is this risk being accepted? This is the record an auditor reads. (at least 20 characters)'
    );
    if (reason === null) return;
    if (reason.trim().length < 20) {
      window.VG.toast('Justification too short', 'At least 20 characters.', 'warn');
      return;
    }

    var days = prompt('Accept for how many days? Acceptances must expire and be revisited.', '90');
    if (days === null) return;

    V.request('/exposure/' + encodeURIComponent(finding.id) + '/accept', {
      method: 'POST',
      body: { reason: reason.trim(), days: Number(days) }
    })
      .then(function (res) {
        window.VG.toast('Risk accepted', res.message, 'ok');
        closeDrawer();
        refresh();
      })
      .catch(function (err) {
        window.VG.toast('Could not accept', err.message, 'crit');
      });
  }

  function patch(id, body, message) {
    V.request('/exposure/' + encodeURIComponent(id), { method: 'PATCH', body: body })
      .then(function () {
        window.VG.toast('Updated', message, 'ok');
        closeDrawer();
        refresh();
      })
      .catch(function (err) {
        window.VG.toast('Could not update', err.message, 'crit');
      });
  }

  function refresh() {
    return Promise.all([load(), loadRanking(), loadScans()]);
  }

  /* --------------------------------------------------------------- wire */

  if (backdrop) backdrop.addEventListener('click', closeDrawer);
  var closeBtn = $('[data-drawer-close]');
  if (closeBtn) closeBtn.addEventListener('click', closeDrawer);

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && current) closeDrawer();
  });

  $('#exp-status').addEventListener('change', function (event) {
    state.status = event.target.value;
    load();
  });

  $('#exp-surface').addEventListener('change', function (event) {
    state.surface = event.target.value;
    load();
  });

  var scanBtn = $('#exp-scan');
  if (scanBtn) {
    scanBtn.hidden = !authed;
    scanBtn.addEventListener('click', function () {
      scanBtn.disabled = true;
      scanBtn.textContent = 'Scanning…';

      V.request('/exposure/scan', {
        method: 'POST',
        body: { surface: state.surface || undefined }
      })
        .then(function (res) {
          window.VG.toast('Discovery complete', res.message, 'ok');
          refresh();
        })
        .catch(function (err) {
          window.VG.toast('Scan failed', err.message, 'crit');
        })
        .then(function () {
          scanBtn.disabled = false;
          scanBtn.textContent = 'Run discovery';
        });
    });
  }

  refresh();
})();
