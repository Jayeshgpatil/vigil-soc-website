/** Platform page: ATT&CK coverage matrix and the searchable rule catalog. */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;
  var $$ = window.VG.$$;
  var el = window.VG.el;

  /* ------------------------------------------------------ ATT&CK matrix */

  V.api
    .attackMatrix()
    .then(function (res) {
      var host = $('#attack-matrix');
      if (!host) return;
      host.innerHTML = '';

      // Present tactics in kill-chain order where we have coverage.
      var ORDER = [
        'Initial Access',
        'Execution',
        'Persistence',
        'Privilege Escalation',
        'Defense Evasion',
        'Credential Access',
        'Discovery',
        'Lateral Movement',
        'Collection',
        'Command and Control',
        'Exfiltration',
        'Impact'
      ];

      var tactics = Object.keys(res.data).sort(function (a, b) {
        var ai = ORDER.indexOf(a);
        var bi = ORDER.indexOf(b);
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
      });

      var allCells = [];

      tactics.forEach(function (tactic) {
        var col = el('div', 'matrix-col');
        col.appendChild(el('h4', null, tactic));

        res.data[tactic].forEach(function (t) {
          var row = el('div', 'tech');
          row.title = t.name + ' (' + t.ruleId + ')';

          var left = el('div');
          left.appendChild(el('div', 'tid', t.technique));
          var name = el('div');
          name.textContent = t.name;
          name.style.fontSize = '.72rem';
          name.style.color = 'var(--muted)';
          left.appendChild(name);
          row.appendChild(left);

          row.appendChild(el('span', 'hits' + (t.hits > 12 ? ' hot' : ''), String(t.hits)));
          col.appendChild(row);
          allCells.push(row);
        });

        host.appendChild(col);
      });

      // The coverage map fills in technique by technique.
      if (window.VGFx) {
        window.VGFx.cascadeOnView(host, allCells, { step: 22, max: 900 });
      }

      var assets = $('[data-plat="assets"]');
      if (assets) window.VG.countTo(assets, res.assets);
      var rules = $('[data-plat="rules"]');
      if (rules) window.VG.countTo(rules, res.coverage);
    })
    .catch(function () {
      var host = $('#attack-matrix');
      if (host) host.innerHTML = '<div class="empty">Coverage matrix unavailable.</div>';
    });

  /* -------------------------------------------------------- rule catalog */

  var tbody = $('#rules-body');
  var search = $('#rule-search');
  var sevSelect = $('#rule-severity');
  var countLabel = $('#rules-count');
  var allRules = [];

  function renderRules(rows) {
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!rows.length) {
      var tr = el('tr');
      var td = el('td', 'empty', 'No rules match that filter.');
      td.colSpan = 7;
      tr.appendChild(td);
      tbody.appendChild(tr);
      countLabel.textContent = '0 rules';
      return;
    }

    rows.forEach(function (r) {
      var tr = el('tr', 'row-click');
      tr.dataset.rule = r.id;

      tr.appendChild(el('td', 'cell-mono strong', r.id));
      tr.appendChild(el('td', 'strong', r.name));

      var tech = el('td', 'cell-mono');
      tech.textContent = r.technique;
      tech.style.color = 'var(--accent-2)';
      tr.appendChild(tech);

      tr.appendChild(el('td', null, r.tactic));

      var sev = el('td');
      sev.appendChild(el('span', 'badge badge-dot sev-' + r.severity, r.severity));
      tr.appendChild(sev);

      tr.appendChild(el('td', null, r.source));
      tr.appendChild(originCell(r));

      tr.addEventListener('click', function () {
        openRule(r);
      });
      tbody.appendChild(tr);
    });

    // Re-deal the rows on every filter change, so a search visibly resolves.
    if (window.VGFx) window.VGFx.cascade(tbody.children, { step: 24 });

    countLabel.textContent = rows.length + ' of ' + allRules.length + ' rules';
  }

  function applyFilters() {
    var q = (search.value || '').toLowerCase();
    var sev = sevSelect.value;

    renderRules(
      allRules.filter(function (r) {
        if (sev && r.severity !== sev) return false;
        if (!q) return true;
        return [r.id, r.name, r.technique, r.techniqueName, r.tactic, r.description].some(
          function (f) {
            return String(f).toLowerCase().indexOf(q) !== -1;
          }
        );
      })
    );
  }


  if (search) search.addEventListener('input', applyFilters);
  if (sevSelect) sevSelect.addEventListener('change', applyFilters);

  /* -------------------------------------------------------------- drawer */

  var drawer = $('[data-drawer]');
  var backdrop = $('[data-drawer-backdrop]');

  function closeDrawer() {
    drawer.classList.remove('open');
    backdrop.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
  }

  function openRule(rule) {
    $('[data-drawer-id]').textContent = rule.id + ' · ' + rule.technique;
    $('[data-drawer-title]').textContent = rule.name;

    var body = $('[data-drawer-body]');
    body.innerHTML = '';

    var dl = el('dl', 'kv');
    [
      ['Technique', rule.technique + ' — ' + rule.techniqueName],
      ['Tactic', rule.tactic],
      ['Severity', rule.severity],
      ['Telemetry source', rule.source],
      ['Fires on', rule.assetTypes ? rule.assetTypes.join(', ') : 'any asset class']
    ].forEach(function (pair) {
      dl.appendChild(el('dt', null, pair[0]));
      dl.appendChild(el('dd', null, pair[1]));
    });
    body.appendChild(dl);

    body.appendChild(el('div', 'stat-label', 'What it detects'));
    var desc = el('p');
    desc.textContent = rule.description;
    desc.style.marginBottom = '1.4rem';
    body.appendChild(desc);

    body.appendChild(el('div', 'stat-label', 'Analyst response playbook'));
    var resp = el('p');
    resp.textContent = rule.response;
    body.appendChild(resp);

    if (window.VGFx) window.VGFx.cascade(dl.children, { step: 30, lead: 150 });

    var note = el('p', 'form-note');
    note.textContent =
      'This rule is live in the detection engine. Search the console for ' +
      rule.id +
      ' to see the detections it has produced.';
    body.appendChild(note);

    drawer.classList.add('open');
    backdrop.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
  }

  if (backdrop) backdrop.addEventListener('click', closeDrawer);
  $$('[data-drawer-close]').forEach(function (b) {
    b.addEventListener('click', closeDrawer);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeDrawer();
  });

  /* ==================================================================
     CUSTOM DETECTION ENGINEERING
     ================================================================== */

  var ruleEditor = $('#rule-editor');
  var ruleForm = $('#rule-form');

  /** Renders the origin cell and, for custom rules, its controls. */
  function originCell(rule) {
    var cell = el('td');

    if (!rule.custom) {
      cell.appendChild(el('span', 'badge', 'Built-in'));
      return cell;
    }

    var wrap = el('div', 'flex gap-sm items-center wrap-flex');
    wrap.appendChild(el('span', 'badge ' + (rule.enabled ? 'is-ok' : ''), rule.enabled ? 'Custom' : 'Disabled'));

    if (!V.session.isAuthed()) return cell.appendChild(wrap), cell;

    var toggle = el('button', 'btn btn-ghost btn-sm', rule.enabled ? 'Disable' : 'Enable');
    toggle.type = 'button';
    toggle.addEventListener('click', function (event) {
      // The row opens the playbook drawer; the buttons must not.
      event.stopPropagation();
      V.request('/detections/' + encodeURIComponent(rule.id), {
        method: 'PATCH',
        body: { enabled: !rule.enabled }
      })
        .then(function (res) {
          window.VG.toast(
            res.data.enabled ? 'Rule enabled' : 'Rule disabled',
            res.data.name + ' — ' + res.activeInPool + ' rules in the detection pool.',
            'ok'
          );
          loadRules();
        })
        .catch(function (err) {
          window.VG.toast('Could not update', err.message, 'crit');
        });
    });
    wrap.appendChild(toggle);

    var remove = el('button', 'btn btn-ghost btn-sm', 'Delete');
    remove.type = 'button';
    remove.addEventListener('click', function (event) {
      event.stopPropagation();
      if (!confirm('Delete "' + rule.name + '"? It stops firing immediately.')) return;
      V.request('/detections/' + encodeURIComponent(rule.id), { method: 'DELETE' })
        .then(function () {
          window.VG.toast('Rule deleted', rule.name, 'ok');
          loadRules();
        })
        .catch(function (err) {
          window.VG.toast('Could not delete', err.message, 'crit');
        });
    });
    wrap.appendChild(remove);

    cell.appendChild(wrap);
    return cell;
  }

  /** Re-fetches the catalogue after any change. */
  function loadRules() {
    return V.request('/detections', { auth: false })
      .then(function (res) {
        allRules = res.data;
        var pool = $('#rule-pool');
        if (pool) pool.textContent = res.activeInPool + ' IN POOL';
        applyFilters();
      })
      .catch(function () {
        if (tbody) {
          tbody.textContent = '';
          tbody.appendChild(window.VG.errorCell(7, 'Rule catalogue unavailable.'));
        }
      });
  }

  /* -------------------------------------------------------- the editor */

  if (ruleEditor && V.session.isAuthed()) {
    ruleEditor.hidden = false;

    // Option lists come from the server so the form can never offer a value
    // the validator will reject.
    V.request('/detections/meta', { auth: false })
      .then(function (meta) {
        var severity = $('#r-severity');
        meta.severities.forEach(function (value) {
          var option = el('option', null, value);
          option.value = value;
          if (value === 'high') option.selected = true;
          severity.appendChild(option);
        });

        var tactic = $('#r-tactic');
        tactic.appendChild(el('option', null, '— none —'));
        meta.tactics.forEach(function (value) {
          var option = el('option', null, value);
          option.value = value;
          tactic.appendChild(option);
        });

        var host = $('#r-asset-types');
        meta.assetTypes.forEach(function (type) {
          var label = el('label', 'flex gap-sm items-center');
          label.style.cssText = 'font-size:.82rem;cursor:pointer';

          var box = document.createElement('input');
          box.type = 'checkbox';
          box.value = type;
          box.name = 'assetTypes';

          label.appendChild(box);
          label.appendChild(document.createTextNode(type));
          host.appendChild(label);
        });
      })
      .catch(function () {
        /* the form still submits; the server validates regardless */
      });

    window.VG.bindForm(
      ruleForm,
      function (values) {
        // FormData keeps only the last value for a repeated name, so the
        // asset-type boxes are read from the DOM.
        var assetTypes = Array.prototype.slice
          .call(ruleForm.querySelectorAll('input[name="assetTypes"]:checked'))
          .map(function (box) { return box.value; });

        return V.request('/detections', {
          method: 'POST',
          body: {
            name: values.name,
            severity: values.severity,
            tactic: values.tactic && values.tactic.indexOf('none') === -1 ? values.tactic : undefined,
            technique: values.technique || undefined,
            techniqueName: values.techniqueName || undefined,
            source: values.source || undefined,
            description: values.description,
            response: values.response || undefined,
            assetTypes: assetTypes
          }
        });
      },
      {
        busyText: 'Creating…',
        onSuccess: function (res) {
          window.VG.toast(
            'Detection rule live',
            res.data.name + ' — now ' + res.activeInPool + ' rules in the pool.',
            'ok'
          );
          ruleForm.reset();
          ruleForm.querySelectorAll('input[name="assetTypes"]').forEach(function (box) {
            box.checked = false;
          });
          loadRules();
        }
      }
    );
  }

  loadRules();
})();
