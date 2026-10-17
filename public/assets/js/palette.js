/**
 * Command palette — Ctrl/Cmd+K, or "/" outside a text field.
 *
 * Searches navigation, page actions and live SOC data in one box. The four
 * existing search inputs each filter only their own table; this is the one
 * place an analyst can type an incident id or a hostname without first
 * working out which page owns it.
 *
 * Every node is built with createElement and textContent. Results include
 * hostnames, usernames and rule names that originate in telemetry, which is
 * attacker-influenced text — interpolating it into innerHTML is exactly the
 * bug that was removed from the table renderers earlier.
 */
(function () {
  'use strict';

  var STATIC_COMMANDS = [
    { label: 'Home', hint: 'Overview', href: '/index.html', group: 'Navigate' },
    { label: 'Services', hint: 'What VGIL runs', href: '/services.html', group: 'Navigate' },
    { label: 'Platform', hint: 'Detection architecture', href: '/platform.html', group: 'Navigate' },
    { label: 'Threat Intel', hint: 'Actors, IOCs, CVEs', href: '/threat-intel.html', group: 'Navigate' },
    { label: 'Live SOC Console', hint: 'Alert queue', href: '/dashboard.html', group: 'Navigate' },
    { label: 'Incidents', hint: 'Incident queue', href: '/incidents.html', group: 'Navigate' },
    { label: 'Research', hint: 'Threat research notes', href: '/research.html', group: 'Navigate' },
    { label: 'API Documentation', hint: 'REST reference', href: '/api-docs.html', group: 'Navigate' },
    { label: 'Compliance', hint: 'Trust and controls', href: '/compliance.html', group: 'Navigate' },
    { label: 'Pricing', hint: 'Plans', href: '/pricing.html', group: 'Navigate' },
    { label: 'About', hint: 'Who we are', href: '/about.html', group: 'Navigate' },
    { label: 'Contact', hint: 'Book a demo', href: '/contact.html', group: 'Navigate' },

    { label: 'Account settings', hint: 'Profile, 2FA, API keys', href: '/account.html', group: 'Account' },
    { label: 'Set up two-factor authentication', hint: 'Account security', href: '/account.html#security', group: 'Account' },
    { label: 'Manage API keys', hint: 'Programmatic access', href: '/account.html#api-keys', group: 'Account' },
    { label: 'Administration', hint: 'Users, webhooks, audit', href: '/admin.html', group: 'Account' },

    {
      label: 'Toggle light / dark theme',
      hint: 'Appearance',
      group: 'Actions',
      run: function () {
        if (window.VGTheme) window.VGTheme.toggle();
      }
    },
    {
      label: 'Export incidents as CSV',
      hint: 'Download',
      group: 'Actions',
      run: function () { download('/api/export/incidents'); }
    },
    {
      label: 'Export alerts as CSV',
      hint: 'Download',
      group: 'Actions',
      run: function () { download('/api/export/alerts'); }
    }
  ];

  var overlay = null;
  var input = null;
  var list = null;
  var results = [];
  var active = 0;
  var searchToken = 0;

  /* ------------------------------------------------------------ helpers */

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  /**
   * Exports need an Authorization header, so a plain link will not do. Fetch
   * it, then hand the blob to a temporary anchor.
   */
  function download(path) {
    var token = window.VGIL && window.VGIL.session && window.VGIL.session.token();
    if (!token) {
      if (window.VG && window.VG.toast) {
        window.VG.toast('Sign in required', 'Exports need an active session.', 'warn');
      }
      return;
    }

    fetch(path, { headers: { Authorization: 'Bearer ' + token } })
      .then(function (res) {
        if (!res.ok) throw new Error('Export failed (' + res.status + ')');
        return res.blob();
      })
      .then(function (blob) {
        var url = URL.createObjectURL(blob);
        var anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = path.split('/').pop() + '.csv';
        document.body.appendChild(anchor);
        anchor.click();
        document.body.removeChild(anchor);
        // Revoke on the next tick; revoking synchronously can cancel the
        // download in some browsers before it has started reading.
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      })
      .catch(function (err) {
        if (window.VG && window.VG.toast) {
          window.VG.toast('Export failed', err.message, 'crit');
        }
      });
  }

  function score(text, needle) {
    var haystack = String(text).toLowerCase();
    var index = haystack.indexOf(needle);
    if (index === -1) return -1;
    // Prefer matches at a word boundary, then earlier matches.
    return (index === 0 ? 0 : haystack[index - 1] === ' ' ? 1 : 2) * 1000 + index;
  }

  /* ------------------------------------------------------------- search */

  function staticMatches(needle) {
    if (!needle) return STATIC_COMMANDS.slice(0, 8);

    return STATIC_COMMANDS.map(function (command) {
      var best = Math.min(
        score(command.label, needle) === -1 ? Infinity : score(command.label, needle),
        score(command.hint, needle) === -1 ? Infinity : score(command.hint, needle) + 500
      );
      return { command: command, rank: best };
    })
      .filter(function (entry) { return entry.rank !== Infinity; })
      .sort(function (a, b) { return a.rank - b.rank; })
      .map(function (entry) { return entry.command; });
  }

  /** Live incident and alert lookups, best-effort — a failure just shows less. */
  function liveMatches(needle) {
    if (needle.length < 2) return Promise.resolve([]);

    var query = encodeURIComponent(needle);

    return Promise.all([
      fetch('/api/incidents?q=' + query + '&limit=5')
        .then(function (r) { return r.ok ? r.json() : { data: [] }; })
        .catch(function () { return { data: [] }; }),
      fetch('/api/alerts?q=' + query + '&limit=5')
        .then(function (r) { return r.ok ? r.json() : { data: [] }; })
        .catch(function () { return { data: [] }; })
    ]).then(function (responses) {
      var incidents = (responses[0].data || []).map(function (incident) {
        return {
          label: incident.id + ' — ' + incident.title,
          hint: incident.severity + ' · ' + incident.status + (incident.host ? ' · ' + incident.host : ''),
          href: '/incidents.html?id=' + encodeURIComponent(incident.id),
          group: 'Incidents'
        };
      });

      var alerts = (responses[1].data || []).map(function (alert) {
        return {
          label: alert.id + ' — ' + alert.rule,
          hint: alert.severity + (alert.host ? ' · ' + alert.host : '') +
                (alert.technique ? ' · ' + alert.technique : ''),
          href: '/dashboard.html?alert=' + encodeURIComponent(alert.id),
          group: 'Alerts'
        };
      });

      return incidents.concat(alerts);
    });
  }

  function render() {
    list.textContent = '';

    if (!results.length) {
      list.appendChild(el('div', 'palette-empty', 'No matches.'));
      return;
    }

    var lastGroup = null;

    results.forEach(function (command, index) {
      if (command.group !== lastGroup) {
        list.appendChild(el('div', 'palette-group', command.group));
        lastGroup = command.group;
      }

      var row = el('button', 'palette-item' + (index === active ? ' is-active' : ''));
      row.type = 'button';
      row.setAttribute('role', 'option');
      row.setAttribute('aria-selected', index === active ? 'true' : 'false');

      row.appendChild(el('span', 'palette-label', command.label));
      if (command.hint) row.appendChild(el('span', 'palette-hint', command.hint));

      row.addEventListener('click', function () { run(command); });
      row.addEventListener('mousemove', function () {
        if (active === index) return;
        active = index;
        render();
      });

      list.appendChild(row);
    });
  }

  function search() {
    var needle = input.value.trim().toLowerCase();
    var token = ++searchToken;

    results = staticMatches(needle);
    active = 0;
    render();

    liveMatches(needle).then(function (live) {
      // A slower earlier request must not overwrite a newer one's results.
      if (token !== searchToken || !live.length) return;
      results = results.slice(0, 6).concat(live);
      render();
    });
  }

  function run(command) {
    close();
    if (command.run) command.run();
    else if (command.href) window.location.href = command.href;
  }

  /* -------------------------------------------------------------- shell */

  function build() {
    overlay = el('div', 'palette-overlay');
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Command palette');

    var panel = el('div', 'palette');

    var field = el('div', 'palette-field');
    var icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.setAttribute('viewBox', '0 0 24 24');
    icon.setAttribute('fill', 'none');
    icon.setAttribute('stroke', 'currentColor');
    icon.setAttribute('stroke-width', '2');
    icon.setAttribute('aria-hidden', 'true');
    var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '11'); circle.setAttribute('cy', '11'); circle.setAttribute('r', '7');
    var handle = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    handle.setAttribute('d', 'm20 20-3.5-3.5');
    handle.setAttribute('stroke-linecap', 'round');
    icon.appendChild(circle); icon.appendChild(handle);
    field.appendChild(icon);

    input = el('input', 'palette-input');
    input.type = 'text';
    input.placeholder = 'Search pages, incidents, alerts…';
    input.setAttribute('aria-label', 'Search');
    input.setAttribute('autocomplete', 'off');
    input.setAttribute('spellcheck', 'false');
    field.appendChild(input);
    field.appendChild(el('kbd', 'palette-esc', 'Esc'));

    list = el('div', 'palette-list');
    list.setAttribute('role', 'listbox');

    panel.appendChild(field);
    panel.appendChild(list);

    var footer = el('div', 'palette-footer');
    footer.appendChild(el('span', null, '↑↓ navigate'));
    footer.appendChild(el('span', null, '↵ open'));
    footer.appendChild(el('span', null, 'esc close'));
    panel.appendChild(footer);

    overlay.appendChild(panel);

    overlay.addEventListener('mousedown', function (event) {
      if (event.target === overlay) close();
    });

    input.addEventListener('input', search);
    input.addEventListener('keydown', onKeydown);

    document.body.appendChild(overlay);
  }

  function onKeydown(event) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      active = Math.min(active + 1, results.length - 1);
      render();
      scrollActiveIntoView();
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      active = Math.max(active - 1, 0);
      render();
      scrollActiveIntoView();
    } else if (event.key === 'Enter') {
      event.preventDefault();
      if (results[active]) run(results[active]);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      close();
    }
  }

  function scrollActiveIntoView() {
    var node = list.querySelector('.palette-item.is-active');
    if (node && node.scrollIntoView) node.scrollIntoView({ block: 'nearest' });
  }

  var lastFocus = null;

  function open() {
    if (!overlay) build();
    lastFocus = document.activeElement;
    overlay.classList.add('is-open');
    document.body.classList.add('palette-open');
    input.value = '';
    search();
    input.focus();
  }

  function close() {
    if (!overlay) return;
    overlay.classList.remove('is-open');
    document.body.classList.remove('palette-open');
    // Returning focus is what makes this usable without a mouse.
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function isTyping(target) {
    if (!target) return false;
    var tag = target.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable;
  }

  document.addEventListener('keydown', function (event) {
    var isOpen = overlay && overlay.classList.contains('is-open');

    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      if (isOpen) close(); else open();
      return;
    }

    // "/" is the other conventional shortcut, but only when the visitor is
    // not already typing into something.
    if (event.key === '/' && !isOpen && !isTyping(event.target)) {
      event.preventDefault();
      open();
    }
  });

  window.VGPalette = { open: open, close: close };
})();
