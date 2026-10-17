/** Services page: renders the service catalog from /api/services. */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;
  var el = window.VG.el;

  var ICONS = {
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 12l7-4"/>',
    shield: '<path d="M12 2 4 5v6c0 5 3.4 8.5 8 10 4.6-1.5 8-5 8-10V5l-8-3Z"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18Z"/>',
    siren: '<path d="M5 20h14M7 20v-6a5 5 0 0 1 10 0v6M12 3v2M4.5 7 6 8.5M19.5 7 18 8.5"/>',
    bug: '<path d="M8 6a4 4 0 0 1 8 0M6 10h12v4a6 6 0 0 1-12 0v-4ZM3 12h3M18 12h3M4.5 7 7 9M19.5 7 17 9M4.5 17 7 15M19.5 17 17 15"/>',
    clipboard: '<rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3h6v1M9 10h6M9 14h6M9 18h3"/>'
  };

  var host = $('#service-list');
  if (!host) return;

  V.api
    .services()
    .then(function (res) {
      host.innerHTML = '';

      res.data.forEach(function (svc, i) {
        var panel = el('section', 'panel reveal');
        panel.id = svc.id;
        panel.style.marginBottom = '1.25rem';
        panel.style.scrollMarginTop = '110px';

        // ---- header
        var head = el('div', 'panel-head');
        var left = el('div', 'flex items-center gap-sm');

        var icon = el('div', 'card-icon');
        icon.style.margin = '0';
        icon.style.width = '38px';
        icon.style.height = '38px';
        icon.innerHTML =
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" ' +
          'stroke-linecap="round" stroke-linejoin="round" style="width:19px;height:19px">' +
          (ICONS[svc.icon] || ICONS.shield) +
          '</svg>';
        left.appendChild(icon);

        var titles = el('div');
        var h = el('h3', null, svc.name);
        h.style.fontSize = '1.15rem';
        titles.appendChild(h);
        var tag = el('div', 'mono text-accent');
        tag.textContent = svc.tagline;
        tag.style.fontSize = '.78rem';
        titles.appendChild(tag);
        left.appendChild(titles);

        head.appendChild(left);

        var metrics = el('div', 'flex gap-sm wrap-flex');
        svc.metrics.forEach(function (m) {
          metrics.appendChild(el('span', 'badge', m.label + ' ' + m.value));
        });
        head.appendChild(metrics);
        panel.appendChild(head);

        // ---- body
        var body = el('div', 'panel-body');
        var split = el('div', 'grid g-lean g-start');
        split.style.gap = '2rem';

        var col1 = el('div');
        var desc = el('p', 'lead');
        desc.textContent = svc.description;
        desc.style.fontSize = '.98rem';
        col1.appendChild(desc);

        var cta = el('a', 'link-arrow mt-2', 'Discuss this service');
        cta.href = '/contact.html?interest=' + encodeURIComponent(svc.id);
        cta.style.display = 'inline-flex';
        col1.appendChild(cta);
        split.appendChild(col1);

        var col2 = el('div');
        var label = el('div', 'stat-label');
        label.textContent = "What's included";
        col2.appendChild(label);

        var list = el('ul', 'feature-list');
        list.style.margin = '.75rem 0 0';
        svc.features.forEach(function (f) {
          list.appendChild(el('li', null, f));
        });
        col2.appendChild(list);
        split.appendChild(col2);

        body.appendChild(split);
        panel.appendChild(body);
        host.appendChild(panel);

        setTimeout(function () {
          panel.classList.add('in');
        }, 60 * i);

        // Each service's inclusions tick in once that panel is on screen.
        if (window.VGFx) {
          window.VGFx.cascadeOnView(panel, list.children, { step: 55, lead: 120, side: true });
        }
      });

      // A deep link like /services.html#ir should land on its section.
      if (location.hash) {
        var target = document.getElementById(location.hash.slice(1));
        if (target) setTimeout(function () {
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 220);
      }
    })
    .catch(function (err) {
      var panel = el('div', 'panel');
      panel.appendChild(
        window.VG.errorBox('Could not load the service catalog. ' + err.message)
      );
      host.replaceChildren(panel);
    });
})();
