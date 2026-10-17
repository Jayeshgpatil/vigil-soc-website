/** Pricing page: renders plan tiers from /api/pricing. */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;
  var el = window.VG.el;

  var grid = $('#plan-grid');
  if (!grid) return;

  V.api
    .pricing()
    .then(function (res) {
      grid.innerHTML = '';

      res.data.forEach(function (plan, i) {
        var card = el('div', 'plan reveal' + (plan.highlight ? ' featured' : ''));

        if (plan.highlight) card.appendChild(el('div', 'plan-flag', 'Most chosen'));

        card.appendChild(el('h3', null, plan.name));

        var blurb = el('p');
        blurb.textContent = plan.blurb;
        blurb.style.fontSize = '.87rem';
        blurb.style.marginTop = '.4rem';
        card.appendChild(blurb);

        var price = el('div', 'plan-price');
        if (plan.price === null) {
          price.textContent = 'Custom';
          price.style.fontSize = '2rem';
        } else {
          price.textContent = '$' + plan.price.toLocaleString();
          var unit = el('small');
          unit.textContent = ' /' + plan.unit.replace('per ', '');
          price.appendChild(unit);
        }
        card.appendChild(price);

        var limits = el('div', 'flex gap-sm wrap-flex mt-1');
        limits.appendChild(el('span', 'badge', plan.limits.assets + ' assets'));
        limits.appendChild(el('span', 'badge', plan.limits.retention));
        limits.appendChild(el('span', 'badge sev-ok', plan.limits.responseSla + ' SLA'));
        card.appendChild(limits);

        var list = el('ul', 'feature-list');
        plan.features.forEach(function (f) {
          list.appendChild(el('li', null, f));
        });
        (plan.notIncluded || []).forEach(function (f) {
          list.appendChild(el('li', 'no', f));
        });
        card.appendChild(list);

        var cta = el(
          'a',
          'btn btn-block ' + (plan.highlight ? 'btn-primary' : 'btn-ghost'),
          plan.price === null ? 'Talk to sales' : 'Get started'
        );
        cta.href = '/vigil-soc-website/contact.html?plan=' + encodeURIComponent(plan.id);
        card.appendChild(cta);

        grid.appendChild(card);
        setTimeout(function () {
          card.classList.add('in');
        }, i * 90);

        // Feature lists tick in behind their plan card.
        if (window.VGFx) {
          window.VGFx.cascadeOnView(card, list.children, {
            step: 45,
            lead: 200 + i * 90,
            side: true
          });
        }
      });

      // Prices are rendered after the effects layer booted, so they need an
      // explicit re-scan to pick up the count-up treatment.
      if (window.VGFx) window.VGFx.scanCounters(grid);
    })
    .catch(function (err) {
      grid.replaceChildren(
        window.VG.errorBox('Could not load pricing: ' + err.message)
      );
    });
})();
