/** Contact form: query-string prefill, submission and the success state. */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;
  var el = window.VG.el;

  var form = $('#contact-form');
  if (!form) return;

  // Fields settle in top to bottom on load.
  if (window.VGFx) {
    window.VGFx.cascade(
      form.querySelectorAll('.field, .btn, .form-note'),
      { step: 55, side: true }
    );
  }

  /* --------------------------------------------------------- prefilling */

  // Links like /contact.html?interest=ir or ?plan=professional arrive from the
  // services and pricing pages — carry that context into the form.
  var params = new URLSearchParams(location.search);

  var interest = params.get('interest');
  if (interest) {
    var select = $('#interest');
    if ([].some.call(select.options, function (o) { return o.value === interest; })) {
      select.value = interest;
    }
  }

  var urgency = params.get('urgency');
  if (urgency) {
    var uSelect = $('#urgency');
    if ([].some.call(uSelect.options, function (o) { return o.value === urgency; })) {
      uSelect.value = urgency;
      if (urgency === 'active-incident') {
        $('#message').placeholder =
          'Briefly: what you are seeing and when it started. Do not include credentials or sensitive system details here — we will move to a secure channel.';
      }
    }
  }

  var plan = params.get('plan');
  if (plan) {
    var msg = $('#message');
    var names = { essential: 'Essential', professional: 'Professional', enterprise: 'Enterprise' };
    if (names[plan]) {
      msg.value =
        'We are interested in the ' + names[plan] + ' plan. Our estate is roughly ___ assets and we currently use ___ for endpoint and identity.';
    }
  }

  /* --------------------------------------------------------- submission */

  function showSuccess(res) {
    var host = $('#contact-success');
    form.hidden = true;
    host.hidden = false;
    host.innerHTML = '';

    var box = el('div', 'notice notice-ok');
    box.style.display = 'block';

    var h = el('h3', null, 'Request received');
    h.style.fontSize = '1.1rem';
    h.style.marginBottom = '.5rem';
    box.appendChild(h);

    var p = el('p');
    p.textContent = res.message;
    p.style.color = 'inherit';
    box.appendChild(p);

    var ref = el('p', 'mono mt-2');
    ref.textContent = 'Reference: ' + res.reference;
    ref.style.color = 'var(--accent)';
    box.appendChild(ref);

    var sla = el('p');
    sla.textContent = 'Expected response: within ' + res.sla + '.';
    sla.style.fontSize = '.85rem';
    sla.style.color = 'var(--muted)';
    sla.style.marginTop = '.35rem';
    box.appendChild(sla);

    host.appendChild(box);

    var actions = el('div', 'btn-row mt-3');

    var again = el('button', 'btn btn-ghost', 'Send another request');
    again.type = 'button';
    again.addEventListener('click', function () {
      form.reset();
      form.hidden = false;
      host.hidden = true;
      $('#name').focus();
    });
    actions.appendChild(again);

    var console_ = el('a', 'btn btn-primary', 'Explore the live console');
    console_.href = '/dashboard.html';
    actions.appendChild(console_);

    host.appendChild(actions);

    if (window.VGFx) window.VGFx.cascade(host.children, { step: 110 });

    window.VG.toast('Request sent', 'Reference ' + res.reference);
    host.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  window.VG.bindForm(
    form,
    function (values) {
      return V.api.contact(values);
    },
    { busyText: 'Sending…', onSuccess: showSuccess }
  );
})();
