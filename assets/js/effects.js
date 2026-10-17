/**
 * Reusable motion effects layered on top of the base UI: text decode,
 * scroll-triggered counters, cursor tilt, click ripples, terminal typing
 * and the background-tab alert title. Loaded on every page.
 */
(function () {
  'use strict';

  var $ = window.VG.$;
  var $$ = window.VG.$$;

  function motionOk() {
    return !(
      window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches
    );
  }

  /** Runs fn once the element first enters the viewport. */
  function onceVisible(node, fn) {
    if (!('IntersectionObserver' in window)) {
      fn();
      return;
    }

    var box = node.getBoundingClientRect();
    if (box.top < window.innerHeight && box.bottom > 0) {
      fn();
      return;
    }

    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          io.unobserve(entry.target);
          fn();
        });
      },
      { threshold: 0.25 }
    );
    io.observe(node);
  }

  /* ------------------------------------------------------- text decode */

  var GLYPHS = '01!<>-_\\/[]{}=+*^?#%$&@';

  /**
   * Resolves text out of random glyphs, left to right. Only used on
   * monospaced labels, where substituting characters causes no reflow.
   */
  function decode(node, duration) {
    var final = node.textContent;
    if (!final.trim()) return;

    var order = [];
    for (var i = 0; i < final.length; i += 1) {
      // Each character resolves at its own moment, weighted left to right.
      order.push((i / final.length) * 0.6 + Math.random() * 0.4);
    }

    var start = performance.now();

    function frame(now) {
      var p = Math.min((now - start) / duration, 1);
      var out = '';

      for (var i = 0; i < final.length; i += 1) {
        var ch = final.charAt(i);
        if (ch === ' ' || p >= order[i]) out += ch;
        else out += GLYPHS.charAt(Math.floor(Math.random() * GLYPHS.length));
      }

      node.textContent = out;
      if (p < 1) requestAnimationFrame(frame);
      else node.textContent = final;
    }

    requestAnimationFrame(frame);
  }

  function initDecode() {
    // Eyebrows are short, uppercase and monospaced — the effect lands there
    // without shifting layout. Anything else must opt in explicitly.
    var targets = $$('.eyebrow, [data-decode]').filter(function (n) {
      return n.children.length === 0 && n.textContent.length < 60;
    });

    targets.forEach(function (node) {
      onceVisible(node, function () {
        decode(node, 900);
      });
    });
  }

  /* --------------------------------------------------- counters on view */

  /**
   * Animates any static stat figure when it scrolls into view. Values owned
   * by a page script (data-kpi, data-metric, …) are left alone, as are
   * figures explicitly opted out with data-nocount.
   */
  function initCounters(root) {
    var MANAGED = ['data-kpi', 'data-metric', 'data-sum', 'data-plat', 'data-nocount'];

    $$('.stat-value, .plan-price', root).forEach(function (node) {
      // Re-scans must not restart a figure that is already counting.
      if (node.__vgCounted) return;
      node.__vgCounted = true;

      var managed = MANAGED.some(function (attr) {
        return node.hasAttribute(attr);
      });
      if (managed) return;

      // Animate only the leading text node, so suffix markup such as
      // <span>%</span> stays exactly where it is.
      var first = node.firstChild;
      if (!first || first.nodeType !== 3) return;

      var raw = first.nodeValue.trim();
      var match = raw.match(/^(\$?)([\d,]+(?:\.\d+)?)(.*)$/);
      if (!match) return;

      var prefix = match[1];
      var target = parseFloat(match[2].replace(/,/g, ''));
      var suffix = match[3];
      if (!isFinite(target) || target === 0) return;

      var decimals = (match[2].split('.')[1] || '').length;

      function finalValue() {
        return (
          prefix +
          (decimals ? target.toFixed(decimals) : target.toLocaleString()) +
          suffix
        );
      }

      // A hidden tab never runs requestAnimationFrame, so zeroing the figure
      // there would leave a permanent "0" on screen. Leave it as authored.
      if (!motionOk() || document.hidden) return;

      first.nodeValue = prefix + '0' + suffix;

      onceVisible(node, function () {
        var start = performance.now();
        var done = false;

        function frame(now) {
          var p = Math.min((now - start) / 1200, 1);
          var eased = 1 - Math.pow(1 - p, 3);
          var value = target * eased;

          first.nodeValue =
            prefix +
            (decimals
              ? value.toFixed(decimals)
              : Math.round(value).toLocaleString()) +
            suffix;

          if (p < 1) {
            requestAnimationFrame(frame);
          } else {
            done = true;
            first.nodeValue = finalValue();
          }
        }

        requestAnimationFrame(frame);

        // Failsafe: if frames never arrive, show the real number rather than 0.
        setTimeout(function () {
          if (!done) first.nodeValue = finalValue();
        }, 2500);
      });
    });
  }

  /* ---------------------------------------------------------- card tilt */

  /**
   * Subtle cursor-follow tilt, capped at a few degrees so text stays crisp.
   *
   * Delegated from the document rather than bound per element: most of these
   * cards (services, actors, plans) are rendered from API data after this
   * runs, and per-element listeners would miss all of them.
   */
  function initTilt() {
    if (!motionOk()) return;
    if (window.matchMedia && window.matchMedia('(pointer: coarse)').matches) return;

    var SELECTOR = '.card-hover, .plan, .person';
    var active = null;

    function release() {
      if (!active) return;
      // Handing the transform back to CSS keeps the hover-out easing.
      active.style.transform = '';
      active = null;
    }

    document.addEventListener(
      'pointermove',
      function (e) {
        var card = e.target.closest ? e.target.closest(SELECTOR) : null;

        if (active && active !== card) release();
        if (!card) return;

        active = card;

        var lift = card.classList.contains('plan') ? -6 : -4;
        var box = card.getBoundingClientRect();
        var px = (e.clientX - box.left) / box.width - 0.5;
        var py = (e.clientY - box.top) / box.height - 0.5;

        card.style.transform =
          'perspective(900px) translateY(' +
          lift +
          'px) rotateX(' +
          (-py * 5).toFixed(2) +
          'deg) rotateY(' +
          (px * 5).toFixed(2) +
          'deg)';
      },
      { passive: true }
    );

    // Pointer leaving the window never fires a move over another element.
    document.documentElement.addEventListener('pointerleave', release);
    window.addEventListener('blur', release);
  }

  /* ------------------------------------------------------------- ripple */

  function initRipple() {
    document.addEventListener('pointerdown', function (e) {
      var btn = e.target.closest ? e.target.closest('.btn, .chip') : null;
      if (!btn || btn.disabled || !motionOk()) return;

      var box = btn.getBoundingClientRect();
      var size = Math.max(box.width, box.height) * 2;

      var ink = document.createElement('span');
      ink.className = 'ripple';
      ink.style.width = size + 'px';
      ink.style.height = size + 'px';
      ink.style.left = e.clientX - box.left - size / 2 + 'px';
      ink.style.top = e.clientY - box.top - size / 2 + 'px';

      btn.appendChild(ink);
      setTimeout(function () {
        ink.remove();
      }, 620);
    });
  }

  /* --------------------------------------------------- terminal typing */

  /**
   * Wipes each console line in from the left, one after another. A clip-path
   * wipe rather than character insertion, so nested markup inside the line
   * survives intact.
   */
  function initTypedConsoles() {
    $$('[data-typed]').forEach(function (box) {
      var lines = $$('.console-line', box);
      if (!lines.length) return;

      if (!motionOk()) return;

      var LEAD = 0.25;
      var STEP = 0.34;
      var RUN = 0.85;

      lines.forEach(function (line, i) {
        line.style.animationDelay = LEAD + i * STEP + 's';
      });

      onceVisible(box, function () {
        box.classList.add('typing');

        // The class only exists while the sequence plays. Removing it returns
        // the lines to their unclipped resting state, so a stalled animation
        // can never leave the console permanently blank.
        var total = (LEAD + (lines.length - 1) * STEP + RUN) * 1000 + 250;
        setTimeout(function () {
          box.classList.remove('typing');
        }, total);
      });
    });
  }

  /* ------------------------------------------------------------ cascade */

  /**
   * Deals a collection of elements in one after another — table rows, list
   * items, matrix cells. Entrance only: the hidden state lives in the
   * keyframe, so an element that never animates still renders normally.
   *
   * @param {Array|NodeList} nodes
   * @param {{step?:number, lead?:number, max?:number, side?:boolean}} opts
   */
  function cascade(nodes, opts) {
    opts = opts || {};
    if (!nodes || !nodes.length || !motionOk()) return;

    var step = opts.step || 32;
    var lead = opts.lead || 0;
    // Beyond a couple of dozen items the stagger stops reading as a cascade
    // and just looks like lag, so the delay is capped.
    var cap = opts.max || 620;
    var cls = opts.side ? 'cascade-side' : 'cascade-in';

    Array.prototype.forEach.call(nodes, function (node, i) {
      node.classList.remove('cascade-in', 'cascade-side');
      void node.offsetWidth; // restart if the element is being re-dealt
      node.style.animationDelay = Math.min(lead + i * step, cap) + 'ms';
      node.classList.add(cls);
    });
  }

  /** Cascades a collection the first time it scrolls into view. */
  function cascadeOnView(container, nodes, opts) {
    if (!container) return;
    onceVisible(container, function () {
      cascade(nodes, opts);
    });
  }

  /**
   * Static tables present in the markup get their rows dealt in on scroll.
   * Tables driven by a page script hold only a placeholder row at boot, so
   * cascading that is harmless — those scripts call cascade() themselves
   * after each render.
   */
  function initTableCascade() {
    $$('table.data').forEach(function (table) {
      var rows = $$('tbody tr', table);
      if (rows.length < 2) return;
      cascadeOnView(table, rows, { step: 26 });
    });
  }

  /* -------------------------------------------------- background alerts */

  /**
   * Flashes the tab title while the operator is looking elsewhere — the
   * behaviour a real console needs when a critical detection lands.
   */
  var titleState = { original: document.title, timer: null, count: 0 };

  function flashTitle(message) {
    if (!document.hidden) return;

    titleState.count += 1;
    if (titleState.timer) return;

    var on = false;
    titleState.timer = setInterval(function () {
      on = !on;
      document.title = on
        ? '(' + titleState.count + ') ' + message
        : titleState.original;
    }, 1100);
  }

  function clearTitle() {
    if (titleState.timer) {
      clearInterval(titleState.timer);
      titleState.timer = null;
    }
    titleState.count = 0;
    document.title = titleState.original;
  }

  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) clearTitle();
  });

  window.VGFx = {
    decode: decode,
    onceVisible: onceVisible,
    cascade: cascade,
    cascadeOnView: cascadeOnView,
    /** Re-scan after a page script renders figures into the DOM. */
    scanCounters: initCounters,
    flashTitle: flashTitle,
    clearTitle: clearTitle,
    motionOk: motionOk
  };

  /* -------------------------------------------------------------- boot */

  function boot() {
    if (motionOk()) initDecode();
    initCounters();
    initTilt();
    initRipple();
    initTypedConsoles();
    initTableCascade();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
