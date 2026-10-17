/**
 * Shared site behaviour: navigation, auth-aware header, scroll reveals,
 * toasts, FAQ accordions, the hero canvas and small formatting helpers.
 * Loaded on every page.
 */
(function () {
  'use strict';

  var V = window.VGIL;

  /* ------------------------------------------------------------- helpers */

  function $(sel, root) {
    return (root || document).querySelector(sel);
  }
  function $$(sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /** Relative time, e.g. "4m ago". Falls back to a date for old records. */
  function timeAgo(iso) {
    var diff = Date.now() - new Date(iso).getTime();
    var s = Math.floor(diff / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return s + 's ago';
    var m = Math.floor(s / 60);
    if (m < 60) return m + 'm ago';
    var h = Math.floor(m / 60);
    if (h < 24) return h + 'h ago';
    var d = Math.floor(h / 24);
    if (d < 14) return d + 'd ago';
    return new Date(iso).toLocaleDateString();
  }

  function clock(iso) {
    var d = new Date(iso);
    return (
      String(d.getHours()).padStart(2, '0') +
      ':' +
      String(d.getMinutes()).padStart(2, '0') +
      ':' +
      String(d.getSeconds()).padStart(2, '0')
    );
  }

  function fullTime(iso) {
    var d = new Date(iso);
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }

  function num(n) {
    return Number(n || 0).toLocaleString();
  }

  function duration(minutes) {
    if (!minutes) return '—';
    if (minutes < 60) return minutes + ' min';
    var h = Math.floor(minutes / 60);
    var m = minutes % 60;
    return h + 'h ' + (m ? m + 'm' : '');
  }

  /** Count-up animation for headline numbers. */
  function countTo(node, target, suffix) {
    suffix = suffix || '';

    function render(value) {
      node.textContent =
        (target % 1 !== 0 ? value.toFixed(1) : Math.round(value).toLocaleString()) + suffix;
    }

    // requestAnimationFrame never fires in a background tab, which would leave
    // the placeholder on screen. Skip straight to the final value instead.
    var reduced =
      window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (document.hidden || reduced) {
      render(target);
      return;
    }

    var startAt = performance.now();
    var dur = 1100;

    function frame(now) {
      var p = Math.min((now - startAt) / dur, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      render(target * eased);
      if (p < 1) requestAnimationFrame(frame);
      else render(target);
    }
    requestAnimationFrame(frame);
  }

  /* --------------------------------------------------------------- toasts */

  function toast(title, body, kind) {
    var host = $('.toasts');
    if (!host) {
      host = el('div', 'toasts');
      document.body.appendChild(host);
    }

    var t = el('div', 'toast' + (kind ? ' ' + kind : ''));
    t.appendChild(el('strong', null, title));
    if (body) t.appendChild(el('div', 'text-muted', body));
    host.appendChild(t);

    setTimeout(function () {
      t.style.transition = 'opacity .3s, transform .3s';
      t.style.opacity = '0';
      t.style.transform = 'translateX(20px)';
      setTimeout(function () {
        t.remove();
      }, 300);
    }, 5200);
  }

  /* ------------------------------------------------------------ navigation */

  function initNav() {
    var toggle = $('.nav-toggle');
    var links = $('.nav-links');

    if (toggle && links) {
      toggle.addEventListener('click', function () {
        var open = links.classList.toggle('open');
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      });

      // Close the mobile menu after navigating.
      links.addEventListener('click', function (e) {
        if (e.target.tagName === 'A') links.classList.remove('open');
      });
    }

    // Mark the current page in the nav.
    var here = location.pathname.replace(/\/$/, '') || '/vigil-soc-website/index.html';
    $$('.nav-links a').forEach(function (a) {
      var href = a.getAttribute('href');
      if (!href || href.charAt(0) === '#') return;
      var path = href.replace(/^\./, '').replace(/\/$/, '');
      if (
        path === here ||
        (here === '/vigil-soc-website' && path === '/vigil-soc-website/index.html') ||
        (here === '/vigil-soc-website/index.html' && path === '/vigil-soc-website')
      ) {
        a.classList.add('active');
        a.setAttribute('aria-current', 'page');
      }
    });
  }

  /** Swaps the header CTA depending on whether a session exists. */
  function initAuthState() {
    var slot = $('[data-auth-slot]');
    if (!slot) return;

    var user = V.session.user();

    if (user) {
      // The palette trigger and theme toggle are page chrome, not auth state.
      // Clearing the slot outright removed them for every signed-in visitor,
      // so they are lifted out and put back rather than rebuilt — the same
      // nodes survive, which is what lets initChrome bind to them afterwards.
      var chrome = Array.prototype.slice.call(
        slot.querySelectorAll('.palette-trigger, .theme-toggle')
      );

      slot.innerHTML = '';
      chrome.forEach(function (node) {
        slot.appendChild(node);
      });

      // Just "Console". Prefixing the first name made this button as wide as
      // the name happened to be, and with four signed-in actions in the bar
      // that pushed an admin's nav past the viewport — worse the longer the
      // name. The greeting lives on the account page, where it has room.
      var dash = el('a', 'btn btn-ghost btn-sm', 'Console');
      dash.href = '/vigil-soc-website/dashboard.html';
      dash.title = 'Signed in as ' + user.name;

      var account = el('a', 'btn btn-ghost btn-sm', 'Account');
      account.href = '/vigil-soc-website/account.html';

      // Only shown to admins; the server enforces the role regardless.
      var admin = null;
      if (user.role === 'admin') {
        admin = el('a', 'btn btn-ghost btn-sm', 'Admin');
        admin.href = '/vigil-soc-website/admin.html';
      }

      var out = el('button', 'btn btn-primary btn-sm', 'Sign out');
      out.type = 'button';
      out.addEventListener('click', function () {
        V.api.logout().then(function () {
          V.session.clear();
          toast('Signed out', 'Your session token was revoked.');
          setTimeout(function () {
            location.href = '/vigil-soc-website/index.html';
          }, 600);
        });
      });

      slot.appendChild(dash);
      slot.appendChild(account);
      if (admin) slot.appendChild(admin);
      slot.appendChild(out);
    }
  }

  /** Pages that require a session redirect to login with a return path. */
  function guard() {
    if (!document.body.hasAttribute('data-requires-auth')) return true;
    if (V.session.isAuthed()) return true;
    location.href = '/vigil-soc-website/login.html?next=' + encodeURIComponent(location.pathname);
    return false;
  }

  /* --------------------------------------------------------- scroll reveal */

  /**
   * Static content grids get a cascade automatically, so a row of cards deals
   * itself out instead of appearing as one block. Grids with an id are skipped
   * — those are populated by page scripts that stagger their own children.
   */
  function markStaggerGrids() {
    $$('section .grid, section .people, section .steps, section .matrix').forEach(function (grid) {
      // Skip containers a page script fills and staggers itself.
      if (grid.id) return;
      if (grid.classList.contains('reveal-stagger')) return;
      if (grid.children.length < 2) return;
      // Children that reveal individually already have their own timing.
      if (grid.querySelector('.reveal')) return;

      // `reveal` fades the container in; `reveal-stagger` cascades its
      // children. A container that is already marked `reveal` only needs
      // the second class adding.
      grid.classList.add('reveal', 'reveal-stagger');
    });
  }

  function initReveal() {
    markStaggerGrids();

    var items = $$('.reveal');
    if (!items.length) return;

    function show(node) {
      var delay = Number(node.dataset.delay || 0);
      if (!delay) {
        node.classList.add('in');
        return;
      }
      setTimeout(function () {
        node.classList.add('in');
      }, delay);
    }

    function revealAll() {
      items.forEach(function (i) {
        i.classList.add('in');
      });
    }

    if (!('IntersectionObserver' in window)) {
      revealAll();
      return;
    }

    // Anything already on screen is shown straight away rather than waiting
    // for the observer's first callback — above-the-fold content should not
    // wait a frame to become readable.
    items.forEach(function (node) {
      var box = node.getBoundingClientRect();
      if (box.top < window.innerHeight && box.bottom > 0) show(node);
    });

    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          show(entry.target);
          io.unobserve(entry.target);
        });
      },
      { threshold: 0.12, rootMargin: '0px 0px -40px 0px' }
    );

    items.forEach(function (i) {
      if (!i.classList.contains('in')) io.observe(i);
    });

    // Failsafe: if the observer never reports anything — throttled, unsupported
    // in some embedded view, or otherwise broken — the page must not be left
    // with invisible content. Only fires when nothing at all has revealed.
    setTimeout(function () {
      if (!document.querySelector('.reveal.in')) revealAll();
    }, 2500);
  }

  /* ------------------------------------------------------------------ FAQ */

  /**
   * Accordion with a height transition. max-height is set from the answer's
   * measured height rather than a guessed constant, so long answers cannot
   * be clipped and the easing always covers the real distance.
   */
  function initFaq() {
    var items = $$('.faq-item');

    function collapse(item) {
      var answer = $('.faq-a', item);
      if (!answer) return;
      // Pin the current height, force a synchronous reflow, then drop to zero.
      // Reading offsetHeight between the two writes commits the first value
      // without depending on a frame being produced.
      answer.style.maxHeight = answer.scrollHeight + 'px';
      void answer.offsetHeight;
      answer.style.maxHeight = '';
      item.classList.remove('open');
    }

    function expand(item) {
      var answer = $('.faq-a', item);
      if (!answer) return;
      item.classList.add('open');
      answer.style.maxHeight = answer.scrollHeight + 32 + 'px';
    }

    items.forEach(function (item) {
      var btn = $('.faq-q', item);
      if (!btn) return;

      btn.setAttribute('aria-expanded', 'false');

      btn.addEventListener('click', function () {
        var open = item.classList.contains('open');
        if (open) collapse(item);
        else expand(item);
        btn.setAttribute('aria-expanded', open ? 'false' : 'true');
      });
    });

    // A resize can change how many lines an open answer needs.
    var resizeTimer;
    window.addEventListener('resize', function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function () {
        $$('.faq-item.open .faq-a').forEach(function (answer) {
          answer.style.maxHeight = answer.scrollHeight + 32 + 'px';
        });
      }, 180);
    });
  }

  /* ----------------------------------------------------------------- tabs */

  function initTabs() {
    $$('[data-tabs]').forEach(function (group) {
      var buttons = $$('.tab', group);
      buttons.forEach(function (btn) {
        btn.addEventListener('click', function () {
          var target = btn.dataset.tab;
          buttons.forEach(function (b) {
            b.classList.toggle('on', b === btn);
            b.setAttribute('aria-selected', b === btn ? 'true' : 'false');
          });
          $$('.tabpane', group.parentElement).forEach(function (pane) {
            pane.hidden = pane.dataset.pane !== target;
          });
        });
      });
    });
  }

  /* ---------------------------------------------------------- topbar feed */

  /**
   * Continuously scrolling headline strip. The track holds two identical
   * copies of the headlines so translating it by exactly -50% wraps with no
   * visible seam.
   */
  function initTicker() {
    var host = $('[data-ticker]');
    if (!host) return;

    var feed = host.parentElement;

    V.api
      .feed()
      .then(function (res) {
        var lines = res.data.headlines;
        if (!lines || !lines.length) return;

        var track = el('div', 'ticker-track mono');
        for (var copy = 0; copy < 2; copy += 1) {
          lines.forEach(function (line) {
            track.appendChild(el('span', 'ticker-item', line));
          });
        }

        feed.innerHTML = '';
        feed.appendChild(track);
      })
      .catch(function () {
        host.textContent = 'threat feed unavailable';
      });
  }

  /* ------------------------------------------------- scroll-driven chrome */

  /** Reading-progress rail plus the condensed nav state. */
  function initScrollChrome() {
    var nav = $('.nav');

    var bar = el('div', 'scroll-progress');
    document.body.appendChild(bar);

    var ticking = false;

    function update() {
      ticking = false;
      var scrolled = window.scrollY || document.documentElement.scrollTop;
      var height =
        document.documentElement.scrollHeight - document.documentElement.clientHeight;

      bar.style.width = height > 0 ? (scrolled / height) * 100 + '%' : '0%';
      if (nav) nav.classList.toggle('scrolled', scrolled > 90);
    }

    window.addEventListener(
      'scroll',
      function () {
        if (ticking) return;
        ticking = true;
        requestAnimationFrame(update);
      },
      { passive: true }
    );

    update();
  }

  /* ---------------------------------------------------------- hero canvas */

  /**
   * Animated network backdrop: drifting nodes, proximity links, traffic
   * packets, a rotating radar sweep and detection rings that fire on
   * compromised nodes. Reacts to the cursor. Pure canvas, no library.
   */
  function initHeroCanvas() {
    var canvas = $('#hero-canvas');
    if (!canvas) return;

    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      return;
    }

    var ctx = canvas.getContext('2d');
    var nodes = [];
    var packets = [];
    var rings = [];
    var w = 0;
    var h = 0;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var raf = null;
    var sweepAngle = 0;
    var mouse = { x: -9999, y: -9999 };

    var LINK_DIST = 132;
    var MOUSE_DIST = 170;

    function resize() {
      var rect = canvas.getBoundingClientRect();
      w = rect.width;
      h = rect.height;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      var count = Math.min(Math.round((w * h) / 15000), 78);
      nodes = [];
      for (var i = 0; i < count; i += 1) {
        nodes.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.22,
          vy: (Math.random() - 0.5) * 0.22,
          r: Math.random() * 1.6 + 0.9,
          hot: Math.random() < 0.09,
          phase: Math.random() * Math.PI * 2
        });
      }
    }

    function spawnPacket() {
      if (nodes.length < 2) return;
      var a = Math.floor(Math.random() * nodes.length);
      var b = Math.floor(Math.random() * nodes.length);
      if (a === b) return;
      packets.push({ a: a, b: b, t: 0, speed: 0.008 + Math.random() * 0.012 });
    }

    /** A detection firing on a compromised node: an expanding warning ring. */
    function spawnRing() {
      var hot = nodes.filter(function (n) {
        return n.hot;
      });
      if (!hot.length) return;
      var n = hot[Math.floor(Math.random() * hot.length)];
      rings.push({ x: n.x, y: n.y, r: 2, life: 1 });
    }

    function draw(now) {
      ctx.clearRect(0, 0, w, h);

      var t = (now || 0) / 1000;

      // --- radar sweep, anchored off the left edge like a console scope
      var cx = w * 0.12;
      var cy = h * 0.52;
      var reach = Math.max(w, h) * 0.95;
      sweepAngle += 0.0055;

      var grad = ctx.createConicGradient
        ? ctx.createConicGradient(sweepAngle, cx, cy)
        : null;

      if (grad) {
        grad.addColorStop(0, 'rgba(0, 240, 168, 0.10)');
        grad.addColorStop(0.055, 'rgba(0, 240, 168, 0.015)');
        grad.addColorStop(0.13, 'rgba(0, 240, 168, 0)');
        grad.addColorStop(1, 'rgba(0, 240, 168, 0)');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(cx, cy, reach, 0, Math.PI * 2);
        ctx.fill();
      }

      // Range rings around the scope origin.
      ctx.strokeStyle = 'rgba(0, 240, 168, .045)';
      ctx.lineWidth = 1;
      for (var ring = 1; ring <= 3; ring += 1) {
        ctx.beginPath();
        ctx.arc(cx, cy, (reach / 3.4) * ring, 0, Math.PI * 2);
        ctx.stroke();
      }

      // --- links between nearby nodes, brighter near the cursor
      for (var i = 0; i < nodes.length; i += 1) {
        for (var j = i + 1; j < nodes.length; j += 1) {
          var dx = nodes[i].x - nodes[j].x;
          var dy = nodes[i].y - nodes[j].y;
          var dist = Math.sqrt(dx * dx + dy * dy);
          if (dist > LINK_DIST) continue;

          var mx = (nodes[i].x + nodes[j].x) / 2 - mouse.x;
          var my = (nodes[i].y + nodes[j].y) / 2 - mouse.y;
          var near = Math.sqrt(mx * mx + my * my) < MOUSE_DIST;

          var alpha = (1 - dist / LINK_DIST) * (near ? 0.5 : 0.16);
          ctx.strokeStyle = near
            ? 'rgba(56, 204, 255, ' + alpha + ')'
            : 'rgba(0, 240, 168, ' + alpha + ')';
          ctx.lineWidth = near ? 0.9 : 0.6;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.stroke();
        }
      }

      // --- nodes
      nodes.forEach(function (n) {
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < 0 || n.x > w) n.vx *= -1;
        if (n.y < 0 || n.y > h) n.vy *= -1;

        // Compromised nodes breathe; the rest sit still.
        var pulse = n.hot ? 1 + Math.sin(t * 2.2 + n.phase) * 0.25 : 1;

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r * pulse, 0, Math.PI * 2);
        ctx.fillStyle = n.hot ? 'rgba(255, 64, 95, .8)' : 'rgba(56, 204, 255, .55)';
        ctx.fill();

        if (n.hot) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, (n.r + 3.5) * pulse, 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(255, 64, 95, .22)';
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      });

      // --- traffic packets
      packets = packets.filter(function (p) {
        p.t += p.speed;
        if (p.t >= 1) return false;
        var a = nodes[p.a];
        var b = nodes[p.b];
        if (!a || !b) return false;

        var x = a.x + (b.x - a.x) * p.t;
        var y = a.y + (b.y - a.y) * p.t;
        var fade = 1 - Math.abs(p.t - 0.5) * 1.4;

        // Short trail behind the packet.
        ctx.strokeStyle = 'rgba(0, 240, 168, ' + fade * 0.35 + ')';
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.moveTo(a.x + (b.x - a.x) * Math.max(p.t - 0.06, 0), a.y + (b.y - a.y) * Math.max(p.t - 0.06, 0));
        ctx.lineTo(x, y);
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(x, y, 2, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0, 240, 168, ' + fade + ')';
        ctx.fill();
        return true;
      });

      // --- detection rings
      rings = rings.filter(function (r) {
        r.r += 1.5;
        r.life -= 0.014;
        if (r.life <= 0) return false;
        ctx.beginPath();
        ctx.arc(r.x, r.y, r.r, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(255, 64, 95, ' + r.life * 0.55 + ')';
        ctx.lineWidth = 1.4;
        ctx.stroke();
        return true;
      });

      raf = requestAnimationFrame(draw);
    }

    canvas.parentElement.addEventListener('pointermove', function (e) {
      var rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
    });

    canvas.parentElement.addEventListener('pointerleave', function () {
      mouse.x = -9999;
      mouse.y = -9999;
    });

    resize();
    raf = requestAnimationFrame(draw);

    var spawner = setInterval(spawnPacket, 900);
    var ringTimer = setInterval(spawnRing, 2600);

    var resizeTimer;
    window.addEventListener('resize', function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(resize, 180);
    });

    // Stop burning CPU while the tab is hidden.
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        cancelAnimationFrame(raf);
        clearInterval(spawner);
        clearInterval(ringTimer);
      } else {
        raf = requestAnimationFrame(draw);
        spawner = setInterval(spawnPacket, 900);
        ringTimer = setInterval(spawnRing, 2600);
      }
    });
  }

  /* ---------------------------------------------------------- form helper */

  /**
   * Wires a form to an API call with per-field error rendering.
   * @param {HTMLFormElement} form
   * @param {Function} submit  (values) => Promise
   * @param {Object}   opts    {onSuccess, busyText}
   */
  function bindForm(form, submit, opts) {
    opts = opts || {};
    var button = form.querySelector('[type=submit]');
    var original = button ? button.textContent : '';
    var notice = form.querySelector('[data-notice]');

    function clearErrors() {
      $$('.err', form).forEach(function (e) {
        e.textContent = '';
      });
      $$('.invalid', form).forEach(function (e) {
        e.classList.remove('invalid');
      });
      if (notice) notice.hidden = true;
    }

    function showErrors(fields) {
      Object.keys(fields).forEach(function (name) {
        var slot = form.querySelector('[data-err="' + name + '"]');
        var input = form.querySelector('[name="' + name + '"]');
        if (slot) slot.textContent = fields[name];
        if (input) input.classList.add('invalid');
      });
      var first = form.querySelector('.invalid');
      if (first) first.focus();
    }

    function showNotice(message, kind) {
      if (!notice) {
        toast(kind === 'notice-err' ? 'Error' : 'Done', message, kind === 'notice-err' ? 'crit' : '');
        return;
      }
      notice.className = 'notice ' + kind;
      notice.textContent = message;
      notice.hidden = false;
    }

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      clearErrors();

      var values = {};
      new FormData(form).forEach(function (v, k) {
        values[k] = typeof v === 'string' ? v.trim() : v;
      });

      if (button) {
        button.disabled = true;
        button.textContent = opts.busyText || 'Working…';
      }

      submit(values)
        .then(function (res) {
          if (opts.onSuccess) opts.onSuccess(res, form, showNotice);
        })
        .catch(function (err) {
          if (err.fields && Object.keys(err.fields).length) showErrors(err.fields);
          showNotice(err.message, 'notice-err');
        })
        .then(function () {
          if (button) {
            button.disabled = false;
            button.textContent = original;
          }
        });
    });
  }

  /* ------------------------------------------------------- error surfaces */

  /**
   * Error placeholders, built with textContent rather than innerHTML.
   *
   * The message can originate from a server response body, which makes it
   * the one value in the UI that is neither authored here nor already
   * escaped on storage. Assembling these as nodes keeps the rule that
   * server strings are never parsed as markup true everywhere, rather than
   * relying on the particular messages happening to be harmless.
   */
  function errorCell(colspan, text) {
    var tr = el('tr');
    var td = el('td', 'empty', text);
    td.colSpan = colspan;
    tr.appendChild(td);
    return tr;
  }

  function errorBox(text) {
    return el('div', 'empty', text);
  }

  /* --------------------------------------------------------------- exports */

  window.VG = {
    $: $,
    $$: $$,
    el: el,
    timeAgo: timeAgo,
    clock: clock,
    fullTime: fullTime,
    num: num,
    duration: duration,
    countTo: countTo,
    toast: toast,
    bindForm: bindForm,
    errorCell: errorCell,
    errorBox: errorBox,
    guard: guard
  };

  /* ------------------------------------------------------------------ boot */

  /**
   * Wires the theme button and the palette trigger.
   *
   * theme.js has already applied the theme by the time this runs — it loads
   * from <head> so there is no flash — so this only has to handle the click
   * and keep the button's accessible label describing what it will do next.
   */
  function initChrome() {
    var toggle = $('.theme-toggle');
    if (toggle && window.VGTheme) {
      var describe = function () {
        var next = window.VGTheme.get() === 'light' ? 'dark' : 'light';
        toggle.setAttribute('aria-label', 'Switch to ' + next + ' theme');
        toggle.setAttribute('title', 'Switch to ' + next + ' theme');
      };
      describe();

      toggle.addEventListener('click', function () {
        var theme = window.VGTheme.toggle();
        describe();
        toast('Theme', 'Switched to ' + theme + ' mode.', 'ok');
      });
    }

    var trigger = $('[data-palette-open]');
    if (trigger) {
      trigger.addEventListener('click', function () {
        if (window.VGPalette) window.VGPalette.open();
      });
    }
  }

  function boot() {
    if (!guard()) return;
    initNav();
    initAuthState();
    initReveal();
    initFaq();
    initTabs();
    initTicker();
    initScrollChrome();
    initHeroCanvas();
    initChrome();

    var year = $('[data-year]');
    if (year) year.textContent = new Date().getFullYear();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
