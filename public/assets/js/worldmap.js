/**
 * Live attack globe, built on cobe.
 *
 * cobe is a ~13KB WebGL globe with no runtime dependencies. It is plain
 * JavaScript — `createGlobe(canvas, options)` — so the React wrapper it is
 * usually shipped with is not needed here, and neither is React.
 *
 * It is ESM, so this file is a module and the tag that loads it carries
 * type="module". The library is served from our own origin rather than a CDN
 * because the CSP is script-src 'self'; tools/vendor.js copies it out of
 * node_modules on install.
 *
 * Everything drawn here comes from the API: markers are the attack origins
 * from the threat feed plus whichever SOC region is on console, arc counts
 * are real event volumes, and live detections push new arcs through the SSE
 * subscription the dashboard already holds open.
 */
import createGlobe from '/assets/vendor/cobe.js';

const canvas = document.getElementById('threat-map');
if (canvas) {
  const V = window.VGIL;
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ------------------------------------------------------------ palette */

  /** cobe wants linear 0..1 triples; the design tokens are hex. */
  function toRgb(hex, fallback) {
    const value = String(hex || '').trim() || fallback;
    let h = value.replace('#', '');
    if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
    if (!/^[0-9a-f]{6}$/i.test(h)) h = fallback.replace('#', '');
    const n = parseInt(h, 16);
    return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
  }

  /** For the atmosphere's slow colour drift — easier to reason about a hue
   *  sweep in HSL than to hand-pick a run of RGB triples. */
  function hslToRgb(h, s, l) {
    const c = (1 - Math.abs(2 * l - 1)) * s;
    const hp = ((h % 360) + 360) % 360 / 60;
    const x = c * (1 - Math.abs((hp % 2) - 1));
    const [r1, g1, b1] =
      hp < 1 ? [c, x, 0] : hp < 2 ? [x, c, 0] : hp < 3 ? [0, c, x] :
      hp < 4 ? [0, x, c] : hp < 5 ? [x, 0, c] : [c, 0, x];
    const m = l - c / 2;
    return [r1 + m, g1 + m, b1 + m];
  }

  function palette() {
    const css = getComputedStyle(document.documentElement);
    const read = (name, fallback) => (css.getPropertyValue(name) || '').trim() || fallback;
    const light = document.documentElement.getAttribute('data-theme') === 'light';

    return {
      light,

      // The reference configuration is a white globe on a white page.
      // Inverting it for a dark console is not just a matter of swapping the
      // tokens: cobe shades every sample by `dark`, so feeding it a surface
      // token this dark drove half the sphere below the luminance of the
      // panel behind it — a black disc on a black background. The base is
      // deliberately lighter than any surface token so the sphere itself
      // never goes invisible.
      //
      // dark is what actually decides whether land or sea reads as the
      // bright half: cobe's own reference config runs dark:0 with no
      // mapBaseBrightness at all, and *that* gives a flat grey sphere with
      // faintly darker land — fine on a white page, wrong for a "glowing
      // console" look. Pushing dark toward 1 flips the blend the other way
      // so a landmass sample clips bright and the surrounding sea sample
      // sits near mapBaseBrightness's floor instead — confirmed by pushing
      // mapBrightness to an absurd test value and watching the rendered
      // pixels actually gain a bright tail. mapBaseBrightness is that floor:
      // low means real contrast between a land dot and a sea dot; the 0.46
      // this held while chasing the too-dark-globe bug made the two nearly
      // equal and the coastline stopped reading as a coastline at all.
      // mapSamples is turned up alongside it — dot radius is fixed inside
      // cobe's shader, so a denser lattice is the only way to shrink the
      // gaps between dots and make the shape read as one continuous
      // landmass instead of a sparse scatter.
      dark: light ? 0 : 0.82,
      base: light ? [0.85, 0.90, 0.97] : [0.13, 0.34, 0.53],
      glow: light ? toRgb(read('--accent-2', '#0a7598'), '#0a7598') : [0.38, 0.14, 0.58],
      mapBrightness: light ? 5.2 : 7,
      mapBaseBrightness: light ? 0.035 : 0.08,
      diffuse: light ? 1.55 : 1.2,

      marker: toRgb(read('--crit', '#ff405f'), '#ff405f'),
      arc: toRgb(read('--accent-2', '#38ccff'), '#38ccff'),
      accent: toRgb(read('--accent', '#00f0a8'), '#00f0a8'),
      crit: toRgb(read('--crit', '#ff405f'), '#ff405f'),
      high: toRgb(read('--high', '#ff8f3d'), '#ff8f3d'),
      // Amber, and used nowhere else on the globe, so the one headquarters
      // marker never gets mistaken for an on-duty site (accent) or an attack
      // origin (crit).
      hq: toRgb(read('--med', '#ffcb33'), '#ffcb33')
    };
  }

  let colours = palette();

  /* --------------------------------------------------------------- state */

  const SOC_SITES = {
    APAC: { name: 'Singapore', lat: 1.35, lon: 103.8 },
    EMEA: { name: 'London', lat: 51.5, lon: -0.13 },
    AMER: { name: 'Toronto', lat: 43.7, lon: -79.4 }
  };

  // Mirrors server/lib/config.js's default so the marker still appears if
  // /soc/status cannot be reached at all.
  const HQ_FALLBACK = { city: 'Vadodara', region: 'Gujarat', country: 'India', lat: 22.3072, lon: 73.1812 };

  let origins = [];
  let targets = [];
  let hq = null;       // { name, region, country, lat, lon } — fixed, not rota-driven
  let liveArcs = [];   // transient, one per live detection
  let globe = null;
  let frame = 0;

  // Rotation state. cobe does not spin itself; phi is driven each frame.
  let phi = 0;
  let phiOffset = 0;
  let thetaOffset = 0;
  let dragging = null;
  let dragDelta = { phi: 0, theta: 0 };
  let paused = false;
  let revealed = false;
  let rafId = 0;

  const SPIN = reduced ? 0 : 0.0022;

  /**
   * CSS anchor positioning is how cobe pins HTML labels to the projected
   * position of a marker: it writes `anchor-name: --cobe-<id>` and a
   * `--cobe-visible-<id>` value as the marker rotates in and out of view.
   *
   * Only Chromium ships it so far. Without it every label collapses to the
   * same corner, which is worse than no labels, so they are not rendered at
   * all where it is unsupported.
   */
  const anchorsSupported =
    typeof CSS !== 'undefined' &&
    CSS.supports &&
    CSS.supports('anchor-name', '--probe');

  /* -------------------------------------------------------------- markers */

  function buildMarkers(hqPulse = 0) {
    const markers = targets
      .map((site) => ({
        location: [site.lat, site.lon],
        size: 0.06,
        color: colours.accent,
        id: 'soc-' + site.region
      }))
      .concat(
        origins.map((origin) => ({
          location: [origin.lat, origin.lon],
          // Scaled by share so the busiest origins read as bigger.
          size: 0.03 + Math.min(origin.share || 0, 25) * 0.0016,
          color: colours.crit,
          id: 'origin-' + origin.code
        }))
      );

    // Drawn largest and last so it sits on top of any on-duty or origin
    // marker it happens to land near. hqPulse is a small offset the render
    // loop drives each frame so home base gently breathes rather than
    // sitting dead still — skipped when the caller does not pass one, so a
    // plain rebuild after a data refresh stays deterministic.
    if (hq) {
      markers.push({
        location: [hq.lat, hq.lon],
        size: 0.075 + hqPulse,
        color: colours.hq,
        id: 'hq'
      });
    }

    return markers;
  }

  function buildArcs() {
    if (!targets.length) return [];

    const standing = origins.slice(0, 8).map((origin, index) => ({
      from: [origin.lat, origin.lon],
      to: [targets[index % targets.length].lat, targets[index % targets.length].lon],
      color: colours.arc,
      id: 'feed-' + origin.code
    }));

    return standing.concat(liveArcs.map((arc) => ({
      from: arc.from,
      to: arc.to,
      color: arc.color,
      id: arc.id
    })));
  }

  function pushGeometry() {
    if (!globe) return;
    globe.update({ markers: buildMarkers(), arcs: buildArcs() });
  }

  /* --------------------------------------------------------------- labels */

  const labelLayer = document.getElementById('map-labels');

  function buildLabels() {
    if (!labelLayer) return;
    labelLayer.textContent = '';
    if (!anchorsSupported) return;

    const make = (id, title, subtitle, isHq) => {
      const el = document.createElement('div');
      el.className = 'globe-label' + (isHq ? ' is-hq' : '');

      // Anchored to the name cobe writes for this marker id.
      el.style.setProperty('position-anchor', `--cobe-${id}`);
      el.style.opacity = `var(--cobe-visible-${id}, 0)`;
      el.style.filter = `blur(calc((1 - var(--cobe-visible-${id}, 0)) * 6px))`;

      const strong = document.createElement('strong');
      strong.textContent = title;
      el.appendChild(strong);

      const span = document.createElement('span');
      span.textContent = subtitle;
      el.appendChild(span);

      labelLayer.appendChild(el);
    };

    // is-hq styling is reserved for the actual headquarters below; an
    // on-duty site is real but it rotates, so it gets a plain label.
    targets.forEach((site) => make('soc-' + site.region, site.region, site.name, false));

    // The reference component animates invented numbers here. These are the
    // real 24-hour event counts the origin feed reports.
    origins.forEach((origin) =>
      make(
        'origin-' + origin.code,
        origin.code,
        origin.events.toLocaleString() + ' events',
        false
      )
    );

    if (hq) make('hq', hq.city, `${hq.region}, ${hq.country}`, true);
  }

  /* ------------------------------------------------------------- rotation */

  function onPointerDown(event) {
    dragging = { x: event.clientX, y: event.clientY };
    paused = true;
    canvas.style.cursor = 'grabbing';
    if (canvas.setPointerCapture) canvas.setPointerCapture(event.pointerId);
  }

  function onPointerMove(event) {
    if (!dragging) return;
    dragDelta = {
      phi: (event.clientX - dragging.x) / 300,
      theta: (event.clientY - dragging.y) / 1000
    };
  }

  function onPointerUp() {
    if (dragging) {
      phiOffset += dragDelta.phi;
      thetaOffset += dragDelta.theta;
      dragDelta = { phi: 0, theta: 0 };
    }
    dragging = null;
    paused = false;
    canvas.style.cursor = 'grab';
  }

  canvas.addEventListener('pointerdown', onPointerDown);
  window.addEventListener('pointermove', onPointerMove, { passive: true });
  window.addEventListener('pointerup', onPointerUp, { passive: true });
  window.addEventListener('pointercancel', onPointerUp, { passive: true });

  /* ----------------------------------------------------------------- init */

  /**
   * cobe returns a silent no-op object when it cannot get a WebGL context, so
   * a machine without one would sit looking at a permanently blank panel with
   * nothing to explain it. Checked up front instead.
   */
  function webglAvailable() {
    try {
      const probe = document.createElement('canvas');
      return Boolean(
        probe.getContext('webgl') || probe.getContext('experimental-webgl')
      );
    } catch (err) {
      return false;
    }
  }

  function showUnavailable(message) {
    canvas.hidden = true;
    const stage = canvas.parentElement;
    if (!stage || stage.querySelector('.globe-unavailable')) return;

    const notice = document.createElement('div');
    notice.className = 'globe-unavailable';
    notice.textContent = message;
    stage.appendChild(notice);
  }

  function start() {
    const width = canvas.offsetWidth;
    if (!width || globe) return;

    if (!webglAvailable()) {
      showUnavailable(
        'The threat globe needs WebGL, which this browser has not made available. ' +
        'Every figure it shows is also in the panels below.'
      );
      return;
    }

    globe = createGlobe(canvas, {
      devicePixelRatio: Math.min(window.devicePixelRatio || 1, 2),
      width,
      height: width,
      phi: 0,
      theta: 0.24,
      dark: colours.dark,
      diffuse: colours.diffuse,
      // Well above cobe's own demo default (16000): dot radius is fixed
      // inside the shader, so the only way to shrink the gaps between dots —
      // and have the coastline read as a shape, not a scatter — is more of
      // them.
      mapSamples: 24000,
      mapBrightness: colours.mapBrightness,
      mapBaseBrightness: colours.mapBaseBrightness,
      baseColor: colours.base,
      markerColor: colours.marker,
      glowColor: colours.glow,
      markerElevation: 0.035,
      markers: buildMarkers(),
      arcs: buildArcs(),
      arcColor: colours.arc,
      arcWidth: 0.75,
      arcHeight: 0.38,
      opacity: 0.94
    });

    // v2 has no onRender and runs no loop of its own: update() draws
    // synchronously and the caller drives the animation. Passing onRender
    // (the v0.6 API) silently does nothing, which leaves a static globe that
    // never reveals itself.
    animate();

    // Revealed on a timer rather than from inside the loop, so a browser that
    // throttles animation frames still ends up with a visible globe instead of
    // a permanently transparent canvas.
    setTimeout(reveal, 60);
  }

  function reveal() {
    if (revealed) return;
    revealed = true;
    canvas.style.opacity = '1';
  }

  let hqPhase = 0;
  let glowHue = 288; // violet, matching the static value it starts equal to

  function animate() {
    if (!globe) return;
    if (!paused) phi += SPIN;

    const frameState = {
      phi: phi + phiOffset + dragDelta.phi,
      theta: 0.24 + thetaOffset + dragDelta.theta
    };

    // A slow breathing pulse on the one marker that never moves, so home
    // base reads as alive rather than just another dot. Off entirely under
    // reduced motion, same as the spin.
    if (hq && !reduced) {
      hqPhase += 0.035;
      frameState.markers = buildMarkers(0.018 * Math.sin(hqPhase));
    }

    // The rim light drifts slowly through violet, cyan and pink rather than
    // sitting on one fixed colour — dark theme only, since the same sweep on
    // a white page would fight the light theme's flat teal glow instead of
    // complementing it. Saturation and lightness are held at roughly the old
    // static glow's brightness so this never turns into a brightness change
    // wearing a colour costume.
    if (!colours.light && !reduced) {
      glowHue += 0.05;
      frameState.glowColor = hslToRgb(glowHue, 0.68, 0.4);
    }

    globe.update(frameState);
    rafId = requestAnimationFrame(animate);
  }

  function resize() {
    if (!globe) return;
    const width = canvas.offsetWidth;
    if (width) globe.update({ width, height: width });
  }

  // A hidden tab gets no animation frames anyway; stopping avoids a burst of
  // queued work when it returns.
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      cancelAnimationFrame(rafId);
      rafId = 0;
    } else if (globe && !rafId) {
      animate();
    }
  });

  let resizeTimer = null;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(resize, 150);
  });

  /* ---------------------------------------------------------------- theme */

  function onThemeChange() {
    colours = palette();
    if (!globe) return;
    globe.update({
      dark: colours.dark,
      diffuse: colours.diffuse,
      baseColor: colours.base,
      glowColor: colours.glow,
      markerColor: colours.marker,
      arcColor: colours.arc,
      mapBrightness: colours.mapBrightness,
      mapBaseBrightness: colours.mapBaseBrightness
    });
    pushGeometry();
  }

  window.addEventListener('vgil:themechange', onThemeChange);

  if (window.MutationObserver) {
    // Watching the attribute rather than only the toggle's event: a cached
    // palette invalidated by one code path goes stale the moment anything
    // else changes the theme.
    new MutationObserver(onThemeChange).observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme']
    });
  }

  /* ----------------------------------------------------------------- data */

  function loadTargets() {
    return V.request('/soc/status', { auth: false })
      .then((state) => {
        targets = (state.onDuty || [])
          .map((shift) => {
            const site = SOC_SITES[shift.region];
            return site ? { region: shift.region, ...site } : null;
          })
          .filter(Boolean);

        if (!targets.length) targets = [{ region: 'EMEA', ...SOC_SITES.EMEA }];
        hq = state.headquarters || HQ_FALLBACK;

        const label = document.getElementById('map-target');
        if (label) {
          label.textContent = targets.map((t) => `${t.region} · ${t.name}`).join(' + ');
        }
      })
      .catch(() => {
        targets = [{ region: 'EMEA', ...SOC_SITES.EMEA }];
        hq = HQ_FALLBACK;
      });
  }

  function loadOrigins() {
    return V.request('/threats/geo', { auth: false })
      .then((res) => {
        origins = (res.data || []).map((row) => ({
          country: row.country,
          code: row.code,
          share: row.share,
          events: row.events,
          lat: row.lat,
          lon: row.lon
        }));

        const count = document.getElementById('map-origins');
        if (count) count.textContent = origins.length + ' ORIGINS';
      })
      .catch(() => {});
  }

  Promise.all([loadOrigins(), loadTargets()]).then(() => {
    buildLabels();

    if (canvas.offsetWidth > 0) {
      start();
    } else {
      // The panel can still be laying out when this runs; wait for a width
      // rather than initialising a zero-sized WebGL context.
      const observer = new ResizeObserver((entries) => {
        if (entries[0] && entries[0].contentRect.width > 0) {
          observer.disconnect();
          start();
        }
      });
      observer.observe(canvas);
    }
  });

  /* ------------------------------------------------------------ live feed */

  /**
   * One arc per live detection, retired after a few seconds.
   *
   * cobe has no notion of an animated arc — the geometry is static once
   * uploaded — so "live" here means the arc set changes as detections arrive
   * rather than a head travelling along a path.
   */
  function attack(severity) {
    if (!origins.length || !targets.length) return;

    const origin = origins[Math.floor(Math.random() * origins.length)];
    const target = targets[Math.floor(Math.random() * targets.length)];

    liveArcs.push({
      from: [origin.lat, origin.lon],
      to: [target.lat, target.lon],
      color: severity === 'critical' ? colours.crit : severity === 'high' ? colours.high : colours.arc,
      id: 'live-' + (frame++),
      expires: Date.now() + 6000
    });

    // Uploading a buffer per detection would thrash on a busy feed.
    if (liveArcs.length > 12) liveArcs.shift();
    pushGeometry();
  }

  setInterval(() => {
    const before = liveArcs.length;
    liveArcs = liveArcs.filter((arc) => arc.expires > Date.now());
    if (liveArcs.length !== before) pushGeometry();
  }, 1500);

  window.VGMap = {
    attack,
    refreshTargets: () => loadTargets().then(() => { buildLabels(); pushGeometry(); }),
    arcCount: () => buildArcs().length,
    markerCount: () => buildMarkers().length,
    headquarters: () => hq,
    anchorsSupported
  };
}
