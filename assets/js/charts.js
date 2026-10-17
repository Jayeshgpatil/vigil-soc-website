/**
 * Minimal canvas charting for the VGIL console — area/line, donut, and
 * horizontal bars. Written here rather than pulled from a CDN because the
 * site's CSP only allows same-origin scripts.
 */
(function () {
  'use strict';

  var PALETTE = {
    accent: '#00f0a8',
    accent2: '#38ccff',
    critical: '#ff405f',
    high: '#ff8f3d',
    medium: '#ffcb33',
    low: '#38ccff',
    info: '#8d9db2',
    grid: 'rgba(40, 54, 71, .55)',
    text: '#5c6b7e'
  };

  function reducedMotion() {
    return (
      window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches
    );
  }

  /**
   * Drives a 0→1 eased progress value over `duration`. Falls straight to the
   * finished state in a hidden tab (where rAF never fires) or when the viewer
   * has asked for reduced motion.
   */
  function animate(duration, onFrame) {
    if (document.hidden || reducedMotion()) {
      onFrame(1);
      return;
    }

    var start = performance.now();

    function frame(now) {
      var p = Math.min((now - start) / duration, 1);
      onFrame(1 - Math.pow(1 - p, 3));
      if (p < 1) requestAnimationFrame(frame);
      else onFrame(1);
    }

    requestAnimationFrame(frame);
  }

  /** Sets up a HiDPI canvas and returns its 2D context plus CSS dimensions. */
  function prepare(canvas, height) {
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var width = canvas.parentElement.clientWidth || canvas.clientWidth || 320;

    canvas.style.height = height + 'px';
    canvas.width = width * dpr;
    canvas.height = height * dpr;

    var ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    return { ctx: ctx, w: width, h: height };
  }

  function roundRect(ctx, x, y, w, h, r) {
    r = Math.min(r, h / 2, w / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  /**
   * Stacked area/line chart over time.
   * @param {HTMLCanvasElement} canvas
   * @param {Array} points  [{label, total, critical, high}]
   */
  function area(canvas, points, opts, progress) {
    opts = opts || {};
    if (progress === undefined) progress = 1;
    var height = opts.height || 200;
    var p = prepare(canvas, height);
    var ctx = p.ctx;

    if (!points || !points.length) return;

    var padL = 34;
    var padR = 8;
    var padT = 12;
    var padB = 24;
    var plotW = p.w - padL - padR;
    var plotH = height - padT - padB;

    var max = Math.max.apply(
      null,
      points.map(function (d) {
        return d.total;
      })
    );
    max = Math.max(max, 4);
    // Round the axis up to a clean number so gridlines read well.
    var step = Math.pow(10, Math.floor(Math.log10(max)));
    max = Math.ceil(max / step) * step;

    var x = function (i) {
      return padL + (i / Math.max(points.length - 1, 1)) * plotW;
    };
    var y = function (v) {
      return padT + plotH - (v / max) * plotH;
    };

    // Gridlines + y labels
    ctx.font = '10px ui-monospace, Menlo, Consolas, monospace';
    ctx.fillStyle = PALETTE.text;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';

    for (var g = 0; g <= 4; g += 1) {
      var val = (max / 4) * g;
      var gy = y(val);
      ctx.strokeStyle = PALETTE.grid;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padL, gy);
      ctx.lineTo(p.w - padR, gy);
      ctx.stroke();
      ctx.fillText(Math.round(val), padL - 6, gy);
    }

    // Series painter: filled gradient + stroke.
    function series(key, color) {
      var grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
      grad.addColorStop(0, color + '55');
      grad.addColorStop(1, color + '00');

      ctx.beginPath();
      ctx.moveTo(x(0), y(points[0][key]));
      points.forEach(function (d, i) {
        if (i === 0) return;
        // Smooth with a midpoint curve so the line is not jagged.
        var px = x(i - 1);
        var py = y(points[i - 1][key]);
        var cx = x(i);
        var cy = y(d[key]);
        ctx.bezierCurveTo((px + cx) / 2, py, (px + cx) / 2, cy, cx, cy);
      });

      ctx.strokeStyle = color;
      ctx.lineWidth = 1.8;
      ctx.stroke();

      ctx.lineTo(x(points.length - 1), padT + plotH);
      ctx.lineTo(x(0), padT + plotH);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
    }

    // The series are drawn inside a clip that widens with progress, so the
    // line traces itself left to right like a plot being written live.
    ctx.save();
    ctx.beginPath();
    ctx.rect(padL, 0, plotW * progress + 1, height);
    ctx.clip();

    series('total', PALETTE.accent2);
    series('critical', PALETTE.critical);

    ctx.restore();

    // Leading marker riding the front of the trace while it draws.
    if (progress < 1 && progress > 0.02) {
      var lead = (points.length - 1) * progress;
      var idx = Math.min(Math.floor(lead), points.length - 2);
      var frac = lead - idx;
      var value = points[idx].total + (points[idx + 1].total - points[idx].total) * frac;

      ctx.beginPath();
      ctx.arc(x(lead), y(value), 3, 0, Math.PI * 2);
      ctx.fillStyle = PALETTE.accent2;
      ctx.fill();
    }

    // X labels — every 4th bucket to avoid crowding.
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillStyle = PALETTE.text;
    points.forEach(function (d, i) {
      if (i % 4 !== 0 && i !== points.length - 1) return;
      ctx.fillText(d.label, x(i), padT + plotH + 7);
    });

    // --- crosshair + readout, once the chart has finished drawing itself
    var hover = canvas.__vgHover;
    if (progress < 1 || hover == null) return;

    var ratio = (hover - padL) / plotW;
    if (ratio < -0.02 || ratio > 1.02) return;

    var idx = Math.max(0, Math.min(points.length - 1, Math.round(ratio * (points.length - 1))));
    var d = points[idx];
    var hx = x(idx);

    ctx.strokeStyle = 'rgba(56, 204, 255, .45)';
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(hx, padT);
    ctx.lineTo(hx, padT + plotH);
    ctx.stroke();
    ctx.setLineDash([]);

    [
      { key: 'total', color: PALETTE.accent2 },
      { key: 'critical', color: PALETTE.critical }
    ].forEach(function (s) {
      ctx.beginPath();
      ctx.arc(hx, y(d[s.key]), 3.5, 0, Math.PI * 2);
      ctx.fillStyle = s.color;
      ctx.fill();
      ctx.strokeStyle = '#0c121b';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });

    // Readout box, flipped to whichever side has room.
    var label = d.label;
    var l1 = d.total + ' detections';
    var l2 = d.critical + ' critical';

    ctx.font = '10px ui-monospace, Menlo, Consolas, monospace';
    var boxW = Math.max(
      ctx.measureText(label).width,
      ctx.measureText(l1).width,
      ctx.measureText(l2).width
    ) + 16;
    var boxH = 46;
    var bx = hx + 10 + boxW > p.w ? hx - boxW - 10 : hx + 10;

    ctx.fillStyle = 'rgba(8, 13, 20, .95)';
    ctx.strokeStyle = 'rgba(40, 54, 71, 1)';
    ctx.lineWidth = 1;
    roundRect(ctx, bx, padT + 6, boxW, boxH, 5);
    ctx.fill();
    ctx.stroke();

    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillStyle = '#e7eef7';
    ctx.fillText(label, bx + 8, padT + 13);
    ctx.fillStyle = PALETTE.accent2;
    ctx.fillText(l1, bx + 8, padT + 26);
    ctx.fillStyle = PALETTE.critical;
    ctx.fillText(l2, bx + 8, padT + 38);
  }

  /**
   * Donut chart.
   * @param {Array} slices [{label, value, color}]
   */
  function donut(canvas, slices, opts, progress) {
    opts = opts || {};
    if (progress === undefined) progress = 1;
    var height = opts.height || 190;
    var p = prepare(canvas, height);
    var ctx = p.ctx;

    var total = slices.reduce(function (s, d) {
      return s + d.value;
    }, 0);
    if (!total) {
      ctx.fillStyle = PALETTE.text;
      ctx.font = '12px system-ui, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No data', p.w / 2, height / 2);
      return;
    }

    var cx = p.w / 2;
    var cy = height / 2;
    var outer = Math.min(p.w, height) / 2 - 6;
    var inner = outer * 0.63;
    var angle = -Math.PI / 2;

    // The ring sweeps open clockwise from twelve o'clock as progress runs.
    var limit = angle + Math.PI * 2 * progress;

    slices.forEach(function (d) {
      if (!d.value) return;
      var sweep = (d.value / total) * Math.PI * 2;
      var end = Math.min(angle + sweep, limit);

      if (end > angle) {
        ctx.beginPath();
        ctx.arc(cx, cy, outer, angle, end);
        ctx.arc(cx, cy, inner, end, angle, true);
        ctx.closePath();
        ctx.fillStyle = d.color;
        ctx.fill();

        // Thin separator so adjacent slices stay distinguishable.
        ctx.strokeStyle = '#0c121b';
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      angle += sweep;
    });

    ctx.globalAlpha = progress;
    ctx.fillStyle = '#e7eef7';
    ctx.font = '700 22px ui-monospace, Menlo, Consolas, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'alphabetic';
    ctx.fillText(Math.round(total * progress).toLocaleString(), cx, cy + 2);

    ctx.fillStyle = PALETTE.text;
    ctx.font = '10px ui-monospace, Menlo, Consolas, monospace';
    ctx.fillText(opts.caption || 'TOTAL', cx, cy + 17);
    ctx.globalAlpha = 1;
  }

  /**
   * Horizontal bars.
   * @param {Array} rows [{label, value, color}]
   */
  function bars(canvas, rows, opts, progress) {
    opts = opts || {};
    if (progress === undefined) progress = 1;
    var barH = opts.barHeight || 22;
    var gap = 8;
    var height = rows.length * (barH + gap) + 8;
    var p = prepare(canvas, height);
    var ctx = p.ctx;

    if (!rows.length) return;

    var labelW = opts.labelWidth || 116;
    var valueW = 44;
    var trackW = Math.max(p.w - labelW - valueW, 40);

    var max = Math.max.apply(
      null,
      rows.map(function (r) {
        return r.value;
      })
    );
    max = Math.max(max, 1);

    rows.forEach(function (r, i) {
      var y = i * (barH + gap) + 4;

      ctx.font = '11px system-ui, -apple-system, sans-serif';
      ctx.fillStyle = '#8d9db2';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';

      var label = r.label;
      // Trim long labels rather than letting them collide with the track.
      while (ctx.measureText(label).width > labelW - 10 && label.length > 4) {
        label = label.slice(0, -2);
      }
      if (label !== r.label) label += '…';
      ctx.fillText(label, 0, y + barH / 2);

      ctx.fillStyle = 'rgba(22, 33, 47, .9)';
      roundRect(ctx, labelW, y, trackW, barH, 4);
      ctx.fill();

      // Bars grow out from the track, each one a beat behind the last.
      var stagger = Math.min(Math.max(progress * 1.35 - i * 0.06, 0), 1);
      var w = Math.max((r.value / max) * trackW * stagger, r.value > 0 && stagger > 0 ? 3 : 0);

      if (w > 0) {
        ctx.fillStyle = r.color || PALETTE.accent;
        roundRect(ctx, labelW, y, w, barH, 4);
        ctx.fill();
      }

      ctx.fillStyle = '#e7eef7';
      ctx.font = '600 11px ui-monospace, Menlo, Consolas, monospace';
      ctx.textAlign = 'right';
      ctx.fillText(Math.round(r.value * stagger).toLocaleString(), p.w, y + barH / 2);
    });
  }

  /**
   * Live attack scope. Origins sit on a ring around a central hub — the
   * monitored estate — and fire inbound projectiles at a rate proportional
   * to their share of observed traffic.
   *
   * Deliberately a radial scope rather than a world map: the data is a
   * per-country share, not a set of coordinates, and drawing it over a
   * fake coastline would imply precision that isn't there.
   *
   * @param {HTMLCanvasElement} canvas
   * @param {Array} sources [{country, code, share, events}]
   */
  function attackMap(canvas, sources, opts) {
    if (!canvas || !sources || !sources.length) return;
    opts = opts || {};

    var height = opts.height || 320;
    var ctx = canvas.getContext('2d');
    var dpr = Math.min(window.devicePixelRatio || 1, 2);

    var w = 0;
    var cx = 0;
    var cy = 0;
    var ringR = 0;

    var shots = [];
    var impacts = [];
    var sweep = 0;
    var raf = null;

    // Strongest origins first, then spread evenly around the ring.
    var origins = sources
      .slice()
      .sort(function (a, b) {
        return b.share - a.share;
      })
      .slice(0, 9);

    var maxShare = Math.max.apply(
      null,
      origins.map(function (o) {
        return o.share;
      })
    );

    function layout() {
      w = canvas.parentElement.clientWidth || 320;
      canvas.style.height = height + 'px';
      canvas.width = w * dpr;
      canvas.height = height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      cx = w / 2;
      cy = height / 2;
      ringR = Math.min(w, height) / 2 - 34;

      origins.forEach(function (o, i) {
        var angle = (i / origins.length) * Math.PI * 2 - Math.PI / 2;
        o._a = angle;
        o._x = cx + Math.cos(angle) * ringR;
        o._y = cy + Math.sin(angle) * ringR;
        o._r = 2.5 + (o.share / maxShare) * 3.5;
      });
    }

    function fire() {
      origins.forEach(function (o) {
        // Share drives how often an origin launches.
        if (Math.random() > o.share / (maxShare * 1.6)) return;
        shots.push({ o: o, t: 0, speed: 0.012 + Math.random() * 0.01 });
      });
    }

    /** Quadratic bend so inbound tracks arc rather than run straight. */
    function pointOn(shot, t) {
      var o = shot.o;
      var mx = (o._x + cx) / 2 + (cy - o._y) * 0.22;
      var my = (o._y + cy) / 2 + (o._x - cx) * 0.22;
      var inv = 1 - t;
      return {
        x: inv * inv * o._x + 2 * inv * t * mx + t * t * cx,
        y: inv * inv * o._y + 2 * inv * t * my + t * t * cy
      };
    }

    function draw(now) {
      var time = (now || 0) / 1000;
      ctx.clearRect(0, 0, w, height);

      // --- range rings
      ctx.strokeStyle = 'rgba(40, 54, 71, .75)';
      ctx.lineWidth = 1;
      [0.4, 0.7, 1].forEach(function (f) {
        ctx.beginPath();
        ctx.arc(cx, cy, ringR * f, 0, Math.PI * 2);
        ctx.stroke();
      });

      // --- rotating sweep
      sweep += 0.012;
      var grad = ctx.createConicGradient ? ctx.createConicGradient(sweep, cx, cy) : null;
      if (grad) {
        grad.addColorStop(0, 'rgba(0, 240, 168, .22)');
        grad.addColorStop(0.08, 'rgba(0, 240, 168, .03)');
        grad.addColorStop(0.2, 'rgba(0, 240, 168, 0)');
        grad.addColorStop(1, 'rgba(0, 240, 168, 0)');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(cx, cy, ringR, 0, Math.PI * 2);
        ctx.fill();
      }

      // --- inbound tracks
      shots = shots.filter(function (s) {
        s.t += s.speed;
        if (s.t >= 1) {
          impacts.push({ r: 3, life: 1 });
          return false;
        }

        // Fading trail behind the head.
        ctx.beginPath();
        for (var k = 0; k <= 12; k += 1) {
          var tt = Math.max(s.t - (k / 12) * 0.22, 0);
          var pt = pointOn(s, tt);
          if (k === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.strokeStyle = 'rgba(255, 64, 95, .5)';
        ctx.lineWidth = 1.3;
        ctx.stroke();

        var head = pointOn(s, s.t);
        ctx.beginPath();
        ctx.arc(head.x, head.y, 2.2, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255, 120, 140, .95)';
        ctx.fill();
        return true;
      });

      // --- origins
      ctx.font = '9px ui-monospace, Menlo, Consolas, monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      origins.forEach(function (o) {
        var pulse = 1 + Math.sin(time * 1.8 + o._a * 3) * 0.18;

        ctx.beginPath();
        ctx.arc(o._x, o._y, o._r * pulse, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255, 64, 95, .85)';
        ctx.fill();

        ctx.beginPath();
        ctx.arc(o._x, o._y, o._r * pulse + 3, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(255, 64, 95, .25)';
        ctx.lineWidth = 1;
        ctx.stroke();

        // Label pushed outward so it never sits on the marker.
        var lx = cx + Math.cos(o._a) * (ringR + 16);
        var ly = cy + Math.sin(o._a) * (ringR + 16);
        ctx.fillStyle = '#8d9db2';
        ctx.fillText(o.code, lx, ly);
      });

      // --- hub
      impacts = impacts.filter(function (im) {
        im.r += 1.6;
        im.life -= 0.03;
        if (im.life <= 0) return false;
        ctx.beginPath();
        ctx.arc(cx, cy, im.r, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(0, 240, 168, ' + im.life * 0.7 + ')';
        ctx.lineWidth = 1.4;
        ctx.stroke();
        return true;
      });

      var hubPulse = 1 + Math.sin(time * 2.4) * 0.12;

      ctx.beginPath();
      ctx.arc(cx, cy, 15 * hubPulse, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0, 240, 168, .12)';
      ctx.fill();
      ctx.strokeStyle = 'rgba(0, 240, 168, .8)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(cx, cy, 4, 0, Math.PI * 2);
      ctx.fillStyle = PALETTE.accent;
      ctx.fill();

      ctx.fillStyle = PALETTE.accent;
      ctx.font = '700 9px ui-monospace, Menlo, Consolas, monospace';
      ctx.fillText(opts.hubLabel || 'ESTATE', cx, cy + 27);

      raf = requestAnimationFrame(draw);
    }

    layout();

    if (reducedMotion()) {
      // Static frame: rings, origins and hub, with no inbound traffic.
      draw(0);
      cancelAnimationFrame(raf);
      return;
    }

    raf = requestAnimationFrame(draw);
    var firing = setInterval(fire, 1300);

    if (typeof ResizeObserver !== 'undefined') {
      var last = 0;
      new ResizeObserver(function (entries) {
        var width = Math.round(entries[0].contentRect.width);
        if (!width || width === last) return;
        last = width;
        layout();
      }).observe(canvas.parentElement || canvas);
    }

    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        cancelAnimationFrame(raf);
        clearInterval(firing);
      } else {
        raf = requestAnimationFrame(draw);
        firing = setInterval(fire, 1300);
      }
    });
  }

  /** Tiny inline sparkline. */
  function spark(canvas, values, color) {
    var height = 40;
    var p = prepare(canvas, height);
    var ctx = p.ctx;
    if (!values.length) return;

    var max = Math.max.apply(null, values) || 1;
    var min = Math.min.apply(null, values);
    var range = max - min || 1;

    ctx.beginPath();
    values.forEach(function (v, i) {
      var x = (i / Math.max(values.length - 1, 1)) * p.w;
      var y = height - 4 - ((v - min) / range) * (height - 10);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color || PALETTE.accent;
    ctx.lineWidth = 1.6;
    ctx.stroke();
  }

  /**
   * A canvas has no intrinsic responsiveness: it keeps whatever pixel size it
   * was given. Wrapping each chart in a ResizeObserver on its container means
   * it repaints both when the window changes and when layout settles after
   * first paint — the case that otherwise leaves a chart drawn at the wrong
   * width for the life of the page.
   */
  function responsive(render, interactive) {
    return function (canvas, data, opts) {
      if (!canvas) return;

      // Only the time-series chart has a crosshair; binding pointer handlers
      // to the others would repaint them for no reason.
      if (interactive && !canvas.__vgHoverBound) {
        canvas.__vgHoverBound = true;
        canvas.style.cursor = 'crosshair';

        canvas.addEventListener('pointermove', function (e) {
          var box = canvas.getBoundingClientRect();
          canvas.__vgHover = e.clientX - box.left;
          if (canvas.__vgRender) canvas.__vgRender(1);
        });

        canvas.addEventListener('pointerleave', function () {
          canvas.__vgHover = null;
          if (canvas.__vgRender) canvas.__vgRender(1);
        });
      }

      canvas.__vgRender = function (progress) {
        render(canvas, data, opts, progress === undefined ? 1 : progress);
      };

      if (!canvas.__vgObserved && typeof ResizeObserver !== 'undefined') {
        canvas.__vgObserved = true;
        var lastWidth = 0;
        var ro = new ResizeObserver(function (entries) {
          var w = Math.round(entries[0].contentRect.width);
          if (!w || w === lastWidth) return;
          lastWidth = w;
          if (canvas.__vgRender) canvas.__vgRender();
        });
        ro.observe(canvas.parentElement || canvas);
      }

      // Draw in only the first time a given canvas is populated. Later data
      // refreshes repaint instantly — re-animating every poll would be noise.
      if (canvas.__vgDrawn) {
        canvas.__vgRender(1);
        return;
      }

      canvas.__vgDrawn = true;
      animate(opts && opts.duration ? opts.duration : 850, function (p) {
        canvas.__vgRender(p);
      });
    };
  }

  window.VGCharts = {
    area: responsive(area, true),
    donut: responsive(donut),
    bars: responsive(bars),
    spark: responsive(spark),
    attackMap: attackMap,
    /** Kept so call sites can group a render with its data fetch. */
    register: function (fn) {
      fn();
    },
    PALETTE: PALETTE
  };
})();
