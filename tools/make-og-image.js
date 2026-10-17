'use strict';

/**
 * Generates the 1200x630 social card at public/assets/img/og-card.png.
 *
 *   node tools/make-og-image.js
 *
 * Written by hand against the PNG spec because there is no image library in
 * this project and adding one to draw a rectangle and some text would be a
 * poor trade. Social platforms largely ignore SVG for og:image, so a raster
 * is the only option that actually renders in a link preview.
 *
 * Text uses a 5x7 bitmap face scaled up with nearest-neighbour, which gives
 * the blocky terminal look the rest of the site already leans on rather than
 * a poor imitation of a smooth typeface.
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const WIDTH = 1200;
const HEIGHT = 630;

/* ------------------------------------------------------------------ font */

// Each glyph is 7 rows of 5 columns, MSB-first in the low 5 bits.
const GLYPHS = {
  A: [0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
  B: [0x1e, 0x11, 0x11, 0x1e, 0x11, 0x11, 0x1e],
  C: [0x0e, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0e],
  D: [0x1e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1e],
  E: [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f],
  F: [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x10],
  G: [0x0e, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0f],
  H: [0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
  I: [0x0e, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0e],
  J: [0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0c],
  K: [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
  L: [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f],
  M: [0x11, 0x1b, 0x15, 0x15, 0x11, 0x11, 0x11],
  N: [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
  O: [0x0e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
  P: [0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10],
  Q: [0x0e, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0d],
  R: [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
  S: [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
  T: [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
  U: [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
  V: [0x11, 0x11, 0x11, 0x11, 0x11, 0x0a, 0x04],
  W: [0x11, 0x11, 0x11, 0x15, 0x15, 0x1b, 0x11],
  X: [0x11, 0x11, 0x0a, 0x04, 0x0a, 0x11, 0x11],
  Y: [0x11, 0x11, 0x0a, 0x04, 0x04, 0x04, 0x04],
  Z: [0x1f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f],
  '0': [0x0e, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0e],
  '1': [0x04, 0x0c, 0x04, 0x04, 0x04, 0x04, 0x0e],
  '2': [0x0e, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1f],
  '3': [0x1f, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0e],
  '4': [0x02, 0x06, 0x0a, 0x12, 0x1f, 0x02, 0x02],
  '5': [0x1f, 0x10, 0x1e, 0x01, 0x01, 0x11, 0x0e],
  '6': [0x06, 0x08, 0x10, 0x1e, 0x11, 0x11, 0x0e],
  '7': [0x1f, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
  '8': [0x0e, 0x11, 0x11, 0x0e, 0x11, 0x11, 0x0e],
  '9': [0x0e, 0x11, 0x11, 0x0f, 0x01, 0x02, 0x0c],
  ' ': [0, 0, 0, 0, 0, 0, 0],
  '.': [0, 0, 0, 0, 0, 0x0c, 0x0c],
  ',': [0, 0, 0, 0, 0x0c, 0x04, 0x08],
  '-': [0, 0, 0, 0x1f, 0, 0, 0],
  '/': [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
  '&': [0x0c, 0x12, 0x14, 0x08, 0x15, 0x12, 0x0d],
  ':': [0, 0x0c, 0x0c, 0, 0x0c, 0x0c, 0]
};

/* --------------------------------------------------------------- canvas */

// Straight RGB, three bytes per pixel.
const pixels = Buffer.alloc(WIDTH * HEIGHT * 3);

function setPixel(x, y, [r, g, b]) {
  if (x < 0 || y < 0 || x >= WIDTH || y >= HEIGHT) return;
  const offset = (y * WIDTH + x) * 3;
  pixels[offset] = r;
  pixels[offset + 1] = g;
  pixels[offset + 2] = b;
}

function fillRect(x, y, w, h, colour) {
  for (let dy = 0; dy < h; dy += 1) {
    for (let dx = 0; dx < w; dx += 1) setPixel(x + dx, y + dy, colour);
  }
}

/** Blends toward a colour, for the soft glow behind the wordmark. */
function blendPixel(x, y, [r, g, b], alpha) {
  if (x < 0 || y < 0 || x >= WIDTH || y >= HEIGHT || alpha <= 0) return;
  const offset = (y * WIDTH + x) * 3;
  pixels[offset] = Math.round(pixels[offset] * (1 - alpha) + r * alpha);
  pixels[offset + 1] = Math.round(pixels[offset + 1] * (1 - alpha) + g * alpha);
  pixels[offset + 2] = Math.round(pixels[offset + 2] * (1 - alpha) + b * alpha);
}

/**
 * Draws a string of the bitmap face.
 * @returns {number} the width consumed, so callers can centre text
 */
function drawText(text, x, y, scale, colour, { measure = false } = {}) {
  let cursor = x;
  const gap = scale;

  for (const char of String(text).toUpperCase()) {
    const glyph = GLYPHS[char];
    if (!glyph) {
      cursor += 5 * scale + gap;
      continue;
    }
    if (!measure) {
      for (let row = 0; row < 7; row += 1) {
        for (let col = 0; col < 5; col += 1) {
          // Bit 4 is the leftmost column.
          if (glyph[row] & (1 << (4 - col))) {
            fillRect(cursor + col * scale, y + row * scale, scale, scale, colour);
          }
        }
      }
    }
    cursor += 5 * scale + gap;
  }

  return cursor - x - gap;
}

const measure = (text, scale) => drawText(text, 0, 0, scale, [0, 0, 0], { measure: true });

/* ----------------------------------------------------------------- PNG */

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buffer) {
  let c = 0xffffffff;
  for (const byte of buffer) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);

  const typed = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typed));

  return Buffer.concat([length, typed, crc]);
}

function encodePng() {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(WIDTH, 0);
  ihdr.writeUInt32BE(HEIGHT, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // colour type: truecolour RGB
  ihdr[10] = 0; // deflate
  ihdr[11] = 0; // adaptive filtering
  ihdr[12] = 0; // no interlace

  // Every scanline carries a leading filter byte; 0 means "none", which
  // compresses well enough here given the large flat areas.
  const raw = Buffer.alloc(HEIGHT * (WIDTH * 3 + 1));
  for (let y = 0; y < HEIGHT; y += 1) {
    const rowStart = y * (WIDTH * 3 + 1);
    raw[rowStart] = 0;
    pixels.copy(raw, rowStart + 1, y * WIDTH * 3, (y + 1) * WIDTH * 3);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0))
  ]);
}

/* ----------------------------------------------------------------- draw */

const BG = [5, 8, 13];
const GRID = [16, 26, 38];
const ACCENT = [0, 240, 168];
const CYAN = [56, 204, 255];
const TEXT = [231, 238, 247];
const MUTED = [141, 157, 178];

fillRect(0, 0, WIDTH, HEIGHT, BG);

// Faint grid, matching the console background elsewhere on the site.
for (let x = 0; x < WIDTH; x += 40) fillRect(x, 0, 1, HEIGHT, GRID);
for (let y = 0; y < HEIGHT; y += 40) fillRect(0, y, WIDTH, 1, GRID);

// Accent rule along the top edge, fading out to the right.
for (let x = 0; x < WIDTH; x += 1) {
  const falloff = Math.max(0, 1 - x / (WIDTH * 0.75));
  fillRect(x, 0, 1, 4, [
    Math.round(ACCENT[0] * falloff + BG[0] * (1 - falloff)),
    Math.round(ACCENT[1] * falloff + BG[1] * (1 - falloff)),
    Math.round(ACCENT[2] * falloff + BG[2] * (1 - falloff))
  ]);
}

// Radial glow behind the wordmark.
const glowX = 150;
const glowY = 300;
for (let y = 0; y < HEIGHT; y += 1) {
  for (let x = 0; x < WIDTH; x += 1) {
    const distance = Math.hypot(x - glowX, y - glowY);
    const alpha = Math.max(0, 1 - distance / 520) ** 3 * 0.22;
    if (alpha > 0.002) blendPixel(x, y, ACCENT, alpha);
  }
}

const MARGIN = 96;

// Eyebrow
drawText('SECURITY OPERATIONS  /  THREAT MONITORING', MARGIN, 140, 4, ACCENT);

// Wordmark
drawText('VGIL', MARGIN, 200, 26, TEXT);

// Rule under the wordmark
fillRect(MARGIN, 420, measure('VGIL', 26), 3, [40, 54, 71]);

// Supporting lines. Scale 5 keeps the longest line clear of the domain,
// which sits on the same baseline as the second one.
drawText('24/7 DETECTION, RESPONSE', MARGIN, 456, 5, MUTED);
drawText('AND INCIDENT CONTAINMENT', MARGIN, 500, 5, MUTED);

// Domain, right-aligned.
const domain = 'VGIL.IO';
drawText(domain, WIDTH - MARGIN - measure(domain, 4), 545, 4, CYAN);

// Corner ticks, echoing the panel styling in the console.
const TICK = 28;
for (const [cx, cy, sx, sy] of [
  [MARGIN - 40, 96, 1, 1],
  [WIDTH - MARGIN + 40, 96, -1, 1],
  [MARGIN - 40, HEIGHT - 96, 1, -1],
  [WIDTH - MARGIN + 40, HEIGHT - 96, -1, -1]
]) {
  fillRect(sx > 0 ? cx : cx - TICK, cy, TICK, 2, [40, 54, 71]);
  fillRect(cx - (sx > 0 ? 0 : 2), sy > 0 ? cy : cy - TICK, 2, TICK, [40, 54, 71]);
}

const out = path.join(__dirname, '..', 'public', 'assets', 'img', 'og-card.png');
fs.writeFileSync(out, encodePng());

const { size } = fs.statSync(out);
console.log(`wrote ${path.relative(process.cwd(), out)} — ${WIDTH}x${HEIGHT}, ${(size / 1024).toFixed(1)} KB`);
