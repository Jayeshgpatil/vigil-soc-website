'use strict';

/**
 * Adds the shared page chrome — theme bootstrap, command palette, the theme
 * toggle button and the palette trigger — to every page.
 *
 *   node tools/wire-chrome.js
 *
 * There is no template engine here; the pages are static HTML by design. That
 * makes "the same three lines in fourteen files" a real maintenance problem,
 * so it is generated and idempotent rather than pasted. Re-running is safe.
 */

const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const THEME_TAG = '<script src="/assets/js/theme.js"></script>';
const PALETTE_TAG = '<script src="/assets/js/palette.js"></script>';

// Two glyphs in one button; CSS shows whichever represents the other mode.
const TOGGLE = `      <button class="theme-toggle" type="button" aria-label="Switch between light and dark theme" title="Switch theme">
        <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>
        <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
      </button>`;

const TRIGGER = `      <button class="palette-trigger" type="button" data-palette-open aria-label="Open the command palette">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5" stroke-linecap="round"/></svg>
        <span>Search</span><kbd>Ctrl K</kbd>
      </button>`;

const pages = fs
  .readdirSync(PUBLIC_DIR)
  .filter((file) => file.endsWith('.html'))
  .sort();

const changed = [];

for (const file of pages) {
  const target = path.join(PUBLIC_DIR, file);
  let html = fs.readFileSync(target, 'utf8');
  const before = html;

  // 1. Theme bootstrap, in <head> and *before* the stylesheet so the attribute
  //    is on <html> by the time the first rule is evaluated.
  if (!html.includes(THEME_TAG)) {
    html = html.replace(
      /(<link rel="stylesheet" href="\/assets\/css\/style\.css">)/,
      `${THEME_TAG}\n$1`
    );
  }

  // 2. Palette script, after main.js so window.VG already exists.
  if (!html.includes(PALETTE_TAG)) {
    html = html.replace(
      /(<script src="\/assets\/js\/main\.js"><\/script>)/,
      `$1\n${PALETTE_TAG}`
    );
  }

  // 3. Nav controls, ahead of whatever the first action already is.
  if (!html.includes('class="theme-toggle"')) {
    html = html.replace(
      /(\n\s*<div class="nav-actions"[^>]*>\n)/,
      `$1${TRIGGER}\n${TOGGLE}\n`
    );
  }

  if (html !== before) {
    fs.writeFileSync(target, html);
    changed.push(file);
  }
}

/* ------------------------------------------------------------- verify */

const missing = [];
for (const file of pages) {
  const html = fs.readFileSync(path.join(PUBLIC_DIR, file), 'utf8');
  const gaps = [];
  if (!html.includes(THEME_TAG)) gaps.push('theme.js');
  if (!html.includes(PALETTE_TAG)) gaps.push('palette.js');
  if (!html.includes('class="theme-toggle"')) gaps.push('toggle button');
  if (gaps.length) missing.push(`${file}: ${gaps.join(', ')}`);
}

console.log(`scanned ${pages.length} page(s), updated ${changed.length}`);
for (const file of changed) console.log(`  ${file}`);

if (missing.length) {
  console.log('\nstill missing:');
  for (const entry of missing) console.log(`  ${entry}`);
  process.exitCode = 1;
} else {
  console.log('\nevery page has the theme bootstrap, palette and toggle');
}
