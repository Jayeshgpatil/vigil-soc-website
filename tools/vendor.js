'use strict';

/**
 * Copies browser dependencies out of node_modules into public/assets/vendor.
 *
 *   node tools/vendor.js
 *
 * There is no bundler here, and node_modules is not served. The CSP is
 * script-src 'self', so a CDN is not an option either — the file has to come
 * from our own origin. Copying it in is the whole build step.
 *
 * Run this after `npm install` or after upgrading a vendored package.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const VENDOR_DIR = path.join(ROOT, 'public', 'assets', 'vendor');

const PACKAGES = [
  {
    name: 'cobe',
    from: 'cobe/dist/index.esm.js',
    to: 'cobe.js',
    // ESM, so whatever loads it needs type="module".
    note: 'WebGL globe renderer'
  }
];

fs.mkdirSync(VENDOR_DIR, { recursive: true });

for (const pkg of PACKAGES) {
  const source = path.join(ROOT, 'node_modules', pkg.from);
  if (!fs.existsSync(source)) {
    throw new Error(`${pkg.from} is missing — run npm install first`);
  }

  const target = path.join(VENDOR_DIR, pkg.to);
  const version = require(path.join(ROOT, 'node_modules', pkg.name, 'package.json')).version;

  // A banner so nobody edits the copy by hand and loses it on the next run.
  const banner =
    `/* ${pkg.name} v${version} — ${pkg.note}\n` +
    `   Vendored by tools/vendor.js. Do not edit; re-run that script instead.\n` +
    `   Served from our own origin because the CSP is script-src 'self'. */\n`;

  fs.writeFileSync(target, banner + fs.readFileSync(source, 'utf8'));

  const size = (fs.statSync(target).size / 1024).toFixed(1);
  console.log(`vendored ${pkg.name}@${version} -> public/assets/vendor/${pkg.to}  (${size} KB)`);
}
