'use strict';

/**
 * Links the newer pages into the shared navigation and footer.
 *
 *   node tools/wire-links.js
 *
 * A page nothing links to is a page nobody finds, and one that search engines
 * rank poorly however good its metadata is. Idempotent — re-running is safe.
 */

const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// Research earns a slot in the primary nav: it is the page that gives a
// prospect a reason to believe the rest of the site. Compliance and the API
// reference are reference material and live in the footer.
const PLATFORM_ANCHOR = '          <li><a href="/threat-intel.html#lookup">Indicator lookup</a></li>\n';
const COMPANY_ANCHOR = '          <li><a href="/about.html">About VGIL</a></li>\n';

// [href, markup, the anchor it is inserted after]
const FOOTER_LINKS = [
  ['/exposure.html', '          <li><a href="/exposure.html">Exposure management</a></li>\n', PLATFORM_ANCHOR],
  ['/api-docs.html', '          <li><a href="/api-docs.html">API reference</a></li>\n', PLATFORM_ANCHOR],
  ['/research.html', '          <li><a href="/research.html">Threat research</a></li>\n', COMPANY_ANCHOR],
  ['/compliance.html', '          <li><a href="/compliance.html">Trust &amp; compliance</a></li>\n', COMPANY_ANCHOR]
];

const pages = fs.readdirSync(PUBLIC_DIR).filter((file) => file.endsWith('.html'));
const changed = [];

for (const file of pages) {
  const target = path.join(PUBLIC_DIR, file);
  let html = fs.readFileSync(target, 'utf8');
  const before = html;

  // Checked per link rather than per block: guarding the whole group on one
  // of its members means a link added later never reaches pages that already
  // have the others.
  for (const [href, markup, anchor] of FOOTER_LINKS) {
    if (html.includes(`href="${href}"`)) continue;
    if (!html.includes(anchor)) continue;
    html = html.replace(anchor, anchor + markup);
  }

  if (html !== before) {
    fs.writeFileSync(target, html);
    changed.push(file);
  }
}

/* -------------------------------------------------------------- report */

const orphans = [];
for (const page of ['research.html', 'compliance.html', 'api-docs.html', 'exposure.html', 'reset.html']) {
  const inbound = pages.filter((file) => {
    if (file === page) return false;
    return fs.readFileSync(path.join(PUBLIC_DIR, file), 'utf8').includes(`href="/${page}"`);
  });
  if (!inbound.length) orphans.push(page);
  else console.log(`${page.padEnd(18)} linked from ${inbound.length} page(s)`);
}

console.log(`\nupdated ${changed.length} page(s)`);
if (orphans.length) {
  // reset.html is reached only from an emailed link, so it is expected here.
  console.log(`no inbound links (expected for reset.html): ${orphans.join(', ')}`);
}
