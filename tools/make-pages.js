'use strict';

/**
 * Assembles content pages from fragments in tools/pages/ plus the shell of an
 * existing page.
 *
 *   node tools/make-pages.js
 *
 * The site is deliberately static HTML with no build step for the app itself,
 * but "static" and "fourteen hand-maintained copies of the same header" are
 * different things. Each fragment holds only its <main>; the nav, footer and
 * script tags come from about.html so they cannot drift.
 *
 * Re-run after editing a fragment. Run tools/seo.js afterwards to generate
 * the social block and refresh the sitemap.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const FRAGMENT_DIR = path.join(__dirname, 'pages');

// Most content pages take the plain marketing shell. A page with a detail
// drawer has to come from one that already has the drawer markup and its
// styles, rather than having a copy pasted into it.
const DEFAULT_SHELL = 'about.html';

const PAGES = [
  {
    file: 'research.html',
    fragment: 'research.html',
    title: 'Threat Research — VGIL',
    description:
      'Detection engineering notes and threat research from the VGIL security operations centre: attacker tradecraft, detection logic, and what actually fires in production.'
  },
  {
    file: 'compliance.html',
    fragment: 'compliance.html',
    title: 'Trust &amp; Compliance — VGIL',
    description:
      'How VGIL handles customer data: certifications, encryption, retention, sub-processors, availability commitments and vulnerability disclosure.'
  },
  {
    file: 'exposure.html',
    fragment: 'exposure.html',
    // Derived from the incident console: this page needs the detail drawer.
    shell: 'incidents.html',
    script: 'exposure.js',
    title: 'Exposure Management — VGIL',
    description:
      'Continuous vulnerability discovery across internal, external and cloud surfaces, prioritised by EPSS, known-exploited status and blast radius rather than raw CVSS.'
  },
  {
    file: 'api-docs.html',
    fragment: 'api-docs.html',
    title: 'API Reference — VGIL',
    description:
      'The VGIL REST API: authentication with session tokens and API keys, alert and incident endpoints, CSV and JSON export, webhook signature verification and rate limits.'
  }
];

const shells = new Map();

function shellFor(file) {
  if (!shells.has(file)) {
    shells.set(file, fs.readFileSync(path.join(PUBLIC_DIR, file), 'utf8'));
  }
  return shells.get(file);
}

for (const page of PAGES) {
  const fragment = fs.readFileSync(path.join(FRAGMENT_DIR, page.fragment), 'utf8').trim();

  let html = shellFor(page.shell || DEFAULT_SHELL);

  html = html.replace(/<title>[\s\S]*?<\/title>/, `<title>${page.title}</title>`);
  html = html.replace(
    /<meta name="description" content="[^"]*">/,
    `<meta name="description" content="${page.description}">`
  );

  // Drop the shell's generated social block; tools/seo.js writes a fresh one
  // for this page's own title and description.
  html = html.replace(/<!-- seo:begin -->[\s\S]*?<!-- seo:end -->\n?/, '');

  html = html.replace(/<main>[\s\S]*?<\/main>/, fragment);

  // Swap the shell's own controller for this page's, where it has one.
  if (page.script) {
    html = html.replace(
      /<script src="\/assets\/js\/(incidents|about|home)\.js"><\/script>/,
      `<script src="/assets/js/${page.script}"></script>`
    );
  }

  fs.writeFileSync(path.join(PUBLIC_DIR, page.file), html);
  console.log(`wrote public/${page.file}  (${(fragment.length / 1024).toFixed(1)} KB of content)`);
}

console.log('\nnow run: node tools/seo.js');
