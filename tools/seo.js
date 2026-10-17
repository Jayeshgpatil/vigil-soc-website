'use strict';

/**
 * Injects social/canonical metadata into every page, and regenerates
 * robots.txt and sitemap.xml from one source of truth.
 *
 *   node tools/seo.js
 *
 * Run this after adding a page. Keeping it generated rather than hand-edited
 * is the only way fourteen pages stay consistent — the previous state had a
 * description tag and nothing else, because keeping five tags in sync by hand
 * across fourteen files does not survive contact with a deadline.
 *
 * The block it writes is delimited, so re-running replaces it rather than
 * appending a second copy.
 */

const fs = require('fs');
const path = require('path');

const ORIGIN = 'https://vgil.io';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const BEGIN = '<!-- seo:begin -->';
const END = '<!-- seo:end -->';

/**
 * `index: false` keeps a page out of search results and the sitemap.
 * Console and account pages are behind a session and have nothing useful to
 * offer a crawler; 404 must never be indexed at all.
 */
const PAGES = {
  'index.html': { index: true, priority: '1.0', changefreq: 'weekly' },
  'services.html': { index: true, priority: '0.9', changefreq: 'monthly' },
  'platform.html': { index: true, priority: '0.9', changefreq: 'monthly' },
  'threat-intel.html': { index: true, priority: '0.8', changefreq: 'daily' },
  'research.html': { index: true, priority: '0.8', changefreq: 'weekly' },
  'compliance.html': { index: true, priority: '0.7', changefreq: 'monthly' },
  'exposure.html': { index: true, priority: '0.8', changefreq: 'weekly' },
  'api-docs.html': { index: true, priority: '0.7', changefreq: 'monthly' },
  'pricing.html': { index: true, priority: '0.8', changefreq: 'monthly' },
  'about.html': { index: true, priority: '0.6', changefreq: 'monthly' },
  'contact.html': { index: true, priority: '0.6', changefreq: 'monthly' },
  'dashboard.html': { index: false },
  'incidents.html': { index: false },
  'login.html': { index: false },
  'signup.html': { index: false },
  'reset.html': { index: false },
  'account.html': { index: false },
  'admin.html': { index: false },
  '404.html': { index: false }
};

/* -------------------------------------------------------------- helpers */

/** Decodes the few entities that appear in these titles, for use in meta. */
function decode(text) {
  return text
    .replace(/&mdash;/g, '—')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"');
}

/** Re-encodes for safe placement inside a double-quoted attribute. */
function attr(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function extract(html, pattern) {
  const match = html.match(pattern);
  return match ? match[1] : null;
}

/* ------------------------------------------------------- structured data */

/**
 * Organisation identity, on the homepage only.
 *
 * Repeating it on every page is a common mistake: it does not help, and it
 * invites conflicting signals if one copy drifts.
 */
function organisationJsonLd() {
  return JSON.stringify(
    {
      '@context': 'https://schema.org',
      '@type': 'Organization',
      name: 'VGIL',
      url: `${ORIGIN}/`,
      logo: `${ORIGIN}/assets/img/og-card.png`,
      description:
        'VGIL runs a 24/7 security operations centre providing continuous threat monitoring, managed detection and response, and incident response.',
      contactPoint: {
        '@type': 'ContactPoint',
        contactType: 'security incident response',
        url: `${ORIGIN}/contact.html`,
        availableLanguage: ['en']
      }
    },
    null,
    2
  );
}

/** Breadcrumb for interior pages, so results show a path rather than a URL. */
function breadcrumbJsonLd(file, title) {
  return JSON.stringify(
    {
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'VGIL', item: `${ORIGIN}/` },
        { '@type': 'ListItem', position: 2, name: title, item: `${ORIGIN}/${file}` }
      ]
    },
    null,
    2
  );
}

/* ------------------------------------------------------------ injection */

function blockFor(file, title, description, config) {
  const canonical = file === 'index.html' ? `${ORIGIN}/` : `${ORIGIN}/${file}`;
  const image = `${ORIGIN}/assets/img/og-card.png`;

  const lines = [BEGIN, `<link rel="canonical" href="${canonical}">`];

  if (!config.index) {
    // noarchive as well: a cached copy of a console page is not wanted even
    // if something ignores noindex.
    lines.push('<meta name="robots" content="noindex, nofollow, noarchive">');
  }

  lines.push(
    '',
    `<meta property="og:type" content="${file === 'index.html' ? 'website' : 'article'}">`,
    `<meta property="og:site_name" content="VGIL">`,
    `<meta property="og:title" content="${attr(title)}">`,
    `<meta property="og:description" content="${attr(description)}">`,
    `<meta property="og:url" content="${canonical}">`,
    `<meta property="og:image" content="${image}">`,
    `<meta property="og:image:width" content="1200">`,
    `<meta property="og:image:height" content="630">`,
    `<meta property="og:image:alt" content="VGIL — security operations and threat monitoring">`,
    `<meta property="og:locale" content="en_GB">`,
    '',
    `<meta name="twitter:card" content="summary_large_image">`,
    `<meta name="twitter:title" content="${attr(title)}">`,
    `<meta name="twitter:description" content="${attr(description)}">`,
    `<meta name="twitter:image" content="${image}">`
  );

  if (config.index) {
    const jsonLd = file === 'index.html' ? organisationJsonLd() : breadcrumbJsonLd(file, title);
    lines.push('', '<script type="application/ld+json">', jsonLd, '</script>');
  }

  lines.push(END);
  return lines.join('\n');
}

/* ----------------------------------------------------------------- main */

const written = [];
const skipped = [];

for (const [file, config] of Object.entries(PAGES)) {
  const target = path.join(PUBLIC_DIR, file);
  if (!fs.existsSync(target)) {
    skipped.push(file);
    continue;
  }

  let html = fs.readFileSync(target, 'utf8');

  const rawTitle = extract(html, /<title>([\s\S]*?)<\/title>/);
  const rawDescription = extract(html, /<meta\s+name="description"\s+content="([^"]*)"/);

  if (!rawTitle || !rawDescription) {
    throw new Error(`${file} is missing a <title> or meta description`);
  }

  const title = decode(rawTitle).trim();
  const description = decode(rawDescription).trim();
  const block = blockFor(file, title, description, config);

  if (html.includes(BEGIN)) {
    html = html.replace(new RegExp(`${BEGIN}[\\s\\S]*?${END}`), block);
  } else {
    // Anchored to the stylesheet link so the block lands in a predictable
    // place rather than wherever </head> happens to be.
    html = html.replace(
      /(<link rel="stylesheet" href="\/assets\/css\/style\.css">)/,
      `${block}\n$1`
    );
  }

  fs.writeFileSync(target, html);
  written.push(`${file}${config.index ? '' : ' (noindex)'}`);
}

/* ------------------------------------------------------------- sitemap */

const today = new Date().toISOString().slice(0, 10);
const indexable = Object.entries(PAGES).filter(
  ([file, config]) => config.index && fs.existsSync(path.join(PUBLIC_DIR, file))
);

const sitemap = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
  ...indexable.map(([file, config]) =>
    [
      '  <url>',
      `    <loc>${file === 'index.html' ? `${ORIGIN}/` : `${ORIGIN}/${file}`}</loc>`,
      `    <lastmod>${today}</lastmod>`,
      `    <changefreq>${config.changefreq}</changefreq>`,
      `    <priority>${config.priority}</priority>`,
      '  </url>'
    ].join('\n')
  ),
  '</urlset>',
  ''
].join('\n');

fs.writeFileSync(path.join(PUBLIC_DIR, 'sitemap.xml'), sitemap);

/* -------------------------------------------------------------- robots */

const robots = `# VGIL — https://vgil.io
#
# The console, account and authentication pages are behind a session and have
# nothing to offer a crawler, so they are disallowed here as well as carrying
# a noindex tag. The API is disallowed outright.

User-agent: *
Allow: /
Disallow: /dashboard.html
Disallow: /incidents.html
Disallow: /account.html
Disallow: /admin.html
Disallow: /login.html
Disallow: /signup.html
Disallow: /reset.html
Disallow: /api/

Sitemap: ${ORIGIN}/sitemap.xml
`;

fs.writeFileSync(path.join(PUBLIC_DIR, 'robots.txt'), robots);

console.log(`updated ${written.length} page(s):`);
for (const entry of written) console.log(`  ${entry}`);
if (skipped.length) console.log(`not present yet: ${skipped.join(', ')}`);
console.log(`\nsitemap.xml — ${indexable.length} indexable URL(s)`);
console.log('robots.txt  — written');
