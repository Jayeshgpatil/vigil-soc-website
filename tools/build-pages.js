#!/usr/bin/env node
/**
 * Builds the static GitHub Pages demo into _site/.
 *
 *   node tools/build-pages.js [base]      (base defaults to /vigil-soc-website)
 *
 * GitHub Pages cannot run the Express server, so the build:
 *   1. copies public/ as-is,
 *   2. prefixes every root-relative link with the Pages sub-path,
 *   3. adds tools/pages/static-api.js, an in-browser stand-in for /api that
 *      answers from tools/pages/demo-data.json (a snapshot of a real server).
 *
 * Use an empty base ("") when the site is served from a domain root.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'public');
const OUT = path.join(ROOT, '_site');
const BASE = (process.argv[2] !== undefined ? process.argv[2] : '/vigil-soc-website').replace(/\/$/, '');

fs.rmSync(OUT, { recursive: true, force: true });
fs.cpSync(SRC, OUT, { recursive: true });

// Root-relative URL inside an attribute or a JS string: "/x" but not "//x".
const ATTR = /\b(href|src|action|content)="\/(?!\/)/g;
const JS_STRING = /(['"`])\/(?=(?:assets\/|api\b|[a-z0-9-]+\.html\b))/g;

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : [p];
  });
}

let pages = 0;
for (const file of walk(OUT)) {
  const ext = path.extname(file);

  if (ext === '.html') {
    let html = fs.readFileSync(file, 'utf8');
    html = html.replace(ATTR, `$1="${BASE}/`);
    html = html.replace(JS_STRING, `$1${BASE}/`);
    // The demo backend must load before api.js so it can intercept requests.
    html = html.replace(
      /<script\s+src="[^"]*\/assets\/js\/api\.js"/,
      (tag) => `<script src="${BASE}/assets/js/static-api.js" data-base="${BASE}"></script>\n  ${tag}`
    );
    fs.writeFileSync(file, html);
    pages++;
  } else if (ext === '.js' && !file.includes(`${path.sep}vendor${path.sep}`)) {
    let js = fs.readFileSync(file, 'utf8');
    js = js.replace(JS_STRING, `$1${BASE}/`);
    // main.js marks the active nav link by comparing against the site root.
    if (BASE) js = js.replace(/here === '\/'/g, `here === '${BASE}'`).replace(/path === '\/'\)/g, `path === '${BASE}')`);
    fs.writeFileSync(file, js);
  } else if (ext === '.css') {
    let css = fs.readFileSync(file, 'utf8');
    css = css.replace(/url\((['"]?)\/(?!\/)/g, `url($1${BASE}/`);
    fs.writeFileSync(file, css);
  }
}

fs.copyFileSync(path.join(__dirname, 'pages', 'static-api.js'), path.join(OUT, 'assets', 'js', 'static-api.js'));
fs.mkdirSync(path.join(OUT, 'assets', 'data'), { recursive: true });
fs.copyFileSync(path.join(__dirname, 'pages', 'demo-data.json'), path.join(OUT, 'assets', 'data', 'demo.json'));

// Serve files and folders starting with "_" or "." (e.g. .well-known) as-is.
fs.writeFileSync(path.join(OUT, '.nojekyll'), '');

console.log(`Built ${pages} pages into _site/ with base "${BASE || '/'}"`);
