# VGIL — Security Operations & Threat Monitoring

A complete cybersecurity company website with a working frontend **and** backend.
Twelve pages, a REST API of 45+ endpoints, live Server-Sent Event streaming, session
authentication, a SQLite database with versioned migrations, and a detection engine
that generates realistic SOC telemetry.

Built with plain **HTML, CSS and JavaScript** on the frontend (no framework, no CDN)
and **Node.js + Express + SQLite** on the backend. Express is the only runtime
dependency — the database uses Node's built-in `node:sqlite`, so there is no native
module to compile.

---

## Quick start

```bash
npm install
```

```bash
npm start
```

Then open <http://localhost:3000>. The database is created and migrated on first run.

Change the port with `PORT=8080 npm start`.

### Other commands

| Command | Effect |
|---|---|
| `npm start` | Run the server |
| `npm run dev` | Run with `--watch` for auto-restart |
| `npm test` | Full API test suite (55 tests, in-memory database) |
| `npm run seed` | Wipe and reseed the database |
| `npm run migrate` | Apply pending migrations and print the schema version |

### Demo accounts

| Email | Password | Role |
|---|---|---|
| `analyst@vgil.io` | `Vgil#Demo2026` | analyst |
| `admin@vgil.io` | `Vgil#Admin2026` | admin |

Both are pre-filled by the **use** buttons on the sign-in page.

These exist **only in development**. Setting `NODE_ENV=production` stops them being
seeded and hides them from the sign-in page — see [Deploying](#deploying).

---

## Pages

| Page | File | What it does |
|---|---|---|
| Home | `public/index.html` | Hero with animated canvas, live detection console, metrics, service cards, threat landscape |
| Services | `public/services.html` | Six service offerings loaded from the API, in-house vs managed comparison, onboarding, FAQ |
| Platform | `public/platform.html` | Detection pipeline, risk-scoring model, live MITRE ATT&CK coverage matrix, searchable rule catalog |
| Threat Intel | `public/threat-intel.html` | Indicator lookup tool, posture assessment tool, actor profiles, IOC feed, CVEs, attack geography |
| Live SOC | `public/dashboard.html` | **Auth required.** Real-time alert queue, charts, triage drawer, asset inventory |
| Incidents | `public/incidents.html` | Incident queue, response timelines, status transitions, create-incident form |
| Pricing | `public/pricing.html` | Three plans from the API, full comparison table, cost-of-breach panel, FAQ |
| About | `public/about.html` | Company story, SOC staffing model, leadership, assurance |
| Contact | `public/contact.html` | Validated demo-request form with honeypot, direct lines, response SLAs |
| Account | `public/account.html` | **Auth required.** Profile, password change, active session list |
| Admin | `public/admin.html` | **Admin only.** Accounts, roles, storage stats, audit trail, data export |
| Sign in | `public/login.html` | Session authentication |
| Sign up | `public/signup.html` | Registration with live password-strength meter |
| 404 | `public/404.html` | Styled not-found page with a request trace |

---

## Project layout

```
vigil soc website/
├── package.json
├── server/
│   ├── server.js              Process entry: open db, seed, start engine, listen
│   ├── app.js                 Express app factory (no side effects — tests import this)
│   ├── db/
│   │   ├── index.js           Connection, pragmas, transactions
│   │   ├── schema.sql         Baseline schema: 9 tables + indexes
│   │   ├── migrate.js         Versioned migrations via PRAGMA user_version
│   │   └── repository.js      Typed query layer (all SQL lives here)
│   ├── lib/
│   │   ├── config.js          Environment flags (demo mode, registration)
│   │   ├── secret.js          Persisted session signing key
│   │   ├── auth.js            scrypt hashing, HMAC session tokens, route guards
│   │   ├── security.js        CSP/hardening headers, rate limiter, validation, escaping
│   │   ├── catalog.js         Detection rules, assets, threat actors, IOCs, CVEs
│   │   ├── engine.js          Alert generation, risk scoring, SSE broadcast, metrics
│   │   └── seed.js            Seeds 24h of alerts, 8 incidents, demo users
│   ├── routes/
│   │   ├── auth.js            register / login / me / logout / password-check
│   │   ├── account.js         profile, password change, session management
│   │   ├── admin.js           users, roles, export, storage stats, audit
│   │   ├── alerts.js          list, filter, stream, detail, triage, escalate
│   │   ├── incidents.js       list, detail, create, update, delete
│   │   ├── threats.js         actors, IOCs, lookup, CVEs, geo, rules, matrix, scan
│   │   └── public.js          stats, assets, services, pricing, contact, health, ready
│   └── data/
│       ├── vgil.db            SQLite database (gitignored)
│       └── .secret            Session signing key (gitignored)
├── test/
│   └── api.test.js            55 tests — node:test, no test framework
└── public/
    ├── *.html                 14 pages
    └── assets/
        ├── css/style.css      Design system + all components
        ├── js/                api.js, main.js, charts.js, effects.js + per-page scripts
        └── img/favicon.svg
```

---

## Database

SQLite via Node's built-in `node:sqlite`. Nine tables with foreign keys enforced and
indexes on every column the API filters or sorts by:

| Table | Holds |
|---|---|
| `users` | Accounts, scrypt password hashes, roles |
| `sessions` | Issued tokens with revocation state, IP and user agent |
| `alerts` | Detections, indexed on `ts`, `severity`, `status`, `technique`, `asset_id`, `risk` |
| `alert_notes` | Analyst notes, cascade-deleted with their alert |
| `incidents` | Escalations and their lifecycle timestamps |
| `incident_timeline` | Response history, cascade-deleted with its incident |
| `assets` | Monitored inventory |
| `contacts` | Demo-request submissions |
| `audit_log` | Authentication and administrative events |

**Migrations** are tracked in SQLite's own `user_version` pragma, so no bookkeeping
table is needed. Each runs in a transaction. To change the schema, append a new entry
to `MIGRATIONS` in `db/migrate.js` — never edit an existing one, or databases already
at that version will silently diverge from fresh ones.

**Design notes**

- Timestamps are ISO-8601 UTC strings: readable in the file, correct under plain
  lexicographic sort, and parseable by SQLite's `julianday()` for duration maths.
- WAL journaling, so the alert write stream doesn't block readers.
- All queries use positional placeholders. There is no string interpolation of caller
  data anywhere in `repository.js`.
- The repository returns camelCase objects shaped exactly as the HTTP API emits them,
  so routes and frontend are decoupled from column naming.
- Notes and timelines are batch-fetched per page rather than per row — no N+1.
- Filtering, sorting, pagination and aggregation happen in SQL, not by loading tables
  into memory.

Point the database elsewhere with `VGIL_DB=/path/to/file.db`, or use `:memory:` for a
throwaway instance (what the test suite does).

---

## API reference

### Public

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Liveness, uptime, record counts |
| `GET` | `/api/ready` | Readiness — 503 if the database cannot be queried |
| `GET` | `/api/stats` | Dashboard metrics, 24h timeline, severity/tactic/source breakdowns |
| `GET` | `/api/services` | Service catalog |
| `GET` | `/api/pricing` | Plan tiers |
| `GET` | `/api/assets` | Monitored asset inventory with 24h alert counts |
| `GET` | `/api/alerts` | Filter by `severity`, `status`, `tactic`, `source`, `zone`, `q`, `since`; `sort`, `page`, `limit` |
| `GET` | `/api/alerts/stream` | **SSE** — live `alert`, `alert-updated`, `incident`, `heartbeat` events |
| `GET` | `/api/alerts/:id` | Single alert |
| `GET` | `/api/alerts/meta/filters` | Available filter values |
| `GET` | `/api/incidents` | Filter by `status`, `severity`, `q`; paginated, with summary counts |
| `GET` | `/api/incidents/:id` | Incident plus linked detections |
| `GET` | `/api/threats/actors` | Tracked actors, filter by `trend`, `motivation`, `q` |
| `GET` | `/api/threats/actors/:id` | Profile + attributed indicators + detection coverage |
| `GET` | `/api/threats/iocs` | Indicator feed, filter by `type`, `severity`, `actor`, `q` |
| `GET` | `/api/threats/vulnerabilities` | CVEs with CVSS, EPSS and KEV status |
| `GET` | `/api/threats/geo` | Attack-origin distribution |
| `GET` | `/api/threats/rules` | Published detection-rule catalog |
| `GET` | `/api/threats/attack-matrix` | ATT&CK coverage with live hit counts |
| `GET` | `/api/threats/feed` | Condensed intel summary |
| `POST` | `/api/threats/lookup` | Indicator reputation check |
| `POST` | `/api/threats/posture-scan` | Heuristic domain posture assessment |
| `POST` | `/api/contact` | Demo/quote request intake |
| `POST` | `/api/auth/register` | Create account → returns token |
| `POST` | `/api/auth/login` | Authenticate → returns token |
| `POST` | `/api/auth/password-check` | Password strength score |

### Authenticated — send `Authorization: Bearer <token>`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/auth/me` | Current identity |
| `POST` | `/api/auth/logout` | Revoke the presented token |
| `PATCH` | `/api/alerts/:id` | Set status, assignee, append an analyst note |
| `POST` | `/api/alerts/:id/escalate` | Promote an alert to a tracked incident |
| `POST` | `/api/incidents` | Open an incident manually |
| `PATCH` | `/api/incidents/:id` | Change status/severity/analyst, add a timeline entry |
| `DELETE` | `/api/incidents/:id` | **admin only** — seeded records are protected |
| `GET` | `/api/contact` | **admin only** — submitted requests |
| `GET` | `/api/audit` | **admin only** — security audit trail |

### Account management

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/account` | Current profile |
| `PATCH` | `/api/account` | Update name, organisation, job title |
| `POST` | `/api/account/password` | Change password — requires the current one, revokes other sessions |
| `GET` | `/api/account/sessions` | Where this account is signed in; the current session is flagged |
| `DELETE` | `/api/account/sessions` | Sign out everywhere except here |

Every route here operates on the caller's own account only — none accepts a user id,
so one account can never act on another.

### Admin — requires `role: admin`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/admin/users` | All accounts, with admin and disabled counts |
| `PATCH` | `/api/admin/users/:id` | Change role or disable; disabling revokes live sessions immediately |
| `GET` | `/api/admin/stats` | Schema version, journal mode, database size, row counts |
| `GET` | `/api/admin/export` | Full tenant export as a JSON download |
| `GET` | `/api/admin/audit` | Audit trail, deeper than the public route |

Guards worth knowing: an admin cannot disable or demote their own account
(`self_lockout`), and the shared demo accounts cannot be modified or have their
password changed (`protected_record` / `demo_account`) — otherwise one visitor
would lock out everyone using the published credentials.

### Example

```bash
curl -s -X POST http://localhost:3000/api/auth/login -H "Content-Type: application/json" -d "{\"email\":\"analyst@vgil.io\",\"password\":\"Vgil#Demo2026\"}"
```

---

## Security measures implemented

Since this is a security product, the site practises what it describes:

- **Password storage** — scrypt (N=16384, r=8, p=1) with per-user salt; hashes never leave the server, and are excluded from the admin export
- **Sessions** — HMAC-SHA256 signed tokens, 12-hour expiry, server-side revocation. The signing key comes from `VGIL_SECRET`, or is generated once into `server/data/.secret` (mode 0600) so logins survive a restart
- **SQL injection** — every query uses positional placeholders; no caller data is ever interpolated into SQL. Covered by a test that submits `'; DROP TABLE alerts; --` as a search term
- **Session revocation on privilege change** — disabling an account or changing a password revokes the affected tokens immediately, rather than waiting for expiry
- **Timing-safe comparison** — `crypto.timingSafeEqual` for both tokens and passwords
- **User enumeration** — login and registration return generic messages; a dummy hash is verified when no user exists so response timing does not leak
- **Rate limiting** — sliding window per IP and per route (12 logins / 15 min, 6 registrations / hr, 8 contact submissions / hr, 10 scans / min)
- **Content Security Policy** — `script-src 'self'`; no inline scripts and no external resources anywhere in the site
- **Hardening headers** — `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP, restrictive `Permissions-Policy`, `X-Powered-By` removed
- **XSS defence** — all user input HTML-escaped on the way into storage; the frontend builds DOM with `textContent`, never `innerHTML`, for any server-supplied value
- **Input validation** — schema-driven validation server-side with per-field error responses; the client mirrors it for UX only
- **Open redirect** — the `?next=` parameter after sign-in accepts only same-origin absolute paths
- **Honeypot** — hidden field on the contact form silently absorbs bots
- **Body limits** — 64 kb cap with a specific 413 response
- **Error handling** — stack traces are logged server-side and never returned to the client; each response carries an `X-Request-Id` for correlation

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Listen port |
| `VGIL_DB` | `server/data/vgil.db` | Database path, or `:memory:` |
| `VGIL_SECRET` | generated file | Session signing key — set this in production |
| `VGIL_RATE_FACTOR` | `1` | Multiplies every rate-limit budget. The test suite raises it; leave it at 1 in production |
| `NODE_ENV` | — | `production` enables static asset caching |

### For real deployment

```bash
VGIL_SECRET=$(openssl rand -hex 48) NODE_ENV=production npm start
```

Serve over HTTPS behind a reverse proxy. The rate limiter keeps its state in process
memory, so a multi-instance deployment needs a shared store (Redis) to enforce limits
globally rather than per instance.

---

## Deploying

The app is a single Node process with a SQLite file. It needs **persistent disk** —
on an ephemeral filesystem the database and signing key are wiped on every restart.
That rules out plain serverless targets; Render, Railway, Fly.io, a VPS or any
container host with a volume all work.

### Before the first deploy

Set two variables. Everything else has a sane default.

```bash
VGIL_SECRET=$(openssl rand -hex 48)
NODE_ENV=production
```

`NODE_ENV=production` is not cosmetic — it turns **demo mode off**, which means the
shared `analyst@vgil.io` / `admin@vgil.io` accounts are never created and their
credentials are never shown on the sign-in page. Leaving them on a public URL would
be publishing an administrator password.

With demo accounts gone a fresh instance has no administrator, so **the first account
to sign up is promoted to admin**. Register yours immediately after the first deploy,
then set `VGIL_BOOTSTRAP_ADMIN=0` and, if you do not want strangers signing up,
`VGIL_REGISTRATION=0`.

### Docker

```bash
docker build -t vgil .
```

```bash
docker run -d -p 3000:3000 -v vgil-data:/data -e VGIL_SECRET=$(openssl rand -hex 48) vgil
```

The image runs as the `node` user, keeps the database on the `/data` volume, and
health-checks against `/api/ready` so an orchestrator removes an instance whose
database has gone away rather than restarting it blindly.

### Environment

See `.env.example` for the annotated list. The ones that matter:

| Variable | Default | Notes |
|---|---|---|
| `VGIL_SECRET` | generated to a file | **Set this.** Sessions break across instances without it |
| `NODE_ENV` | — | `production` enables asset caching and disables demo mode |
| `VGIL_DB` | `server/data/vgil.db` | Point at a persistent volume |
| `VGIL_DEMO` | off in production | Only enable for a public showcase you are happy anyone can administer |
| `VGIL_REGISTRATION` | `1` | Set `0` to close sign-up |
| `VGIL_BOOTSTRAP_ADMIN` | `1` | First account becomes admin; turn off once you have yours |

### Known limits at scale

- The rate limiter keeps state in process memory, so limits are enforced per
  instance. More than one replica needs a shared store.
- SQLite means one writer. That is ample for this workload but is a real ceiling.
- The detection engine writes continuously, so the disk grows until the 600-alert
  retention cap kicks in.

### GitHub Pages demo

GitHub Pages only serves static files, so it cannot run the API. `npm run build:pages`
builds a self-contained demo into `_site/` instead:

- every root-relative link is prefixed with the Pages sub-path (`/vigil-soc-website`
  by default; pass another base, or `""` for a domain root, as the first argument);
- `tools/pages/static-api.js` is loaded before `api.js` and answers `/api/*` requests
  and the live alert stream inside the browser, from `tools/pages/demo-data.json` — a
  snapshot of a real server. Filters, search, paging, triage, escalation and sign-up
  work; changes are kept in the visitor's own browser only.

Sign in with the demo accounts above. Password reset, two-factor setup, API keys,
email and webhooks need the real server and are switched off in the demo.

The built site is published from the `gh-pages` branch.

---

## Tests

```bash
npm test
```

55 tests via `node:test` — no test framework, no mocking library. Each run uses an
in-memory database on an ephemeral port, so it never touches `server/data` and can run
while a real server is live.

Coverage includes: schema migration and seeding, foreign-key cascades, id allocation,
pagination, filtering, sorting and search, the full auth lifecycle, token tampering,
role gates on every write route, triage and escalation, incident lifecycle,
account and admin flows, self-lockout guards, XSS escaping, SQL-injection resistance,
oversized and malformed bodies, and rate-limit thresholds.

---

## Visual design & motion

### Typography

The stack names the best face actually installed on each platform, starting with the
variable-weight Segoe faces on Windows 11, falling back through `system-ui` and the SF
Pro faces on macOS. Headings use the Display cut, body text the Text cut, and code
`Cascadia Mono`.

No webfont is loaded, and none is asked for: the CSP forbids external requests and
there is no font file to serve. An earlier version declared `Inter` without ever
loading it, which meant every visitor silently got a fallback — worse than choosing a
good fallback deliberately.

Tracking tightens as size grows (`-0.032em` on `h1` down to `-0.012em` on `h4`), since
large type set at body tracking reads loose. `text-wrap: balance` keeps headings from
leaving one orphaned word on the last line.

### Backdrop

The page background is four stacked layers, built entirely from CSS on `<html>` and
`<body>` pseudo-elements — no images, no extra markup:

1. **Aurora field** — large, slow, low-contrast colour blooms drifting on a 42-second
   cycle. Reads as depth rather than as a pattern.
2. **Scanner pass** — a soft band travelling down the viewport every 13 seconds, the way
   a monitoring sweep moves across a console.
3. **Scanlines** — 1px terminal texture at the threshold of visibility.
4. **Vignette** — corners fall away so content sits forward.

### Page composition

Every visual asset is inline SVG or CSS — no image files, no external requests, nothing
to 404.

- **Contrast bands** (`.band`) break the page into chapters. Without them every section
  repeated the same rhythm — eyebrow, heading, lead, card grid — and read as one long
  list.
- **Sector grid** on the home page: six industries with stroked icons and the framework
  each answers to, sharing a hairline grid.
- **Pull-quotes** with an oversized watermark glyph, avatar initials, and the metric that
  mattered to each account. Labelled as illustrative, since the accounts are written for
  this project.
- **Pipeline diagram** on the Platform page: a hand-authored SVG of the five detection
  stages with telemetry packets travelling the track via `offset-path`. It carries an
  `aria-label` describing the flow, and scrolls inside its own container on narrow
  screens rather than widening the page.

### Animation

| Where | What happens |
|---|---|
| Page top | Reading-progress rail; the nav condenses once you scroll past 90px |
| Platform diagram | Telemetry packets flow along the pipeline track, staggered so the line is never empty |
| Sector icons | Lift and scale on hover |
| Pull-quotes | Lift with an accent border on hover |
| Top bar | Headlines scroll continuously as a seamless marquee, pausing on hover |
| Brand mark | The shield's radar arcs rotate; the whole mark tilts on hover |
| Eyebrow labels | Text resolves out of random glyphs, left to right — monospaced, so nothing reflows |
| Hero headline | Light sweeps across the highlighted words |
| Hero entrance | Eyebrow → headline → lead → buttons → trust row cascade in |
| Hero canvas | Node graph with proximity links, traffic packets with trails, a rotating radar sweep with range rings, expanding detection rings on compromised nodes, and links that brighten near the cursor |
| Threat Intel | **Live attack scope** — origins on a ring fire curved inbound tracks at the estate hub, at a rate set by each country's share of observed traffic, with impact rings and a rotating sweep |
| Charts | Area chart traces itself left to right behind a widening clip with a leading marker; donut sweeps open clockwise; bars grow with a per-row stagger. First render only — data refreshes repaint instantly |
| Volume chart | Crosshair with dot markers and a readout box that flips to whichever side has room |
| Figures | Static stat and price figures count up when scrolled into view |
| Sections | Content reveals on scroll; static grids cascade their children |
| Section dividers | A pulse of light runs along each one |
| Cards | Lift, cursor-follow 3D tilt, gradient edge-light traced around the border, and a radar ping from the icon |
| Card icons | SVG strokes draw themselves on |
| Stat tiles | Lift with a glowing accent rail (one variable drives rail colour and glow) |
| Meters | Fill from zero with a travelling sheen |
| Tables | Rows flash green when streamed in live; accent bar on hover |
| Buttons | Light sweep across primary buttons on hover; ripple from the click point |
| Nav links | Underline wipes in from the left |
| Consoles | Static terminal blocks type themselves in line by line |
| Drawers | Slide in, then contents cascade |
| Toasts | Slide in with a draining timer bar |
| KPIs | Flash when a value actually changes — not on every poll |
| Background tab | The tab title flashes when a critical detection lands while you're elsewhere |
| 404 | Glitch treatment on the headline with offset colour ghosts |

### Per-page motion

Beyond the shared layer above, each page animates its own content:

| Page | What animates |
|---|---|
| **Services** | Each service's inclusion list ticks in when that panel reaches the viewport; comparison-table rows deal in; onboarding steps cascade; FAQ answers expand with a measured height transition |
| **Platform** | The ATT&CK coverage map fills in technique by technique; rule-table rows re-deal on every search or filter change, so a query visibly resolves; the risk-scoring console types itself in; the rule drawer cascades its detail rows |
| **Threat Intel** | Live attack scope; the posture assessment sweeps an SVG score dial round to the measured score and pops the grade letter, then ticks the nine checks down the list; IOC, CVE and geography rows deal in; lookup results and actor profiles cascade their fields |
| **Live SOC** | The alert queue deals in on load and on every filter or page change; asset inventory and performance metrics cascade; KPIs flash only when a value actually moves; charts draw themselves in |
| **Incidents** | Queue rows deal in; opening an incident cascades its detail fields, then plays the response timeline back newest-first |
| **Pricing** | Plan cards stagger, each feature list ticking in behind its card; prices count up (an explicit counter re-scan, since plans render after the effects layer boots); comparison rows deal in |
| **About** | Leadership cards and metric grids cascade; company figures count up on scroll |
| **Contact** | Form fields settle in top to bottom; the success state cascades its confirmation, reference and actions |

The cascade helper caps its total delay, so a long table deals in briskly rather than
crawling — past a couple of dozen rows a stagger stops reading as intent and starts
reading as lag.

### Motion safety

Everything above is `transform`/`opacity` only, so it stays on the compositor.

`prefers-reduced-motion: reduce` suppresses all of it — and, importantly, force-shows every
element whose resting state is hidden (`.reveal`, staggered children, drawer contents).
Suppressing an animation without that would leave content invisible rather than merely
static. The scanner sweep, glitch ghosts, meter sheen and button shine are removed entirely.

There is also a `<noscript>` fallback on every page so scroll-revealed sections are visible
with JavaScript disabled, plus a runtime failsafe that reveals everything if
IntersectionObserver never reports (throttled tab, embedded webview, or an unsupported
environment).

**No effect may leave content permanently invisible.** Anything that hides an element at rest
and only reveals it through animation is a blank-content risk if those frames never arrive, so:

- Typed console lines keep their clipped state inside the `@keyframes`, not on the element,
  and the `.typing` class is stripped once the sequence should have finished
- Icon stroke dashes live in the keyframe too, with no `animation-delay` for a backwards fill
  to hold
- Count-ups skip entirely in a hidden tab (`requestAnimationFrame` never fires there, which
  would strand the figure at zero) and carry a timeout that writes the real number if frames
  stop arriving
- Chart draw-ins and the count-up helper fall straight to their finished state when
  `document.hidden` is true

Cursor tilt is delegated from the document rather than bound per element, since most cards are
rendered from API data after page scripts run.

Script order is `api → [charts] → main → effects → page script` on every page, so `window.VGFx`
is guaranteed to exist by the time a page script runs. The cascade helper is entrance-only —
its hidden state lives in the `@keyframes`, never on the element — so a row that never animates
is simply visible.

---

## How the detection engine works

`server/lib/engine.js` generates alerts from the rule catalog every ~4 seconds, in bursts,
because real attacks cluster rather than arriving evenly.

Each alert is anchored to reality in three ways:

1. **Rule → asset coherence.** Every rule declares which asset classes it can fire on, so
   Kerberoasting lands on a domain controller and an S3 exposure lands on cloud storage —
   never the reverse.
2. **Severity weighting.** Rules are drawn weighted by severity (~8% critical, ~22% high),
   so a critical alert still means something when it appears.
3. **Risk scoring.** `risk = severityWeight + assetCriticality + (confidence × 0.25)`, capped
   at 100 — the same detection scores 98 on a finance database and 51 on a designer's laptop.

Internal-origin detections report an internal source address; external ones report a public IP.

New alerts are pushed to every connected browser over Server-Sent Events, which is what
makes the home page console and the dashboard queue update live.

---

## Notes

- **VGIL is a demonstration project.** The company, customers, incidents, threat actors and
  indicators are fictional and generated for illustration. The ATT&CK technique IDs are real;
  the CVEs, IP addresses and hashes are not.
- The posture-assessment tool derives its findings from the hostname alone and sends no
  traffic to the target. It is not a substitute for an authorised external assessment.
- `server/data/vgil.db` is created and migrated on first run, then persists across
  restarts. Run `npm run seed` to wipe and reseed from scratch.
- `node:sqlite` is marked experimental in Node 22, which is why the npm scripts pass
  `--disable-warning=ExperimentalWarning`. The API it uses (`DatabaseSync`,
  `StatementSync`) is stable in Node 23+.
- No build step, no bundler, no external dependencies at runtime beyond Express.
