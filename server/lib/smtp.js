'use strict';

/**
 * Minimal SMTP client over node:net / node:tls.
 *
 * This project has exactly one runtime dependency, and a mail library would
 * bring a tree of its own to speak a line protocol that fits in a page. SMTP
 * is a request/response conversation over a socket: send a verb, read a
 * three-digit status, repeat.
 *
 * Supports implicit TLS (465), STARTTLS (587/25), and AUTH PLAIN / LOGIN.
 * What it deliberately does not do is queue, retry with backoff, or handle
 * bounces — that is a mail server's job, and this hands off to one.
 */

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

const CRLF = '\r\n';
const DEFAULT_TIMEOUT_MS = 15000;

/* ------------------------------------------------------------ responses */

/**
 * SMTP replies may span several lines: `250-STARTTLS` continues, `250 OK`
 * ends. Anything else and the caller would hang waiting for a terminator
 * that already arrived.
 */
function parseReply(raw) {
  const lines = raw.split(/\r?\n/).filter(Boolean);
  const last = lines[lines.length - 1] || '';
  return {
    code: Number(last.slice(0, 3)),
    lines: lines.map((line) => line.slice(4)),
    raw
  };
}

function isComplete(buffer) {
  const lines = buffer.split(/\r?\n/).filter(Boolean);
  if (!lines.length) return false;
  // A space in the fourth column marks the final line of a reply.
  return /^\d{3} /.test(lines[lines.length - 1]);
}

/* ------------------------------------------------------------ the wire */

class SmtpSession {
  constructor(socket, timeoutMs) {
    this.socket = socket;
    this.buffer = '';
    this.pending = null;
    this.timeoutMs = timeoutMs;

    socket.setEncoding('utf8');
    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('error', (err) => this._fail(err));
    socket.on('close', () => this._fail(new Error('Connection closed by the mail server.')));
  }

  _onData(chunk) {
    this.buffer += chunk;
    if (!this.pending || !isComplete(this.buffer)) return;

    const reply = parseReply(this.buffer);
    this.buffer = '';

    const { resolve, reject, expect, timer } = this.pending;
    this.pending = null;
    clearTimeout(timer);

    if (expect && !expect.includes(reply.code)) {
      reject(new Error(`SMTP ${reply.code}: ${reply.lines.join(' ')}`));
      return;
    }
    resolve(reply);
  }

  _fail(err) {
    if (!this.pending) return;
    const { reject, timer } = this.pending;
    this.pending = null;
    clearTimeout(timer);
    reject(err);
  }

  /** Waits for a reply without sending anything — used for the greeting. */
  read(expect) {
    return this._await(expect);
  }

  send(line, expect) {
    this.socket.write(line + CRLF);
    return this._await(expect);
  }

  /** Message body: dots leading a line must be doubled (RFC 5321 §4.5.2). */
  sendData(body, expect) {
    this.socket.write(body.replace(/\r\n\./g, '\r\n..') + CRLF + '.' + CRLF);
    return this._await(expect);
  }

  _await(expect) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => this._fail(new Error('Timed out waiting for the mail server.')),
        this.timeoutMs
      );
      this.pending = { resolve, reject, expect, timer };

      // The reply may already be sitting in the buffer.
      if (isComplete(this.buffer)) this._onData('');
    });
  }

  /** Swaps the plaintext socket for a TLS one after STARTTLS. */
  upgrade(options) {
    return new Promise((resolve, reject) => {
      this.socket.removeAllListeners('data');
      this.socket.removeAllListeners('error');
      this.socket.removeAllListeners('close');

      const secure = tls.connect(
        { socket: this.socket, servername: options.host, rejectUnauthorized: options.rejectUnauthorized },
        () => {
          this.socket = secure;
          this.buffer = '';
          secure.setEncoding('utf8');
          secure.on('data', (chunk) => this._onData(chunk));
          secure.on('error', (err) => this._fail(err));
          secure.on('close', () => this._fail(new Error('Connection closed by the mail server.')));
          resolve();
        }
      );
      secure.once('error', reject);
    });
  }

  close() {
    try {
      this.socket.write('QUIT' + CRLF);
      this.socket.end();
    } catch {
      /* already gone */
    }
  }
}

/* ------------------------------------------------------------- message */

/**
 * Encodes a header value that contains non-ASCII, per RFC 2047.
 * A raw UTF-8 subject line is not legal in a header and gets mangled.
 */
function encodeHeader(value) {
  const text = String(value);
  if (/^[\x20-\x7e]*$/.test(text)) return text;
  return `=?UTF-8?B?${Buffer.from(text, 'utf8').toString('base64')}?=`;
}

/**
 * Base64 with hard line breaks. Transfer-encoding the body sidesteps both the
 * 998-octet line limit and any 8-bit cleanliness question about the relay.
 */
function encodeBody(text) {
  return (Buffer.from(text, 'utf8').toString('base64').match(/.{1,76}/g) || []).join(CRLF);
}

/** Builds a multipart/alternative message with plain-text and HTML parts. */
function buildMessage({ from, fromName, to, subject, text, html, messageId }) {
  const boundary = `----vgil-${crypto.randomBytes(12).toString('hex')}`;
  const sender = fromName ? `${encodeHeader(fromName)} <${from}>` : from;

  const headers = [
    `From: ${sender}`,
    `To: ${to}`,
    `Subject: ${encodeHeader(subject)}`,
    `Message-ID: <${messageId || crypto.randomUUID()}@vgil.io>`,
    `Date: ${new Date().toUTCString()}`,
    'MIME-Version: 1.0',
    // Alerts are transactional; this keeps them out of vacation-responder and
    // list-detection heuristics.
    'Auto-Submitted: auto-generated',
    'X-Auto-Response-Suppress: All',
    `Content-Type: multipart/alternative; boundary="${boundary}"`
  ];

  const parts = [
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    encodeBody(text),
    ''
  ];

  if (html) {
    parts.push(
      `--${boundary}`,
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      encodeBody(html),
      ''
    );
  }

  parts.push(`--${boundary}--`);

  return headers.join(CRLF) + CRLF + CRLF + parts.join(CRLF);
}

/* -------------------------------------------------------------- client */

function connect({ host, port, secure, timeoutMs, rejectUnauthorized }) {
  return new Promise((resolve, reject) => {
    const socket = secure
      ? tls.connect({ host, port, servername: host, rejectUnauthorized }, () => resolve(socket))
      : net.connect({ host, port }, () => resolve(socket));

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error('Timed out connecting to the mail server.'));
    });
    socket.once('error', reject);
  });
}

/**
 * Delivers one message.
 *
 * @returns {Promise<{accepted:boolean, response:string}>}
 * @throws on connection, authentication or rejection
 */
async function send(config, message) {
  const timeoutMs = config.timeoutMs || DEFAULT_TIMEOUT_MS;
  const rejectUnauthorized = config.rejectUnauthorized !== false;

  const socket = await connect({
    host: config.host,
    port: config.port,
    secure: config.secure,
    timeoutMs,
    rejectUnauthorized
  });

  const session = new SmtpSession(socket, timeoutMs);

  try {
    await session.read([220]);

    // The hostname announced here should resolve; a bare "localhost" is
    // rejected outright by some relays.
    const greeting = config.name || 'vgil.io';
    let ehlo = await session.send(`EHLO ${greeting}`, [250]);

    const supports = (verb) =>
      ehlo.lines.some((line) => line.toUpperCase().includes(verb));

    if (!config.secure && supports('STARTTLS')) {
      await session.send('STARTTLS', [220]);
      await session.upgrade({ host: config.host, rejectUnauthorized });
      // Capabilities are re-advertised after the upgrade, and AUTH is
      // commonly absent from the pre-TLS list on purpose.
      ehlo = await session.send(`EHLO ${greeting}`, [250]);
    }

    if (config.user && config.pass) {
      if (supports('AUTH') && ehlo.lines.some((l) => /AUTH[ =].*PLAIN/i.test(l))) {
        const token = Buffer.from(`\0${config.user}\0${config.pass}`, 'utf8').toString('base64');
        await session.send(`AUTH PLAIN ${token}`, [235]);
      } else {
        await session.send('AUTH LOGIN', [334]);
        await session.send(Buffer.from(config.user, 'utf8').toString('base64'), [334]);
        await session.send(Buffer.from(config.pass, 'utf8').toString('base64'), [235]);
      }
    }

    await session.send(`MAIL FROM:<${message.from}>`, [250]);
    await session.send(`RCPT TO:<${message.to}>`, [250, 251]);
    await session.send('DATA', [354]);

    const reply = await session.sendData(buildMessage(message), [250]);

    session.close();
    return { accepted: true, response: reply.lines.join(' ') };
  } catch (err) {
    session.close();
    throw err;
  }
}

module.exports = { send, buildMessage, encodeHeader, encodeBody, parseReply, isComplete };
