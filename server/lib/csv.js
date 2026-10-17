'use strict';

/**
 * RFC 4180 CSV serialisation, with spreadsheet formula injection neutralised.
 *
 * The second part matters more than it looks. Alert fields carry attacker-
 * controlled text — usernames, hostnames, command lines, indicator values. A
 * cell beginning `=`, `+`, `-`, `@` or a control character is interpreted by
 * Excel, LibreOffice and Sheets as a formula, so an adversary who can get a
 * string into an alert can get code to run on the analyst's workstation when
 * the export is opened. Exporting is exactly what an analyst does with a
 * suspicious alert, which makes this a realistic path rather than a
 * theoretical one.
 */

// Tab and carriage return are included because both are treated as leading
// whitespace by spreadsheet parsers, which then re-examine the next character.
const FORMULA_PREFIXES = ['=', '+', '-', '@', '\t', '\r'];

/**
 * Renders one value as a CSV field.
 *
 * Dangerous leading characters are defused with a leading apostrophe, which
 * spreadsheets consume as a "treat this as text" marker rather than showing.
 */
function cell(value) {
  if (value === null || value === undefined) return '';

  let text = Array.isArray(value) ? value.join('; ') : String(value);

  if (typeof value === 'object' && !Array.isArray(value)) {
    text = JSON.stringify(value);
  }

  if (FORMULA_PREFIXES.some((prefix) => text.startsWith(prefix))) {
    text = `'${text}`;
  }

  // Quote when the field contains a delimiter, a quote or a line break;
  // embedded quotes are doubled.
  if (/[",\r\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

/**
 * Serialises rows to a CSV document.
 *
 * @param {Array<Object>} rows
 * @param {Array<{key:string,label:string}>} columns explicit, so the export
 *   has a stable shape that does not drift when a new database column appears
 * @returns {string}
 */
function serialise(rows, columns) {
  const header = columns.map((column) => cell(column.label)).join(',');

  const body = rows.map((row) =>
    columns
      .map((column) => {
        // Dotted keys read nested values, e.g. "asset.host".
        const value = column.key
          .split('.')
          .reduce((acc, part) => (acc == null ? acc : acc[part]), row);
        return cell(column.get ? column.get(row) : value);
      })
      .join(',')
  );

  // CRLF per RFC 4180, and a UTF-8 BOM so Excel on Windows does not mangle
  // non-ASCII hostnames and analyst names.
  return `﻿${[header, ...body].join('\r\n')}\r\n`;
}

/** Sets the headers that make a browser download rather than render. */
function attach(res, filename, body) {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  // Exports are point-in-time; a cached copy would be misleading.
  res.setHeader('Cache-Control', 'no-store');
  return res.send(body);
}

/** `vgil-incidents-2026-08-26.csv` */
function filename(kind, extension = 'csv') {
  return `vgil-${kind}-${new Date().toISOString().slice(0, 10)}.${extension}`;
}

module.exports = { cell, serialise, attach, filename };
