'use strict';

/**
 * Runtime configuration derived from the environment.
 *
 * The important one is demoMode. In development the seeded demo accounts and
 * the credentials printed on the sign-in page are a convenience. On a public
 * deployment they are a published admin password, so they default to OFF as
 * soon as NODE_ENV is production and must be re-enabled deliberately.
 */

const production = process.env.NODE_ENV === 'production';

function flag(name, defaultValue) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return defaultValue;
  return raw === '1' || raw.toLowerCase() === 'true';
}

const config = {
  production,

  /** Seed demo accounts and advertise their credentials on the sign-in page. */
  demoMode: flag('VGIL_DEMO', !production),

  /** Allow self-service sign-up. Turn off to lock a deployment to existing users. */
  registrationOpen: flag('VGIL_REGISTRATION', true),

  /**
   * With demo accounts disabled a fresh deployment has no administrator, so
   * the very first account created is promoted. Every later one is an analyst.
   */
  bootstrapFirstAdmin: flag('VGIL_BOOTSTRAP_ADMIN', true),

  /**
   * Outbound mail.
   *
   * With no host configured, notifications are still generated and recorded —
   * they just land in the delivery log marked "spooled" instead of being
   * handed to a relay. That keeps the whole path exercisable on a machine
   * with no mail server, and means enabling delivery in production is a
   * matter of setting three variables rather than changing any code.
   */
  smtp: {
    host: process.env.VGIL_SMTP_HOST || '',
    port: Number(process.env.VGIL_SMTP_PORT) || 587,
    // Implicit TLS on 465; anything else negotiates STARTTLS.
    secure: flag('VGIL_SMTP_SECURE', Number(process.env.VGIL_SMTP_PORT) === 465),
    user: process.env.VGIL_SMTP_USER || '',
    pass: process.env.VGIL_SMTP_PASS || '',
    from: process.env.VGIL_SMTP_FROM || 'soc@vgil.io',
    fromName: process.env.VGIL_SMTP_FROM_NAME || 'VGIL Security Operations',
    // Announced in EHLO and used in the Message-ID domain.
    name: process.env.VGIL_SMTP_NAME || 'vgil.io',
    // Only ever loosened deliberately, for a relay with a self-signed cert on
    // an internal network.
    rejectUnauthorized: flag('VGIL_SMTP_TLS_VERIFY', true),
    get configured() {
      return Boolean(this.host);
    }
  },

  /** Base URL used to build links inside notification emails. */
  publicUrl: (process.env.VGIL_PUBLIC_URL || 'http://localhost:3000').replace(/\/$/, ''),

  /**
   * Where the SOC actually is. A physical fact about the company, not a
   * per-deployment setting like the rota — so it is a constant rather than
   * something an admin configures, and env overrides exist only so a fork of
   * this codebase is not stuck advertising our address as its own.
   */
  headquarters: {
    city: process.env.VGIL_HQ_CITY || 'Vadodara',
    region: process.env.VGIL_HQ_REGION || 'Gujarat',
    country: process.env.VGIL_HQ_COUNTRY || 'India',
    lat: Number(process.env.VGIL_HQ_LAT) || 22.3072,
    lon: Number(process.env.VGIL_HQ_LON) || 73.1812,
    timezone: process.env.VGIL_HQ_TZ || 'Asia/Kolkata'
  }
};

module.exports = config;
