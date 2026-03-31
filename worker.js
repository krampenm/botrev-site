/**
 * BotRev Cloudflare Worker — Combined Monolithic Worker
 * Bot Sniffer | Publisher Domain Intercept | Dashboard UI | Admin Portal
 * Version 28.1 (Combined) — March 2026
 *
 * This is the combined v28.1 worker — a single export default with one
 * handleRequest function, merging the bot interception worker and the
 * dashboard Pages function back into a monolithic deployment.
 *
 * Features:
 *   - Publisher domain bot detection, classification, logging, and routing
 *   - TollBit log sink (batched)
 *   - Surge Intelligence detection and email alerts
 *   - /api/sniff endpoint (JS snippet integration)
 *   - /health endpoint (monitoring)
 *   - Admin Fleet Command, Surge Intelligence admin panel
 *   - Publisher dashboard, domain drilldown, marketplace drilldown
 *   - Onboarding, login, session token auth (HttpOnly cookies)
 *   - Claude-powered audit report generation
 *
 * Changelog v28.1:
 *   - SECURITY: Remove admin password from surge alert email links.
 *     Admin must now authenticate via the dashboard login page.
 *   - FIX: Remove meta-externalagent from TRAINING_BOT_TOKENS — it is a Meta AI
 *     inference bot, not a training crawler.
 *   - Session token authentication: admin password no longer appears in
 *     URLs, HTML source, or browser history. Uses HttpOnly session cookies
 *     with HMAC-signed tokens.
 *   - Login rate limiting to prevent brute-force attacks.
 *   - HTML escaping (escHtml) to prevent XSS from attacker-controlled UA strings.
 *
 * WORKER SECRETS REQUIRED (Cloudflare Workers → Settings → Variables & Secrets):
 *   TOLLBIT_KEY        — TollBit org-level log sink auth key
 *   RESEND_API_KEY     — Resend email API key for surge alerts
 *   ADMIN_PASS         — Admin portal password
 *   ANTHROPIC_API_KEY  — Claude API key for report generation
 *
 * BINDINGS REQUIRED in wrangler.toml:
 *   [[d1_databases]]
 *   binding = "DB"
 *   database_name = "exchange_db"
 *   database_id = "<YOUR_D1_ID>"
 */

// ── TOLLBIT LOG SINK — MODULE-LEVEL BATCH STATE ─────────────────────────────
const TB_BATCH_INTERVAL_MS  = 20000;
const TB_MAX_BATCH_SIZE     = 500;
const TB_BACKOFF_INTERVAL   = 10000;
let   tbLogBatch            = [];
let   tbBackoffUntil        = 0;
let   tbBatchScheduled      = false;

// ── v27.2 SECURITY — CRYPTOGRAPHIC HELPERS ──────────────────────────────────

/**
 * HMAC-SHA256 sign a message using env.ADMIN_PASS as the key.
 * Used to sign surge action URLs so they can't be forged or replayed.
 */
async function hmacSign(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verify an HMAC-SHA256 signature. Constant-time comparison.
 */
async function hmacVerify(message, signature, secret) {
  const expected = await hmacSign(message, secret);
  if (expected.length !== signature.length) return false;
  // Constant-time compare to prevent timing attacks
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) {
    mismatch |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * Compute a SHA-256 hash chain entry.
 * Each bot_log entry hashes (prevHash + entryData).
 * Any modification to historical entries breaks the chain.
 */
async function computeEntryHash(prevHash, entryData) {
  const enc = new TextEncoder();
  const input = `${prevHash || 'botrev-genesis'}:${entryData}`;
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(input));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate a signed, time-limited surge action URL.
 * Payload: surgeId:auditId:action:expiresTimestamp
 * Expires after 30 minutes. Cannot be replayed after expiry.
 */
async function signedSurgeActionUrl(baseUrl, surgeId, auditId, action, adminPass) {
  const expires = Date.now() + (30 * 60 * 1000); // 30 min
  const payload = `${surgeId}:${auditId}:${action}:${expires}`;
  const sig = await hmacSign(payload, adminPass);
  const encoded = encodeURIComponent(payload);
  return `${baseUrl}/api/admin/surge-action?payload=${encoded}&sig=${sig}`;
}

/**
 * Verify a signed surge action URL.
 * Returns { valid: true, surgeId, auditId, action } or { valid: false, reason }
 */
async function verifySurgeToken(payload, sig, adminPass) {
  if (!payload || !sig) return { valid: false, reason: 'Missing token parameters' };
  const isValid = await hmacVerify(payload, sig, adminPass);
  if (!isValid) return { valid: false, reason: 'Invalid signature' };
  const parts = payload.split(':');
  if (parts.length < 4) return { valid: false, reason: 'Malformed token' };
  const [surgeId, auditId, action, expiresStr] = parts;
  const expires = parseInt(expiresStr, 10);
  if (Date.now() > expires) return { valid: false, reason: 'Token expired — surge links are valid for 30 minutes' };
  if (!['approve', 'reject'].includes(action)) return { valid: false, reason: 'Invalid action in token' };
  return { valid: true, surgeId, auditId, action };
}

/**
 * v27.2 Admin rate limiter — max 10 requests per IP per minute.
 * Logs to D1 admin_requests table.
 * Returns { allowed: true } or { allowed: false, retryAfter: seconds }
 */
async function checkAdminRateLimit(ip, path, env) {
  try {
    // Log this request
    await env.DB.prepare(
      `INSERT INTO admin_requests (ip, path, ts) VALUES (?, ?, datetime('now'))`
    ).bind(ip || 'unknown', path).run();

    // Count requests from this IP in the last minute
    const result = await env.DB.prepare(
      `SELECT COUNT(*) as cnt FROM admin_requests
       WHERE ip = ? AND ts > datetime('now', '-1 minute')`
    ).bind(ip || 'unknown').first();

    const count = result?.cnt || 0;
    if (count > 10) {
      return { allowed: false, retryAfter: 60 };
    }

    // Cleanup old entries occasionally (1 in 20 chance to avoid D1 bloat)
    if (Math.random() < 0.05) {
      env.DB.prepare(
        `DELETE FROM admin_requests WHERE ts < datetime('now', '-10 minutes')`
      ).run().catch(() => {});
    }

    return { allowed: true };
  } catch {
    // If rate limit check fails, allow through — don't break admin access
    return { allowed: true };
  }
}

// ── v28.1 SESSION TOKEN AUTHENTICATION ──────────────────────────────────────
// Replaces pass= query parameters with HttpOnly session cookies.
// Admin password no longer appears in HTML source, browser history, or URLs.

const SESSION_COOKIE_NAME = 'botrev_session';
const SESSION_EXPIRY_HOURS = 8;

async function createSessionToken(adminPass) {
  const expires = Date.now() + (SESSION_EXPIRY_HOURS * 60 * 60 * 1000);
  const payload = `admin:${expires}`;
  const sig = await hmacSign(payload, adminPass);
  return `${payload}:${sig}`;
}

async function verifySessionToken(token, adminPass) {
  if (!token || !adminPass) return false;
  const parts = token.split(':');
  if (parts.length < 3) return false;
  const [role, expiresStr, sig] = [parts[0], parts[1], parts.slice(2).join(':')];
  const payload = `${role}:${expiresStr}`;
  const valid = await hmacVerify(payload, sig, adminPass);
  if (!valid) return false;
  const expires = parseInt(expiresStr, 10);
  if (Date.now() > expires) return false;
  return true;
}

function getSessionCookie(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function sessionCookieHeader(token) {
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_EXPIRY_HOURS * 3600}`;
}

async function isAdminAuthenticated(request, env) {
  // Check session cookie first
  const token = getSessionCookie(request);
  if (token && await verifySessionToken(token, env.ADMIN_PASS)) return true;
  // Legacy fallback: check pass= query param (for backward compat during transition)
  const url = new URL(request.url);
  const pass = url.searchParams.get('pass');
  if (pass && pass === env.ADMIN_PASS) return true;
  return false;
}

// ── T5 TRAINING BOT FINGERPRINTS (MODULE LEVEL) ─────────────────────────────
// These crawlers collect content for LLM model training.
// TollBit does NOT monetize these. Logged at $0 CPM, passed to origin.
// Future: route to BotRev Training Deals product line.
//
// Sources: OpenAI, Anthropic, Google, Meta, ByteDance, Common Crawl
// official documentation + verified server log analysis (2026).
// CHECKED FIRST in classifyBot() — training bots must never land in T1-T4.
//
// v28.1 FIX: meta-externalagent REMOVED — it is Meta's inference bot, not training.
const TRAINING_BOT_TOKENS = [
  // OpenAI — training (distinct from ChatGPT-User which is inference/retrieval)
  'gptbot',
  // Anthropic — bulk model training (distinct from claudebot/claude-web which are retrieval)
  'anthropic-ai',
  // Google — Gemini training opt-out agent
  'google-extended',
  // Meta — LLM training (meta-externalagent is inference, handled in T1)
  'facebookbot',
  // ByteDance / TikTok — LLMs including Doubao
  'bytespider',
  // Common Crawl — open dataset used by many LLMs for training
  'ccbot',
  // Apple — training-specific variant (distinct from standard Applebot)
  'applebot-extended',
  // Cohere — explicit training crawlers
  'cohere-ai',
  'cohere-training-data-crawler',
  // DeepSeek
  'deepseekbot',
  // Data brokers that sell crawled content to LLM companies
  'diffbot',
  'omgili',
  'img2dataset',
  // Google additional training agents
  'google-cloudvertexbot',
  'cloudvertexbot',
  // Miscellaneous confirmed training agents
  'friendlycrawler',
  'iaskspider',
  'magpie-crawler',
  'webzio-extended',
];

// ── TOLLBIT LOG BUILDING AND BATCHING ────────────────────────────────────────

function buildTollBitLog(request, responseStatus, tier, isStealthFlag) {
  const cf = request.cf ? { ...request.cf } : {};
  delete cf.tlsClientAuth;
  delete cf.tlsExportedAuthenticator;

  return {
    timestamp:          new Date().toISOString(),
    ip_address:         request.headers.get('cf-connecting-ip'),
    geo_country:        cf.country        || null,
    geo_city:           cf.city           || null,
    geo_postal_code:    cf.postalCode      || null,
    geo_latitude:       cf.latitude        || null,
    geo_longitude:      cf.longitude       || null,
    host:               request.headers.get('host'),
    url:                (() => { try { const u = new URL(request.url); return u.pathname + u.search; } catch { return '/'; } })(),
    request_method:     request.method,
    request_protocol:   cf.httpProtocol   || 'HTTPS',
    request_user_agent: request.headers.get('user-agent'),
    request_latency:    null,
    request_referer:    request.headers.get('referer'),
    response_state:     null,
    response_status:    responseStatus || 200,
    response_reason:    responseStatus === 302 ? 'Found' : 'OK',
    response_body_size: null,
    signature:          request.headers.get('signature'),
    signature_agent:    request.headers.get('signature-agent'),
    signature_input:    request.headers.get('signature-input'),
    botrev_tier:        tier || null,
    botrev_is_stealth:  isStealthFlag || 0,
  };
}

async function postTollBitBatch(tollbitKey) {
  if (tbLogBatch.length === 0) return;
  if (Date.now() < tbBackoffUntil) return;

  const batchInFlight = [...tbLogBatch];
  tbLogBatch = [];

  const body = batchInFlight.map(e => JSON.stringify(e)).join('\n');

  try {
    const resp = await fetch('https://log.tollbit.com/log', {
      method:  'POST',
      headers: {
        'TollbitKey':    tollbitKey,
        'Content-Type': 'application/json',
      },
      body,
    });

    if (resp.status === 403 || resp.status === 429) {
      tbBackoffUntil = Date.now() + TB_BACKOFF_INTERVAL;
    }
  } catch {
    // Network error — drop the batch, don't crash the Worker
  }
}

function enqueueTollBitLog(logEntry, tollbitKey, ctx) {
  tbLogBatch.push(logEntry);

  if (tbLogBatch.length >= TB_MAX_BATCH_SIZE) {
    ctx.waitUntil(postTollBitBatch(tollbitKey));
    return;
  }

  if (!tbBatchScheduled) {
    tbBatchScheduled = true;
    ctx.waitUntil(
      new Promise(resolve => setTimeout(resolve, TB_BATCH_INTERVAL_MS))
        .then(() => {
          tbBatchScheduled = false;
          return postTollBitBatch(tollbitKey);
        })
    );
  }
}

// ── SURGE INTELLIGENCE — CONSTANTS AND FUNCTIONS ─────────────────────────────
const SURGE_BETA_DEFAULT      = 1.5;
const SURGE_FLOOR_CPM_DEFAULT = 3.0;
const SURGE_PLATFORM_BASELINE = 10;
const SURGE_ALERT_EMAIL       = 'matt@botrev.com';
const SURGE_FROM_EMAIL        = 'BotRev Surge Intelligence <surge@botrev.com>';

function calculateGamma(path) {
  const currentYear = new Date().getFullYear();
  const match = path.match(/\b(20\d{2})\b/);
  if (!match) return 1.0;
  const pathYear = parseInt(match[1]);
  if (pathYear >= currentYear)      return 1.2;
  if (pathYear === currentYear - 1) return 1.0;
  return 0.8;
}

async function getSurgeBaseline(auditId, env) {
  try {
    const [hitsRow, daysRow] = await Promise.all([
      env.DB.prepare(
        "SELECT COUNT(*) as cnt FROM bot_logs WHERE audit_id = ? AND timestamp > datetime('now', '-7 days')"
      ).bind(auditId).first(),
      env.DB.prepare(
        "SELECT CAST(julianday('now') - julianday(MIN(timestamp)) AS REAL) as days FROM bot_logs WHERE audit_id = ?"
      ).bind(auditId).first(),
    ]);
    const totalHits  = hitsRow?.cnt  || 0;
    const daysOfData = Math.min(daysRow?.days || 0, 7);
    if (daysOfData < 1) {
      return { vbase: SURGE_PLATFORM_BASELINE, daysOfData: 0, isEstimated: true };
    }
    const windowsPer10Min = daysOfData * 24 * 6;
    const vbase = totalHits / windowsPer10Min;
    return { vbase: Math.max(vbase, 0.1), daysOfData, isEstimated: daysOfData < 7 };
  } catch {
    return { vbase: SURGE_PLATFORM_BASELINE, daysOfData: 0, isEstimated: true };
  }
}

async function evaluateSurge(auditId, hostname, reqPath, env, ctx) {
  try {
    // v27: Exclude T5 training hits from V10 — training bots are bulk crawlers,
    // not demand signals. Only T1-T4 monetizable hits count toward surge detection.
    const v10Row = await env.DB.prepare(
      "SELECT COUNT(*) as cnt FROM bot_logs WHERE audit_id = ? AND timestamp > datetime('now', '-10 minutes') AND is_training = 0"
    ).bind(auditId).first();
    const v10 = v10Row?.cnt || 0;

    const { vbase, daysOfData, isEstimated } = await getSurgeBaseline(auditId, env);

    const pub = await env.DB.prepare(
      "SELECT floor_cpm, beta, domain_name FROM publisher_entities WHERE audit_id = ? LIMIT 1"
    ).bind(auditId).first();
    const pfloor = pub?.floor_cpm || SURGE_FLOOR_CPM_DEFAULT;
    const beta   = pub?.beta      || SURGE_BETA_DEFAULT;
    const domain = pub?.domain_name || hostname;

    const gamma = calculateGamma(reqPath);
    const vrat  = vbase > 0 ? v10 / vbase : (v10 > 0 ? 10 : 0);
    const pt    = pfloor * (1 + beta * Math.log10(1 + vrat) * gamma);

    if (pt <= pfloor || v10 === 0) return;

    const upliftPct = ((pt - pfloor) / pfloor * 100).toFixed(1);

    // v27.2 FIX: Check throttle BEFORE inserting.
    const recentCount = await env.DB.prepare(
      `SELECT COUNT(*) as cnt FROM surge_events
       WHERE audit_id = ? AND detected_at > datetime('now', '-4 hours')`
    ).bind(auditId).first().catch(() => ({ cnt: 0 }));

    if ((recentCount?.cnt || 0) >= 1) return;

    // v27.2 FIX: Also check minimum insert interval — 2 minutes between
    // any two surge_events rows regardless of alert status.
    const lastInsert = await env.DB.prepare(
      `SELECT detected_at FROM surge_events
       WHERE audit_id = ? ORDER BY detected_at DESC LIMIT 1`
    ).bind(auditId).first().catch(() => null);

    if (lastInsert?.detected_at) {
      const lastMs = new Date(lastInsert.detected_at + 'Z').getTime();
      if (Date.now() - lastMs < 2 * 60 * 1000) return; // 2-min cooldown
    }

    // Now safe to insert — only one surge event per 4-hour window
    let surgeEventId = null;
    try {
      const insertResult = await env.DB.prepare(
        `INSERT INTO surge_events
          (audit_id, domain_name, page_path, hits_per_10min, vbase, vrat,
           gamma, surge_score, floor_cpm, recommended_cpm, status, detected_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'))`
      ).bind(auditId, domain, reqPath, v10, vbase, vrat, gamma, vrat, pfloor, pt).run();
      surgeEventId = insertResult?.meta?.last_row_id ?? null;
    } catch { /* surge log failure must never break request flow */ }

    ctx.waitUntil(sendSurgeAlert(env, {
      domain, reqPath, v10, vbase, vrat, gamma, pfloor, pt, beta, upliftPct,
      daysOfData, isEstimated, surgeEventId, auditId
    }));

  } catch { /* surge detection must never break request flow */ }
}

async function sendSurgeAlert(env, d) {
  if (!env.RESEND_API_KEY) return;
  const surge5  = (d.pfloor * (1 + d.beta * Math.log10(6)  * d.gamma)).toFixed(2);
  const surge10 = (d.pfloor * (1 + d.beta * Math.log10(11) * d.gamma)).toFixed(2);
  const gammaLabel = d.gamma === 1.2 ? 'Current year (1.2)' : d.gamma === 0.8 ? '2+ years ago (0.8)' : 'Neutral (1.0)';

  // v27.2: admin pass from env — signed tokens replace plain pass= URLs
  const adminPass = env.ADMIN_PASS;
  if (!adminPass) return; // can't sign without a key

  const baseUrl = 'https://dash.botrev.com';
  const approveUrl = d.surgeEventId
    ? await signedSurgeActionUrl(baseUrl, d.surgeEventId, d.auditId || '', 'approve', adminPass)
    : null;
  const rejectUrl = d.surgeEventId
    ? await signedSurgeActionUrl(baseUrl, d.surgeEventId, d.auditId || '', 'reject', adminPass)
    : null;

  const html = `
<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#0a1220; color:#e2e8f0; margin:0; padding:0; }
  .wrap { max-width:600px; margin:0 auto; padding:32px 24px; }
  .logo { font-size:24px; font-weight:700; color:#fff; margin-bottom:4px; }
  .logo span { color:#00e5a0; }
  .tag { font-size:10px; letter-spacing:3px; text-transform:uppercase; color:#64748b; margin-bottom:32px; }
  .alert-box { background:#0d1f33; border:1px solid rgba(0,229,160,0.3); border-top:3px solid #00e5a0; border-radius:12px; padding:24px; margin-bottom:20px; }
  .alert-title { font-size:20px; font-weight:700; color:#fff; margin-bottom:4px; }
  .alert-sub { font-size:13px; color:#94a3b8; margin-bottom:20px; }
  .stat-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:20px; }
  .stat { background:#0a1622; border:1px solid rgba(255,255,255,0.06); border-radius:8px; padding:14px; }
  .stat-label { font-size:11px; letter-spacing:1px; text-transform:uppercase; color:#64748b; margin-bottom:6px; }
  .stat-val { font-size:22px; font-weight:700; color:#00e5a0; }
  .stat-val.amber { color:#f59e0b; }
  .stat-val.white { color:#fff; }
  .formula-box { background:#061018; border:1px solid rgba(255,255,255,0.06); border-radius:8px; padding:16px; font-family:monospace; font-size:13px; color:#a8c5e8; margin-bottom:20px; line-height:1.8; }
  .formula-box .highlight { color:#00e5a0; font-weight:bold; }
  .estimated { background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.3); border-radius:8px; padding:12px 16px; font-size:12px; color:#f59e0b; margin-bottom:20px; }
  .var-row { display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.05); font-size:13px; }
  .var-row:last-child { border-bottom:none; }
  .var-name { color:#64748b; }
  .var-val { color:#e2e8f0; font-family:monospace; }
</style></head><body><div class="wrap">
  <div class="logo">Bot<span>Rev</span></div>
  <div class="tag">Surge Intelligence · Phase 2 Alert</div>

  <div class="alert-box">
    <div class="alert-title">⚡ Surge detected on ${d.domain}</div>
    <div class="alert-sub">${d.reqPath === '/' ? 'Homepage' : d.reqPath} · ${new Date().toUTCString()}</div>

    ${d.isEstimated ? `<div class="estimated">⚠ Baseline estimated — only ${d.daysOfData < 1 ? 'less than 1 day' : d.daysOfData.toFixed(1) + ' days'} of data. Alert sensitivity may be elevated until 7-day baseline is established.</div>` : ''}

    <div class="stat-grid">
      <div class="stat"><div class="stat-label">Recommended CPM</div><div class="stat-val">$${d.pt.toFixed(2)}</div></div>
      <div class="stat"><div class="stat-label">Price uplift</div><div class="stat-val">+${d.upliftPct}%</div></div>
      <div class="stat"><div class="stat-label">Current floor CPM</div><div class="stat-val amber">$${d.pfloor.toFixed(2)}</div></div>
      <div class="stat"><div class="stat-label">Hits last 10 min</div><div class="stat-val white">${d.v10}</div></div>
      <div class="stat"><div class="stat-label">Baseline (per 10 min)</div><div class="stat-val white">${d.vbase.toFixed(1)}</div></div>
      <div class="stat"><div class="stat-label">Traffic ratio</div><div class="stat-val white">${d.vrat.toFixed(1)}×</div></div>
    </div>

    <div class="formula-box">
      Pt = Pfloor × (1 + β × log₁₀(1 + V10/Vbase) × γ)<br>
      <span class="highlight">$${d.pt.toFixed(2)}</span> = $${d.pfloor.toFixed(2)} × (1 + ${d.beta} × log₁₀(1 + ${d.v10}/${d.vbase.toFixed(1)}) × ${d.gamma})
    </div>

    <div style="margin-bottom:16px;">
      <div style="font-size:11px; letter-spacing:1px; text-transform:uppercase; color:#64748b; margin-bottom:10px;">Formula variables</div>
      <div class="var-row"><span class="var-name">β (Beta)</span><span class="var-val">${d.beta}</span></div>
      <div class="var-row"><span class="var-name">γ (Gamma)</span><span class="var-val">${d.gamma} — ${gammaLabel}</span></div>
      <div class="var-row"><span class="var-name">Pfloor</span><span class="var-val">$${d.pfloor.toFixed(2)} CPM</span></div>
      <div class="var-row"><span class="var-name">At 5× surge</span><span class="var-val">$${surge5} CPM</span></div>
      <div class="var-row"><span class="var-name">At 10× surge</span><span class="var-val">$${surge10} CPM</span></div>
    </div>

    ${approveUrl && rejectUrl ? `
    <div style="background:rgba(0,229,160,0.06); border:1px solid rgba(0,229,160,0.25); border-radius:10px; padding:16px; margin-bottom:12px;">
      <div style="font-size:11px; letter-spacing:2px; text-transform:uppercase; color:#00e5a0; margin-bottom:12px;">⚡ Phase 2 — One-Click Action</div>
      <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:10px;">
        <tr>
          <td width="48%" style="padding-right:6px;">
            <a href="${approveUrl}" style="display:block; text-align:center; background:#059669; color:#fff; text-decoration:none; padding:14px 12px; border-radius:8px; font-weight:700; font-size:15px;">✓ Approve $${d.pt.toFixed(2)} CPM</a>
          </td>
          <td width="4%"></td>
          <td width="48%" style="padding-left:6px;">
            <a href="${rejectUrl}" style="display:block; text-align:center; background:#1e293b; color:#94a3b8; text-decoration:none; padding:14px 12px; border-radius:8px; font-weight:700; font-size:15px; border:1px solid rgba(255,255,255,0.08);">✗ Dismiss Surge</a>
          </td>
        </tr>
      </table>
      <div style="font-size:11px; color:#475569; text-align:center; line-height:1.6;">Approve applies the recommended rate via partner API. Rate resets to floor CPM after next evaluation window.</div>
    </div>
    ` : `<a style="display:block; text-align:center; background:#00a896; color:#fff; text-decoration:none; padding:14px 24px; border-radius:8px; font-weight:700; font-size:15px; margin-bottom:12px;" href="https://dash.botrev.com/admin-surge">View in Surge Intelligence →</a>`}

    <a href="https://dash.botrev.com/admin-surge" style="display:block; text-align:center; font-size:13px; color:#64748b; text-decoration:none;">View full Surge Intelligence dashboard →</a>
  </div>

  <div style="font-size:11px; color:#334155; text-align:center; margin-top:32px;">BotRev Surge Intelligence · Phase 2 — One-Click Approval Active<br>Phase 3 (full automation) coming soon.</div>
</div></body></html>`;

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from:    SURGE_FROM_EMAIL,
      to:      [SURGE_ALERT_EMAIL],
      subject: `⚡ Surge on ${d.domain} — recommend $${d.pt.toFixed(2)} CPM (+${d.upliftPct}%)`,
      html,
    }),
  }).catch(() => {});
}

// ── BOT DISPLAY NAME MAPPING ─────────────────────────────────────────────────
// Maps raw User-Agent tokens to human-readable company/product names.
const BOT_DISPLAY_NAMES = [
  // ── OpenAI ──
  { match: /chatgpt-user/i,           name: "ChatGPT",                  company: "OpenAI",        icon: "🤖" },
  { match: /gptbot/i,                 name: "GPT Training Crawler",      company: "OpenAI",        icon: "🤖" },
  { match: /oai-searchbot/i,          name: "SearchGPT",                 company: "OpenAI",        icon: "🔍" },
  // ── Anthropic ──
  { match: /claudebot/i,              name: "Claude",                    company: "Anthropic",     icon: "🤖" },
  { match: /claude-web/i,             name: "Claude Web",                company: "Anthropic",     icon: "🤖" },
  { match: /anthropic-ai/i,           name: "Claude Training Crawler",   company: "Anthropic",     icon: "🤖" },
  // ── Google ──
  { match: /googlebot/i,              name: "Googlebot",                 company: "Google",        icon: "🔍" },
  { match: /google-extended/i,        name: "Google AI Training",        company: "Google",        icon: "🤖" },
  { match: /googleother/i,            name: "Google Other Crawler",      company: "Google",        icon: "🔍" },
  { match: /google-inspectiontool/i,  name: "Google Inspection",         company: "Google",        icon: "🔍" },
  { match: /gemini/i,                 name: "Gemini",                    company: "Google",        icon: "🤖" },
  // ── Microsoft / Bing ──
  { match: /bingbot/i,                name: "Bingbot",                   company: "Microsoft",     icon: "🔍" },
  { match: /msnbot/i,                 name: "MSN Bot",                   company: "Microsoft",     icon: "🔍" },
  { match: /bingpreview/i,            name: "Bing Preview",              company: "Microsoft",     icon: "🔍" },
  // ── Perplexity ──
  { match: /perplexitybot/i,          name: "Perplexity AI",             company: "Perplexity",    icon: "🔍" },
  { match: /perplexity/i,             name: "Perplexity AI",             company: "Perplexity",    icon: "🔍" },
  // ── Meta — specific patterns first (FBAN = Facebook in-app browser) ──
  { match: /meta-externalads/i,       name: "Meta Ad Crawler",           company: "Meta",          icon: "🔍" },
  { match: /meta-externalagent/i,     name: "Meta AI Agent",             company: "Meta",          icon: "🤖" },
  { match: /facebookbot/i,            name: "Meta AI Training",          company: "Meta",          icon: "🤖" },
  { match: /facebookexternalhit/i,    name: "Facebook Link Preview",     company: "Meta",          icon: "🔍" },
  { match: /FBAN\/FB4A/,              name: "Facebook In-App Browser",   company: "Meta",          icon: "🔍" },
  { match: /FBAN\/Orca/,              name: "Messenger In-App Browser",  company: "Meta",          icon: "🔍" },
  { match: /Barcelona/,               name: "Threads In-App Browser",    company: "Meta",          icon: "🔍" },
  { match: /Instagram/i,              name: "Instagram In-App Browser",  company: "Meta",          icon: "🔍" },
  // ── Amazon ──
  { match: /amazon-kendra/i,          name: "Amazon Kendra AI",          company: "Amazon",        icon: "🤖" },
  { match: /amazon-quick/i,           name: "Amazon Kendra AI",          company: "Amazon",        icon: "🤖" },
  { match: /amazonbot/i,              name: "Amazonbot",                 company: "Amazon",        icon: "🔍" },
  // ── Apple ──
  { match: /applebot/i,               name: "Applebot",                  company: "Apple",         icon: "🔍" },
  // ── ByteDance / TikTok ──
  { match: /bytespider/i,             name: "ByteDance AI Training",     company: "ByteDance",     icon: "🤖" },
  { match: /tiktokspider/i,           name: "TikTok Crawler",            company: "ByteDance",     icon: "🔍" },
  // ── DuckDuckGo ──
  { match: /duckassistbot/i,          name: "DuckDuckGo AI Assistant",   company: "DuckDuckGo",    icon: "🤖" },
  { match: /duckduckbot/i,            name: "DuckDuckBot",               company: "DuckDuckGo",    icon: "🔍" },
  { match: /duckduckgo/i,             name: "DuckDuckGo",                company: "DuckDuckGo",    icon: "🔍" },
  // ── Yandex ──
  { match: /yandexbot/i,              name: "YandexBot",                 company: "Yandex",        icon: "🔍" },
  { match: /yandex/i,                 name: "Yandex",                    company: "Yandex",        icon: "🔍" },
  // ── Yahoo ──
  { match: /yahoo.*slurp/i,           name: "Yahoo Search Crawler",      company: "Yahoo",         icon: "🔍" },
  // ── LinkedIn ──
  { match: /linkedinbot/i,            name: "LinkedIn Bot",              company: "LinkedIn",      icon: "🔍" },
  // ── Common Crawl ──
  { match: /ccbot/i,                  name: "Common Crawl",              company: "Common Crawl",  icon: "🤖" },
  // ── Huawei / Petal Search ──
  { match: /petalbot/i,               name: "Petal Search Bot",          company: "Huawei",        icon: "🔍" },
  // ── Semrush ──
  { match: /siteauditbot/i,           name: "Site Audit Bot",            company: "Semrush",       icon: "🔍" },
  { match: /semrushbot/i,             name: "SEMrush Bot",               company: "Semrush",       icon: "🔍" },
  // ── Ahrefs ──
  { match: /ahrefsbot/i,              name: "Ahrefs Bot",                company: "Ahrefs",        icon: "🔍" },
  // ── Majestic ──
  { match: /mj12bot/i,                name: "Majestic Bot",              company: "Majestic",      icon: "🔍" },
  // ── QuillBot (AI writing assistant) ──
  { match: /quillbot/i,               name: "QuillBot AI",               company: "QuillBot",      icon: "🤖" },
  // ── Paqle (Danish search) ──
  { match: /paqlebot/i,               name: "Paqle Search Bot",          company: "Paqle",         icon: "🔍" },
  // ── Ground News (news aggregator app) ──
  { match: /ground news/i,            name: "Ground News App",           company: "Ground News",   icon: "🔍" },
  // ── HanaleiBot (unknown, beta) ──
  { match: /hanaleibot/i,             name: "HanaleiBot (Beta)",         company: "Unknown",       icon: "🤖" },
  // ── ContextualBot ──
  { match: /contextualbot/i,          name: "ContextualBot",             company: "Outcomes.net",  icon: "🔍" },
  // ── SEBot-WA ──
  { match: /sebot-wa/i,               name: "SEBot",                     company: "Unknown",       icon: "🔍" },
  // ── Headless Chrome / Automation (must come after named bots) ──
  { match: /headlesschrome/i,         name: "Headless Chrome",           company: "Automation",    icon: "⚡" },
  { match: /puppeteer/i,              name: "Puppeteer",                 company: "Automation",    icon: "⚡" },
  { match: /playwright/i,             name: "Playwright",                company: "Automation",    icon: "⚡" },
  { match: /selenium/i,               name: "Selenium",                  company: "Automation",    icon: "⚡" },
  { match: /phantomjs/i,              name: "PhantomJS",                 company: "Automation",    icon: "⚡" },
];

function getBotDisplayName(rawUA) {
  if (!rawUA) return { name: "Unknown Bot", company: "Unknown", icon: "🤖", raw: rawUA };
  for (const entry of BOT_DISPLAY_NAMES) {
    if (entry.match.test(rawUA)) {
      return { name: entry.name, company: entry.company, icon: entry.icon, raw: rawUA };
    }
  }
  // Fallback: use first meaningful token from UA string
  const firstToken = rawUA.split(/[\/\s]/)[0];
  return { name: firstToken || rawUA.substring(0, 40), company: "Unknown", icon: "🤖", raw: rawUA };
}

// ── HTML + TEMPLATE LITERAL ESCAPE HELPERS ───────────────────────────────────
// escHtml: Escapes HTML special characters to prevent XSS when injecting
// DB values (including attacker-controlled User-Agent strings) into HTML.
const escHtml = s => String(s || "")
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#39;");

// esc: Legacy alias — all callsites now go through escHtml which handles
// both HTML injection and template literal safety (< and $ are escaped).
const esc = escHtml;

// ══════════════════════════════════════════════════════════════════
// EXPORT DEFAULT — TOP-LEVEL TRY/CATCH PASSTHROUGH FALLBACK
// ══════════════════════════════════════════════════════════════════

// ============================================================
// DOCX REPORT GENERATOR — Worker compatible, no npm deps
// Pure JS ZIP (CRC32 STORE) + OOXML 2007 strict schema
// ============================================================
const _CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c;
  }
  return t;
})();

function _crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) crc = _CRC_TABLE[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function _buildZip(files) {
  const enc = s => new TextEncoder().encode(s);
  const parts = [], cd = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const nb = enc(name);
    const data = typeof content === 'string' ? enc(content) : content;
    const crc = _crc32(data);
    const sz = data.length;
    const lh = new Uint8Array(30 + nb.length);
    const lv = new DataView(lh.buffer);
    lv.setUint32(0,0x04034b50,true); lv.setUint16(4,20,true); lv.setUint16(6,0,true);
    lv.setUint16(8,0,true); lv.setUint16(10,0,true); lv.setUint16(12,0,true);
    lv.setUint32(14,crc,true); lv.setUint32(18,sz,true); lv.setUint32(22,sz,true);
    lv.setUint16(26,nb.length,true); lv.setUint16(28,0,true);
    lh.set(nb, 30);
    parts.push(lh, data);
    const ce = new Uint8Array(46 + nb.length);
    const cv = new DataView(ce.buffer);
    cv.setUint32(0,0x02014b50,true); cv.setUint16(4,20,true); cv.setUint16(6,20,true);
    cv.setUint16(8,0,true); cv.setUint16(10,0,true); cv.setUint16(12,0,true); cv.setUint16(14,0,true);
    cv.setUint32(16,crc,true); cv.setUint32(20,sz,true); cv.setUint32(24,sz,true);
    cv.setUint16(28,nb.length,true); cv.setUint16(30,0,true); cv.setUint16(32,0,true);
    cv.setUint16(34,0,true); cv.setUint16(36,0,true); cv.setUint32(38,0,true); cv.setUint32(42,offset,true);
    ce.set(nb, 46);
    cd.push(ce);
    offset += lh.length + data.length;
  }
  const cdbParts = cd;
  let cdLen = 0; cdbParts.forEach(c => cdLen += c.length);
  const eor = new Uint8Array(22);
  const ev = new DataView(eor.buffer);
  ev.setUint32(0,0x06054b50,true); ev.setUint16(4,0,true); ev.setUint16(6,0,true);
  ev.setUint16(8,cd.length,true); ev.setUint16(10,cd.length,true);
  ev.setUint32(12,cdLen,true); ev.setUint32(16,offset,true); ev.setUint16(20,0,true);
  const all = [...parts, ...cdbParts, eor];
  let total = 0; all.forEach(a => total += a.length);
  const out = new Uint8Array(total); let pos = 0;
  all.forEach(a => { out.set(a, pos); pos += a.length; });
  return out;
}

const _DNAVY='1E3A5F', _DGREEN='10B981', _DAMBER='F59E0B', _DMUTED='5A7FA8', _DWHITE='FFFFFF';
const _dEsc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const _dRun = (text, {bold=false,size=20,color=_DNAVY}={}) =>
  `<w:r><w:rPr>${bold?'<w:b/>':''}<w:color w:val="${color}"/><w:sz w:val="${size}"/><w:szCs w:val="${size}"/><w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:cs="Arial"/></w:rPr><w:t xml:space="preserve">${_dEsc(text)}</w:t></w:r>`;
const _dPara = (content, {align='',before=80,after=80,borderBottom='',borderTop='',indent=0}={}) => {
  const bdr = borderBottom?`<w:pBdr><w:bottom w:val="single" w:sz="4" w:space="4" w:color="${borderBottom}"/></w:pBdr>`:borderTop?`<w:pBdr><w:top w:val="single" w:sz="4" w:space="4" w:color="${borderTop}"/></w:pBdr>`:'';
  const jc = align?`<w:jc w:val="${align}"/>`:'';
  const ind = indent?`<w:ind w:left="${indent}" w:hanging="240"/>`:'';
  return `<w:p><w:pPr>${bdr}<w:spacing w:before="${before}" w:after="${after}"/>${ind}${jc}</w:pPr>${content}</w:p>`;
};
const _dTcPr = (w, fill, padH=160, padV=80) =>
  `<w:tcPr><w:tcW w:w="${w}" w:type="dxa"/><w:shd w:val="clear" w:fill="${fill}"/><w:tcMar><w:top w:w="${padV}" w:type="dxa"/><w:start w:w="${padH}" w:type="dxa"/><w:bottom w:w="${padV}" w:type="dxa"/><w:end w:w="${padH}" w:type="dxa"/></w:tcMar></w:tcPr>`;

function buildReportDocx(data) {
  const {publisher, auditId, period, integration, date, totalHits, estNetRevenue,
         stealthCount, trainingCount, topBots, reportText} = data;

  const coverRow = (label, value, hl=false) => `<w:tr>
    <w:tc>${_dTcPr(2800,'F0F7FF')}<w:p><w:pPr><w:spacing w:before="0" w:after="0"/></w:pPr>${_dRun(label,{bold:true,size:18})}</w:p></w:tc>
    <w:tc>${_dTcPr(6560,hl?'E6FAF4':'FFFFFF')}<w:p><w:pPr><w:spacing w:before="0" w:after="0"/></w:pPr>${_dRun(value,{size:18,color:hl?'0D7F5F':_DNAVY,bold:hl})}</w:p></w:tc>
  </w:tr>`;

  const statCell = (value, label) => `<w:tc>${_dTcPr(2340,'E6FAF4',160,120)}
    <w:p><w:pPr><w:spacing w:before="0" w:after="60"/><w:jc w:val="center"/></w:pPr>${_dRun(value,{bold:true,size:40,color:_DGREEN})}</w:p>
    <w:p><w:pPr><w:spacing w:before="0" w:after="0"/><w:jc w:val="center"/></w:pPr>${_dRun(label,{size:16,color:_DMUTED})}</w:p>
  </w:tc>`;

  const bhc = (text,w,align='left') =>
    `<w:tc>${_dTcPr(w,_DNAVY,120,80)}<w:p><w:pPr><w:spacing w:before="0" w:after="0"/><w:jc w:val="${align}"/></w:pPr>${_dRun(text,{bold:true,size:17,color:_DWHITE})}</w:p></w:tc>`;

  const botRow = (bot, idx) => {
    const bg = idx%2===0?'FFFFFF':'F0F7FF';
    const tc = w => `<w:tcPr><w:tcW w:w="${w}" w:type="dxa"/><w:shd w:val="clear" w:fill="${bg}"/><w:tcMar><w:top w:w="80" w:type="dxa"/><w:start w:w="120" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:end w:w="120" w:type="dxa"/></w:tcMar></w:tcPr>`;
    const tc2 = bot.tier===1?_DGREEN:bot.tier===5?_DAMBER:_DMUTED;
    const rev = bot.tier===5?'$0.0000 ⚡':`$${bot.revenue}`;
    const rc = bot.tier===5?_DAMBER:_DGREEN;
    return `<w:tr>
      <w:tc>${tc(3800)}<w:p><w:pPr><w:spacing w:before="0" w:after="40"/></w:pPr>${_dRun(bot.name,{bold:true,size:18})}</w:p>
        <w:p><w:pPr><w:spacing w:before="0" w:after="0"/></w:pPr>${_dRun(bot.company,{size:15,color:_DMUTED})}</w:p></w:tc>
      <w:tc>${tc(1200)}<w:p><w:pPr><w:spacing w:before="0" w:after="0"/><w:jc w:val="center"/></w:pPr>${_dRun(`T${bot.tier}`,{bold:true,size:17,color:tc2})}</w:p></w:tc>
      <w:tc>${tc(1800)}<w:p><w:pPr><w:spacing w:before="0" w:after="0"/><w:jc w:val="right"/></w:pPr>${_dRun(Number(bot.hits).toLocaleString(),{size:18,color:'2D3748'})}</w:p></w:tc>
      <w:tc>${tc(2560)}<w:p><w:pPr><w:spacing w:before="0" w:after="0"/><w:jc w:val="right"/></w:pPr>${_dRun(rev,{size:18,color:rc})}</w:p></w:tc>
    </w:tr>`;
  };

  const parseBody = text => text.split('\n').map(line => {
    const t = line.trim();
    if (!t) return '<w:p><w:pPr><w:spacing w:before="60" w:after="60"/></w:pPr></w:p>';
    if (/^[A-Z][A-Z\s\-—:]+$/.test(t) && t.length > 4)
      return _dPara(_dRun(t,{bold:true,size:24,color:_DNAVY}),{before:360,after:100,borderBottom:_DGREEN});
    if (t.startsWith('→')||t.startsWith('•')||/^\d+\./.test(t))
      return _dPara(_dRun('→  ',{bold:true,size:20,color:_DGREEN})+_dRun(t.replace(/^[→•\d.]\s*/,''),{size:20,color:'2D3748'}),{before:60,after:60,indent:480});
    return _dPara(_dRun(t,{size:20,color:'2D3748'}),{before:80,after:80});
  }).join('\n');

  const BORDERS_LIGHT = `<w:tblBorders><w:top w:val="single" w:sz="1" w:color="D5E8F0"/><w:start w:val="single" w:sz="1" w:color="D5E8F0"/><w:bottom w:val="single" w:sz="1" w:color="D5E8F0"/><w:end w:val="single" w:sz="1" w:color="D5E8F0"/><w:insideH w:val="single" w:sz="1" w:color="D5E8F0"/><w:insideV w:val="single" w:sz="1" w:color="D5E8F0"/></w:tblBorders>`;
  const BORDERS_GREEN = `<w:tblBorders><w:top w:val="single" w:sz="2" w:color="${_DGREEN}"/><w:start w:val="single" w:sz="2" w:color="${_DGREEN}"/><w:bottom w:val="single" w:sz="2" w:color="${_DGREEN}"/><w:end w:val="single" w:sz="2" w:color="${_DGREEN}"/><w:insideV w:val="single" w:sz="2" w:color="${_DGREEN}"/></w:tblBorders>`;

  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
${_dPara(_dRun('Bot',{bold:true,size:72,color:_DGREEN})+_dRun('Rev',{bold:true,size:72,color:_DMUTED}),{before:0,after:40})}
${_dPara(_dRun('Content Intelligence Audit Report',{bold:true,size:36,color:_DNAVY}),{before:0,after:320,borderBottom:_DGREEN})}
<w:tbl><w:tblPr><w:tblW w:w="9360" w:type="dxa"/>${BORDERS_LIGHT}</w:tblPr>
<w:tblGrid><w:gridCol w:w="2800"/><w:gridCol w:w="6560"/></w:tblGrid>
${coverRow('Publisher',publisher,true)}${coverRow('Audit ID',auditId)}${coverRow('Period',period)}${coverRow('Integration',integration)}${coverRow('Date',date)}
</w:tbl>
<w:p><w:pPr><w:spacing w:before="320" w:after="120"/></w:pPr></w:p>
<w:tbl><w:tblPr><w:tblW w:w="9360" w:type="dxa"/>${BORDERS_GREEN}</w:tblPr>
<w:tblGrid><w:gridCol w:w="2340"/><w:gridCol w:w="2340"/><w:gridCol w:w="2340"/><w:gridCol w:w="2340"/></w:tblGrid>
<w:tr>${statCell(Number(totalHits).toLocaleString(),'Total Bot Hits')}${statCell('$'+Number(estNetRevenue).toFixed(2),'Est. Net Revenue')}${statCell(Number(stealthCount).toLocaleString(),'Stealth Crawlers')}${statCell(Number(trainingCount).toLocaleString(),'Training Hits ⚡')}</w:tr>
</w:tbl>
${_dPara(_dRun('TOP BOT BREAKDOWN',{bold:true,size:24,color:_DNAVY}),{before:360,after:120,borderBottom:_DGREEN})}
<w:tbl><w:tblPr><w:tblW w:w="9360" w:type="dxa"/></w:tblPr>
<w:tblGrid><w:gridCol w:w="3800"/><w:gridCol w:w="1200"/><w:gridCol w:w="1800"/><w:gridCol w:w="2560"/></w:tblGrid>
<w:tr>${bhc('Bot / Company',3800,'left')}${bhc('Tier',1200,'center')}${bhc('Hits',1800,'right')}${bhc('Est. Net Revenue',2560,'right')}</w:tr>
${(topBots||[]).map((b,i)=>botRow(b,i)).join('')}
</w:tbl>
<w:p><w:pPr><w:spacing w:before="360" w:after="0"/></w:pPr></w:p>
${parseBody(reportText||'')}
${_dPara(_dRun('Confidential — Prepared by BotRev LLC  ·  botrev.com',{size:16,color:_DMUTED}),{before:480,after:0,borderTop:'D5E8F0'})}
<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1080" w:right="1260" w:bottom="1080" w:left="1260" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>
</w:body></w:document>`;

  return _buildZip({
    '[Content_Types].xml': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
    '_rels/.rels': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
    'word/_rels/document.xml.rels': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`,
    'word/document.xml': xml,
  });
}
// ── END DOCX GENERATOR ──────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      console.error('[BotRev Worker Error]', err?.message || err);

      // Quick bot check without full classification to decide fallback
      const ua    = request.headers.get('User-Agent') || '';
      const uaLow = ua.toLowerCase();
      const looksLikeBot = /bot|crawler|spider|gptbot|claudebot|ccbot|bytespider|anthropic-ai|google-extended|headless|puppeteer|selenium|scrapy|python-requests|curl|wget/i.test(uaLow);
      const looksLikeHuman = /mozilla/i.test(uaLow) && /applewebkit|gecko\/\d|trident/i.test(uaLow) && !looksLikeBot;

      if (looksLikeHuman) {
        // Human: pass through to origin silently — zero publisher impact
        try { return await fetch(request); } catch { /* origin also down */ }
      }

      // Bot or unknown: return 503
      return new Response('Service temporarily unavailable', {
        status: 503,
        headers: { 'Retry-After': '30' },
      });
    }
  }
};

// ══════════════════════════════════════════════════════════════════
// MAIN REQUEST HANDLER — extracted for clean try/catch wrapping
// ══════════════════════════════════════════════════════════════════

async function handleRequest(request, env, ctx) {
    const url = new URL(request.url);
    let path = url.pathname.toLowerCase();
    if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);

    // v27.2: ADMIN_PASSWORD is now required — no fallback to Morgan123.
    const ADMIN_PASSWORD = env.ADMIN_PASS;
    if (!ADMIN_PASSWORD && (path.startsWith('/admin') || path.startsWith('/api/admin'))) {
      return new Response(
        JSON.stringify({ ok: false, error: 'ADMIN_PASS secret not configured. Set it in Cloudflare Workers → Settings → Variables & Secrets.' }),
        { status: 503, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const SECRET_ADMIN_PATH = "/admin-portal-access";
    const ONBOARDING_PATH   = "/admin-onboard-client";
    const SURGE_ADMIN_PATH  = "/admin-surge";
    const MANAGEMENT_FEE    = 0.30;

    // CPM Recovery Tiers (value per single hit)
    const TIERS = {
      TIER1: 10.00 / 1000,   // T1 · Premium AI — TollBit CEO cited $10–$15 CPM (Business Standard, Mar 2026)
      TIER2:  2.00 / 1000,   // T2 · Headless — automation/scraping, lower marketplace demand
      TIER3:  0.00 / 1000,   // T3 · Verified Search (pass-through — protects publisher SEO)
      TIER4:  0.25 / 1000,   // T4 · General/Utility — minimal marketplace value
      TIER5:  0.00 / 1000,   // T5 · Training ($0 CPM across all marketplaces — industry gap, not TollBit-specific. Direct licensing is the only path to revenue for training bots.)
    };

    const DAMPER_WINDOW_MINUTES  = 10;
    const DAMPER_SURGE_MULTIPLIER = 4;

    // ============================================================
    // 2. TIER DETECTION ENGINE (Bot Sniffer) — closure-based, TIERS in scope
    // ============================================================
    function classifyBot(ua = "") {
      const l = ua.toLowerCase();

      // ── T5 · TRAINING BOTS (check FIRST — must never land in T1-T4) ──
      for (const token of TRAINING_BOT_TOKENS) {
        if (l.includes(token)) {
          return { tier: 5, cpm: TIERS.TIER5, label: "Training", isTraining: true };
        }
      }

      // ── T1 · PREMIUM AI INFERENCE / RETRIEVAL ──
      if (/claudebot|claude-web|chatgpt-user|oai-searchbot|applebot(?!-extended)|perplexitybot|perplexity-user|you\.com|phind|groq|amazonbot|timpibot|gemini-deep-research|google-notebooklm|googleagent-mariner|cloudflare-autorag|meta-externalagent/.test(l)) {
        return { tier: 1, cpm: TIERS.TIER1, label: "Premium AI", isTraining: false };
      }
      if (/openai|imagesift/.test(l)) {
        return { tier: 1, cpm: TIERS.TIER1, label: "Premium AI", isTraining: false };
      }

      // ── T2 · HEADLESS / AUTOMATION ──
      if (/headlesschrome|puppeteer|selenium|playwright|phantomjs|webdriver|chrome-lighthouse|scrapy|python-requests|axios|go-http-client/.test(l) ||
          /headless/.test(l)) {
        return { tier: 2, cpm: TIERS.TIER2, label: "Headless Scraper", isTraining: false };
      }

      // ── T3 · VERIFIED SEARCH ENGINES ──
      if (/googlebot|bingbot|duckduckbot|yahoo! slurp|baiduspider|yandexbot|sogou|exabot/.test(l)) {
        return { tier: 3, cpm: TIERS.TIER3, label: "Verified Search", isTraining: false };
      }

      // ── T4 · GENERAL / UTILITY BOTS ──
      const isFullBrowserUA = /^mozilla\/5\.0/.test(l) && /applewebkit|gecko\/\d|trident/.test(l);
      if (!isFullBrowserUA && /bot|crawler|spider|scraper|monitor|fetch|scan|archive|feed|rss|wget|curl|java|ruby|php/.test(l)) {
        return { tier: 4, cpm: TIERS.TIER4, label: "Utility Bot", isTraining: false };
      }

      return null; // human traffic
    }

    function isStealthCrawler(request) {
      const ua     = request.headers.get("User-Agent") || "";
      const accept = request.headers.get("Accept") || "";
      const lang   = request.headers.get("Accept-Language") || "";
      const enc    = request.headers.get("Accept-Encoding") || "";
      const secFetch = request.headers.get("Sec-Fetch-Site") || "";
      const secMode  = request.headers.get("Sec-Fetch-Mode") || "";

      const looksLikeDesktopBrowser = /mozilla\/5\.0.*(windows|macintosh|linux).*(applewebkit|gecko)/i.test(ua);
      if (!looksLikeDesktopBrowser) return false;

      const hasHumanAccept    = /text\/html/.test(accept);
      const hasHumanLang      = lang.length > 0;
      const hasHumanEnc       = /gzip/.test(enc);
      const hasSecFetchHeader = secFetch.length > 0 || secMode.length > 0;

      const humanScore = [hasHumanAccept, hasHumanLang, hasHumanEnc, hasSecFetchHeader].filter(Boolean).length;

      return humanScore < 2;
    }

    // ============================================================
    // 3. LOGARITHMIC DAMPER ALGORITHM
    // ============================================================
    async function getDampedCPM(auditId, baseCPM) {
      try {
        const windowStart = new Date(Date.now() - DAMPER_WINDOW_MINUTES * 60 * 1000).toISOString();
        const result = await env.DB
          .prepare("SELECT COUNT(*) as surge FROM bot_logs WHERE audit_id = ? AND timestamp > ? AND is_training = 0")
          .bind(auditId, windowStart)
          .first();
        const surge = result?.surge || 0;

        const anchor        = 100;
        const rawMultiplier = 1 + Math.log((surge / anchor) + 1);
        const multiplier    = Math.min(rawMultiplier, DAMPER_SURGE_MULTIPLIER);

        return baseCPM * multiplier;
      } catch {
        return baseCPM;
      }
    }

    // ============================================================
    // UTILITY HELPERS (from dashboard)
    // ============================================================
    async function getDomainName(aid) {
      const res = await env.DB.prepare("SELECT domain_name FROM publisher_entities WHERE audit_id = ? LIMIT 1").bind(aid).first();
      return res ? res.domain_name : aid;
    }

    async function getMarketplaceDetails(aid, m, range = "all") {
      try {
        const entity = await env.DB.prepare(
          "SELECT api_key, domain_name FROM publisher_marketplaces JOIN publisher_entities ON publisher_marketplaces.audit_id = publisher_entities.audit_id WHERE publisher_marketplaces.audit_id = ? AND marketplace_name = ? LIMIT 1"
        ).bind(aid, m).first();

        if (!entity?.api_key || entity.api_key.length < 5 || entity.api_key === "DEMO") {
          return { status: "Offline", gross: 0, net: 0, breakdown: [], msg: "Missing Key" };
        }

        const days = (range === "7") ? 7 : (range === "30") ? 30 : 90;
        const endpoints = {
          "TollBit":   `https://api.tollbit.com/v1/publisher/analytics?days=${days}`,
          "Dappier":   `https://api.dappier.com/v1/publisher/stats?period=${days}d`,
          "Microsoft": "https://api.bing.com/v1/publisher/revenue",
          "Amazon":    "https://api.amazon.com/v1/publisher/ad-intel",
        };

        const res = await fetch(endpoints[m], {
          headers: {
            "Authorization": `Bearer ${entity.api_key}`,
            "x-api-key":     entity.api_key,
            "Content-Type":  "application/json",
          },
          signal: AbortSignal.timeout(4000),
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data  = await res.json();
        const gross = Number(data.total_earnings || data.revenue || data.earnings || data.amount || 0);

        return { status: "Active", gross, net: gross * (1 - MANAGEMENT_FEE), breakdown: data.bots || data.breakdown || [] };
      } catch (e) {
        return { status: "Sync Error", gross: 0, net: 0, breakdown: [], msg: e.message };
      }
    }

    // ============================================================
    // SHARED BRAND CSS
    // ============================================================
    const brandHead = `
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:          #F0F4F8;
    --surface:     #FFFFFF;
    --surface-2:   #EBF2FF;
    --border:      #E2EAF4;
    --border-lit:  #C5D5E8;
    --navy:        #1E3A5F;
    --navy-mid:    #2D5A8E;
    --green:       #10B981;
    --green-dim:   #059669;
    --green-tint:  #ECFDF5;
    --amber:       #f59e0b;
    --red:         #ef4444;
    --blue:        #2D5A8E;
    --text:        #1E3A5F;
    --muted:       #5A7FA8;
    --font-display: 'Syne', sans-serif;
    --font-mono:    'DM Mono', monospace;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: var(--font-display); background: var(--bg); color: var(--text); min-height: 100vh; }
  body::before {
    content: ''; position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background: radial-gradient(ellipse 80% 50% at 10% 0%, rgba(16,185,129,0.05) 0%, transparent 60%),
                radial-gradient(ellipse 60% 40% at 90% 100%, rgba(45,90,142,0.06) 0%, transparent 60%);
  }
  .wrap { position: relative; z-index: 1; max-width: 1280px; margin: auto; padding: 0 32px; }
  .top-bar { background: var(--navy); padding: 0 32px; position: sticky; top: 0; z-index: 100;
             box-shadow: 0 2px 12px rgba(30,58,95,0.15); }
  .logo { font-family: var(--font-display); font-weight: 800; font-size: 1.3rem;
          color: var(--green); letter-spacing: 2px; text-transform: uppercase; text-decoration: none; }
  .logo span { color: #A8C5E8; }
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: 12px; padding: 24px; margin-bottom: 16px;
          box-shadow: 0 1px 4px rgba(30,58,95,0.06); }
  .card-lit { border-color: var(--navy-mid); border-top: 3px solid var(--green); }
  .stat-val { font-family: var(--font-mono); font-size: 2.4rem; font-weight: 500;
              color: var(--navy); line-height: 1; }
  .stat-label { font-family: var(--font-mono); font-size: 0.6rem; letter-spacing: 2px;
                text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
  .btn { display: inline-flex; align-items: center; gap: 6px; padding: 10px 20px; border-radius: 8px;
         font-family: var(--font-display); font-weight: 700; font-size: 0.8rem; letter-spacing: 1px;
         text-transform: uppercase; cursor: pointer; border: none; text-decoration: none; transition: all 0.15s; }
  .btn-primary { background: var(--green); color: #fff; }
  .btn-primary:hover { background: var(--green-dim); }
  .btn-ghost { background: transparent; border: 1px solid var(--border-lit); color: var(--text); }
  .btn-ghost:hover { border-color: var(--green); color: var(--green); }
  .btn-navy { background: var(--navy); color: #fff; }
  .btn-navy:hover { background: var(--navy-mid); }
  .btn-sm { padding: 6px 14px; font-size: 0.7rem; }
  .input { width: 100%; padding: 11px 14px; background: var(--bg); border: 1px solid var(--border);
           border-radius: 8px; color: var(--text); font-family: var(--font-mono);
           font-size: 0.85rem; outline: none; transition: border-color 0.15s; }
  .input:focus { border-color: var(--green); box-shadow: 0 0 0 3px rgba(16,185,129,0.1); }
  table { width: 100%; border-collapse: collapse; }
  th { font-family: var(--font-mono); font-size: 0.6rem; letter-spacing: 2px; text-transform: uppercase;
       color: var(--muted); padding: 12px 8px; border-bottom: 2px solid var(--border); text-align: left; }
  td { padding: 14px 8px; border-bottom: 1px solid var(--border); font-size: 0.85rem; vertical-align: middle; }
  tr:hover td { background: var(--surface-2); }
  .badge { display: inline-block; font-family: var(--font-mono); font-size: 0.55rem; letter-spacing: 1px;
           font-weight: 500; padding: 3px 7px; border-radius: 4px; text-transform: uppercase; border: 1px solid; }
  .badge-t1 { border-color: var(--green); color: var(--green); background: var(--green-tint); }
  .badge-t2 { border-color: var(--blue); color: var(--blue); background: #EBF2FF; }
  .badge-t3 { border-color: var(--amber); color: var(--amber); background: #FFFBEB; }
  .badge-t4 { border-color: var(--muted); color: var(--muted); background: var(--bg); }
  .badge-t5 { border-color: #d97706; color: #d97706; background: #fffbeb; }
  .badge-active { border-color: var(--green); color: var(--green); background: var(--green-tint); }
  .badge-error  { border-color: var(--red); color: var(--red); background: #FEF2F2; }
  .badge-warn   { border-color: var(--amber); color: var(--amber); background: #FFFBEB; }
  .tab-nav { display: flex; gap: 4px; margin-bottom: 32px; background: var(--surface);
             border: 1px solid var(--border); border-radius: 10px; padding: 4px; width: fit-content;
             box-shadow: 0 1px 3px rgba(30,58,95,0.06); }
  .tab-link { padding: 8px 20px; border-radius: 7px; font-family: var(--font-mono); font-size: 0.7rem;
              letter-spacing: 1px; text-transform: uppercase; text-decoration: none; color: var(--muted);
              font-weight: 500; transition: all 0.15s; }
  .tab-link.active { background: var(--navy); color: #fff; font-weight: 700; }
  .tab-link:not(.active):hover { color: var(--text); background: var(--bg); }
  .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
  .dot-green { background: var(--green); animation: pulse 2s infinite; }
  .dot-amber { background: var(--amber); }
  .dot-gray  { background: var(--muted); }
  @keyframes pulse { 0%,100% { opacity:1; box-shadow: 0 0 0 0 rgba(16,185,129,0.4); } 50% { opacity:.7; box-shadow: 0 0 0 6px rgba(16,185,129,0); } }
  code { font-family: var(--font-mono); font-size: 0.78rem; background: var(--green-tint);
         color: var(--green-dim); padding: 2px 7px; border-radius: 4px; }
  .grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
  .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
  @media(max-width: 768px) { .grid-3,.grid-4 { grid-template-columns: 1fr 1fr; } .grid-2 { grid-template-columns: 1fr; } }
  .sniffer-live { position: relative; overflow: hidden; }
  .sniffer-live::after { content: ''; position: absolute; top: 0; left: -100%; width: 60%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(16,185,129,0.06), transparent);
    animation: sweep 3s linear infinite; }
  @keyframes sweep { to { left: 150%; } }
  .tier-bar { height: 4px; border-radius: 2px; background: var(--border); overflow: hidden; margin-top: 6px; }
  .tier-fill { height: 100%; border-radius: 2px; transition: width 0.6s ease; }
  .top-bar-inner { display: flex; justify-content: space-between; align-items: center;
                   max-width: 1280px; margin: auto; height: 56px; }
  .top-bar-right { display: flex; gap: 8px; align-items: center; }
  .top-bar .btn-ghost { border-color: rgba(168,197,232,0.3); color: #A8C5E8; }
  .top-bar .btn-ghost:hover { border-color: var(--green); color: var(--green); }
  .top-bar .stat-label { color: #A8C5E8; }
  /* v27: Training gap callout */
  .training-gap-callout {
    background: #fffbeb; border: 1px solid #fcd34d; border-left: 4px solid #f59e0b;
    border-radius: 10px; padding: 16px 20px; margin-bottom: 20px;
  }
  .training-gap-callout h4 { color: #92400e; font-size: 0.88rem; font-weight: 700; margin-bottom: 4px; }
  .training-gap-callout p  { color: #b45309; font-size: 0.78rem; line-height: 1.6; }
</style>`;

    // ============================================================
    // 0. PUBLISHER DOMAIN INTERCEPT
    // ============================================================
    const rawHostname = url.hostname;
    const hostname    = rawHostname.replace(/^www\./, '');
    const isBotRevDomain = hostname === 'dash.botrev.com';

    if (!isBotRevDomain) {
      let publisherAuditId = null;
      let integrationType  = "A";
      let publisherOrigin  = null;
      let tollbitKey       = null;
      let publisherMarket  = null;

      try {
        const pub = await env.DB
          .prepare(`
            SELECT audit_id, integration_type, origin_server, marketplace, floor_cpm, beta
            FROM publisher_entities
            WHERE LOWER(domain_name) = LOWER(?)
            LIMIT 1
          `)
          .bind(hostname)
          .first();
        publisherAuditId = pub?.audit_id        || null;
        integrationType  = pub?.integration_type || "A";
        publisherOrigin  = pub?.origin_server    || null;
        tollbitKey       = env.TOLLBIT_KEY        || null;
        publisherMarket  = pub?.marketplace       || 'tollbit';
      } catch (e) {
        // DB lookup failed — pass traffic through, don't log
      }

      if (publisherAuditId) {
        const ua           = request.headers.get("User-Agent") || "Unknown";
        const ref          = request.headers.get("Referer") || "";
        const reqPath      = url.pathname + (url.search || "");
        const botClass     = classifyBot(ua);
        const stealth      = isStealthCrawler(request);
        const isCleanHuman = /mozilla|chrome|safari|firefox/i.test(ua) && !stealth && !botClass;

        if (!isCleanHuman) {
          const effectiveTier  = botClass ? botClass.tier : 4;
          const effectiveCPM   = botClass ? botClass.cpm  : TIERS.TIER4;
          const isStealthFlag  = (stealth && !botClass) ? 1 : 0;
          const isTrainingFlag = (botClass?.isTraining) ? 1 : 0;

          const dampedCPM = isTrainingFlag ? 0 : await getDampedCPM(publisherAuditId, effectiveCPM).catch(() => effectiveCPM);
          ctx.waitUntil((async () => {
            try {
              const prevEntry = await env.DB.prepare(
                `SELECT entry_hash FROM bot_logs WHERE audit_id = ? ORDER BY id DESC LIMIT 1`
              ).bind(publisherAuditId).first().catch(() => null);
              const prevHash = prevEntry?.entry_hash || null;
              const entryData = `${publisherAuditId}:${effectiveTier}:${ua}:${reqPath}:${new Date().toISOString()}`;
              const entryHash = await computeEntryHash(prevHash, entryData).catch(() => null);

              await env.DB.prepare(
                "INSERT INTO bot_logs (audit_id, bot_name, tier, cpm_value, is_bot, is_stealth, is_training, referer, path, domain, entry_hash) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)"
              ).bind(publisherAuditId, ua, effectiveTier, dampedCPM, isStealthFlag, isTrainingFlag, ref, reqPath, rawHostname, entryHash).run();
            } catch { /* log failure must never break request flow */ }
          })());

          // TollBit log sink (non-blocking, batched)
          if (tollbitKey && !isTrainingFlag) {
            const responseStatus = (botClass?.tier === 1) ? 302 : (botClass?.tier === 2 ? 403 : 200);
            const tbLog = buildTollBitLog(request, responseStatus, effectiveTier, isStealthFlag);
            enqueueTollBitLog(tbLog, tollbitKey, ctx);
          }

          // Surge Intelligence (non-blocking)
          if (publisherAuditId && !isTrainingFlag) {
            ctx.waitUntil(evaluateSurge(publisherAuditId, hostname, reqPath, env, ctx));
          }

          // ── ROUTING DECISION ──────────────────────────────────────
          if (botClass && tollbitKey && publisherMarket) {
            if (botClass.tier === 3) {
              // T3 · Search — pass through, critical for SEO
            } else if (botClass.tier === 5) {
              // T5 · Training — pass through, TollBit gap
            } else {
              // T1, T2, T4 · Monetizable — redirect to marketplace
              const dest = `https://${publisherMarket}.${hostname}${reqPath}`;
              return Response.redirect(dest, 302);
            }
          }
        }
      }

      // Pass through to publisher origin
      try {
        let fetchURL     = request.url;
        let fetchHeaders = new Headers(request.headers);

        if (integrationType === "A" && publisherOrigin) {
          const originURL    = new URL(request.url);
          originURL.hostname = hostname;
          originURL.protocol = "https:";
          fetchURL           = originURL.toString();

          fetchHeaders.set("X-Forwarded-Host",  rawHostname);
          fetchHeaders.set("X-Forwarded-Proto", "https");

          const realUA = fetchHeaders.get("User-Agent") || "";
          if (realUA) fetchHeaders.set("X-BotRev-Original-UA", realUA);
          fetchHeaders.set("User-Agent", "Mozilla/5.0 (compatible; BotRev-Proxy/1.0)");
        }

        const originRequest = new Request(fetchURL, {
          method:   request.method,
          headers:  fetchHeaders,
          body:     request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
          redirect: "manual",
        });

        let originResponse = await fetch(originRequest, {
          cf: integrationType === "A" && publisherOrigin ? {
            resolveOverride: publisherOrigin,
          } : {}
        });

        if (originResponse.status >= 300 && originResponse.status < 400) {
          const location = originResponse.headers.get("Location") || "";
          if (location.includes(publisherOrigin)) {
            const rewritten  = location.replace(publisherOrigin, hostname);
            const newHeaders = new Headers(originResponse.headers);
            newHeaders.set("Location", rewritten);
            return new Response(originResponse.body, {
              status:  originResponse.status,
              headers: newHeaders,
            });
          }
        }

        return originResponse;
      } catch (e) {
        return new Response("BotRev: Origin unreachable — check origin_server config in Fleet Command (Type A integration)", { status: 502 });
      }
    }

    // ============================================================
    // DASHBOARD ROUTES — BotRev domain (dash.botrev.com)
    // ============================================================

    // ============================================================
    // 6. ADMIN FLEET COMMAND
    // ============================================================
    if (path.startsWith(SECRET_ADMIN_PATH)) {
      // v27.2: Rate limit admin routes
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const rateCheck = await checkAdminRateLimit(ip, path, env);
      if (!rateCheck.allowed) {
        return new Response('Too many requests — slow down.', {
          status: 429,
          headers: { 'Retry-After': String(rateCheck.retryAfter) }
        });
      }

      if (!await isAdminAuthenticated(request, env)) return new Response("Forbidden", { status: 403 });

      const { results } = await env.DB.prepare(`
        SELECT pe.*,
          (SELECT COUNT(*) FROM bot_logs WHERE audit_id = pe.audit_id AND is_bot = 1) as total_bot_hits,
          (SELECT COUNT(*) FROM bot_logs WHERE audit_id = pe.audit_id AND is_bot = 1 AND timestamp > datetime('now','-1 day')) as recent_bot_hits,
          (SELECT COUNT(*) FROM bot_logs WHERE audit_id = pe.audit_id AND is_training = 1) as training_hits
        FROM publisher_entities pe
      `).all();

      const markets  = ['TollBit', 'Dappier', 'Microsoft', 'Amazon'];
      const fullList = await Promise.all(results.map(async r => {
        const mktData = await Promise.all(markets.map(m => getMarketplaceDetails(r.audit_id, m)));
        return { ...r, total_mkt_gross: mktData.reduce((sum, mk) => sum + mk.gross, 0), mktStats: mktData };
      }));

      const fleetGross      = fullList.reduce((sum, r) => sum + r.total_mkt_gross, 0);
      const totalBots       = results.reduce((sum, r) => sum + (r.total_bot_hits    || 0), 0);
      const totalTraining   = results.reduce((sum, r) => sum + (r.training_hits     || 0), 0);
      const trainingGapEst  = totalTraining * (3.00 / 1000);

      const pendingSurgeRow = await env.DB.prepare(
        `SELECT COUNT(*) as cnt FROM surge_events WHERE status = 'pending' OR status IS NULL`
      ).first().catch(() => ({ cnt: 0 }));
      const pendingSurgeCount = pendingSurgeRow?.cnt || 0;

      return new Response(`<!DOCTYPE html><html><head>${brandHead}<title>Fleet Command — BotRev</title></head><body>
<div class="top-bar">
  <div class="top-bar-inner">
    <div>
      <a class="logo" href="#">Bot<span>Rev</span></a>
      <div style="font-family:var(--font-mono); font-size:0.6rem; letter-spacing:3px; color:#A8C5E8; margin-top:2px; text-transform:uppercase;">Fleet Command · Admin</div>
    </div>
    <div class="top-bar-right">
      <button onclick="exportSelectedCSV()" class="btn btn-ghost btn-sm">↓ Export CSV</button>
      <button onclick="generateFleetReport()" id="fleet-report-btn" class="btn btn-ghost btn-sm" style="color:var(--green); border-color:rgba(16,185,129,0.4);">⚡ Fleet Report</button>
      <a href="${SURGE_ADMIN_PATH}" class="btn btn-ghost btn-sm" style="color:#f59e0b; border-color:rgba(245,158,11,0.4); position:relative;">
        ⚡ Surge Intelligence
        ${pendingSurgeCount > 0 ? `<span style="position:absolute; top:-8px; right:-8px; background:#f59e0b; color:#0a1220; font-family:var(--font-mono); font-size:0.6rem; font-weight:700; padding:2px 6px; border-radius:10px; line-height:1.4;">${pendingSurgeCount}</span>` : ''}
      </a>
      <a href="${ONBOARDING_PATH}" class="btn btn-primary btn-sm">+ Onboard Publisher</a>
    </div>
  </div>
</div>
<div class="wrap" style="padding-top:32px; padding-bottom:80px;">

  <!-- Fleet Stats — v27: added T5 training gap cards -->
  <div class="grid-4" style="margin-bottom:32px;">
    <div class="card card-lit sniffer-live">
      <div class="stat-label">Fleet Gross Revenue</div>
      <div class="stat-val" style="color:var(--green);">$${fleetGross.toFixed(2)}</div>
      <div style="margin-top:8px; font-family:var(--font-mono); font-size:0.65rem; color:var(--muted);">30% management fee</div>
    </div>
    <div class="card">
      <div class="stat-label">Total Bot Hits</div>
      <div class="stat-val">${totalBots.toLocaleString()}</div>
    </div>
    <div class="card" style="border-top:3px solid #f59e0b;">
      <div class="stat-label" style="color:#b45309;">T5 Training Hits (Unmonetized)</div>
      <div class="stat-val" style="color:#d97706;">${totalTraining.toLocaleString()}</div>
      <div style="margin-top:8px; font-family:var(--font-mono); font-size:0.65rem; color:#b45309;">TollBit gap · Training Deals opportunity</div>
    </div>
    <div class="card" style="border-top:3px solid #f59e0b;">
      <div class="stat-label" style="color:#b45309;">Est. Training Revenue Gap</div>
      <div class="stat-val" style="color:#d97706;">~$${trainingGapEst.toFixed(2)}</div>
      <div style="margin-top:8px; font-family:var(--font-mono); font-size:0.65rem; color:#b45309;">At floor CPM · recoverable via direct licensing</div>
    </div>
  </div>

  ${totalTraining > 0 ? `
  <div class="training-gap-callout" style="margin-bottom:24px;">
    <h4>⚡ Training Revenue Gap — ${totalTraining.toLocaleString()} unmonetized training bot hits across fleet</h4>
    <p>These bots are collecting publisher content for LLM model training. These bots are not monetized through standard marketplace channels. BotRev Training Deals can recover this revenue through direct LLM licensing agreements with OpenAI, Anthropic, Google, Meta, and others.</p>
  </div>` : ''}

  <!-- Publisher Table -->
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
      <div style="font-family:var(--font-mono); font-size:0.7rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted);">Publisher Fleet</div>
      <input type="text" id="netSearch" onkeyup="filterTable()" placeholder="Search domain or network ID…" class="input" style="max-width:280px; padding:8px 12px; font-size:0.75rem;">
    </div>
    <table>
      <thead><tr>
        <th style="width:30px;"><input type="checkbox" id="masterCb" onclick="toggleAll(this)" style="accent-color:var(--green);"></th>
        <th>Property</th>
        <th>Sniffer</th>
        <th>T5 Training</th>
        <th>Marketplaces</th>
        <th>Gross Rev.</th>
        <th>Actions</th>
      </tr></thead>
      <tbody>
      ${fullList.map(r => {
        let snColor = "var(--muted)", snLabel = "PENDING", snPulse = false;
        if (r.total_bot_hits > 0) {
          if (r.recent_bot_hits > 0) { snColor = "var(--green)"; snLabel = "ACTIVE"; snPulse = true; }
          else { snColor = "var(--amber)"; snLabel = "STALE"; }
        }
        const trainingHits = r.training_hits || 0;
        return `
        <tr class="net-row">
          <td><input type="checkbox" class="row-cb" data-aid="${esc(r.audit_id)}" style="accent-color:var(--green);"></td>
          <td>
            <div style="font-weight:700;">${esc(r.domain_name)}</div>
            <div style="font-family:var(--font-mono); font-size:0.65rem; color:var(--muted);">${esc(r.pub_user_id)}</div>
            <div style="font-family:var(--font-mono); font-size:0.55rem; margin-top:4px; display:inline-block; padding:1px 7px; border-radius:8px; background:${r.integration_type==='B'?'rgba(245,158,11,0.1)':'rgba(0,229,160,0.07)'}; color:${r.integration_type==='B'?'#f59e0b':'var(--green)'};">${r.integration_type==='B'?'Snippet':'Standard'}</div>
          </td>
          <td>
            <div style="display:flex; align-items:center; gap:6px;">
              <span class="dot ${snPulse ? 'dot-green' : ''}" style="background:${snColor};"></span>
              <span style="font-family:var(--font-mono); font-size:0.6rem; color:${snColor}; letter-spacing:1px;">${snLabel}</span>
            </div>
          </td>
          <td>
            ${trainingHits > 0
              ? `<span style="font-family:var(--font-mono); font-size:0.75rem; color:#d97706; font-weight:600;">${trainingHits.toLocaleString()} ⚡</span>`
              : `<span style="font-family:var(--font-mono); font-size:0.7rem; color:var(--muted);">—</span>`}
          </td>
          <td><div style="display:flex; gap:4px;">${r.mktStats.map((m,i)=>`<span class="badge badge-${m.status==='Active'?'active':'error'}">P${i+1}</span>`).join('')}</div></td>
          <td><span style="font-family:var(--font-mono); font-weight:500; color:var(--green);">$${r.total_mkt_gross.toFixed(2)}</span></td>
          <td>
            <div style="display:flex; gap:6px; flex-wrap:wrap;">
              <button onclick="window.location.href='/dashboard?entity=${esc(r.pub_user_id)}&mode=admin'" class="btn btn-ghost btn-sm">Dash</button>
              <button onclick="openEditModal('${esc(r.audit_id)}')" class="btn btn-ghost btn-sm" style="color:var(--green); border-color:var(--green);">Edit</button>
              <button onclick="generateAuditReport('${esc(r.audit_id)}','${esc(r.domain_name)}',this)" class="btn btn-ghost btn-sm" style="color:var(--navy-mid); border-color:var(--navy-mid);">Report</button>
              <button onclick="var p=document.getElementById('snip-panel-${esc(r.audit_id)}');p.style.display=p.style.display==='none'?'block':'none'" class="btn btn-ghost btn-sm" style="font-size:0.65rem;">&lt;/&gt;</button>
              <button onclick="deletePublisher('${esc(r.audit_id)}','${esc(r.domain_name)}')" class="btn btn-sm" style="background:rgba(239,68,68,0.12); color:#F87171; border:1px solid rgba(239,68,68,0.3);">Delete</button>
            </div>
            <div id="snip-panel-${esc(r.audit_id)}" style="display:none; margin-top:8px; position:relative; min-width:320px;">
              <pre id="snip-code-${esc(r.audit_id)}" style="font-family:var(--font-mono); font-size:0.6rem; background:rgba(0,0,0,0.25); border:1px solid var(--border); border-radius:6px; padding:10px 50px 10px 12px; color:#a8c5e8; white-space:pre-wrap; word-break:break-all; line-height:1.6; margin:0;">&lt;script&gt;(function(){var u="https://dash.botrev.com/api/sniff?audit_id=${encodeURIComponent(esc(r.audit_id))}&amp;path="+encodeURIComponent(window.location.pathname);if(navigator.sendBeacon){navigator.sendBeacon(u)}else{fetch(u,{mode:"no-cors",keepalive:true})}})();&lt;/script&gt;</pre>
              <button onclick="navigator.clipboard.writeText(document.getElementById('snip-code-${esc(r.audit_id)}').innerText).then(function(){var b=document.getElementById('snip-copy-${esc(r.audit_id)}');b.textContent='✓';b.style.color='var(--green)';setTimeout(function(){b.textContent='Copy';b.style.color='';},2000)})" id="snip-copy-${esc(r.audit_id)}" style="position:absolute; top:6px; right:6px; font-family:var(--font-mono); font-size:0.58rem; padding:3px 8px; border-radius:4px; border:1px solid var(--border); background:rgba(255,255,255,0.05); color:var(--light-muted); cursor:pointer;">Copy</button>
            </div>
          </td>
        </tr>`;
      }).join('')}
      </tbody>
    </table>
  </div>
</div>

<script>
  const fullData = ${JSON.stringify(fullList).replace(/<\/script>/gi, '<\\/script>')};
  function toggleAll(m){ document.querySelectorAll('.row-cb').forEach(c => { if(c.closest('tr').style.display !== 'none') c.checked = m.checked; }); }
  function filterTable(){ var v = document.getElementById("netSearch").value.toUpperCase(); document.querySelectorAll(".net-row").forEach(r => { r.style.display = r.innerText.toUpperCase().includes(v) ? "" : "none"; }); }

  let _editAuditId = null;

  async function openEditModal(auditId) {
    _editAuditId = auditId;
    document.getElementById('edit-modal').style.display = 'flex';
    document.getElementById('edit-save-btn').textContent = 'Save Changes';
    document.getElementById('edit-save-btn').disabled = false;
    document.getElementById('edit-msg').style.display = 'none';
    ['edit-network-id','edit-audit-id','edit-domain','edit-email','edit-password','edit-integration','edit-origin'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
    document.getElementById('edit-loading').style.display = 'block';
    document.getElementById('edit-form-body').style.display = 'none';
    const res = await fetch("/api/admin/publisher-detail?audit_id="+encodeURIComponent(auditId), {credentials:'same-origin'});
    const data = await res.json();
    document.getElementById('edit-loading').style.display = 'none';
    document.getElementById('edit-form-body').style.display = 'block';
    if(!data.ok){ document.getElementById('edit-msg').textContent = 'Error loading publisher.'; document.getElementById('edit-msg').style.display='block'; return; }
    const p = data.publisher;
    document.getElementById('edit-network-id').value  = p.pub_user_id || '';
    document.getElementById('edit-audit-id').value    = p.audit_id || '';
    document.getElementById('edit-domain').value      = p.domain_name || '';
    document.getElementById('edit-email').value       = p.email || '';
    document.getElementById('edit-password').value    = p.password || '';
    document.getElementById('edit-integration').value = p.integration_type || 'A';
    document.getElementById('edit-origin').value      = p.origin_server || '';
    document.getElementById('edit-marketplace').value = p.marketplace || 'tollbit';
  }

  function closeEditModal(){ document.getElementById('edit-modal').style.display = 'none'; _editAuditId = null; }

  async function saveEdit(){
    const btn = document.getElementById('edit-save-btn');
    btn.textContent = 'Saving…'; btn.disabled = true;
    const payload = {
      original_audit_id: _editAuditId,
      pub_user_id:       document.getElementById('edit-network-id').value.trim().toLowerCase(),
      audit_id:          document.getElementById('edit-audit-id').value.trim(),
      domain_name:       document.getElementById('edit-domain').value.trim(),
      email:             document.getElementById('edit-email').value.trim(),
      password:          document.getElementById('edit-password').value.trim(),
      integration_type:  document.getElementById('edit-integration').value.trim(),
      origin_server:     document.getElementById('edit-origin').value.trim() || null,
      marketplace:       document.getElementById('edit-marketplace').value.trim() || 'tollbit',
    };
    const res  = await fetch("/api/admin/update-publisher", { method: "POST", credentials:'same-origin', headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const data = await res.json();
    const msg  = document.getElementById('edit-msg');
    if(data.ok){ msg.style.color='var(--green)'; msg.textContent='✓ Saved successfully. Reloading…'; msg.style.display='block'; setTimeout(()=>{ closeEditModal(); location.reload(); },1200); }
    else { msg.style.color='#F87171'; msg.textContent='Error: '+(data.error||'Unknown error'); msg.style.display='block'; btn.textContent='Save Changes'; btn.disabled=false; }
  }

  let _pendingDelete = null;
  function deletePublisher(auditId, domain){ _pendingDelete={auditId,domain}; document.getElementById('del-domain-name').textContent=domain; document.getElementById('del-confirm-input').value=''; document.getElementById('del-modal').style.display='flex'; document.getElementById('del-confirm-input').focus(); }
  function closeDeleteModal(){ document.getElementById('del-modal').style.display='none'; _pendingDelete=null; }
  async function confirmDelete(){
    const typed = document.getElementById('del-confirm-input').value.trim();
    if(typed !== 'DELETE'){ document.getElementById('del-error').style.display='block'; return; }
    const btn = document.getElementById('del-confirm-btn'); btn.textContent='Deleting…'; btn.disabled=true;
    const res = await fetch("/api/admin/delete-publisher?audit_id="+encodeURIComponent(_pendingDelete.auditId),{method:"POST",credentials:'same-origin'});
    const data = await res.json();
    if(data.ok){ closeDeleteModal(); location.reload(); }
    else { btn.textContent='Confirm Delete'; btn.disabled=false; document.getElementById('del-error').textContent='Error: '+(data.error||'Unknown error'); document.getElementById('del-error').style.display='block'; }
  }

  document.addEventListener('keydown', function(e){ if(e.key==='Escape'){ closeDeleteModal(); closeEditModal(); } });

  function exportSelectedCSV(){
    const ids = Array.from(document.querySelectorAll('.row-cb:checked')).map(cb=>cb.getAttribute('data-aid'));
    if(!ids.length) return alert("Select at least one property.");
    const data = fullData.filter(r => ids.includes(r.audit_id));
    let csv = "NetworkID,Domain,Sniffer,TrainingHits,TollBit,Dappier,GrossRevenue,MgmtFee,NetPayout\\n";
    data.forEach(r => {
      const fee = r.total_mkt_gross * 0.30;
      csv += [r.pub_user_id, r.domain_name, r.total_bot_hits > 0 ? 'ACTIVE' : 'OFFLINE',
              r.training_hits||0, ...r.mktStats.map(m=>m.status),
              r.total_mkt_gross.toFixed(2), fee.toFixed(2), (r.total_mkt_gross-fee).toFixed(2)].join(',') + "\\n";
    });
    const b=new Blob([csv],{type:"text/csv"}), u=URL.createObjectURL(b), a=document.createElement("a");
    a.href=u; a.download="BotRev_Fleet_"+new Date().toISOString().split('T')[0]+".csv"; a.click();
  }

  async function generateFleetReport(){
    const ids = Array.from(document.querySelectorAll('.row-cb:checked')).map(cb=>cb.getAttribute('data-aid'));
    if(!ids.length) return alert("Select at least one property.");
    const btn = document.getElementById('fleet-report-btn'); btn.textContent='Generating…'; btn.disabled=true;
    try {
      const res = await fetch('/api/generate-fleet-report?ids='+encodeURIComponent(ids.join(',')), {credentials:'same-origin'});
      if(res.ok){
        const blob = await res.blob();
        const blobUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href=blobUrl; a.download='BotRev_Fleet_Report_'+new Date().toISOString().split('T')[0]+'.docx'; a.click();
      } else {
        const d = await res.json().catch(()=>({}));
        alert('Error: '+(d.error||'Report generation failed'));
      }
    } catch(e){ alert('Network error: '+e.message); }
    finally { btn.textContent='⚡ Fleet Report'; btn.disabled=false; }
  }

  async function generateAuditReport(auditId, domain, btn){
    const orig = btn.textContent; btn.textContent='Generating…'; btn.disabled=true;
    try {
      const res = await fetch('/api/generate-report?audit_id='+encodeURIComponent(auditId)+'&range=all', {credentials:'same-origin'});
      if(res.ok){
        const blob = await res.blob();
        const blobUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href=blobUrl; a.download='BotRev_Audit_'+domain+'_'+new Date().toISOString().split('T')[0]+'.docx'; a.click();
      } else {
        const d = await res.json().catch(()=>({}));
        alert('Error: '+(d.error||'Report generation failed'));
      }
    } catch(e){ alert('Network error: '+e.message); }
    finally { btn.textContent=orig; btn.disabled=false; }
  }
</script>

<!-- EDIT PUBLISHER MODAL -->
<div id="edit-modal" style="display:none; position:fixed; inset:0; z-index:1000; background:rgba(10,20,35,0.88); backdrop-filter:blur(6px); justify-content:center; align-items:flex-start; padding:24px; overflow-y:auto;">
  <div style="background:var(--surface); border:1px solid var(--border); border-top:3px solid var(--green); border-radius:14px; padding:36px; width:100%; max-width:640px; margin:auto; box-shadow:0 32px 80px rgba(0,0,0,0.4);">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
      <div>
        <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:3px; text-transform:uppercase; color:var(--green); margin-bottom:6px;">Fleet Command</div>
        <h3 style="font-size:1.1rem; font-weight:700; color:var(--text);">Edit Publisher</h3>
      </div>
      <button onclick="closeEditModal()" style="background:none; border:none; font-size:1.4rem; color:var(--muted); cursor:pointer; line-height:1;">×</button>
    </div>
    <div id="edit-loading" style="text-align:center; padding:32px; font-family:var(--font-mono); font-size:0.75rem; color:var(--muted);">Loading publisher data…</div>
    <div id="edit-form-body" style="display:none;">
      <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin-bottom:14px; padding-bottom:8px; border-bottom:1px solid var(--border);">Publisher Info</div>
      <div class="grid-2" style="margin-bottom:14px;">
        <div><label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Network ID</label><input id="edit-network-id" class="input" placeholder="e.g. publisher01" autocomplete="off"></div>
        <div><label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Audit ID</label><input id="edit-audit-id" class="input" placeholder="e.g. Audit-001" autocomplete="off"></div>
      </div>
      <div style="margin-bottom:14px;"><label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Domain</label><input id="edit-domain" class="input" placeholder="e.g. techdigest.com" autocomplete="off"></div>
      <div class="grid-2" style="margin-bottom:14px;">
        <div><label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Email Contact</label><input id="edit-email" class="input" type="email" placeholder="publisher@domain.com" autocomplete="off"></div>
        <div><label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Access Key (Password)</label><input id="edit-password" class="input" type="text" placeholder="Access key" autocomplete="off"></div>
      </div>
      <div class="grid-2" style="margin-bottom:24px;">
        <div><label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Integration Type</label><select id="edit-integration" class="input" style="cursor:pointer;"><option value="A">A — Standard (CNAME Proxy)</option><option value="B">B — Snippet (JS Tag)</option></select></div>
        <div><label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Origin Server</label><input id="edit-origin" class="input" placeholder="e.g. 184.94.213.18 (Standard only)" autocomplete="off"></div>
      </div>
      <div style="margin-bottom:24px;">
        <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Active Marketplace</label>
        <select id="edit-marketplace" class="input" style="cursor:pointer;"><option value="tollbit">Partner A (TollBit)</option><option value="dappier">Partner B (Dappier)</option><option value="none">None (pass-through)</option></select>
        <div style="font-family:var(--font-mono); font-size:0.6rem; color:var(--muted); margin-top:6px;">Sets the active monetization partner. Change takes effect on next bot request — no deploy needed.</div>
      </div>
      <div id="edit-msg" style="display:none; font-family:var(--font-mono); font-size:0.75rem; margin-bottom:14px; padding:10px 14px; border-radius:6px; background:var(--bg);"></div>
      <div style="display:flex; gap:10px;">
        <button onclick="closeEditModal()" style="flex:1; padding:11px; background:var(--bg); color:var(--muted); border:1px solid var(--border); border-radius:8px; cursor:pointer; font-weight:600; font-size:0.88rem;">Cancel</button>
        <button id="edit-save-btn" onclick="saveEdit()" style="flex:2; padding:11px; background:var(--green); color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:700; font-size:0.88rem;">Save Changes</button>
      </div>
    </div>
  </div>
</div>

<!-- DELETE CONFIRMATION MODAL -->
<div id="del-modal" style="display:none; position:fixed; inset:0; z-index:1001; background:rgba(10,20,35,0.85); backdrop-filter:blur(6px); justify-content:center; align-items:center; padding:24px;">
  <div style="background:#0d1f33; border:1px solid rgba(239,68,68,0.3); border-top:3px solid #EF4444; border-radius:14px; padding:36px; width:100%; max-width:420px; box-shadow:0 32px 80px rgba(0,0,0,0.5);">
    <div style="font-family:'DM Mono',monospace; font-size:0.58rem; letter-spacing:3px; text-transform:uppercase; color:#F87171; margin-bottom:10px;">⚠ Permanent Action</div>
    <h3 style="font-size:1.1rem; font-weight:700; color:#fff; margin-bottom:8px;">Delete Publisher</h3>
    <p style="font-size:0.87rem; color:#A8C5E8; line-height:1.6; margin-bottom:6px;">You are about to permanently delete:</p>
    <div id="del-domain-name" style="font-family:'DM Mono',monospace; font-size:1rem; font-weight:500; color:#F87171; margin-bottom:16px; padding:10px 14px; background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.2); border-radius:8px;"></div>
    <p style="font-size:0.83rem; color:#A8C5E8; line-height:1.7; margin-bottom:20px;">This will erase the publisher account, all bot logs, and all marketplace keys. <strong style="color:#fff;">This cannot be undone.</strong></p>
    <label style="font-family:'DM Mono',monospace; font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:#A8C5E8; display:block; margin-bottom:8px;">Type DELETE to confirm</label>
    <input id="del-confirm-input" type="text" placeholder="DELETE" autocomplete="off" style="width:100%; padding:11px 14px; background:#0a1622; border:1px solid rgba(239,68,68,0.3); border-radius:8px; color:#fff; font-family:'DM Mono',monospace; font-size:0.95rem; outline:none; margin-bottom:8px; letter-spacing:2px;" oninput="document.getElementById('del-error').style.display='none'" onkeydown="if(event.key==='Enter') confirmDelete()">
    <div id="del-error" style="display:none; font-size:0.78rem; color:#F87171; margin-bottom:12px;">You must type DELETE exactly to proceed.</div>
    <div style="display:flex; gap:10px; margin-top:16px;">
      <button onclick="closeDeleteModal()" style="flex:1; padding:11px; background:rgba(168,197,232,0.08); color:#A8C5E8; border:1px solid rgba(168,197,232,0.2); border-radius:8px; cursor:pointer; font-weight:600; font-size:0.88rem;">Cancel</button>
      <button id="del-confirm-btn" onclick="confirmDelete()" style="flex:1; padding:11px; background:#EF4444; color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:700; font-size:0.88rem;">Confirm Delete</button>
    </div>
  </div>
</div>

</body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // 6b. SURGE INTELLIGENCE ADMIN — /admin-surge
    // ============================================================
    if (path === SURGE_ADMIN_PATH) {
      if (!await isAdminAuthenticated(request, env)) return new Response("Forbidden", { status: 403 });

      const { results: pubs } = await env.DB.prepare(`
        SELECT audit_id, domain_name, floor_cpm, beta,
          (SELECT COUNT(*) FROM bot_logs WHERE audit_id = pe.audit_id AND timestamp > datetime('now','-10 minutes') AND is_training = 0) as v10,
          (SELECT COUNT(*) FROM bot_logs WHERE audit_id = pe.audit_id AND timestamp > datetime('now','-7 days') AND is_training = 0) as hits7d,
          (SELECT COUNT(*) FROM surge_events WHERE audit_id = pe.audit_id AND detected_at > datetime('now','-24 hours')) as surges24h
        FROM publisher_entities pe
      `).all();

      const { results: recentSurges } = await env.DB.prepare(`
        SELECT se.*, pe.domain_name
        FROM surge_events se
        JOIN publisher_entities pe ON pe.audit_id = se.audit_id
        ORDER BY se.detected_at DESC LIMIT 50
      `).all();

      const pendingCount = recentSurges.filter(s => s.status === 'pending' || !s.status).length;

      return new Response(`<!DOCTYPE html><html><head>${brandHead}<title>Surge Intelligence — BotRev</title></head><body>
<div class="top-bar">
  <div class="top-bar-inner">
    <div>
      <a class="logo" href="#">Bot<span>Rev</span></a>
      <div style="font-family:var(--font-mono); font-size:0.6rem; letter-spacing:3px; color:#f59e0b; margin-top:2px; text-transform:uppercase;">⚡ Surge Intelligence · Phase 2 — One-Click Approval</div>
    </div>
    <div class="top-bar-right">
      <a href="${SECRET_ADMIN_PATH}" class="btn btn-ghost btn-sm">← Fleet Command</a>
    </div>
  </div>
</div>
<div class="wrap" style="padding-top:32px; padding-bottom:80px;">
  <div class="card" style="border-top:3px solid #f59e0b; margin-bottom:28px;">
    <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:#f59e0b; margin-bottom:10px;">Pricing Formula</div>
    <div style="font-family:var(--font-mono); font-size:1rem; color:var(--text); margin-bottom:8px;">Pt = Pfloor × (1 + β × log₁₀(1 + V₁₀/Vbase) × γ)</div>
    <div style="font-size:0.78rem; color:var(--muted); line-height:1.8;">
      <span style="color:var(--text);">Pt</span> = recommended CPM &nbsp;·&nbsp;
      <span style="color:var(--text);">Pfloor</span> = floor CPM per publisher &nbsp;·&nbsp;
      <span style="color:var(--text);">β</span> = price sensitivity &nbsp;·&nbsp;
      <span style="color:var(--text);">V₁₀</span> = monetizable hits last 10 min (T1-T4 only, T5 excluded) &nbsp;·&nbsp;
      <span style="color:var(--text);">Vbase</span> = 7-day rolling avg &nbsp;·&nbsp;
      <span style="color:var(--text);">γ</span> = content freshness (URL year: 1.2 / 1.0 / 0.8)
    </div>
  </div>

  <div class="card" style="border-top:3px solid #f59e0b; margin-bottom:28px;">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
      <div>
        <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:#f59e0b; margin-bottom:4px;">Phase 2 — Pending Actions</div>
        <div style="font-size:0.85rem; color:var(--muted);">Surge events awaiting one-click approval or dismissal.</div>
      </div>
      <div style="text-align:center; background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.3); border-radius:10px; padding:12px 24px; flex-shrink:0; margin-left:20px;">
        <div style="font-family:var(--font-mono); font-size:2rem; font-weight:500; color:#f59e0b; line-height:1;">${pendingCount}</div>
        <div style="font-family:var(--font-mono); font-size:0.55rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); margin-top:4px;">Pending</div>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:28px;">
    <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid var(--border);">Publisher Formula Variables</div>
    <table>
      <thead><tr><th>Publisher</th><th>Floor CPM (Pfloor)</th><th>Beta (β)</th><th>V₁₀ (now)</th><th>Surge alerts (24h)</th><th>Est. Pt now</th><th></th></tr></thead>
      <tbody>
      ${pubs.map(p => {
        const pfloor = p.floor_cpm || 3.0;
        const beta   = p.beta || 1.5;
        const v10    = p.v10 || 0;
        const vbase  = p.hits7d > 0 ? (p.hits7d / (7 * 144)) : 10;
        const vrat   = vbase > 0 ? v10 / vbase : 0;
        const pt     = pfloor * (1 + beta * Math.log10(1 + vrat) * 1.0);
        const uplift = ((pt - pfloor) / pfloor * 100).toFixed(0);
        const hasAlert = pt > pfloor && v10 > 0;
        return `
        <tr>
          <td><div style="font-weight:700;">${p.domain_name}</div><div style="font-family:var(--font-mono); font-size:0.6rem; color:var(--muted);">${p.audit_id}</div></td>
          <td><input id="pfloor-${p.audit_id}" type="number" value="${pfloor.toFixed(2)}" step="0.5" min="0.5" class="input" style="width:90px; padding:6px 10px;"></td>
          <td><input id="beta-${p.audit_id}" type="number" value="${beta.toFixed(1)}" step="0.1" min="0.1" max="5" class="input" style="width:80px; padding:6px 10px;"></td>
          <td><span style="font-family:var(--font-mono); font-size:0.8rem; color:${v10 > 0 ? 'var(--green)' : 'var(--muted)'};">${v10}</span></td>
          <td><span style="font-family:var(--font-mono); font-size:0.8rem; color:${(p.surges24h||0) > 0 ? '#f59e0b' : 'var(--muted)'};">${p.surges24h || 0}</span></td>
          <td>
            <span style="font-family:var(--font-mono); font-size:0.8rem; color:${hasAlert ? '#f59e0b' : 'var(--green)'};">$${pt.toFixed(2)}</span>
            ${hasAlert ? `<span style="font-size:0.6rem; color:#f59e0b; margin-left:4px;">+${uplift}%</span>` : ''}
          </td>
          <td><button onclick="saveFormula('${p.audit_id}')" class="btn btn-ghost btn-sm" style="color:var(--green); border-color:var(--green);">Save</button></td>
        </tr>`;
      }).join('')}
      </tbody>
    </table>
  </div>

  <div class="card" style="margin-bottom:28px;">
    <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid var(--border);">Live Formula Visualizer</div>
    <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:20px;">
      <div><label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Floor CPM ($)</label><input type="range" id="viz-pfloor" min="0.5" max="20" step="0.5" value="3" oninput="updateViz()" style="width:100%;"><div style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text); margin-top:4px;">$<span id="viz-pfloor-out">3.00</span></div></div>
      <div><label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Beta (β)</label><input type="range" id="viz-beta" min="0.5" max="4" step="0.1" value="1.5" oninput="updateViz()" style="width:100%;"><div style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text); margin-top:4px;"><span id="viz-beta-out">1.5</span></div></div>
      <div><label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Gamma (γ)</label><select id="viz-gamma" oninput="updateViz()" class="input" style="padding:6px 10px; font-size:0.8rem;"><option value="1.2">Current year (1.2)</option><option value="1.0" selected>Last year / no date (1.0)</option><option value="0.8">2+ years ago (0.8)</option></select></div>
    </div>
    <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:20px;">
      <div class="card" style="text-align:center; padding:14px;"><div style="font-family:var(--font-mono); font-size:0.55rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); margin-bottom:6px;">At 1× traffic</div><div style="font-size:1.1rem; font-weight:700; color:var(--text);" id="viz-pt1">—</div></div>
      <div class="card" style="text-align:center; padding:14px;"><div style="font-family:var(--font-mono); font-size:0.55rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); margin-bottom:6px;">At 2× surge</div><div style="font-size:1.1rem; font-weight:700; color:var(--green);" id="viz-pt2">—</div></div>
      <div class="card" style="text-align:center; padding:14px;"><div style="font-family:var(--font-mono); font-size:0.55rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); margin-bottom:6px;">At 5× surge</div><div style="font-size:1.1rem; font-weight:700; color:#f59e0b;" id="viz-pt5">—</div></div>
      <div class="card" style="text-align:center; padding:14px;"><div style="font-family:var(--font-mono); font-size:0.55rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); margin-bottom:6px;">At 10× surge</div><div style="font-size:1.1rem; font-weight:700; color:#f87171;" id="viz-pt10">—</div></div>
    </div>
    <div style="position:relative; height:260px;"><canvas id="surgeChart"></canvas></div>
  </div>

  <div class="card">
    <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid var(--border);">Recent Surge Events (last 50)</div>
    ${recentSurges.length === 0
      ? `<div style="text-align:center; padding:32px; font-family:var(--font-mono); font-size:0.75rem; color:var(--muted);">No surge events yet.</div>`
      : `<table><thead><tr><th>Domain</th><th>Path</th><th>V₁₀</th><th>Vbase</th><th>γ</th><th>Pfloor</th><th>Rec. CPM</th><th>Uplift</th><th>Status</th><th>Detected</th><th></th></tr></thead><tbody>
      ${recentSurges.map(s => {
        const uplift = s.floor_cpm > 0 ? (((s.recommended_cpm - s.floor_cpm) / s.floor_cpm) * 100).toFixed(0) : 0;
        const status = s.status || 'pending';
        const isPending = status === 'pending';
        const statusBadge = status === 'approved'
          ? `<span style="font-family:var(--font-mono); font-size:0.6rem; color:var(--green); background:rgba(0,229,160,0.1); border:1px solid rgba(0,229,160,0.3); padding:3px 8px; border-radius:4px;">✓ approved</span>`
          : status === 'rejected'
          ? `<span style="font-family:var(--font-mono); font-size:0.6rem; color:var(--muted); background:rgba(168,197,232,0.06); border:1px solid var(--border); padding:3px 8px; border-radius:4px;">✗ dismissed</span>`
          : `<span style="font-family:var(--font-mono); font-size:0.6rem; color:#f59e0b; background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.3); padding:3px 8px; border-radius:4px;">⏳ pending</span>`;
        const actionBtns = isPending && s.id
          ? `<div style="display:flex; gap:6px;"><button onclick="surgeAction(${esc(s.id)},'${esc(s.audit_id)}','approve',this)" class="btn btn-ghost btn-sm" style="color:var(--green); border-color:var(--green); font-size:0.65rem; padding:4px 10px;">✓ Approve</button><button onclick="surgeAction(${esc(s.id)},'${esc(s.audit_id)}','reject',this)" class="btn btn-ghost btn-sm" style="color:var(--muted); font-size:0.65rem; padding:4px 10px;">✗</button></div>`
          : status === 'approved' && s.actioned_cpm ? `<span style="font-family:var(--font-mono); font-size:0.65rem; color:var(--green);">@$${Number(s.actioned_cpm).toFixed(2)}</span>` : '';
        return `<tr id="surge-row-${esc(s.id)}">
          <td style="font-weight:600;">${esc(s.domain_name)}</td>
          <td style="font-family:var(--font-mono); font-size:0.65rem; color:var(--muted);">${esc(s.page_path || '/')}</td>
          <td style="font-family:var(--font-mono);">${s.hits_per_10min || 0}</td>
          <td style="font-family:var(--font-mono);">${(s.vbase||0).toFixed(1)}</td>
          <td style="font-family:var(--font-mono);">${(s.gamma||1).toFixed(1)}</td>
          <td style="font-family:var(--font-mono);">$${(s.floor_cpm||0).toFixed(2)}</td>
          <td style="font-family:var(--font-mono); color:#f59e0b; font-weight:600;">$${(s.recommended_cpm||0).toFixed(2)}</td>
          <td style="font-family:var(--font-mono); color:var(--green);">+${uplift}%</td>
          <td>${statusBadge}</td>
          <td style="font-family:var(--font-mono); font-size:0.65rem; color:var(--muted);">${esc(s.detected_at || '')}</td>
          <td>${actionBtns}</td>
        </tr>`;
      }).join('')}
      </tbody></table>`}
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>
  async function saveFormula(auditId) {
    const pfloor = parseFloat(document.getElementById('pfloor-'+auditId).value);
    const beta   = parseFloat(document.getElementById('beta-'+auditId).value);
    if (isNaN(pfloor) || isNaN(beta)) return alert('Invalid values');
    const res = await fetch('/api/admin/save-formula', { method: 'POST', credentials:'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ audit_id: auditId, floor_cpm: pfloor, beta }) });
    const d = await res.json();
    if (d.ok) { const btn = event.target; btn.textContent='✓ Saved'; btn.style.color='var(--green)'; setTimeout(()=>{ btn.textContent='Save'; btn.style.color=''; },2000); } else { alert('Error: '+(d.error||'Unknown')); }
  }

  async function surgeAction(surgeId, auditId, action, btn) {
    btn.textContent = action==='approve'?'Approving…':'Dismissing…'; btn.disabled=true;
    try {
      const res = await fetch('/api/admin/surge-action', { method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:surgeId,audit_id:auditId,action}) });
      const d = await res.json();
      if (d.ok) {
        const row = document.getElementById('surge-row-'+surgeId);
        if (row) {
          row.cells[8].innerHTML = action==='approve' ? '<span style="font-family:var(--font-mono); font-size:0.6rem; color:var(--green); background:rgba(0,229,160,0.1); border:1px solid rgba(0,229,160,0.3); padding:3px 8px; border-radius:4px;">✓ approved</span>' : '<span style="font-family:var(--font-mono); font-size:0.6rem; color:var(--muted); background:rgba(168,197,232,0.06); border:1px solid var(--border); padding:3px 8px; border-radius:4px;">✗ dismissed</span>';
          row.cells[10].innerHTML = action==='approve' && d.actioned_cpm ? '<span style="font-family:var(--font-mono); font-size:0.65rem; color:var(--green);">@$'+d.actioned_cpm.toFixed(2)+'</span>' : '';
        }
      } else { btn.textContent=action==='approve'?'✓ Approve':'✗'; btn.disabled=false; alert('Error: '+(d.error||'Unknown')); }
    } catch(e) { btn.textContent=action==='approve'?'✓ Approve':'✗'; btn.disabled=false; alert('Network error — try again'); }
  }

  let surgeChart;
  function calcPt(pf,b,vrat,g){ return pf*(1+b*Math.log10(1+vrat)*g); }
  function updateViz(){
    const pf=parseFloat(document.getElementById('viz-pfloor').value), b=parseFloat(document.getElementById('viz-beta').value), g=parseFloat(document.getElementById('viz-gamma').value);
    document.getElementById('viz-pfloor-out').textContent=pf.toFixed(2); document.getElementById('viz-beta-out').textContent=b.toFixed(1);
    document.getElementById('viz-pt1').textContent='$'+calcPt(pf,b,1,g).toFixed(2); document.getElementById('viz-pt2').textContent='$'+calcPt(pf,b,2,g).toFixed(2);
    document.getElementById('viz-pt5').textContent='$'+calcPt(pf,b,5,g).toFixed(2); document.getElementById('viz-pt10').textContent='$'+calcPt(pf,b,10,g).toFixed(2);
    const xs=Array.from({length:101},(_,i)=>i/10);
    surgeChart.data.datasets[0].data=xs.map(x=>({x,y:parseFloat(calcPt(pf,1.5,x,g).toFixed(4))}));
    surgeChart.data.datasets[1].data=xs.map(x=>({x,y:parseFloat(calcPt(pf,1.0,x,g).toFixed(4))}));
    surgeChart.data.datasets[2].data=xs.map(x=>({x,y:parseFloat(calcPt(pf,2.5,x,g).toFixed(4))}));
    surgeChart.data.datasets[3].data=[{x:0,y:pf},{x:10,y:pf}];
    surgeChart.update('none');
  }
  window.addEventListener('load',()=>{
    const ctx=document.getElementById('surgeChart').getContext('2d');
    surgeChart=new Chart(ctx,{type:'scatter',data:{datasets:[
      {label:'β=1.5',data:[],borderColor:'#185FA5',backgroundColor:'transparent',showLine:true,borderWidth:2.5,pointRadius:0,tension:0.4},
      {label:'β=1.0',data:[],borderColor:'#1D9E75',backgroundColor:'transparent',showLine:true,borderWidth:1.5,pointRadius:0,tension:0.4},
      {label:'β=2.5',data:[],borderColor:'#D85A30',backgroundColor:'transparent',showLine:true,borderWidth:1.5,pointRadius:0,tension:0.4},
      {label:'Floor',data:[],borderColor:'rgba(168,197,232,0.3)',backgroundColor:'transparent',showLine:true,borderWidth:1,pointRadius:0,borderDash:[5,4]},
    ]},options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false},tooltip:{enabled:false}},scales:{x:{title:{display:true,text:'Traffic ratio (V₁₀/Vbase)',font:{size:11},color:'#64748b'},min:0,max:10,ticks:{callback:v=>v+'×',font:{size:10},color:'#64748b'},grid:{color:'rgba(255,255,255,0.04)'}},y:{title:{display:true,text:'Recommended CPM ($)',font:{size:11},color:'#64748b'},min:0,ticks:{callback:v=>'$'+v.toFixed(2),font:{size:10},color:'#64748b'},grid:{color:'rgba(255,255,255,0.04)'}}}}});
    updateViz();
  });
</script>
</body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // 8. DOMAIN DRILLDOWN
    // ============================================================
    if (path === "/domain-drilldown") {
      const aid   = url.searchParams.get("audit_id");
      const r     = url.searchParams.get("range") || "all";
      const dName = await getDomainName(aid);
      const dF    = r === "7" ? "AND timestamp > datetime('now','-7 days')" : r === "30" ? "AND timestamp > datetime('now','-30 days')" : "";

      const { results: bots } = await env.DB.prepare(
        `SELECT bot_name, tier, is_training, COUNT(*) as c, SUM(cpm_value) as revenue FROM bot_logs WHERE audit_id = ? AND is_bot = 1 ${dF} GROUP BY bot_name ORDER BY revenue DESC`
      ).bind(aid).all();

      const { results: stealth } = await env.DB.prepare(
        `SELECT COUNT(*) as cnt FROM bot_logs WHERE audit_id = ? AND is_stealth = 1 ${dF}`
      ).bind(aid).all();

      const { results: trainingRow } = await env.DB.prepare(
        `SELECT COUNT(*) as cnt FROM bot_logs WHERE audit_id = ? AND is_training = 1 ${dF}`
      ).bind(aid).all();

      // v27.4: Page-level analytics — top pages by bot hit count
      const { results: topPages } = await env.DB.prepare(
        `SELECT path, COUNT(*) as hits, SUM(cpm_value) as revenue
         FROM bot_logs
         WHERE audit_id = ? AND is_bot = 1 AND path IS NOT NULL AND path != '' ${dF}
         GROUP BY path ORDER BY hits DESC LIMIT 25`
      ).bind(aid).all();

      const hasPageData = topPages.length > 0;

      let totalRec  = 0;
      let trainingCount = trainingRow[0]?.cnt || 0;
      bots.forEach(b => totalRec += (b.revenue || 0));

      const tierColors = { 1: "var(--green)", 2: "var(--blue)", 3: "var(--amber)", 4: "var(--muted)", 5: "#d97706" };
      const tierBadge  = { 1: "badge-t1", 2: "badge-t2", 3: "badge-t3", 4: "badge-t4", 5: "badge-t5" };

      return new Response(`<!DOCTYPE html><html><head>${brandHead}<title>Domain Drilldown — ${dName}</title></head><body>
<div class="wrap" style="padding-top:32px; padding-bottom:80px;">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:32px;">
    <button onclick="history.back()" class="btn btn-ghost btn-sm">← Back</button>
    <div style="font-family:var(--font-mono); font-size:0.7rem; color:var(--muted); text-transform:uppercase; letter-spacing:2px;">Audit · ${dName}</div>
    <div style="font-family:var(--font-mono); font-size:0.9rem; color:var(--green);">$${totalRec.toFixed(4)}</div>
  </div>

  <div class="grid-4" style="margin-bottom:24px;">
    <div class="card"><div class="stat-label">Total Bot Hits</div><div class="stat-val">${bots.reduce((a,b)=>a+b.c,0).toLocaleString()}</div></div>
    <div class="card"><div class="stat-label">Est. Net Revenue</div><div class="stat-val" style="color:var(--green);">$${totalRec.toFixed(4)}</div></div>
    <div class="card"><div class="stat-label">Stealth Crawlers</div><div class="stat-val" style="color:var(--amber);">${stealth[0]?.cnt || 0}</div></div>
    <div class="card" style="border-top:3px solid #f59e0b;"><div class="stat-label" style="color:#b45309;">T5 Training Hits</div><div class="stat-val" style="color:#d97706;">${trainingCount.toLocaleString()}</div></div>
  </div>

  ${trainingCount > 0 ? `
  <div class="training-gap-callout">
    <h4>⚡ ${trainingCount.toLocaleString()} Training Bot Hits — Unmonetized (TollBit Gap)</h4>
    <p>These bots are collecting your content for LLM model training. TollBit doesn't monetize them. Ask your BotRev account manager about BotRev Training Deals — direct LLM licensing agreements that can recover this revenue.</p>
  </div>` : ''}

  <div style="display:grid; grid-template-columns:3fr 2fr; gap:20px; align-items:start;">

  <!-- BOT TABLE with top 5 + expand -->
  <div class="card" style="min-width:0;">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
      <div style="font-family:var(--font-mono); font-size:0.65rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted);">Bot / Company</div>
      <div style="display:flex; gap:12px; align-items:center;">
        <span style="font-family:var(--font-mono); font-size:0.58rem; color:var(--muted);">${bots.length} bots detected</span>
        ${bots.length > 5 ? '<button onclick="toggleBots()" id="bot-expand-btn" style="font-family:var(--font-mono); font-size:0.6rem; padding:3px 10px; border-radius:4px; border:1px solid var(--border); background:rgba(255,255,255,0.05); color:var(--green); cursor:pointer;">Show all ↓</button>' : ''}
      </div>
    </div>
    <table id="bot-table">
      <thead><tr>
        <th onclick="sortTable('name')" style="cursor:pointer; user-select:none;">Bot / Company <span id="sort-name" style="font-size:0.7rem; color:var(--muted);"></span></th>
        <th onclick="sortTable('tier')" style="cursor:pointer; user-select:none;">Tier <span id="sort-tier" style="font-size:0.7rem; color:var(--muted);"></span></th>
        <th onclick="sortTable('hits')" style="cursor:pointer; user-select:none;">Hits <span id="sort-hits" style="font-size:0.7rem; color:var(--muted);">↓</span></th>
        <th onclick="sortTable('revenue')" style="cursor:pointer; user-select:none; text-align:right;">Revenue <span id="sort-revenue" style="font-size:0.7rem; color:var(--muted);"></span></th>
      </tr></thead>
      <tbody id="bot-tbody">
      ${bots.map((b, idx) => {
        const reclassified = classifyBot(b.bot_name || "");
        const t = reclassified ? reclassified.tier : 4;
        const display = getBotDisplayName(b.bot_name || "");
        const rev = b.revenue || 0;
        return '<tr data-name="' + esc(display.name) + '" data-tier="' + t + '" data-hits="' + b.c + '" data-revenue="' + rev + '" class="bot-row' + (idx >= 5 ? ' bot-extra" style="display:none;' : '') + '">' +
          '<td><div style="display:flex; align-items:center; gap:8px;"><span style="font-size:1rem;">' + display.icon + '</span><div>' +
          '<div style="font-weight:700; font-size:0.85rem; color:var(--text);">' + esc(display.name) + '</div>' +
          '<div style="font-size:0.7rem; color:var(--muted); font-family:var(--font-mono);">' + esc(display.company) + '</div>' +
          '</div></div>' + (b.is_training ? '<span class="badge badge-t5" style="margin-top:4px; display:inline-block;">training</span>' : '') + '</td>' +
          '<td><span class="badge ' + (tierBadge[t] || 'badge-t4') + '">T' + t + '</span></td>' +
          '<td style="font-family:var(--font-mono);">' + b.c.toLocaleString() + '</td>' +
          '<td style="text-align:right; font-family:var(--font-mono); color:' + (tierColors[t] || 'var(--muted)') + ';">' + (t === 5 ? '<span style="color:#d97706;">$0.0000 ⚡</span>' : '$' + rev.toFixed(6)) + '</td>' +
          '</tr>';
      }).join('')}
      </tbody>
    </table>
  </div>
  <script>
    let _sortCol = 'hits', _sortDir = -1;
    let _botsExpanded = false;
    function toggleBots() {
      _botsExpanded = !_botsExpanded;
      document.querySelectorAll('.bot-extra').forEach(r => r.style.display = _botsExpanded ? '' : 'none');
      const btn = document.getElementById('bot-expand-btn');
      if (btn) btn.textContent = _botsExpanded ? 'Show less ↑' : 'Show all ↓';
    }
    function sortTable(col) {
      if (_sortCol === col) { _sortDir *= -1; } else { _sortCol = col; _sortDir = col === 'name' ? 1 : -1; }
      ['name','tier','hits','revenue'].forEach(c => {
        document.getElementById('sort-' + c).textContent = c === _sortCol ? (_sortDir === 1 ? '↑' : '↓') : '';
      });
      const tbody = document.getElementById('bot-tbody');
      const rows = Array.from(tbody.querySelectorAll('tr'));
      rows.sort((a, b) => {
        let av = a.dataset[col], bv = b.dataset[col];
        if (col === 'name') return _sortDir * av.localeCompare(bv);
        return _sortDir * (parseFloat(bv) - parseFloat(av));
      });
      rows.forEach(r => tbody.appendChild(r));
      // Re-apply visibility after sort
      if (!_botsExpanded) {
        let visible = 0;
        tbody.querySelectorAll('tr').forEach(r => {
          r.style.display = visible < 5 ? '' : 'none';
          if (r.style.display !== 'none') visible++;
          r.classList.toggle('bot-extra', visible > 5);
        });
      }
    }
  </script>
  </div>

  <!-- PAGE ANALYTICS with top 5 + expand -->
  <div class="card" style="min-width:0;">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
      <div style="font-family:var(--font-mono); font-size:0.65rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted);">Top Pages by Bot Traffic</div>
      ${hasPageData && topPages.length > 5 ? '<button onclick="togglePages()" id="page-expand-btn" style="font-family:var(--font-mono); font-size:0.6rem; padding:3px 10px; border-radius:4px; border:1px solid var(--border); background:rgba(255,255,255,0.05); color:var(--green); cursor:pointer;">Show all ↓</button>' : ''}
    </div>
    ${hasPageData ? '<table><thead><tr><th>Page Path</th><th style="text-align:right;">Hits</th></tr></thead><tbody>' +
      topPages.map((p, idx) => '<tr class="page-row' + (idx >= 5 ? ' page-extra" style="display:none;' : '') + '"><td><code style="font-size:0.68rem; word-break:break-all;">' + esc(p.path) + '</code></td><td style="text-align:right; font-family:var(--font-mono); white-space:nowrap;">' + p.hits.toLocaleString() + '</td></tr>').join('') +
      '</tbody></table><script>function togglePages(){var e=!window._pEx;window._pEx=e;document.querySelectorAll(".page-extra").forEach(function(r){r.style.display=e?"":"none"});var b=document.getElementById("page-expand-btn");if(b)b.textContent=e?"Show less ↑":"Show all ↓";}<\/script>' :
      '<div style="padding:24px 0; text-align:center;"><div style="font-size:1.8rem; margin-bottom:10px;">📄</div><div style="font-weight:700; font-size:0.85rem; color:var(--text); margin-bottom:8px;">No Page Data Yet</div><div style="font-size:0.78rem; color:var(--muted); line-height:1.7;"><strong style="color:var(--green);">CNAME publishers</strong> — paths log automatically.<br><br><strong style="color:var(--amber);">Snippet publishers</strong> — update your snippet to enable page-level tracking.</div></div>'}
  </div>
  </div>

</div></body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // 9. MARKETPLACE DRILLDOWN
    // ============================================================
    if (path === "/market-drilldown") {
      const aid   = url.searchParams.get("audit_id");
      const m     = url.searchParams.get("market");
      const r     = url.searchParams.get("range") || "all";
      const det   = await getMarketplaceDetails(aid, m, r);
      const mColor = { TollBit: "var(--green)", Dappier: "var(--blue)", Microsoft: "#00a4ef", Amazon: "#ff9900" }[m] || "var(--green)";

      return new Response(`<!DOCTYPE html><html><head>${brandHead}</head><body>
<div class="wrap" style="padding-top:32px; padding-bottom:80px;">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:32px;">
    <button onclick="history.back()" class="btn btn-ghost btn-sm">← Back</button>
    <div style="font-family:var(--font-mono); font-size:0.9rem; color:${mColor};">Partner Revenue NET: $${det.net.toFixed(4)}</div>
  </div>
  <div class="card" style="border-left: 3px solid ${mColor};">
    <div style="font-family:var(--font-mono); font-size:0.65rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin-bottom:20px;">Partner · Breakdown</div>
    <table>
      <thead><tr><th>Agent</th><th>Requests</th><th style="text-align:right;">Net Revenue</th></tr></thead>
      <tbody>
      ${det.breakdown.length > 0
        ? det.breakdown.map(b => `<tr><td><code>${b.name || b.bot}</code></td><td style="font-family:var(--font-mono);">${(b.count || b.hits || 0).toLocaleString()}</td><td style="text-align:right; font-family:var(--font-mono); color:${mColor};">$${((b.revenue||0)*(1-MANAGEMENT_FEE)).toFixed(6)}</td></tr>`).join('')
        : '<tr><td colspan="3" style="text-align:center; padding:40px; color:var(--muted);">No breakdown data available.</td></tr>'}
      </tbody>
    </table>
  </div>
</div></body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // 10. ONBOARDING PAGE
    // ============================================================
    if (path === ONBOARDING_PATH) {
      if (!await isAdminAuthenticated(request, env)) return new Response("Unauthorized", { status: 401 });

      // ── SINGLE PUBLISHER QUICK-ADD ──
      if (request.method === "POST" && url.searchParams.get("mode") === "single") {
        try {
          const fd         = await request.formData();
          const networkId  = (fd.get("network_id") || "").trim().toLowerCase();
          const _auditId   = (fd.get("audit_id")    || "").trim();
          const auditId    = _auditId || ('Audit-' + Math.random().toString(36).substring(2,8).toUpperCase());
          const domain     = (fd.get("domain")      || "").trim();
          const intType    = (fd.get("integration_type") || "B").trim();
          const marketplace= (fd.get("marketplace") || "TollBit").trim();
          const originSvr  = (fd.get("origin_server") || "").trim() || null;

          if (!networkId || !domain) {
            return new Response("Missing required fields: Network ID and Domain", { status: 400 });
          }

          await env.DB.prepare(
            "INSERT OR IGNORE INTO publisher_entities (pub_user_id, audit_id, domain_name, integration_type, origin_server) VALUES (?, ?, ?, ?, ?)"
          ).bind(networkId, auditId, domain, intType, originSvr).run();

          await env.DB.prepare(
            "INSERT OR IGNORE INTO publisher_marketplaces (audit_id, marketplace_name, api_key) VALUES (?, ?, ?)"
          ).bind(auditId, marketplace, "").run();

          return Response.redirect(url.origin + SECRET_ADMIN_PATH, 302);
        } catch (e) {
          return new Response("Error: " + e.message, { status: 500 });
        }
      }

      if (request.method === "POST") {
        try {
          const formData = await request.formData();
          const file     = formData.get("csv_file");
          const content  = await file.text();
          const lines    = content.split('\n').filter(l => l.trim() !== "");
          let imported   = 0;
          const warnings = [];

          for (const line of lines) {
            const parts = line.split(',').map(s => s.trim());
            if (parts.length < 6) continue;
            const [net, _aid, dom, mkt, key, p, intType, origin] = parts;
            const aid = _aid.trim() || ('Audit-' + Math.random().toString(36).substring(2,8).toUpperCase());
            const integType = intType || "A";
            const originSvr = origin  || null;

            // v27.2: Origin server validation for Type A integrations
            if (integType === "A" && originSvr) {
              try {
                const originCheck = await fetch(`https://${originSvr}/`, {
                  method: 'HEAD',
                  headers: { 'User-Agent': 'BotRev-Origin-Validator/1.0' },
                  signal: AbortSignal.timeout(5000),
                  redirect: 'follow',
                });
                if (!originCheck.ok && originCheck.status === 0) {
                  warnings.push(`⚠ ${dom}: Origin server ${originSvr} unreachable — imported anyway, verify before going live.`);
                }
              } catch (originErr) {
                warnings.push(`⚠ ${dom}: Could not verify origin server ${originSvr} (${originErr.message}) — imported, verify before activating.`);
              }
            }

            await env.DB.prepare("INSERT OR IGNORE INTO publisher_entities (pub_user_id, audit_id, domain_name, password, integration_type, origin_server) VALUES (?, ?, ?, ?, ?, ?)").bind(net.toLowerCase(), aid, dom, p, integType, originSvr).run();
            await env.DB.prepare("INSERT OR IGNORE INTO publisher_marketplaces (audit_id, marketplace_name, api_key) VALUES (?, ?, ?)").bind(aid, mkt, key).run();
            imported++;
          }

          // If there are warnings, show them before redirecting
          if (warnings.length > 0) {
            return new Response(`<!DOCTYPE html><html><head>${brandHead}<title>Onboarding — BotRev</title></head><body>
<div class="wrap" style="display:flex; justify-content:center; align-items:center; min-height:100vh;">
  <div class="card" style="max-width:560px;">
    <a class="logo" href="#">Bot<span>Rev</span></a>
    <div style="font-family:var(--font-mono); font-size:0.6rem; letter-spacing:2px; color:var(--green); margin: 8px 0 16px; text-transform:uppercase;">Import Complete — ${imported} publisher${imported !== 1 ? 's' : ''} added</div>
    <div style="background:#fffbeb; border:1px solid #fcd34d; border-left:4px solid #f59e0b; border-radius:8px; padding:16px; margin-bottom:20px;">
      <div style="font-family:var(--font-mono); font-size:0.65rem; font-weight:700; color:#92400e; margin-bottom:8px; text-transform:uppercase; letter-spacing:1px;">⚠ Origin Validation Warnings</div>
      ${warnings.map(w => `<div style="font-size:0.78rem; color:#b45309; margin-bottom:6px; line-height:1.5;">${w}</div>`).join('')}
      <div style="font-size:0.75rem; color:#b45309; margin-top:10px; font-style:italic;">Publishers were imported but should be verified in Fleet Command before DNS is activated.</div>
    </div>
    <a href="${url.origin + SECRET_ADMIN_PATH}" class="btn btn-primary" style="width:100%; justify-content:center;">→ Go to Fleet Command</a>
  </div>
</div></body></html>`, { headers: { "Content-Type": "text/html" } });
          }

          return Response.redirect(url.origin + SECRET_ADMIN_PATH, 302);
        } catch (e) {
          return new Response("Error: " + e.message, { status: 500 });
        }
      }

      return new Response(`<!DOCTYPE html><html><head>${brandHead}<title>Onboarding — BotRev</title></head><body>
<div class="wrap" style="display:flex; justify-content:center; align-items:flex-start; min-height:100vh; padding:48px 24px;">
  <div style="width:100%; max-width:560px;">
    <a class="logo" href="#">Bot<span>Rev</span></a>
    <div style="font-family:var(--font-mono); font-size:0.6rem; letter-spacing:2px; color:var(--muted); margin: 8px 0 32px; text-transform:uppercase;">Fleet Onboarding</div>

    <!-- QUICK ADD SINGLE PUBLISHER -->
    <div class="card" style="margin-bottom:24px; border-top:3px solid var(--green);">
      <div style="font-family:var(--font-mono); font-size:0.65rem; letter-spacing:2px; text-transform:uppercase; color:var(--green); margin-bottom:16px;">⚡ Quick Add — Single Publisher</div>
      <form method="POST" action="${ONBOARDING_PATH}?mode=single">
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px;">
          <div>
            <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Network ID *</label>
            <input name="network_id" class="input" placeholder="e.g. OpsCo" required autocomplete="off">
          </div>
          <div>
            <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Audit ID <span style="color:var(--muted); font-weight:400;">(optional — auto-generated if blank)</span></label>
            <input name="audit_id" class="input" placeholder="e.g. Audit-002 — leave blank to auto-generate" autocomplete="off">
          </div>
        </div>
        <div style="margin-bottom:12px;">
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Domain *</label>
          <input name="domain" class="input" placeholder="e.g. wishtv.com" required autocomplete="off">
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px;">
          <div>
            <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Integration Type</label>
            <select name="integration_type" class="input" style="cursor:pointer;">
              <option value="B">B — Snippet (JS Tag)</option>
              <option value="A">A — Standard (CNAME)</option>
            </select>
          </div>
          <div>
            <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Marketplace</label>
            <select name="marketplace" class="input" style="cursor:pointer;">
              <option value="TollBit">TollBit</option>
              <option value="Dappier">Dappier</option>
              <option value="none">None</option>
            </select>
          </div>
        </div>
        <div style="margin-bottom:20px;">
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Origin Server <span style="color:var(--muted); font-weight:400;">(Standard/CNAME only)</span></label>
          <input name="origin_server" class="input" placeholder="e.g. origin.wishtv.com (leave blank for Snippet)" autocomplete="off">
        </div>
        <button class="btn btn-primary" style="width:100%;">+ Add Publisher</button>
      </form>
    </div>

    <!-- BULK CSV IMPORT -->
    <div class="card" style="border-top:3px solid var(--muted);">
      <div style="font-family:var(--font-mono); font-size:0.65rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin-bottom:16px;">Bulk CSV Import</div>
      <p style="font-size:0.8rem; color:var(--muted); margin-bottom:16px; line-height:1.6;">
        No headers. Column order:<br>
        <code style="font-size:0.72rem;">NetworkID, AuditID, Domain, Marketplace, APIKey, AccessKey, IntegrationType, OriginServer</code>
      </p>
      <form method="POST" enctype="multipart/form-data">
        <input type="file" name="csv_file" class="input" accept=".csv" required style="margin-bottom:12px;">
        <button class="btn btn-primary" style="width:100%;">Execute Bulk Import</button>
      </form>
    </div>

    <a href="${SECRET_ADMIN_PATH}" class="btn btn-ghost" style="width:100%; margin-top:16px; justify-content:center;">← Back to Fleet Command</a>
  </div>
</div></body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // 11. MAIN PUBLISHER DASHBOARD
    // ============================================================
    if (path === "/dashboard") {
      const eId    = (url.searchParams.get("entity") || "").toLowerCase();
      const tab    = url.searchParams.get("tab")    || "audit";
      const range  = url.searchParams.get("range")  || "all";
      const isAdmin = url.searchParams.get("mode") === "admin";

      const { results: domains } = await env.DB.prepare(
        "SELECT * FROM publisher_entities WHERE LOWER(pub_user_id) = ?"
      ).bind(eId).all();
      if (domains.length === 0) return new Response("Access Denied", { status: 403 });

      // True if any domain is on JS Snippet (B) — used to conditionally show CNAME upgrade CTA
      const hasSnippetDomain = domains.some(d => d.integration_type === 'B');

      const dateFilter = range === "7" ? "AND timestamp > datetime('now','-7 days')" : range === "30" ? "AND timestamp > datetime('now','-30 days')" : "";
      const filterBar  = `
        <div style="display:flex; gap:8px; margin-bottom:32px;">
          ${["7","30","all"].map(v => `<a href="?entity=${eId}&tab=${tab}&range=${v}" class="btn btn-ghost btn-sm ${range===v?'btn-primary':''}">${v==='all'?'All Time':v+' Days'}</a>`).join('')}
        </div>`;

      let tabContent = "";

      if (tab === "audit") {
        const stats = await env.DB.prepare(
          `SELECT
             SUM(CASE WHEN is_bot=1 THEN 1 ELSE 0 END) as tB,
             SUM(CASE WHEN is_stealth=1 THEN 1 ELSE 0 END) as tS,
             SUM(CASE WHEN is_bot=1 AND is_training=0 THEN cpm_value ELSE 0 END) as tRev,
             SUM(CASE WHEN is_training=1 THEN 1 ELSE 0 END) as tTraining
           FROM bot_logs
           WHERE audit_id IN (${domains.map(()=>'?').join(',')}) ${dateFilter}`
        ).bind(...domains.map(d=>d.audit_id)).first();

        const tierBreak = await env.DB.prepare(
          `SELECT tier, COUNT(*) as c, SUM(cpm_value) as rev
           FROM bot_logs WHERE is_bot=1 ${dateFilter}
           AND audit_id IN (${domains.map(()=>'?').join(',')})
           GROUP BY tier`
        ).bind(...domains.map(d=>d.audit_id)).all();

        const totalHits    = stats?.tB || 0;
        const trainingHits = stats?.tTraining || 0;

        // Revenue projection: extrapolate current period to 30-day estimate
        const obsRevenue   = stats?.tRev || 0;
        const daysOfData   = range === '7' ? 7 : range === '30' ? 30 : null;
        const dailyRate    = daysOfData && obsRevenue > 0 ? obsRevenue / daysOfData : null;
        const projMonthly  = dailyRate ? dailyRate * 30 : null;
        const projAnnual   = dailyRate ? dailyRate * 365 : null;
        const tierData     = Object.fromEntries((tierBreak.results || []).map(r => [r.tier, r]));
        const tierLabels   = { 1: "Premium AI", 2: "Headless", 3: "Search", 4: "Utility", 5: "Training ⚡" };
        const tierColors   = { 1: 'var(--green)', 2: 'var(--blue)', 3: 'var(--amber)', 4: 'var(--muted)', 5: '#d97706' };

        const domainCards = await Promise.all(domains.map(async d => {
          const active  = await env.DB.prepare("SELECT timestamp FROM bot_logs WHERE audit_id = ? AND is_bot = 1 LIMIT 1").bind(d.audit_id).first();
          const dnsLive = !!active;
          const statusLabel = dnsLive ? 'Active' : (d.integration_type === 'B' ? 'Snippet Pending' : 'DNS Pending');
          return `
          <div class="card ${dnsLive ? 'sniffer-live' : ''}">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px;">
              <div>
                <div style="font-weight:700; font-size:1.05rem;">${esc(d.domain_name)}</div>
                <div style="font-family:var(--font-mono); font-size:0.6rem; color:var(--muted); margin-top:3px;">${esc(d.audit_id)}</div>
                ${isAdmin ? `<div style="font-weight:700; color:var(--text); margin-bottom:6px; font-family:var(--font-mono); font-size:0.55rem; display:inline-block; padding:2px 8px; border-radius:10px; background:${d.integration_type==='B'?'rgba(245,158,11,0.1)':'rgba(0,229,160,0.07)'}; color:${d.integration_type==='B'?'#f59e0b':'var(--green)'};">${d.integration_type==='B'?'Snippet':'Standard'}</div>` : ''}
              </div>
              <div style="display:flex; align-items:center; gap:6px; padding:5px 12px; border-radius:20px; border:1px solid ${dnsLive?'var(--green)':'var(--border)'}; background:${dnsLive?'rgba(0,229,160,0.05)':'transparent'};">
                <span class="dot ${dnsLive?'dot-green':'dot-gray'}"></span>
                <span style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:${dnsLive?'var(--green)':'var(--amber)'};">` + statusLabel + `</span>
              </div>
            </div>
            <a href="/domain-drilldown?audit_id=${esc(d.audit_id)}&range=${range}" class="btn btn-primary btn-sm">View Audit Log →</a>
          </div>`;
        }));

        tabContent = `
          ${filterBar}
          <div class="grid-3" style="margin-bottom:16px;">
            <div class="card card-lit"><div class="stat-label">Total Bot Hits</div><div class="stat-val">${totalHits.toLocaleString()}</div></div>
            <div class="card card-lit"><div class="stat-label">Est. Net Revenue</div><div class="stat-val" style="color:var(--green);">$${(stats?.tRev||0).toFixed(4)}</div></div>
            <div class="card card-lit"><div class="stat-label">Stealth Crawlers</div><div class="stat-val" style="color:var(--amber);">${(stats?.tS||0).toLocaleString()}</div></div>
          </div>

          ${projMonthly ? `
          <div class="card" style="margin-bottom:24px; border-top:3px solid var(--green); background:linear-gradient(135deg, rgba(16,185,129,0.04) 0%, transparent 60%);">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px;">
              <div>
                <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--green); margin-bottom:4px;">Revenue Projection</div>
                <div style="font-size:0.82rem; color:var(--muted); line-height:1.5;">Based on your last ${range === '7' ? '7 days' : '30 days'} of AI bot traffic at current rates</div>
              </div>
              <span style="font-family:var(--font-mono); font-size:0.6rem; color:var(--muted); padding:3px 8px; border:1px solid var(--border); border-radius:4px;">ESTIMATE</span>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:16px;">
              <div style="text-align:center; padding:16px; background:var(--surface-2); border-radius:10px;">
                <div style="font-family:var(--font-mono); font-size:0.55rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); margin-bottom:8px;">Daily Rate</div>
                <div style="font-family:var(--font-mono); font-size:1.4rem; font-weight:500; color:var(--text);">$${dailyRate.toFixed(4)}</div>
                <div style="font-size:0.7rem; color:var(--muted); margin-top:4px;">per day</div>
              </div>
              <div style="text-align:center; padding:16px; background:rgba(16,185,129,0.06); border:1px solid rgba(16,185,129,0.2); border-radius:10px;">
                <div style="font-family:var(--font-mono); font-size:0.55rem; letter-spacing:1px; text-transform:uppercase; color:var(--green); margin-bottom:8px;">Est. Monthly</div>
                <div style="font-family:var(--font-mono); font-size:1.4rem; font-weight:500; color:var(--green);">$${projMonthly.toFixed(2)}</div>
                <div style="font-size:0.7rem; color:var(--green); margin-top:4px;">publisher net / month</div>
              </div>
              <div style="text-align:center; padding:16px; background:var(--surface-2); border-radius:10px;">
                <div style="font-family:var(--font-mono); font-size:0.55rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); margin-bottom:8px;">Est. Annual</div>
                <div style="font-family:var(--font-mono); font-size:1.4rem; font-weight:500; color:var(--text);">$${projAnnual.toFixed(2)}</div>
                <div style="font-size:0.7rem; color:var(--muted); margin-top:4px;">at current traffic</div>
              </div>
            </div>
            <div style="margin-top:12px; font-size:0.72rem; color:var(--muted); font-style:italic;">
              ${hasSnippetDomain ? 'Upgrade to CNAME integration to capture an estimated 40–60% more bot traffic — raw HTTP crawlers, including most AI training and inference bots, do not execute JavaScript and are invisible to the snippet.' : 'Projection assumes consistent traffic patterns.'}
            </div>
          </div>` : `
          <div class="card" style="margin-bottom:24px; border-top:3px solid var(--green);">
            <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--green); margin-bottom:8px;">Revenue Projection</div>
            <p style="font-size:0.82rem; color:var(--muted);">Select a 7-day or 30-day window to see your projected monthly and annual earnings based on current traffic patterns.</p>
          </div>`}

          <div class="card" style="margin-bottom:24px;">
            <div class="stat-label" style="margin-bottom:16px;">Tier Breakdown</div>
            <div style="display:grid; grid-template-columns:repeat(5,1fr); gap:16px;">
              ${[1,2,3,4,5].map(t => {
                const d = tierData[t] || { c: 0, rev: 0 };
                const pct = totalHits > 0 ? (d.c / totalHits * 100) : 0;
                const isTrainingTier = t === 5;
                return `<div>
                  <div style="font-family:var(--font-mono); font-size:0.58rem; text-transform:uppercase; letter-spacing:1px; color:${tierColors[t]}; margin-bottom:4px;">T${t} · ${tierLabels[t]}</div>
                  <div style="font-family:var(--font-mono); font-size:1.1rem; font-weight:500;">${d.c.toLocaleString()}</div>
                  <div style="font-family:var(--font-mono); font-size:0.65rem; color:${isTrainingTier?'#d97706':'var(--muted)'};">
                    ${isTrainingTier ? '$0.0000 ⚡' : '$'+(d.rev||0).toFixed(4)}
                  </div>
                  <div class="tier-bar"><div class="tier-fill" style="width:${pct.toFixed(1)}%; background:${tierColors[t]};"></div></div>
                </div>`;
              }).join('')}
            </div>
          </div>

          ${trainingHits > 0 ? `
          <div class="training-gap-callout">
            <h4>⚡ ${trainingHits.toLocaleString()} Training Bot Hits — Unmonetized (TollBit Gap)</h4>
            <p>These bots are collecting your content for LLM model training. These hits are not monetized through standard marketplace channels — but BotRev Training Deals can recover this revenue through direct licensing agreements with AI companies. Contact your BotRev account manager to learn more.</p>
          </div>` : ''}

          ${domainCards.join('')}`;

      } else if (tab === "market") {
        const markets = ['TollBit', 'Dappier', 'Microsoft', 'Amazon'];
        const allMarketData = await Promise.all(domains.map(d =>
          Promise.all(markets.map(m => getMarketplaceDetails(d.audit_id, m, range)))
        ));
        let gNet = 0;
        allMarketData.forEach(dm => dm.forEach(m => { gNet += m.net; }));
        const mktColors = { TollBit: "var(--green)", Dappier: "var(--blue)", Microsoft: "#00a4ef", Amazon: "#ff9900" };

        tabContent = `
          ${filterBar}
          <div class="card card-lit" style="max-width:380px; margin:0 0 28px; border:1px solid var(--green);">
            <div class="stat-label">Total Network Net Revenue</div>
            <div class="stat-val" style="color:var(--green); font-size:3rem;">$${gNet.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2})}</div>
          </div>
          ${(await Promise.all(domains.map(async (d, idx) => {
            const stats  = allMarketData[idx];
            const domNet = stats.reduce((a,b)=>a+b.net,0);
            return `<div class="card">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                <div style="font-weight:700;">${d.domain_name}</div>
                <div style="text-align:right; font-family:var(--font-mono); font-size:0.8rem; color:var(--text);">$${domNet.toFixed(4)} net</div>
              </div>
              <div class="grid-3">
              ${markets.map((m, i) => `
                <div style="background:var(--bg); padding:16px; border-radius:10px; border:1px solid var(--border);">
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <span style="font-family:var(--font-mono); font-size:0.6rem; text-transform:uppercase; letter-spacing:1px; color:${mktColors[m]};">${m}</span>
                    <span class="badge badge-${stats[i].status==='Active'?'active':stats[i].status==='Offline'?'error':'warn'}">${stats[i].status}</span>
                  </div>
                  <div style="font-family:var(--font-mono); font-size:1.2rem; font-weight:500; color:var(--text);">$${stats[i].net.toFixed(4)}</div>
                  <a href="/market-drilldown?audit_id=${d.audit_id}&market=${m}&range=${range}" style="font-family:var(--font-mono); font-size:0.6rem; color:${mktColors[m]}; text-decoration:none; display:block; margin-top:8px;">Analysis →</a>
                </div>`).join('')}
              </div>
            </div>`;
          }))).join('')}`;

      } else if (tab === "faq") {
        tabContent = `
          <div style="max-width:780px;">
            <div class="card card-lit" style="margin-bottom:16px;">
              <div style="margin-bottom:18px;">
                <div style="font-family:var(--font-mono); font-size:0.65rem; letter-spacing:2px; text-transform:uppercase; color:var(--green); margin-bottom:6px;">Sniffer Deployment Guide</div>
              </div>
              <div style="border-top:1px solid var(--border); padding-top:16px; margin-bottom:16px;">
                <div style="font-family:var(--font-mono); font-size:0.6rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); margin-bottom:12px;">How We Deploy the Sniffer</div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; font-size:0.78rem;">
                  <div style="background:rgba(0,229,160,0.05); border:1px solid rgba(0,229,160,0.2); border-radius:8px; padding:14px;">
                    <div style="font-family:var(--font-mono); font-size:0.6rem; color:var(--green); letter-spacing:1px; margin-bottom:8px;">STANDARD · DEFAULT</div>
                    <div style="font-weight:700; color:var(--text); margin-bottom:6px;">CNAME Proxy</div>
                    <div style="color:var(--muted); line-height:1.6; font-size:0.75rem;">Publisher adds one CNAME record pointing <code>www</code> to <code>proxy.botrev.com</code>. Works on any host. Full headless + stealth detection. <b style="color:var(--text);">Default for all new publishers.</b></div>
                  </div>
                  <div style="background:rgba(245,158,11,0.05); border:1px solid rgba(245,158,11,0.2); border-radius:8px; padding:14px;">
                    <div style="font-family:var(--font-mono); font-size:0.6rem; color:#f59e0b; letter-spacing:1px; margin-bottom:8px;">SNIPPET · FALLBACK</div>
                    <div style="font-weight:700; color:var(--text); margin-bottom:6px;">JS Tag</div>
                    <div style="color:var(--muted); line-height:1.6; font-size:0.75rem;">Publisher pastes a single script tag in their site header. No DNS changes needed. Best as a quick audit start — migrate to Standard once comfortable.</div>
                  </div>
                </div>
              </div>
            </div>
            </div>

            <div class="card" style="margin-bottom:16px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                <div class="stat-label">AI Crawler Intelligence Directory</div>
                <div style="font-family:var(--font-mono); font-size:0.58rem; color:var(--muted);">Updated from live fleet data</div>
              </div>
              <p style="font-size:0.78rem; color:var(--muted); margin-bottom:16px; line-height:1.6;">Every known AI crawler BotRev monitors across the publisher fleet — who they are, what they do, which tier they belong to, and how BotRev monetizes them.</p>

              <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--green); margin:16px 0 8px; padding-bottom:6px; border-bottom:2px solid rgba(16,185,129,0.15);">T1 · Premium AI Inference</div>
              <table style="margin-bottom:20px; font-size:0.78rem;">
                <thead><tr><th>Bot</th><th>Company</th><th>Purpose</th><th style="text-align:right;">Monetized</th></tr></thead>
                <tbody>
                  <tr><td><code>ChatGPT-User</code></td><td>OpenAI</td><td style="color:var(--muted);">Real-time inference — fetches pages to answer live ChatGPT user queries</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>ClaudeBot</code></td><td>Anthropic</td><td style="color:var(--muted);">Real-time inference — fetches pages to answer live Claude user queries</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>PerplexityBot</code></td><td>Perplexity AI</td><td style="color:var(--muted);">Real-time AI search — retrieves content to generate Perplexity answers</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>OAI-SearchBot</code></td><td>OpenAI</td><td style="color:var(--muted);">SearchGPT crawler — indexes content for OpenAI's AI search product</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>amazon-kendra / amazon-Quick</code></td><td>Amazon</td><td style="color:var(--muted);">Amazon Kendra enterprise AI search — indexes publisher content for enterprise AI</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>Amazonbot</code></td><td>Amazon</td><td style="color:var(--muted);">Alexa and Amazon AI product crawler — fetches content for Amazon's AI responses</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>meta-externalagent</code></td><td>Meta</td><td style="color:var(--muted);">Meta AI inference agent — fetches content for Meta AI assistant responses</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>YouBot</code></td><td>You.com</td><td style="color:var(--muted);">AI search engine — fetches pages to power You.com AI-generated answers</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>cohere-ai</code></td><td>Cohere</td><td style="color:var(--muted);">Enterprise AI inference — retrieves content for Cohere's business AI products</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                </tbody>
              </table>

              <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--blue); margin:16px 0 8px; padding-bottom:6px; border-bottom:2px solid rgba(45,90,142,0.15);">T2 · Headless Scrapers</div>
              <table style="margin-bottom:20px; font-size:0.78rem;">
                <thead><tr><th>Bot</th><th>Company</th><th>Purpose</th><th style="text-align:right;">Monetized</th></tr></thead>
                <tbody>
                  <tr><td><code>HeadlessChrome</code></td><td>Automation</td><td style="color:var(--muted);">Chrome running without a display — used for scraping, testing, and AI data pipelines</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>Puppeteer</code></td><td>Google / Automation</td><td style="color:var(--muted);">Node.js browser automation — commonly used in AI data collection pipelines</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>Playwright</code></td><td>Microsoft / Automation</td><td style="color:var(--muted);">Cross-browser automation — used for large-scale web scraping and AI training data</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>Selenium</code></td><td>Automation</td><td style="color:var(--muted);">Browser automation framework — oldest and most common headless scraper</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>PhantomJS</code></td><td>Automation</td><td style="color:var(--muted);">Headless WebKit browser — legacy automation tool still used in scraping pipelines</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>quillbot.com</code></td><td>QuillBot</td><td style="color:var(--muted);">AI writing assistant crawler — collects content to improve paraphrasing models</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                </tbody>
              </table>

              <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--amber); margin:16px 0 8px; padding-bottom:6px; border-bottom:2px solid rgba(245,158,11,0.15);">T3 · Search Crawlers · Pass-Through (SEO Protected)</div>
              <table style="margin-bottom:20px; font-size:0.78rem;">
                <thead><tr><th>Bot</th><th>Company</th><th>Purpose</th><th style="text-align:right;">Status</th></tr></thead>
                <tbody>
                  <tr><td><code>Googlebot</code></td><td>Google</td><td style="color:var(--muted);">Primary Google search crawler — indexes content for Google Search</td><td style="text-align:right;"><span class="badge badge-warn">Pass-Through</span></td></tr>
                  <tr><td><code>bingbot</code></td><td>Microsoft</td><td style="color:var(--muted);">Bing search crawler — indexes content for Bing and Microsoft Copilot search</td><td style="text-align:right;"><span class="badge badge-warn">Pass-Through</span></td></tr>
                  <tr><td><code>Yahoo! Slurp</code></td><td>Yahoo</td><td style="color:var(--muted);">Yahoo search crawler — powers Yahoo Search indexing</td><td style="text-align:right;"><span class="badge badge-warn">Pass-Through</span></td></tr>
                  <tr><td><code>DuckAssistBot</code></td><td>DuckDuckGo</td><td style="color:var(--muted);">DuckDuckGo AI Answer crawler — retrieves content for DuckDuckGo AI features</td><td style="text-align:right;"><span class="badge badge-warn">Pass-Through</span></td></tr>
                  <tr><td><code>DuckDuckBot</code></td><td>DuckDuckGo</td><td style="color:var(--muted);">Standard DuckDuckGo search crawler</td><td style="text-align:right;"><span class="badge badge-warn">Pass-Through</span></td></tr>
                  <tr><td><code>Baiduspider</code></td><td>Baidu</td><td style="color:var(--muted);">Chinese search engine crawler</td><td style="text-align:right;"><span class="badge badge-warn">Pass-Through</span></td></tr>
                  <tr><td><code>YandexBot</code></td><td>Yandex</td><td style="color:var(--muted);">Russian search engine crawler</td><td style="text-align:right;"><span class="badge badge-warn">Pass-Through</span></td></tr>
                  <tr><td><code>Applebot</code></td><td>Apple</td><td style="color:var(--muted);">Apple crawler — powers Spotlight, Siri Suggestions, and Safari search</td><td style="text-align:right;"><span class="badge badge-warn">Pass-Through</span></td></tr>
                  <tr><td><code>PetalBot</code></td><td>Huawei</td><td style="color:var(--muted);">Huawei Petal Search crawler</td><td style="text-align:right;"><span class="badge badge-warn">Pass-Through</span></td></tr>
                </tbody>
              </table>

              <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin:16px 0 8px; padding-bottom:6px; border-bottom:2px solid rgba(90,127,168,0.15);">T4 · Utility Crawlers</div>
              <table style="margin-bottom:20px; font-size:0.78rem;">
                <thead><tr><th>Bot</th><th>Company</th><th>Purpose</th><th style="text-align:right;">Monetized</th></tr></thead>
                <tbody>
                  <tr><td><code>SiteAuditBot</code></td><td>Semrush</td><td style="color:var(--muted);">SEO audit crawler — analyzes site structure and content for SEO reports</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>AhrefsBot</code></td><td>Ahrefs</td><td style="color:var(--muted);">SEO backlink and keyword research crawler</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>MJ12bot</code></td><td>Majestic</td><td style="color:var(--muted);">Link intelligence crawler — builds Majestic's web link index</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>LinkedInBot</code></td><td>LinkedIn</td><td style="color:var(--muted);">LinkedIn link preview and content crawler</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>meta-externalads</code></td><td>Meta</td><td style="color:var(--muted);">Meta advertising crawler — fetches content for Facebook and Instagram ad targeting</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>FBAN/FB4A</code></td><td>Meta</td><td style="color:var(--muted);">Facebook in-app browser — users clicking links inside the Facebook mobile app</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>Instagram</code></td><td>Meta</td><td style="color:var(--muted);">Instagram in-app browser — users clicking links inside the Instagram app</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>Barcelona</code></td><td>Meta</td><td style="color:var(--muted);">Threads in-app browser — users clicking links inside the Threads app</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>ContextualBot</code></td><td>Outcomes.net</td><td style="color:var(--muted);">Contextual advertising crawler — analyzes content for ad targeting signals</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>Ground News</code></td><td>Ground News</td><td style="color:var(--muted);">News aggregator app — fetches publisher articles for the Ground News platform</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                  <tr><td><code>Paqlebot</code></td><td>Paqle</td><td style="color:var(--muted);">Danish search engine crawler</td><td style="text-align:right;"><span class="badge badge-active">✓</span></td></tr>
                </tbody>
              </table>

              <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:#d97706; margin:16px 0 8px; padding-bottom:6px; border-bottom:2px solid rgba(217,119,6,0.15);">T5 · Training Crawlers · ⚡ Training Deals Opportunity</div>
              <p style="font-size:0.75rem; color:var(--muted); margin-bottom:8px; line-height:1.6;">These bots collect your content for LLM model training. No current AI content marketplace — TollBit, Microsoft PCM, Amazon, or Dappier — monetizes training crawlers through standard per-access pricing. Training data licensing happens exclusively through direct deals between publishers and AI companies. BotRev logs every T5 hit, building the verified audit record you need to negotiate those deals.</p>
              <table style="font-size:0.78rem;">
                <thead><tr><th>Bot</th><th>Company</th><th>Purpose</th><th style="text-align:right;">Path to Revenue</th></tr></thead>
                <tbody>
                  <tr><td><code>GPTBot</code></td><td>OpenAI</td><td style="color:var(--muted);">OpenAI's primary training data crawler — collects content to train GPT models</td><td style="text-align:right;"><span class="badge badge-t5">Training Deals ⚡</span></td></tr>
                  <tr><td><code>anthropic-ai</code></td><td>Anthropic</td><td style="color:var(--muted);">Anthropic training crawler — 43,214 requests per referral sent back to publishers</td><td style="text-align:right;"><span class="badge badge-t5">Training Deals ⚡</span></td></tr>
                  <tr><td><code>Google-Extended</code></td><td>Google</td><td style="color:var(--muted);">Google AI training crawler — collects content for Gemini model training</td><td style="text-align:right;"><span class="badge badge-t5">Training Deals ⚡</span></td></tr>
                  <tr><td><code>CCBot</code></td><td>Common Crawl</td><td style="color:var(--muted);">Largest open LLM training dataset — used by OpenAI, Meta, and most major AI labs</td><td style="text-align:right;"><span class="badge badge-t5">Training Deals ⚡</span></td></tr>
                  <tr><td><code>Bytespider</code></td><td>ByteDance</td><td style="color:var(--muted);">TikTok / ByteDance AI training crawler — collects content for LLM development</td><td style="text-align:right;"><span class="badge badge-t5">Training Deals ⚡</span></td></tr>
                  <tr><td><code>FacebookBot</code></td><td>Meta</td><td style="color:var(--muted);">Meta AI training crawler — collects content for Llama model training</td><td style="text-align:right;"><span class="badge badge-t5">Training Deals ⚡</span></td></tr>
                  <tr><td><code>Diffbot</code></td><td>Diffbot</td><td style="color:var(--muted);">AI-powered web extraction — builds structured knowledge graphs sold to AI companies</td><td style="text-align:right;"><span class="badge badge-t5">Training Deals ⚡</span></td></tr>
                  <tr><td><code>DataForSeoBot</code></td><td>DataForSEO</td><td style="color:var(--muted);">Data aggregator — collects content for AI training datasets and SEO intelligence</td><td style="text-align:right;"><span class="badge badge-t5">Training Deals ⚡</span></td></tr>
                  <tr><td><code>ImagesiftBot</code></td><td>Imagesift</td><td style="color:var(--muted);">Image and content crawler for AI training datasets</td><td style="text-align:right;"><span class="badge badge-t5">Training Deals ⚡</span></td></tr>
                  <tr><td><code>TurnitinBot</code></td><td>Turnitin</td><td style="color:var(--muted);">Academic AI detection — indexes content for AI writing detection model training</td><td style="text-align:right;"><span class="badge badge-t5">Training Deals ⚡</span></td></tr>
                </tbody>
              </table>
            </div>
          </div>`;

      } else if (tab === "account") {
        tabContent = `
          <div class="card" style="max-width:420px;">
            <div class="stat-label" style="margin-bottom:20px;">Account Settings</div>
            <label style="font-family:var(--font-mono); font-size:0.6rem; text-transform:uppercase; letter-spacing:1px; color:var(--muted);">Network ID</label>
            <input type="text" value="${eId.toUpperCase()}" class="input" readonly style="opacity:0.5; margin: 8px 0 16px;">
            <label style="font-family:var(--font-mono); font-size:0.6rem; text-transform:uppercase; letter-spacing:1px; color:var(--muted);">New Access Key</label>
            <input type="password" id="nP" class="input" style="margin: 8px 0 20px;" placeholder="Enter new key…">
            <button onclick="upAcc()" class="btn btn-primary" style="width:100%;">Save Key</button>
          </div>
          <script>async function upAcc(){ var p=document.getElementById('nP').value; if(!p) return; await fetch("/api/update-account?entity=${eId}&pass="+encodeURIComponent(p),{method:"POST"}); alert("Access key saved."); }</script>`;
      }

      const tabs = [
        { id: "audit",  label: "Audit" },
        { id: "market", label: "Marketplaces" },
        { id: "faq",    label: "Resources" },
      ];

      return new Response(`<!DOCTYPE html><html><head>${brandHead}<title>BotRev · ${eId.toUpperCase()}</title></head><body>
<div class="top-bar">
  <div class="top-bar-inner">
    <div style="display:flex; align-items:center; gap:16px;">
      <a class="logo" href="#">Bot<span>Rev</span></a>
      <div style="width:1px; height:20px; background:rgba(168,197,232,0.2);"></div>
      <div style="font-family:var(--font-mono); font-size:0.75rem; font-weight:500; letter-spacing:1px; color:#A8C5E8;">${eId.toUpperCase()}</div>
      ${isAdmin ? '<span class="badge badge-error">Admin View</span>' : ''}
    </div>
    <div class="top-bar-right">
      <a href="?entity=${eId}&tab=account" class="btn btn-ghost btn-sm">Account</a>
      <a href="/login" class="btn btn-ghost btn-sm">Logout</a>
    </div>
  </div>
</div>
<div class="wrap" style="padding-top:32px; padding-bottom:80px;">
  <div class="tab-nav">
    ${tabs.map(t => `<a href="?entity=${eId}&tab=${t.id}&range=${range}" class="tab-link ${tab===t.id?'active':''}">${t.label}</a>`).join('')}
  </div>
  ${tabContent}
</div>
</body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // 12. LOGIN
    // ============================================================
    if (path === "/login") {
      if (request.method === "POST") {
        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const rateCheck = await checkAdminRateLimit(ip, '/login', env);
        if (!rateCheck.allowed) {
          return new Response('Too many login attempts. Try again in 60 seconds.', {
            status: 429,
            headers: { 'Retry-After': String(rateCheck.retryAfter) }
          });
        }
        const d = await request.formData();
        const u = (d.get("user") || "").trim().toLowerCase();
        const p = (d.get("pass") || "").trim();
        if (p === ADMIN_PASSWORD) {
          const sessionToken = await createSessionToken(ADMIN_PASSWORD);
          return new Response(null, {
            status: 302,
            headers: {
              'Location': url.origin + SECRET_ADMIN_PATH,
              'Set-Cookie': sessionCookieHeader(sessionToken),
            },
          });
        }
        const auth = await env.DB.prepare("SELECT pub_user_id FROM publisher_entities WHERE LOWER(pub_user_id) = ? AND password = ? LIMIT 1").bind(u, p).first();
        if (auth) return Response.redirect(url.origin + "/dashboard?entity=" + auth.pub_user_id.toLowerCase(), 302);
        return new Response(`<!DOCTYPE html><html><head>${brandHead}</head><body>
<div style="display:flex; justify-content:center; align-items:center; min-height:100vh; background: linear-gradient(135deg, #1E3A5F 0%, #2D5A8E 50%, #1E3A5F 100%);">
  <div class="card" style="width:360px; text-align:center; box-shadow: 0 20px 60px rgba(30,58,95,0.3);">
    <a class="logo" href="#" style="font-size:1.6rem;">Bot<span>Rev</span></a>
    <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--red); margin:12px 0;">Invalid credentials</div>
    <form method="POST" style="text-align:left;"><label class="stat-label">Network ID</label><input name="user" class="input" style="margin:6px 0 14px;" required><label class="stat-label">Access Key</label><input name="pass" type="password" class="input" style="margin:6px 0 20px;" required><button class="btn btn-primary" style="width:100%;">Sign In</button></form>
  </div>
</div></body></html>`, { headers: { "Content-Type": "text/html" } });
      }

      return new Response(`<!DOCTYPE html><html><head>${brandHead}</head><body>
<div style="display:flex; justify-content:center; align-items:center; min-height:100vh; background: linear-gradient(135deg, #1E3A5F 0%, #2D5A8E 50%, #1E3A5F 100%);">
  <div class="card" style="width:360px; text-align:center; box-shadow: 0 20px 60px rgba(30,58,95,0.3);">
    <a class="logo" href="#" style="font-size:1.6rem;">Bot<span>Rev</span></a>
    <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin:8px 0 24px;">Publisher Portal</div>
    <form method="POST" style="text-align:left;"><label class="stat-label">Network ID</label><input name="user" class="input" style="margin:6px 0 14px;" required><label class="stat-label">Access Key</label><input name="pass" type="password" class="input" style="margin:6px 0 20px;" required><button class="btn btn-primary" style="width:100%;">Sign In</button></form>
  </div>
</div></body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // API ENDPOINTS
    // ============================================================

    // v27.2: Rate limit all /api/admin/* endpoints
    if (path.startsWith('/api/admin/')) {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const rateCheck = await checkAdminRateLimit(ip, path, env);
      if (!rateCheck.allowed) {
        return Response.json(
          { ok: false, error: 'Rate limit exceeded. Max 10 admin requests per minute per IP.' },
          { status: 429, headers: { 'Retry-After': String(rateCheck.retryAfter) } }
        );
      }
    }

    // ============================================================
    // /api/generate-report — Claude API personalized audit report
    // ============================================================
    if (path === "/api/generate-report") {
      if (!await isAdminAuthenticated(request, env)) return Response.json({ error: "Unauthorized" }, { status: 401 });
      const auditId = url.searchParams.get("audit_id");
      const range   = url.searchParams.get("range") || "all";
      if (!auditId) return Response.json({ error: "Missing audit_id" }, { status: 400 });

      const publisher = await env.DB.prepare(
        "SELECT * FROM publisher_entities WHERE audit_id = ? LIMIT 1"
      ).bind(auditId).first();
      if (!publisher) return Response.json({ error: "Audit not found" }, { status: 404 });

      const dF = range === "7" ? "AND timestamp > datetime('now','-7 days')"
               : range === "30" ? "AND timestamp > datetime('now','-30 days')" : "";

      const [statsRow, botsResult, topPagesResult, stealthRow, trainingRow] = await Promise.all([
        env.DB.prepare(`SELECT SUM(CASE WHEN is_bot=1 THEN 1 ELSE 0 END) as tB, SUM(CASE WHEN is_stealth=1 THEN 1 ELSE 0 END) as tS, SUM(CASE WHEN is_bot=1 AND is_training=0 THEN cpm_value ELSE 0 END) as tRev, SUM(CASE WHEN is_training=1 THEN 1 ELSE 0 END) as tTraining FROM bot_logs WHERE audit_id = ? ${dF}`).bind(auditId).first(),
        env.DB.prepare(`SELECT bot_name, tier, COUNT(*) as hits, SUM(cpm_value) as revenue FROM bot_logs WHERE audit_id = ? AND is_bot = 1 ${dF} GROUP BY bot_name ORDER BY hits DESC LIMIT 10`).bind(auditId).all(),
        env.DB.prepare(`SELECT path, COUNT(*) as hits FROM bot_logs WHERE audit_id = ? AND is_bot = 1 AND path IS NOT NULL AND path != '' ${dF} GROUP BY path ORDER BY hits DESC LIMIT 10`).bind(auditId).all(),
        env.DB.prepare(`SELECT COUNT(*) as cnt FROM bot_logs WHERE audit_id = ? AND is_stealth = 1 ${dF}`).bind(auditId).first(),
        env.DB.prepare(`SELECT COUNT(*) as cnt FROM bot_logs WHERE audit_id = ? AND is_training = 1 ${dF}`).bind(auditId).first(),
      ]);

      const totalHits     = statsRow?.tB || 0;
      const totalRevenue  = statsRow?.tRev || 0;
      const stealthCount  = stealthRow?.cnt || 0;
      const trainingCount = trainingRow?.cnt || 0;
      const daysOfData    = range === "7" ? 7 : range === "30" ? 30 : null;
      const dailyRate     = daysOfData && totalRevenue > 0 ? totalRevenue / daysOfData : null;
      const projMonthly   = dailyRate ? (dailyRate * 30).toFixed(2) : null;
      const projAnnual    = dailyRate ? (dailyRate * 365).toFixed(2) : null;
      const isSnippet     = publisher.integration_type === "B";
      const today         = new Date().toLocaleDateString("en-US", { year:"numeric", month:"long", day:"numeric" });

      const bots = botsResult.results || [];
      const pages = topPagesResult.results || [];

      const auditContext = {
        publisher: publisher.domain_name,
        auditId,
        integrationName: isSnippet ? "JS Snippet" : "CNAME Standard",
        period: daysOfData ? `${daysOfData} Days` : "All Time",
        date: today,
        totalHits,
        estNetRevenue: totalRevenue.toFixed(4),
        projMonthly: projMonthly || "N/A (select 7 or 30 day range)",
        projAnnual: projAnnual || "N/A",
        stealthCount,
        trainingCount,
        topBots: bots.map(b => {
          const display = getBotDisplayName(b.bot_name || "");
          return { name: display.name, company: display.company, tier: b.tier, hits: b.hits, revenue: (b.revenue||0).toFixed(4) };
        }),
        topPages: pages.map(p => ({ path: p.path, hits: p.hits })),
        isSnippet,
        cnameBenefit: isSnippet ? "40–60% additional bot traffic would be captured by upgrading to CNAME integration." : null,
      };

      try {
        const claudeRes = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
          body: JSON.stringify({
            model: "claude-sonnet-4-20250514",
            max_tokens: 2000,
            system: "You are BotRev's AI report writer. Generate a professional, publisher-facing audit report in clean plain text with section headers. Be specific with the provided numbers. Do not invent data — only use what is provided. Write in a confident, clear tone. The report should feel personalized and actionable, not generic. Output ONLY the report text — no preamble, no markdown backticks.",
            messages: [{
              role: "user",
              content: `Write a BotRev Content Intelligence Audit Report for ${auditContext.publisher} using this data: ${JSON.stringify(auditContext)}

Include these sections:
1. EXECUTIVE SUMMARY — 2-3 sentences with the key numbers. Lead with total bot hits and estimated revenue.
2. TRAFFIC ANALYSIS — Describe the bot composition. Name the top 3-5 bots specifically (use display names and companies). Note any stealth crawlers.
3. REVENUE MODEL — State the ${auditContext.period} net revenue. ${projMonthly ? `Project monthly ($${projMonthly}) and annual ($${projAnnual}) earnings.` : "Note that a 7 or 30-day window is needed for projections."}
4. INTEGRATION STATUS — ${isSnippet ? `Publisher is on JS Snippet integration. Note that upgrading to CNAME would capture an estimated 40-60% more bot traffic including raw HTTP crawlers that skip JavaScript entirely. The T1 Premium AI bots (GPTBot, ClaudeBot, Perplexity) are likely visiting but invisible to the snippet.` : "Publisher is on full CNAME integration — all bot traffic captured at the DNS layer."}
5. THE BIGGER PICTURE — This is the most important section. Explain that the real value of the BotRev audit log is not just the marketplace revenue — it is the tamper-evident, independent record of every AI interaction on the site. This log is the publisher's leverage for direct licensing negotiations with AI companies. As AI bot traffic grows, publishers with audit data will be in a fundamentally stronger negotiating position than those without. Marketplace CPMs are the floor. Direct licensing deals are the ceiling. Encourage the publisher to continue building their audit record and to contact their BotRev account manager about direct licensing opportunities.
6. NEXT STEPS — 3-4 concrete recommendations based on the data.

Sign off: Matt Krampen, Founder — BotRev | matt@botrev.com | botrev.com`
            }]
          })
        });

        const claudeData = await claudeRes.json();
        if (claudeData.type === "error" || claudeData.error) {
          return Response.json({ error: "Claude API error: " + (claudeData.error?.message || JSON.stringify(claudeData)) }, { status: 502 });
        }
        const reportText = claudeData.content?.find(b => b.type === "text")?.text || "";

        const docxBytes = buildReportDocx({
          publisher:      auditContext.publisher,
          auditId,
          period:         auditContext.period,
          integration:    auditContext.integrationName,
          date:           today,
          totalHits:      auditContext.totalHits,
          estNetRevenue:  auditContext.estNetRevenue,
          stealthCount:   auditContext.stealthCount,
          trainingCount:  auditContext.trainingCount,
          topBots:        auditContext.topBots,
          reportText,
        });

        const filename = `BotRev_Audit_${auditId}_${today.replace(/[,\s]+/g,"_")}.docx`;
        return new Response(docxBytes, {
          headers: {
            "Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "Content-Disposition": `attachment; filename="${filename}"`,
            "Access-Control-Allow-Origin": "*",
          }
        });

      } catch(err) {
        return Response.json({ error: "Report generation failed: " + err.message }, { status: 500 });
      }
    }

    // ============================================================
    // /api/generate-fleet-report — Consolidated fleet report via Claude API
    // ============================================================
    if (path === "/api/generate-fleet-report") {
      if (!await isAdminAuthenticated(request, env)) return Response.json({ error: "Unauthorized" }, { status: 401 });
      const idsParam = url.searchParams.get("ids") || "";
      const auditIds = idsParam.split(",").map(s => s.trim()).filter(Boolean);
      if (auditIds.length === 0) return Response.json({ error: "No publisher IDs provided" }, { status: 400 });

      const today = new Date().toLocaleDateString("en-US", { year:"numeric", month:"long", day:"numeric" });

      const publisherData = await Promise.all(auditIds.map(async (auditId) => {
        const [publisher, statsRow, botsResult, trainingRow] = await Promise.all([
          env.DB.prepare("SELECT * FROM publisher_entities WHERE audit_id = ? LIMIT 1").bind(auditId).first(),
          env.DB.prepare("SELECT SUM(CASE WHEN is_bot=1 THEN 1 ELSE 0 END) as tB, SUM(CASE WHEN is_bot=1 AND is_training=0 THEN cpm_value ELSE 0 END) as tRev, SUM(CASE WHEN is_training=1 THEN 1 ELSE 0 END) as tTraining FROM bot_logs WHERE audit_id = ?").bind(auditId).first(),
          env.DB.prepare("SELECT bot_name, tier, COUNT(*) as hits, SUM(cpm_value) as revenue FROM bot_logs WHERE audit_id = ? AND is_bot = 1 GROUP BY bot_name ORDER BY hits DESC LIMIT 5").bind(auditId).all(),
          env.DB.prepare("SELECT COUNT(*) as cnt FROM bot_logs WHERE audit_id = ? AND is_training = 1").bind(auditId).first(),
        ]);
        if (!publisher) return null;
        const bots = botsResult.results || [];
        return {
          domain: publisher.domain_name,
          auditId,
          integration: publisher.integration_type === "B" ? "JS Snippet" : "CNAME Standard",
          totalHits: statsRow?.tB || 0,
          estRevenue: (statsRow?.tRev || 0).toFixed(4),
          trainingHits: trainingRow?.cnt || 0,
          topBots: bots.map(b => {
            const display = getBotDisplayName(b.bot_name || "");
            return { name: display.name, company: display.company, tier: b.tier, hits: b.hits };
          }),
        };
      }));

      const validData = publisherData.filter(Boolean);
      if (validData.length === 0) return Response.json({ error: "No publishers found" }, { status: 404 });

      const fleetTotalHits = validData.reduce((s, p) => s + p.totalHits, 0);
      const fleetTotalRevenue = validData.reduce((s, p) => s + parseFloat(p.estRevenue), 0).toFixed(4);
      const fleetTrainingHits = validData.reduce((s, p) => s + p.trainingHits, 0);

      try {
        const claudeRes = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": env.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01"
          },
          body: JSON.stringify({
            model: "claude-sonnet-4-20250514",
            max_tokens: 3000,
            system: "You are BotRev's AI report writer. Generate a professional fleet-wide audit report in clean plain text with section headers. NEVER invent, estimate, or substitute numbers — only use what is provided in the data. If a number is not available, say so explicitly. Write in a confident, clear tone. Output ONLY the report text — no preamble, no markdown backticks.",
            messages: [{
              role: "user",
              content: `Write a BotRev Fleet Intelligence Report for ${validData.length} publishers. Date: ${today}.

Fleet summary: ${fleetTotalHits} total bot hits, $${fleetTotalRevenue} est. net revenue, ${fleetTrainingHits} unmonetized training hits.

Publisher data:
${validData.map(p => `- ${p.domain} (${p.integration}): ${p.totalHits} hits, $${p.estRevenue} revenue, ${p.trainingHits} training hits. Top bots: ${p.topBots.map(b => b.name + ' (' + b.company + ', T' + b.tier + ', ' + b.hits + ' hits)').join(', ')}`).join('\n')}

Include sections:
1. FLEET EXECUTIVE SUMMARY — Key numbers across all publishers.
2. PUBLISHER BREAKDOWN — 2-3 sentences per publisher with their specific numbers.
3. BOT LANDSCAPE — Which AI companies are crawling the fleet most aggressively.
4. TRAINING GAP ANALYSIS — Quantify the unmonetized training bot hits and the revenue opportunity.
5. STRATEGIC RECOMMENDATIONS — 3-4 fleet-wide recommendations.

Sign off: Matt Krampen, Founder — BotRev | matt@botrev.com | botrev.com`
            }]
          })
        });

        const claudeData = await claudeRes.json();
        if (claudeData.error) {
          return Response.json({ error: "Claude API error: " + (claudeData.error.message || JSON.stringify(claudeData.error)) }, { status: 502 });
        }
        const reportText = claudeData.content?.find(b => b.type === "text")?.text || "";

        // Build fleet report using same docx generator
        // Use first publisher's data for the cover, fleet totals for stats
        const firstPub = validData[0] || {};
        const docxBytes = buildReportDocx({
          publisher:      validData.map(p => p.domain).join(", "),
          auditId:        validData.map(p => p.auditId).join(", "),
          period:         "Fleet Report",
          integration:    `${validData.length} Publisher${validData.length > 1 ? 's' : ''}`,
          date:           today,
          totalHits:      fleetTotalHits,
          estNetRevenue:  fleetTotalRevenue,
          stealthCount:   0,
          trainingCount:  fleetTrainingHits,
          topBots:        validData.flatMap(p => (p.topBots||[]).slice(0,2)).slice(0,8),
          reportText,
        });

        const filename = `BotRev_Fleet_Report_${today.replace(/[,\s]+/g,"_")}.docx`;
        return new Response(docxBytes, {
          headers: {
            "Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "Content-Disposition": `attachment; filename="${filename}"`,
          }
        });
      } catch(err) {
        return Response.json({ error: "Fleet report generation failed: " + err.message }, { status: 500 });
      }
    }

    if (path === "/api/update-account" && request.method === "POST") {
      const eId = url.searchParams.get("entity");
      const pa  = url.searchParams.get("pass");
      await env.DB.prepare("UPDATE publisher_entities SET password = ? WHERE LOWER(pub_user_id) = ?").bind(pa, eId.toLowerCase()).run();
      return new Response("OK");
    }

    if (path === "/api/admin/delete-publisher" && request.method === "POST") {
      if (!await isAdminAuthenticated(request, env)) return Response.json({ ok: false, error: "Unauthorized" }, { status: 401 });
      const auditId = url.searchParams.get("audit_id");
      if (!auditId) return Response.json({ ok: false, error: "Missing audit_id" }, { status: 400 });
      try {
        await env.DB.prepare("DELETE FROM bot_logs               WHERE audit_id = ?").bind(auditId).run();
        await env.DB.prepare("DELETE FROM publisher_marketplaces WHERE audit_id = ?").bind(auditId).run();
        await env.DB.prepare("DELETE FROM surge_events           WHERE audit_id = ?").bind(auditId).run();
        await env.DB.prepare("DELETE FROM publisher_entities     WHERE audit_id = ?").bind(auditId).run();
        return Response.json({ ok: true, deleted: auditId });
      } catch (err) {
        return Response.json({ ok: false, error: err.message }, { status: 500 });
      }
    }

    if (path === "/api/admin/publisher-detail") {
      if (!await isAdminAuthenticated(request, env)) return Response.json({ ok: false, error: "Unauthorized" }, { status: 401 });
      const auditId = url.searchParams.get("audit_id");
      if (!auditId) return Response.json({ ok: false, error: "Missing audit_id" }, { status: 400 });
      const publisher = await env.DB.prepare("SELECT * FROM publisher_entities WHERE audit_id = ? LIMIT 1").bind(auditId).first();
      if (!publisher) return Response.json({ ok: false, error: "Publisher not found" }, { status: 404 });
      const markets = ['TollBit', 'Dappier', 'Microsoft', 'Amazon'];
      const keyRows = await env.DB.prepare("SELECT marketplace_name, api_key FROM publisher_marketplaces WHERE audit_id = ?").bind(auditId).all();
      const keys = {};
      markets.forEach(m => { keys[m] = ""; });
      (keyRows.results || []).forEach(r => { keys[r.marketplace_name] = r.api_key || ""; });
      return Response.json({ ok: true, publisher, keys });
    }

    if (path === "/api/admin/update-publisher" && request.method === "POST") {
      if (!await isAdminAuthenticated(request, env)) return Response.json({ ok: false, error: "Unauthorized" }, { status: 401 });
      let body;
      try { body = await request.json(); } catch { return Response.json({ ok: false, error: "Invalid JSON" }, { status: 400 }); }
      const { original_audit_id, pub_user_id, audit_id, domain_name, email, password, integration_type, origin_server, marketplace } = body;
      if (!original_audit_id || !pub_user_id || !audit_id || !domain_name) return Response.json({ ok: false, error: "Missing required fields" }, { status: 400 });
      try {
        const auditIdChanged = audit_id !== original_audit_id;
        await env.DB.prepare("UPDATE publisher_entities SET pub_user_id=?, audit_id=?, domain_name=?, email=?, password=?, integration_type=?, origin_server=?, marketplace=? WHERE audit_id=?").bind(pub_user_id.toLowerCase(), audit_id, domain_name, email||null, password||null, integration_type||"A", origin_server||null, marketplace||'tollbit', original_audit_id).run();
        if (auditIdChanged) {
          await env.DB.prepare("UPDATE bot_logs SET audit_id=? WHERE audit_id=?").bind(audit_id, original_audit_id).run();
          await env.DB.prepare("UPDATE publisher_marketplaces SET audit_id=? WHERE audit_id=?").bind(audit_id, original_audit_id).run();
          await env.DB.prepare("UPDATE surge_events SET audit_id=? WHERE audit_id=?").bind(audit_id, original_audit_id).run();
        }
        return Response.json({ ok: true, audit_id });
      } catch (err) {
        return Response.json({ ok: false, error: err.message }, { status: 500 });
      }
    }

    if (path === "/api/admin/save-formula" && request.method === "POST") {
      if (!await isAdminAuthenticated(request, env)) return Response.json({ ok: false, error: "Forbidden" }, { status: 403 });
      try {
        const body = await request.json();
        const { audit_id, floor_cpm, beta } = body;
        if (!audit_id) return Response.json({ ok: false, error: "Missing audit_id" }, { status: 400 });
        const pfloor = parseFloat(floor_cpm), b = parseFloat(beta);
        if (isNaN(pfloor) || pfloor <= 0) return Response.json({ ok: false, error: "Invalid floor_cpm" }, { status: 400 });
        if (isNaN(b) || b <= 0 || b > 10) return Response.json({ ok: false, error: "Invalid beta" }, { status: 400 });
        await env.DB.prepare("UPDATE publisher_entities SET floor_cpm = ?, beta = ? WHERE audit_id = ?").bind(pfloor, b, audit_id).run();
        return Response.json({ ok: true, audit_id, floor_cpm: pfloor, beta: b });
      } catch (err) {
        return Response.json({ ok: false, error: err.message }, { status: 500 });
      }
    }

    if (path === "/api/admin/surge-action") {
      // v27.2: Verify HMAC-signed token instead of plain pass= parameter
      const tokenPayload = url.searchParams.get("payload");
      const tokenSig     = url.searchParams.get("sig");

      const legacyPass = url.searchParams.get("pass");
      let surgeId, auditId, action;

      if (tokenPayload && tokenSig) {
        const verified = await verifySurgeToken(tokenPayload, tokenSig, env.ADMIN_PASS || '');
        if (!verified.valid) {
          const isHtml = (request.headers.get("Accept") || "").includes("text/html") || request.method === "GET";
          const msg = verified.reason || 'Invalid or expired token';
          if (isHtml) return new Response(`<!DOCTYPE html><html><head>${brandHead}</head><body><div style="display:flex;justify-content:center;align-items:center;min-height:100vh;"><div class="card" style="max-width:480px;text-align:center;"><div style="font-size:2rem;margin-bottom:12px;">🔒</div><h2 style="color:var(--red);margin-bottom:8px;">Token Invalid</h2><p style="color:var(--muted);font-size:0.88rem;">${msg}</p></div></div></body></html>`, { headers: { "Content-Type": "text/html" } });
          return Response.json({ ok: false, error: msg }, { status: 403 });
        }
        surgeId = verified.surgeId;
        auditId = verified.auditId;
        action  = verified.action;
      } else if (legacyPass && legacyPass === ADMIN_PASSWORD) {
        if (request.method === "POST") {
          try { const body = await request.json(); surgeId=body.id; auditId=body.audit_id; action=body.action; } catch { return Response.json({ ok: false, error: "Invalid JSON" }, { status: 400 }); }
        } else {
          surgeId = url.searchParams.get("id"); auditId = url.searchParams.get("audit_id"); action = url.searchParams.get("action");
        }
      } else if (await isAdminAuthenticated(request, env)) {
        // Session cookie auth for dashboard surge actions
        if (request.method === "POST") {
          try { const body = await request.json(); surgeId=body.id; auditId=body.audit_id; action=body.action; } catch { return Response.json({ ok: false, error: "Invalid JSON" }, { status: 400 }); }
        } else {
          surgeId = url.searchParams.get("id"); auditId = url.searchParams.get("audit_id"); action = url.searchParams.get("action");
        }
      } else {
        return Response.json({ ok: false, error: "Unauthorized — use signed token" }, { status: 401 });
      }

      if (!surgeId || !action) return Response.json({ ok: false, error: "Missing id or action" }, { status: 400 });
      if (!['approve', 'reject'].includes(action)) return Response.json({ ok: false, error: "Invalid action" }, { status: 400 });

      const surgeEvent = await env.DB.prepare("SELECT * FROM surge_events WHERE id = ? LIMIT 1").bind(surgeId).first().catch(() => null);
      if (!surgeEvent) return Response.json({ ok: false, error: "Surge event not found" }, { status: 404 });

      if (surgeEvent.status === 'approved' || surgeEvent.status === 'rejected') {
        const msg = `This surge event was already ${surgeEvent.status}.`;
        const isHtml = (request.headers.get("Accept") || "").includes("text/html") || request.method === "GET";
        if (isHtml) return new Response(`<!DOCTYPE html><html><head>${brandHead}</head><body><div style="display:flex; justify-content:center; align-items:center; min-height:100vh;"><div class="card" style="max-width:480px; text-align:center;"><div style="font-size:2rem; margin-bottom:12px;">ℹ️</div><h2 style="font-size:1.2rem; font-weight:700; color:var(--text); margin-bottom:8px;">Already Actioned</h2><p style="font-size:0.88rem; color:var(--muted); margin-bottom:20px;">${msg}</p><a href="${SURGE_ADMIN_PATH}" class="btn btn-primary">View Surge Intelligence →</a></div></div></body></html>`, { headers: { "Content-Type": "text/html" } });
        return Response.json({ ok: false, error: msg });
      }

      let actionedCpm = null, tollbitResult = null;

      if (action === 'approve') {
        actionedCpm = surgeEvent.recommended_cpm;
        try {
          const pubMarket = await env.DB.prepare("SELECT api_key FROM publisher_marketplaces WHERE audit_id = ? AND marketplace_name = 'TollBit' LIMIT 1").bind(surgeEvent.audit_id).first();
          const tollbitKey = pubMarket?.api_key || env.TOLLBIT_KEY;
          if (tollbitKey) {
            const cpmCents = Math.round(actionedCpm * 100);
            const tbRes = await fetch('https://api.tollbit.com/api/v1/access-rules/rate', { method: 'PATCH', headers: { 'Authorization': `Bearer ${tollbitKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: surgeEvent.domain_name, cpm_rate: cpmCents }) });
            tollbitResult = { status: tbRes.status, ok: tbRes.ok };
          } else {
            tollbitResult = { status: 0, ok: false, note: 'No TollBit API key — manual rate update required' };
          }
        } catch (e) { tollbitResult = { status: 0, ok: false, note: e.message }; }
        await env.DB.prepare("UPDATE surge_events SET status='approved', actioned_cpm=?, actioned_at=datetime('now') WHERE id=?").bind(actionedCpm, surgeId).run();
      } else {
        await env.DB.prepare("UPDATE surge_events SET status='rejected', actioned_at=datetime('now') WHERE id=?").bind(surgeId).run();
      }

      const isHtmlResponse = (request.headers.get("Accept") || "").includes("text/html") || request.method === "GET";
      if (isHtmlResponse) {
        const isApprove = action === 'approve';
        const tollbitNote = isApprove && tollbitResult ? (tollbitResult.ok ? `<div style="background:rgba(0,229,160,0.08); border:1px solid rgba(0,229,160,0.3); border-radius:8px; padding:12px 16px; margin-bottom:16px; font-size:0.82rem; color:var(--green);">✓ Partner rate API responded successfully — rate updated to $${actionedCpm.toFixed(2)} CPM.</div>` : `<div style="background:rgba(245,158,11,0.08); border:1px solid rgba(245,158,11,0.3); border-radius:8px; padding:12px 16px; margin-bottom:16px; font-size:0.82rem; color:#f59e0b;">⚠ Partner API ${tollbitResult.note || 'did not confirm'}. Verify manually.<br><a href="https://app.tollbit.com/content-access" style="color:#f59e0b; text-decoration:underline;" target="_blank">Open partner dashboard →</a></div>`) : '';
        return new Response(`<!DOCTYPE html><html><head>${brandHead}<title>${isApprove?'Surge Approved':'Surge Dismissed'} — BotRev</title></head><body>
<div style="display:flex; justify-content:center; align-items:center; min-height:100vh;">
  <div class="card" style="max-width:520px; text-align:center;">
    <div style="font-size:2.5rem; margin-bottom:12px;">${isApprove?'⚡':'✓'}</div>
    <div style="font-family:var(--font-mono); font-size:0.55rem; letter-spacing:2px; text-transform:uppercase; color:${isApprove?'#f59e0b':'var(--muted)'}; margin-bottom:12px;">Surge Intelligence · Phase 2</div>
    <h2 style="font-size:1.3rem; font-weight:800; color:var(--text); margin-bottom:8px;">${isApprove?`Surge Approved — $${actionedCpm.toFixed(2)} CPM`:'Surge Dismissed'}</h2>
    <p style="font-size:0.88rem; color:var(--muted); margin-bottom:20px; line-height:1.6;">${isApprove?`Recommended rate of $${actionedCpm.toFixed(2)} CPM applied to <strong>${surgeEvent.domain_name}</strong>.`:`Surge event for <strong>${surgeEvent.domain_name}</strong> dismissed.`}</p>
    ${tollbitNote}
    <a href="${SURGE_ADMIN_PATH}" class="btn btn-primary" style="display:inline-block; margin-bottom:10px;">← Back to Surge Intelligence</a><br>
    <a href="${SECRET_ADMIN_PATH}" style="font-family:var(--font-mono); font-size:0.65rem; color:var(--muted); text-decoration:none;">Fleet Command →</a>
  </div>
</div></body></html>`, { headers: { "Content-Type": "text/html" } });
      }

      return Response.json({ ok: true, action, surge_id: surgeId, actioned_cpm: actionedCpm, tollbit: tollbitResult });
    }

    // ============================================================
    // BOT SNIFFER API — /api/sniff  (v27: is_training flag added)
    // ============================================================
    if (path === "/api/sniff") {
      const ua      = request.headers.get("User-Agent") || "Unknown";
      const auditId = url.searchParams.get("audit_id") || "unknown";
      const ref     = request.headers.get("Referer") || "";
      const pagePath = url.searchParams.get("path") || null;

      const botClass = classifyBot(ua);
      const stealth  = isStealthCrawler(request);

      const isCleanHuman = /mozilla|chrome|safari|firefox/i.test(ua)
        && !stealth
        && !botClass;

      if (!isCleanHuman) {
        const effectiveTier  = botClass ? botClass.tier : 4;
        const effectiveCPM   = botClass ? botClass.cpm  : TIERS.TIER4;
        const dampedCPM      = botClass?.isTraining ? 0 : await getDampedCPM(auditId, effectiveCPM);
        const isStealthFlag  = (stealth && !botClass) ? 1 : 0;
        const isTrainingFlag = botClass?.isTraining ? 1 : 0;

        await env.DB.prepare(
          "INSERT INTO bot_logs (audit_id, bot_name, tier, cpm_value, is_bot, is_stealth, is_training, referer, path) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)"
        ).bind(auditId, ua, effectiveTier, dampedCPM, isStealthFlag, isTrainingFlag, ref, pagePath).run();
      }

      return new Response("OK", {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "no-store",
        },
      });
    }

    // ============================================================
    // HEALTH CHECK ENDPOINT — /health
    // ============================================================
    if (path === "/health") {
      const startMs = Date.now();

      let d1Status = "ok";
      let d1LatencyMs = null;
      try {
        const d1Start = Date.now();
        await env.DB.prepare("SELECT 1").first();
        d1LatencyMs = Date.now() - d1Start;
      } catch {
        d1Status = "error";
      }

      let publisherCount = null;
      try {
        const res = await env.DB.prepare(
          "SELECT COUNT(*) as cnt FROM publisher_entities"
        ).first();
        publisherCount = res?.cnt ?? 0;
      } catch { /* non-critical */ }

      const workerLatencyMs = Date.now() - startMs;
      const healthy = d1Status === "ok";

      const body = JSON.stringify({
        status:           healthy ? "ok" : "degraded",
        version:          "28.1-combined",
        timestamp:        new Date().toISOString(),
        d1:               d1Status,
        d1_latency_ms:    d1LatencyMs,
        worker_latency_ms: workerLatencyMs,
        active_publishers: publisherCount,
        region:           request.cf?.colo || "unknown",
      }, null, 2);

      return new Response(body, {
        status: healthy ? 200 : 503,
        headers: {
          "Content-Type":  "application/json",
          "Cache-Control": "no-store, no-cache",
          "X-BotRev-Version": "28.1-combined",
        },
      });
    }

    // ============================================================
    // FALLBACK — pass through to origin
    // ============================================================
    return fetch(request);
}
