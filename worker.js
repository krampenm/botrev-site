/**
 * BotRev Cloudflare Worker — dash.botrev.com
 * Bot Sniffer | Full AOR Infrastructure
 * Version 22.1 — March 2026 — Vault remnants fully purged, 1101 fix
 *
 * BINDINGS REQUIRED in wrangler.toml:
 *   [[d1_databases]]
 *   binding = "DB"
 *   database_name = "botrev-db"
 *   database_id = "<YOUR_D1_ID>"
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let path = url.pathname.toLowerCase();
    if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);

    // CPM Recovery Tiers (value per single hit)
    const TIERS = {
      TIER1: 20.00 / 1000,   // Premium AI
      TIER2: 10.00 / 1000,   // Advanced Scrapers
      TIER3:  5.00 / 1000,   // Verified Search
      TIER4:  1.00 / 1000,   // General/Utility
    };

    // Logarithmic Damper config
    const DAMPER_WINDOW_MINUTES = 10;
    const DAMPER_SURGE_MULTIPLIER = 4; // max 4x CPM during burst

    // ============================================================
    // 0. PUBLISHER DOMAIN INTERCEPT
    // ============================================================
    // When this Worker is deployed as a route on a publisher's domain
    // (e.g. *krampencrawler.com/*), the hostname will NOT be dash.botrev.com.
    // In that case we:
    //   1. Look up the publisher's audit_id by hostname in publisher_entities
    //   2. Run bot detection on every request
    //   3. Log bot hits to D1 tagged with that publisher's audit_id
    //   4. Fetch and return the original request from the publisher's origin
    // Human traffic is passed through transparently with zero latency impact.

    const rawHostname = url.hostname;                          // e.g. www.krampencrawler.com
    const hostname    = rawHostname.replace(/^www\./, '');   // e.g. krampencrawler.com
    const isBotRevDomain = hostname === 'dash.botrev.com' || hostname === 'botrev.com';

    if (!isBotRevDomain) {
      // ── Look up publisher by domain ────────────────────────────
      // Pulls audit_id, integration_type (B/C), and origin_server (Standard/CNAME only)
      let publisherAuditId   = null;
      let integrationType    = "B";
      let publisherOrigin    = null;

      try {
        const pub = await env.DB
          .prepare("SELECT audit_id, integration_type, origin_server FROM publisher_entities WHERE LOWER(domain_name) = LOWER(?) LIMIT 1")
          .bind(hostname)
          .first();
        publisherAuditId = pub?.audit_id       || null;
        integrationType  = pub?.integration_type || "B";
        publisherOrigin  = pub?.origin_server   || null;
      } catch (e) {
        // DB lookup failed — still pass traffic through, just don't log
      }

      // ── Run bot detection ──────────────────────────────────────
      if (publisherAuditId) {
        const ua   = request.headers.get("User-Agent") || "Unknown";
        const ref  = request.headers.get("Referer") || "";
        const path = url.pathname + (url.search || "");
        const botClass = classifyBot(ua);
        const stealth  = isStealthCrawler(request);
        const isCleanHuman = /mozilla|chrome|safari|firefox/i.test(ua) && !stealth && !botClass;

        if (!isCleanHuman) {
          try {
            const effectiveTier = botClass ? botClass.tier : 4;
            const effectiveCPM  = botClass ? botClass.cpm : TIERS.TIER4;
            const dampedCPM     = await getDampedCPM(publisherAuditId, effectiveCPM);
            const isStealthFlag = (stealth && !botClass) ? 1 : 0;

            await env.DB.prepare(
              "INSERT INTO bot_logs (audit_id, bot_name, tier, cpm_value, is_bot, is_stealth, referer, path, domain) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)"
            ).bind(publisherAuditId, ua, effectiveTier, dampedCPM, isStealthFlag, ref, path, rawHostname).run();
          } catch (e) {
            // Log failure — don't block the request
          }
        }
      }

      // ── Pass request through to publisher origin ───────────────
      // Standard (B): Cloudflare for SaaS. Publisher's www CNAMEs to proxy.botrev.com.
      //   → MUST rewrite the URL to their stored origin_server.
      //     Fetching the original URL here would re-enter BotRev's zone → infinite loop.
      //
      // Snippet (C): JS snippet. Never hits this intercept block (snippet calls /api/sniff directly).

      try {
        let fetchURL = request.url;
        let fetchHeaders = new Headers(request.headers);

        if (integrationType === "B" && publisherOrigin) {
          // CRITICAL: Use the apex hostname (no www) for the fetch URL.
          // www.krampencrawler.com CNAMEs to proxy.botrev.com — if we fetch
          // that URL with resolveOverride it re-enters BotRev's Worker and loops.
          // The apex domain (krampencrawler.com) resolves to Cloudflare's proxy
          // for krampencrawler.com's own zone, which correctly forwards to Namecheap.
          // resolveOverride then forces that connection to the real origin IP,
          // bypassing Cloudflare's public DNS. This is exactly what the debug test
          // confirmed returns 200 with LiteSpeed headers from Namecheap.
          const originURL = new URL(request.url);
          originURL.hostname = hostname;   // apex domain, www stripped
          originURL.protocol = "https:";
          fetchURL = originURL.toString();

          fetchHeaders.set("X-Forwarded-Host", rawHostname);  // tell origin the real requested host
          fetchHeaders.set("X-Forwarded-Proto", "https");

          // Replace the incoming User-Agent with a neutral browser UA before
          // forwarding to origin. Cloudflare's Bot Fight Mode on the publisher's
          // zone would otherwise block known bot UAs (GPTBot, CCBot, etc.) before
          // they reach Namecheap. We already logged the real UA to D1 above.
          // The original UA is preserved in X-BotRev-Original-UA for transparency.
          const realUA = fetchHeaders.get("User-Agent") || "";
          if (realUA) fetchHeaders.set("X-BotRev-Original-UA", realUA);
          fetchHeaders.set("User-Agent", "Mozilla/5.0 (compatible; BotRev-Proxy/1.0)");
        }

        const originRequest = new Request(fetchURL, {
          method:  request.method,
          headers: fetchHeaders,
          body:    request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
          redirect: "manual", // don't follow redirects — we handle them below
        });

        let originResponse = await fetch(originRequest, {
          cf: integrationType === "B" && publisherOrigin ? {
            // Force DNS to resolve to the real origin server IP.
            // This bypasses Cloudflare's public DNS so we hit Namecheap's actual
            // server directly, while keeping the hostname intact for correct TLS SNI.
            resolveOverride: publisherOrigin,
          } : {}
        });

        // If origin returns a redirect (e.g. HTTP→HTTPS 301), rewrite the
        // Location header to point back to the public hostname, not the origin IP.
        if (originResponse.status >= 300 && originResponse.status < 400) {
          const location = originResponse.headers.get("Location") || "";
          if (location.includes(publisherOrigin)) {
            const rewritten = location.replace(publisherOrigin, hostname);
            const newHeaders = new Headers(originResponse.headers);
            newHeaders.set("Location", rewritten);
            return new Response(originResponse.body, {
              status: originResponse.status,
              headers: newHeaders,
            });
          }
        }

        return originResponse;
      } catch (e) {
        return new Response("BotRev: Origin unreachable — check origin_server config in Fleet Command (Standard integration)", { status: 502 });
      }
    }

    // ============================================================
    // 1. CORE CONFIGURATION
    // ============================================================
    const ADMIN_PASSWORD    = "Morgan123";
    const SECRET_ADMIN_PATH = "/admin-portal-access";
    const ONBOARDING_PATH   = "/admin-onboard-client";
    const MANAGEMENT_FEE    = 0.15;

    // ============================================================
    // 2. TIER DETECTION ENGINE (Bot Sniffer) — defined above intercept block
    // ============================================================
    function classifyBot(ua = "") {
      const l = ua.toLowerCase();

      // TIER 1 — Premium AI Agents (check BEFORE generic bot patterns)
      if (/gptbot|openai|chatgpt|gpt-?[45]|oai-searchbot|claudebot|claude-web|anthropic|applebot|perplexity|bytespider|ccbot|imagesift|gemini|google-extended|cohere|you\.com|phind|groq|amazonbot|diffbot|meta-externalagent|facebookexternalhit/.test(l)) {
        return { tier: 1, cpm: TIERS.TIER1, label: "Premium AI" };
      }

      // TIER 2 — Advanced Headless / Automation (check BEFORE generic bot)
      // Match full token "headlesschrome" or standalone "headless" keyword
      if (/headlesschrome|puppeteer|selenium|playwright|phantomjs|webdriver|chrome-lighthouse|scrapy|python-requests|axios|go-http-client/.test(l) ||
          /headless/.test(l)) {
        return { tier: 2, cpm: TIERS.TIER2, label: "Headless Scraper" };
      }

      // TIER 3 — Verified Search Engines (check BEFORE generic bot)
      // Use word-boundary style match to catch Mozilla-wrapped UAs like
      // "Mozilla/5.0 (compatible; Googlebot/2.1; ...)"
      if (/googlebot|bingbot|duckduckbot|yahoo! slurp|baiduspider|yandexbot|sogou|exabot/.test(l)) {
        return { tier: 3, cpm: TIERS.TIER3, label: "Verified Search" };
      }

      // TIER 4 — Generic bot detection
      // Exclude common false positives: full browser UAs that contain "http" in
      // a URL (e.g. Googlebot's info URL), or "compatible" desktop UA strings.
      // Only flag as bot if the UA isn't a full Mozilla browser string.
      const isFullBrowserUA = /^mozilla\/5\.0/.test(l) && /applewebkit|gecko\/\d|trident/.test(l);
      if (!isFullBrowserUA && /bot|crawler|spider|scraper|monitor|fetch|scan|archive|feed|rss|wget|curl|java|ruby|php/.test(l)) {
        return { tier: 4, cpm: TIERS.TIER4, label: "Utility Bot" };
      }

      return null; // not a bot
    }

    function isStealthCrawler(request) {
      const ua     = request.headers.get("User-Agent") || "";
      const accept = request.headers.get("Accept") || "";
      const lang   = request.headers.get("Accept-Language") || "";
      const enc    = request.headers.get("Accept-Encoding") || "";

      // Stealth heuristics: looks human but lacks human signals
      const looksHuman = /mozilla|chrome|safari|firefox/i.test(ua);
      const hasHumanAcceptHeader = /text\/html/.test(accept);
      const hasHumanLang  = lang.length > 0;
      const hasHumanEnc   = /gzip/.test(enc);
      const humanScore = [hasHumanAcceptHeader, hasHumanLang, hasHumanEnc].filter(Boolean).length;

      // Stealth = claims to be human browser but missing ≥2 human signals
      return looksHuman && humanScore < 2;
    }

    // ============================================================
    // 3. LOGARITHMIC DAMPER ALGORITHM
    // ============================================================
    async function getDampedCPM(auditId, baseCPM) {
      try {
        const windowStart = new Date(Date.now() - DAMPER_WINDOW_MINUTES * 60 * 1000).toISOString();
        const result = await env.DB
          .prepare("SELECT COUNT(*) as surge FROM bot_logs WHERE audit_id = ? AND timestamp > ?")
          .bind(auditId, windowStart)
          .first();
        const surge = result?.surge || 0;

        // Logarithmic damper: multiplier = 1 + log(surge/anchor + 1)
        // Caps at DAMPER_SURGE_MULTIPLIER to keep rates viable for buyers
        const anchor = 100; // baseline hits per window (set per-publisher in production)
        const rawMultiplier = 1 + Math.log((surge / anchor) + 1);
        const multiplier = Math.min(rawMultiplier, DAMPER_SURGE_MULTIPLIER);

        return baseCPM * multiplier;
      } catch {
        return baseCPM;
      }
    }

    // ============================================================
    // 4. UTILITY HELPERS
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
          "ProRata":   `https://api.prorata.ai/v1/publisher/revenue?days=${days}`,
          "Microsoft": "https://api.bing.com/v1/publisher/revenue",
          "Amazon":    "https://api.amazon.com/v1/publisher/ad-intel",
        };

        const res = await fetch(endpoints[m], {
          headers: {
            "Authorization": `Bearer ${entity.api_key}`,
            "x-api-key": entity.api_key,
            "Content-Type": "application/json",
          },
          signal: AbortSignal.timeout(4000),
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const gross = Number(data.total_earnings || data.revenue || data.earnings || data.amount || 0);

        return { status: "Active", gross, net: gross * (1 - MANAGEMENT_FEE), breakdown: data.bots || data.breakdown || [] };
      } catch (e) {
        return { status: "Sync Error", gross: 0, net: 0, breakdown: [], msg: e.message };
      }
    }

    // ============================================================
    // 5. SHARED BRAND CSS
    // ============================================================
    const brandHead = `
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  /* ── ARCTIC SLATE THEME ─────────────────────────────────────── */
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

  /* Logo — navy background bar at top */
  .top-bar { background: var(--navy); padding: 0 32px; position: sticky; top: 0; z-index: 100;
             box-shadow: 0 2px 12px rgba(30,58,95,0.15); }
  .logo { font-family: var(--font-display); font-weight: 800; font-size: 1.3rem;
          color: var(--green); letter-spacing: 2px; text-transform: uppercase; text-decoration: none; }
  .logo span { color: #A8C5E8; }

  /* Cards */
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: 12px; padding: 24px; margin-bottom: 16px;
          box-shadow: 0 1px 4px rgba(30,58,95,0.06); }
  .card-lit { border-color: var(--navy-mid); border-top: 3px solid var(--green); }

  /* Stats */
  .stat-val { font-family: var(--font-mono); font-size: 2.4rem; font-weight: 500;
              color: var(--navy); line-height: 1; }
  .stat-label { font-family: var(--font-mono); font-size: 0.6rem; letter-spacing: 2px;
                text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }

  /* Buttons */
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

  /* Inputs */
  .input { width: 100%; padding: 11px 14px; background: var(--bg); border: 1px solid var(--border);
           border-radius: 8px; color: var(--text); font-family: var(--font-mono);
           font-size: 0.85rem; outline: none; transition: border-color 0.15s; }
  .input:focus { border-color: var(--green); box-shadow: 0 0 0 3px rgba(16,185,129,0.1); }

  /* Table */
  table { width: 100%; border-collapse: collapse; }
  th { font-family: var(--font-mono); font-size: 0.6rem; letter-spacing: 2px; text-transform: uppercase;
       color: var(--muted); padding: 12px 8px; border-bottom: 2px solid var(--border); text-align: left; }
  td { padding: 14px 8px; border-bottom: 1px solid var(--border); font-size: 0.85rem; vertical-align: middle; }
  tr:hover td { background: var(--surface-2); }

  /* Badges */
  .badge { display: inline-block; font-family: var(--font-mono); font-size: 0.55rem; letter-spacing: 1px;
           font-weight: 500; padding: 3px 7px; border-radius: 4px; text-transform: uppercase; border: 1px solid; }
  .badge-t1 { border-color: var(--green); color: var(--green); background: var(--green-tint); }
  .badge-t2 { border-color: var(--blue); color: var(--blue); background: #EBF2FF; }
  .badge-t3 { border-color: var(--amber); color: var(--amber); background: #FFFBEB; }
  .badge-t4 { border-color: var(--muted); color: var(--muted); background: var(--bg); }
  .badge-active { border-color: var(--green); color: var(--green); background: var(--green-tint); }
  .badge-error  { border-color: var(--red); color: var(--red); background: #FEF2F2; }
  .badge-warn   { border-color: var(--amber); color: var(--amber); background: #FFFBEB; }

  /* Tab nav */
  .tab-nav { display: flex; gap: 4px; margin-bottom: 32px; background: var(--surface);
             border: 1px solid var(--border); border-radius: 10px; padding: 4px; width: fit-content;
             box-shadow: 0 1px 3px rgba(30,58,95,0.06); }
  .tab-link { padding: 8px 20px; border-radius: 7px; font-family: var(--font-mono); font-size: 0.7rem;
              letter-spacing: 1px; text-transform: uppercase; text-decoration: none; color: var(--muted);
              font-weight: 500; transition: all 0.15s; }
  .tab-link.active { background: var(--navy); color: #fff; font-weight: 700; }
  .tab-link:not(.active):hover { color: var(--text); background: var(--bg); }

  /* Pulse dot */
  .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
  .dot-green { background: var(--green); animation: pulse 2s infinite; }
  .dot-amber { background: var(--amber); }
  .dot-gray  { background: var(--muted); }
  @keyframes pulse { 0%,100% { opacity:1; box-shadow: 0 0 0 0 rgba(16,185,129,0.4); } 50% { opacity:.7; box-shadow: 0 0 0 6px rgba(16,185,129,0); } }

  /* Code */
  code { font-family: var(--font-mono); font-size: 0.78rem; background: var(--green-tint);
         color: var(--green-dim); padding: 2px 7px; border-radius: 4px; }

  /* Grid helpers */
  .grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
  .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
  @media(max-width: 768px) { .grid-3,.grid-4 { grid-template-columns: 1fr 1fr; } .grid-2 { grid-template-columns: 1fr; } }


  /* Sniffer wave */
  .sniffer-live { position: relative; overflow: hidden; }
  .sniffer-live::after { content: ''; position: absolute; top: 0; left: -100%; width: 60%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(16,185,129,0.06), transparent);
    animation: sweep 3s linear infinite; }
  @keyframes sweep { to { left: 150%; } }

  /* Tier bar chart */
  .tier-bar { height: 4px; border-radius: 2px; background: var(--border); overflow: hidden; margin-top: 6px; }
  .tier-fill { height: 100%; border-radius: 2px; transition: width 0.6s ease; }

  /* Top bar nav layout */
  .top-bar-inner { display: flex; justify-content: space-between; align-items: center;
                   max-width: 1280px; margin: auto; height: 56px; }
  .top-bar-right { display: flex; gap: 8px; align-items: center; }
  .top-bar .btn-ghost { border-color: rgba(168,197,232,0.3); color: #A8C5E8; }
  .top-bar .btn-ghost:hover { border-color: var(--green); color: var(--green); }
  .top-bar .stat-label { color: #A8C5E8; }
</style>`;

    // ============================================================
    // 6. ADMIN FLEET COMMAND
    // ============================================================
    if (path.startsWith(SECRET_ADMIN_PATH)) {
      const pass = url.searchParams.get("pass");
      if (pass !== ADMIN_PASSWORD) return new Response("Forbidden", { status: 403 });

      const { results } = await env.DB.prepare(`
        SELECT pe.*,
          (SELECT COUNT(*) FROM bot_logs WHERE audit_id = pe.audit_id AND is_bot = 1) as total_bot_hits,
          (SELECT COUNT(*) FROM bot_logs WHERE audit_id = pe.audit_id AND is_bot = 1 AND timestamp > datetime('now','-1 day')) as recent_bot_hits
        FROM publisher_entities pe
      `).all();

      const markets = ['TollBit', 'Dappier', 'ProRata', 'Microsoft', 'Amazon'];
      const fullList = await Promise.all(results.map(async r => {
        const mktData = await Promise.all(markets.map(m => getMarketplaceDetails(r.audit_id, m)));
        return { ...r, total_mkt_gross: mktData.reduce((sum, mk) => sum + mk.gross, 0), mktStats: mktData };
      }));

      const fleetGross = fullList.reduce((sum, r) => sum + r.total_mkt_gross, 0);
      const totalBots  = results.reduce((sum, r) => sum + (r.total_bot_hits || 0), 0);

      return new Response(`<!DOCTYPE html><html><head>${brandHead}<title>Fleet Command — BotRev</title></head><body>
<div class="top-bar">
  <div class="top-bar-inner">
    <div>
      <a class="logo" href="#">Bot<span>Rev</span></a>
      <div style="font-family:var(--font-mono); font-size:0.6rem; letter-spacing:3px; color:#A8C5E8; margin-top:2px; text-transform:uppercase;">Fleet Command · Admin</div>
    </div>
    <div class="top-bar-right">
      <button onclick="exportSelectedCSV()" class="btn btn-ghost btn-sm">↓ Export CSV</button>
      <a href="${ONBOARDING_PATH}?pass=${ADMIN_PASSWORD}" class="btn btn-primary btn-sm">+ Onboard Publisher</a>
    </div>
  </div>
</div>
<div class="wrap" style="padding-top:32px; padding-bottom:80px;">

  <!-- Fleet Stats -->
  <div class="grid-3" style="margin-bottom:32px;">
    <div class="card card-lit sniffer-live">
      <div class="stat-label">Fleet Gross Revenue</div>
      <div class="stat-val" style="color:var(--green);">$${fleetGross.toFixed(2)}</div>
      <div style="margin-top:8px; font-family:var(--font-mono); font-size:0.65rem; color:var(--muted);">BotRev 15% → $${(fleetGross*0.15).toFixed(2)}</div>
    </div>
    <div class="card">
      <div class="stat-label">Total Bot Hits</div>
      <div class="stat-val">${totalBots.toLocaleString()}</div>
    </div>
    <div class="card">
      <div class="stat-label">Active Properties</div>
      <div class="stat-val">${fullList.length}</div>
    </div>
  </div>

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
        return `
        <tr class="net-row">
          <td><input type="checkbox" class="row-cb" data-aid="${r.audit_id}" style="accent-color:var(--green);"></td>
          <td>
            <div style="font-weight:700;">${r.domain_name}</div>
            <div style="font-family:var(--font-mono); font-size:0.65rem; color:var(--muted);">${r.pub_user_id}</div>
            <div style="font-family:var(--font-mono); font-size:0.55rem; margin-top:4px; display:inline-block; padding:1px 7px; border-radius:8px; background:${r.integration_type==='C'?'rgba(245,158,11,0.1)':'rgba(0,229,160,0.07)'}; color:${r.integration_type==='C'?'#f59e0b':'var(--green)'};">${r.integration_type==='C'?'Snippet':'Standard'}</div>
          </td>
          <td>
            <div style="display:flex; align-items:center; gap:6px;">
              <span class="dot ${snPulse ? 'dot-green' : ''}" style="background:${snColor};"></span>
              <span style="font-family:var(--font-mono); font-size:0.6rem; color:${snColor}; letter-spacing:1px;">${snLabel}</span>
            </div>
          </td>
          <td><div style="display:flex; gap:4px;">${r.mktStats.map((m,i)=>`<span class="badge badge-${m.status==='Active'?'active':'error'}">${markets[i][0]}</span>`).join('')}</div></td>
          <td><span style="font-family:var(--font-mono); font-weight:500; color:var(--green);">$${r.total_mkt_gross.toFixed(2)}</span></td>
          <td>
            <div style="display:flex; gap:6px; flex-wrap:wrap;">
              <button onclick="window.location.href='/dashboard?entity=${r.pub_user_id}&mode=admin'" class="btn btn-ghost btn-sm">Dash</button>
              <button onclick="openEditModal('${r.audit_id}')" class="btn btn-ghost btn-sm" style="color:var(--green); border-color:var(--green);">Edit</button>
              <button onclick="var p=document.getElementById('snip-panel-${r.audit_id}');p.style.display=p.style.display==='none'?'block':'none'" class="btn btn-ghost btn-sm" style="font-size:0.65rem;">&lt;/&gt;</button>
              <button onclick="deletePublisher('${r.audit_id}','${r.domain_name}')" class="btn btn-sm" style="background:rgba(239,68,68,0.12); color:#F87171; border:1px solid rgba(239,68,68,0.3);">Delete</button>
            </div>
            <div id="snip-panel-${r.audit_id}" style="display:none; margin-top:8px; position:relative; min-width:320px;">
              <pre id="snip-code-${r.audit_id}" style="font-family:var(--font-mono); font-size:0.6rem; background:rgba(0,0,0,0.25); border:1px solid var(--border); border-radius:6px; padding:10px 50px 10px 12px; color:#a8c5e8; white-space:pre-wrap; word-break:break-all; line-height:1.6; margin:0;">&lt;script&gt;(function(){var u="https://dash.botrev.com/api/sniff?audit_id=${encodeURIComponent(r.audit_id)}";if(navigator.sendBeacon){navigator.sendBeacon(u)}else{fetch(u,{mode:"no-cors",keepalive:true})}})();&lt;/script&gt;</pre>
              <button onclick="navigator.clipboard.writeText(document.getElementById('snip-code-${r.audit_id}').innerText).then(function(){var b=document.getElementById('snip-copy-${r.audit_id}');b.textContent='✓';b.style.color='var(--green)';setTimeout(function(){b.textContent='Copy';b.style.color='';},2000)})" id="snip-copy-${r.audit_id}" style="position:absolute; top:6px; right:6px; font-family:var(--font-mono); font-size:0.58rem; padding:3px 8px; border-radius:4px; border:1px solid var(--border); background:rgba(255,255,255,0.05); color:var(--light-muted); cursor:pointer;">Copy</button>
            </div>
          </td>
        </tr>`;
      }).join('')}
      </tbody>
    </table>
  </div>
</div>

<script>
  const fullData = ${JSON.stringify(fullList)};
  function toggleAll(m){ document.querySelectorAll('.row-cb').forEach(c => { if(c.closest('tr').style.display !== 'none') c.checked = m.checked; }); }
  function filterTable(){ var v = document.getElementById("netSearch").value.toUpperCase(); document.querySelectorAll(".net-row").forEach(r => { r.style.display = r.innerText.toUpperCase().includes(v) ? "" : "none"; }); }

  // ── EDIT MODAL ──────────────────────────────────────────────────
  let _editAuditId = null;

  async function openEditModal(auditId) {
    _editAuditId = auditId;
    document.getElementById('edit-modal').style.display = 'flex';
    document.getElementById('edit-save-btn').textContent = 'Save Changes';
    document.getElementById('edit-save-btn').disabled = false;
    document.getElementById('edit-msg').style.display = 'none';

    // Clear fields while loading
    ['edit-network-id','edit-audit-id','edit-domain','edit-email','edit-password',
     'edit-integration','edit-origin','edit-key-tollbit','edit-key-dappier',
     'edit-key-prorata','edit-key-microsoft','edit-key-amazon'].forEach(id => {
      const el = document.getElementById(id);
      if(el) el.value = '';
    });
    document.getElementById('edit-loading').style.display = 'block';
    document.getElementById('edit-form-body').style.display = 'none';

    const res = await fetch("/api/admin/publisher-detail?audit_id="+encodeURIComponent(auditId)+"&pass="+encodeURIComponent("${ADMIN_PASSWORD}"));
    const data = await res.json();

    document.getElementById('edit-loading').style.display = 'none';
    document.getElementById('edit-form-body').style.display = 'block';

    if(!data.ok){ document.getElementById('edit-msg').textContent = 'Error loading publisher.'; document.getElementById('edit-msg').style.display='block'; return; }

    const p = data.publisher;
    document.getElementById('edit-network-id').value   = p.pub_user_id || '';
    document.getElementById('edit-audit-id').value     = p.audit_id || '';
    document.getElementById('edit-domain').value       = p.domain_name || '';
    document.getElementById('edit-email').value        = p.email || '';
    document.getElementById('edit-password').value     = p.password || '';
    document.getElementById('edit-integration').value  = p.integration_type || 'B';
    document.getElementById('edit-origin').value       = p.origin_server || '';
    document.getElementById('edit-key-tollbit').value  = data.keys['TollBit'] || '';
    document.getElementById('edit-key-dappier').value  = data.keys['Dappier'] || '';
    document.getElementById('edit-key-prorata').value  = data.keys['ProRata'] || '';
    document.getElementById('edit-key-microsoft').value= data.keys['Microsoft'] || '';
    document.getElementById('edit-key-amazon').value   = data.keys['Amazon'] || '';
  }

  function closeEditModal(){
    document.getElementById('edit-modal').style.display = 'none';
    _editAuditId = null;
  }

  async function saveEdit(){
    const btn = document.getElementById('edit-save-btn');
    btn.textContent = 'Saving…';
    btn.disabled = true;

    const payload = {
      original_audit_id: _editAuditId,
      pub_user_id:      document.getElementById('edit-network-id').value.trim().toLowerCase(),
      audit_id:         document.getElementById('edit-audit-id').value.trim(),
      domain_name:      document.getElementById('edit-domain').value.trim(),
      email:            document.getElementById('edit-email').value.trim(),
      password:         document.getElementById('edit-password').value.trim(),
      integration_type: document.getElementById('edit-integration').value.trim(),
      origin_server:    document.getElementById('edit-origin').value.trim() || null,
      keys: {
        TollBit:   document.getElementById('edit-key-tollbit').value.trim(),
        Dappier:   document.getElementById('edit-key-dappier').value.trim(),
        ProRata:   document.getElementById('edit-key-prorata').value.trim(),
        Microsoft: document.getElementById('edit-key-microsoft').value.trim(),
        Amazon:    document.getElementById('edit-key-amazon').value.trim(),
      }
    };

    const res = await fetch("/api/admin/update-publisher?pass="+encodeURIComponent("${ADMIN_PASSWORD}"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    const msg = document.getElementById('edit-msg');
    if(data.ok){
      msg.style.color = 'var(--green)';
      msg.textContent = '✓ Saved successfully. Reloading…';
      msg.style.display = 'block';
      setTimeout(() => { closeEditModal(); location.reload(); }, 1200);
    } else {
      msg.style.color = '#F87171';
      msg.textContent = 'Error: ' + (data.error || 'Unknown error');
      msg.style.display = 'block';
      btn.textContent = 'Save Changes';
      btn.disabled = false;
    }
  }

  // ── DELETE MODAL ────────────────────────────────────────────────
  let _pendingDelete = null;
  function deletePublisher(auditId, domain){
    _pendingDelete = { auditId, domain };
    document.getElementById('del-domain-name').textContent = domain;
    document.getElementById('del-confirm-input').value = '';
    document.getElementById('del-modal').style.display = 'flex';
    document.getElementById('del-confirm-input').focus();
  }
  function closeDeleteModal(){
    document.getElementById('del-modal').style.display = 'none';
    _pendingDelete = null;
  }
  async function confirmDelete(){
    const typed = document.getElementById('del-confirm-input').value.trim();
    if(typed !== 'DELETE'){
      document.getElementById('del-error').style.display = 'block';
      return;
    }
    const btn = document.getElementById('del-confirm-btn');
    btn.textContent = 'Deleting…';
    btn.disabled = true;
    const res = await fetch("/api/admin/delete-publisher?audit_id="+encodeURIComponent(_pendingDelete.auditId)+"&pass="+encodeURIComponent("${ADMIN_PASSWORD}"), {method:"POST"});
    const data = await res.json();
    if(data.ok){
      closeDeleteModal();
      location.reload();
    } else {
      btn.textContent = 'Confirm Delete';
      btn.disabled = false;
      document.getElementById('del-error').textContent = 'Error: ' + (data.error || 'Unknown error');
      document.getElementById('del-error').style.display = 'block';
    }
  }

  document.addEventListener('keydown', function(e){ if(e.key === 'Escape'){ closeDeleteModal(); closeEditModal(); } });

  function exportSelectedCSV(){
    const ids = Array.from(document.querySelectorAll('.row-cb:checked')).map(cb=>cb.getAttribute('data-aid'));
    if(!ids.length) return alert("Select at least one property.");
    const data = fullData.filter(r => ids.includes(r.audit_id));
    let csv = "NetworkID,Domain,Sniffer,TollBit,Dappier,ProRata,GrossRevenue,MgmtFee,NetPayout\\n";
    const markets = ['TollBit','Dappier','ProRata','Microsoft','Amazon'];
    data.forEach(r => {
      const fee = r.total_mkt_gross * 0.15;
      csv += [r.pub_user_id, r.domain_name, r.total_bot_hits > 0 ? 'ACTIVE' : 'OFFLINE',
              ...r.mktStats.map(m=>m.status), r.total_mkt_gross.toFixed(2), fee.toFixed(2), (r.total_mkt_gross-fee).toFixed(2)].join(',') + "\\n";
    });
    const b = new Blob([csv],{type:"text/csv"}), u = URL.createObjectURL(b), a = document.createElement("a");
    a.href=u; a.download="BotRev_Fleet_"+new Date().toISOString().split('T')[0]+".csv"; a.click();
  }
</script>

<!-- ═══════════════════════════════════════════════════════════════ -->
<!-- EDIT PUBLISHER MODAL                                           -->
<!-- ═══════════════════════════════════════════════════════════════ -->
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

      <!-- Publisher Info -->
      <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin-bottom:14px; padding-bottom:8px; border-bottom:1px solid var(--border);">Publisher Info</div>
      <div class="grid-2" style="margin-bottom:14px;">
        <div>
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Network ID</label>
          <input id="edit-network-id" class="input" placeholder="e.g. publisher01" autocomplete="off">
        </div>
        <div>
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Audit ID</label>
          <input id="edit-audit-id" class="input" placeholder="e.g. Audit-001" autocomplete="off">
        </div>
      </div>
      <div style="margin-bottom:14px;">
        <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Domain</label>
        <input id="edit-domain" class="input" placeholder="e.g. techdigest.com" autocomplete="off">
      </div>
      <div class="grid-2" style="margin-bottom:14px;">
        <div>
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Email Contact</label>
          <input id="edit-email" class="input" type="email" placeholder="publisher@domain.com" autocomplete="off">
        </div>
        <div>
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Access Key (Password)</label>
          <input id="edit-password" class="input" type="text" placeholder="Access key" autocomplete="off">
        </div>
      </div>
      <div class="grid-2" style="margin-bottom:24px;">
        <div>
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Integration Type</label>
          <select id="edit-integration" class="input" style="cursor:pointer;">
            <option value="B">B — Standard (CNAME Proxy)</option>
            <option value="C">C — Snippet (JS Tag)</option>
          </select>
        </div>
        <div>
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:6px;">Origin Server</label>
          <input id="edit-origin" class="input" placeholder="e.g. 184.94.213.18 (Standard only)" autocomplete="off">
        </div>
      </div>

      <!-- Marketplace Keys -->
      <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin-bottom:14px; padding-bottom:8px; border-bottom:1px solid var(--border);">Marketplace API Keys</div>
      <div class="grid-2" style="margin-bottom:14px;">
        <div>
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--green); display:block; margin-bottom:6px;">TollBit</label>
          <input id="edit-key-tollbit" class="input" placeholder="API key" autocomplete="off">
        </div>
        <div>
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--blue); display:block; margin-bottom:6px;">Dappier</label>
          <input id="edit-key-dappier" class="input" placeholder="API key" autocomplete="off">
        </div>
      </div>
      <div class="grid-2" style="margin-bottom:14px;">
        <div>
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:var(--amber); display:block; margin-bottom:6px;">ProRata</label>
          <input id="edit-key-prorata" class="input" placeholder="API key" autocomplete="off">
        </div>
        <div>
          <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:#00a4ef; display:block; margin-bottom:6px;">Microsoft</label>
          <input id="edit-key-microsoft" class="input" placeholder="API key" autocomplete="off">
        </div>
      </div>
      <div style="margin-bottom:24px;">
        <label style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:#ff9900; display:block; margin-bottom:6px;">Amazon</label>
        <input id="edit-key-amazon" class="input" placeholder="API key" autocomplete="off">
      </div>

      <div id="edit-msg" style="display:none; font-family:var(--font-mono); font-size:0.75rem; margin-bottom:14px; padding:10px 14px; border-radius:6px; background:var(--bg);"></div>

      <div style="display:flex; gap:10px;">
        <button onclick="closeEditModal()" style="flex:1; padding:11px; background:var(--bg); color:var(--muted); border:1px solid var(--border); border-radius:8px; cursor:pointer; font-weight:600; font-size:0.88rem;">Cancel</button>
        <button id="edit-save-btn" onclick="saveEdit()" style="flex:2; padding:11px; background:var(--green); color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:700; font-size:0.88rem;">Save Changes</button>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════ -->
<!-- DELETE CONFIRMATION MODAL                                      -->
<!-- ═══════════════════════════════════════════════════════════════ -->
<div id="del-modal" style="display:none; position:fixed; inset:0; z-index:1001; background:rgba(10,20,35,0.85); backdrop-filter:blur(6px); justify-content:center; align-items:center; padding:24px;">
  <div style="background:#0d1f33; border:1px solid rgba(239,68,68,0.3); border-top:3px solid #EF4444; border-radius:14px; padding:36px; width:100%; max-width:420px; box-shadow:0 32px 80px rgba(0,0,0,0.5);">
    <div style="font-family:'DM Mono',monospace; font-size:0.58rem; letter-spacing:3px; text-transform:uppercase; color:#F87171; margin-bottom:10px;">⚠ Permanent Action</div>
    <h3 style="font-size:1.1rem; font-weight:700; color:#fff; margin-bottom:8px;">Delete Publisher</h3>
    <p style="font-size:0.87rem; color:#A8C5E8; line-height:1.6; margin-bottom:6px;">You are about to permanently delete:</p>
    <div id="del-domain-name" style="font-family:'DM Mono',monospace; font-size:1rem; font-weight:500; color:#F87171; margin-bottom:16px; padding:10px 14px; background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.2); border-radius:8px;"></div>
    <p style="font-size:0.83rem; color:#A8C5E8; line-height:1.7; margin-bottom:20px;">This will erase the publisher account, all bot logs, and all marketplace keys. <strong style="color:#fff;">This cannot be undone.</strong></p>
    <label style="font-family:'DM Mono',monospace; font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:#A8C5E8; display:block; margin-bottom:8px;">Type DELETE to confirm</label>
    <input id="del-confirm-input" type="text" placeholder="DELETE" autocomplete="off"
      style="width:100%; padding:11px 14px; background:#0a1622; border:1px solid rgba(239,68,68,0.3); border-radius:8px; color:#fff; font-family:'DM Mono',monospace; font-size:0.95rem; outline:none; margin-bottom:8px; letter-spacing:2px;"
      oninput="document.getElementById('del-error').style.display='none'"
      onkeydown="if(event.key==='Enter') confirmDelete()">
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
    // 7. BOT SNIFFER API — /api/sniff
    // ============================================================
    if (path === "/api/sniff") {
      const ua      = request.headers.get("User-Agent") || "Unknown";
      const auditId = url.searchParams.get("audit_id") || "unknown";
      const ref     = request.headers.get("Referer") || "";

      const botClass = classifyBot(ua);
      const stealth  = isStealthCrawler(request);

      // COMPLIANCE FILTER: Never log clean human browsers.
      // A "clean human" is a request that:
      //   1. Has a recognizable human browser UA (Chrome, Safari, Firefox, Mozilla)
      //   2. Does NOT trigger stealth crawler heuristics
      //   3. Does NOT match any bot tier pattern
      // This keeps us GDPR/CCPA compliant — bots are not natural persons,
      // so bot logs are not "personal data" under either regulation.
      // We never store IP addresses for the same reason.
      const isCleanHuman = /mozilla|chrome|safari|firefox/i.test(ua)
        && !stealth
        && !botClass;

      if (!isCleanHuman) {
        // Log ALL non-human traffic.
        // Confirmed bots get their detected tier; everything else is Tier 4 Utility.
        const effectiveTier = botClass ? botClass.tier : 4;
        const effectiveCPM  = botClass ? botClass.cpm : TIERS.TIER4;
        const dampedCPM     = await getDampedCPM(auditId, effectiveCPM);
        const isStealthFlag = (stealth && !botClass) ? 1 : 0;

        await env.DB.prepare(
          "INSERT INTO bot_logs (audit_id, bot_name, tier, cpm_value, is_bot, is_stealth, referer) VALUES (?, ?, ?, ?, 1, ?, ?)"
        ).bind(auditId, ua, effectiveTier, dampedCPM, isStealthFlag, ref).run();
      }

      return new Response("OK", {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "no-store",
        },
      });
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
        `SELECT bot_name, tier, COUNT(*) as c, SUM(cpm_value) as revenue FROM bot_logs WHERE audit_id = ? AND is_bot = 1 ${dF} GROUP BY bot_name ORDER BY revenue DESC`
      ).bind(aid).all();

      const { results: stealth } = await env.DB.prepare(
        `SELECT COUNT(*) as cnt FROM bot_logs WHERE audit_id = ? AND is_stealth = 1 ${dF}`
      ).bind(aid).all();

      let totalRec = 0;
      bots.forEach(b => totalRec += (b.revenue || 0));

      const tierColors = { 1: "var(--green)", 2: "var(--blue)", 3: "var(--amber)", 4: "var(--muted)" };
      const tierBadge  = { 1: "badge-t1", 2: "badge-t2", 3: "badge-t3", 4: "badge-t4" };

      return new Response(`<!DOCTYPE html><html><head>${brandHead}<title>Domain Drilldown — ${dName}</title></head><body>
<div class="wrap" style="padding-top:32px; padding-bottom:80px;">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:32px;">
    <button onclick="history.back()" class="btn btn-ghost btn-sm">← Back</button>
    <div style="font-family:var(--font-mono); font-size:0.7rem; color:var(--muted); text-transform:uppercase; letter-spacing:2px;">Audit · ${dName}</div>
    <div style="font-family:var(--font-mono); font-size:0.9rem; color:var(--green);">$${totalRec.toFixed(4)} est. recovered</div>
  </div>

  <div class="grid-3" style="margin-bottom:24px;">
    <div class="card"><div class="stat-label">Total Bot Hits</div><div class="stat-val">${bots.reduce((a,b)=>a+b.c,0).toLocaleString()}</div></div>
    <div class="card"><div class="stat-label">Est. Recovery Potential</div><div class="stat-val" style="color:var(--green);">$${totalRec.toFixed(4)}</div></div>
    <div class="card"><div class="stat-label">Stealth Crawlers</div><div class="stat-val" style="color:var(--amber);">${stealth[0]?.cnt || 0}</div></div>
  </div>

  <div class="card">
    <table>
      <thead><tr><th>Bot Agent</th><th>Tier</th><th>Hits</th><th style="text-align:right;">Est. Recovery</th></tr></thead>
      <tbody>
      ${bots.map(b => {
        // Re-classify UA on the fly so old log entries with wrong stored tier
        // automatically display the correct tier without needing a DB migration.
        const reclassified = classifyBot(b.bot_name || "");
        const t = reclassified ? reclassified.tier : (b.tier || 4);
        return `<tr>
          <td><code>${(b.bot_name || "").substring(0, 80)}</code></td>
          <td><span class="badge ${tierBadge[t]}">T${t}</span></td>
          <td style="font-family:var(--font-mono);">${b.c.toLocaleString()}</td>
          <td style="text-align:right; font-family:var(--font-mono); color:${tierColors[t]};">$${(b.revenue||0).toFixed(6)}</td>
        </tr>`;
      }).join('')}
      </tbody>
    </table>
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
      const mColor = { TollBit: "var(--green)", Dappier: "var(--blue)", ProRata: "var(--amber)", Microsoft: "#00a4ef", Amazon: "#ff9900" }[m] || "var(--green)";

      return new Response(`<!DOCTYPE html><html><head>${brandHead}</head><body>
<div class="wrap" style="padding-top:32px; padding-bottom:80px;">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:32px;">
    <button onclick="history.back()" class="btn btn-ghost btn-sm">← Back</button>
    <div style="font-family:var(--font-mono); font-size:0.9rem; color:${mColor};">${m} NET: $${det.net.toFixed(4)}</div>
  </div>
  <div class="card" style="border-left: 3px solid ${mColor};">
    <div style="font-family:var(--font-mono); font-size:0.65rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin-bottom:20px;">${m} · Breakdown</div>
    <table>
      <thead><tr><th>Agent</th><th>Requests</th><th style="text-align:right;">Net Revenue</th></tr></thead>
      <tbody>
      ${det.breakdown.length > 0
        ? det.breakdown.map(b => `<tr><td><code>${b.name || b.bot}</code></td><td style="font-family:var(--font-mono);">${(b.count || b.hits || 0).toLocaleString()}</td><td style="text-align:right; font-family:var(--font-mono); color:${mColor};">$${((b.revenue||0)*(1-MANAGEMENT_FEE)).toFixed(6)}</td></tr>`).join('')
        : '<tr><td colspan="3" style="text-align:center; padding:40px; color:var(--muted);">No breakdown data available from API.</td></tr>'}
      </tbody>
    </table>
  </div>
</div></body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // 10. ONBOARDING PAGE
    // ============================================================
    if (path === ONBOARDING_PATH) {
      const pass = url.searchParams.get("pass");
      if (pass !== ADMIN_PASSWORD) return new Response("Unauthorized", { status: 401 });

      if (request.method === "POST") {
        try {
          const formData = await request.formData();
          const file     = formData.get("csv_file");
          const content  = await file.text();
          const lines    = content.split('\n').filter(l => l.trim() !== "");
          let imported   = 0;

          for (const line of lines) {
            const parts = line.split(',').map(s => s.trim());
            if (parts.length < 6) continue;
            const [net, aid, dom, mkt, key, p, intType, origin] = parts;
            const integType   = intType  || "B";
            const originSvr   = origin   || null;
            await env.DB.prepare("INSERT OR IGNORE INTO publisher_entities (pub_user_id, audit_id, domain_name, password, integration_type, origin_server) VALUES (?, ?, ?, ?, ?, ?)").bind(net.toLowerCase(), aid, dom, p, integType, originSvr).run();
            await env.DB.prepare("INSERT OR IGNORE INTO publisher_marketplaces (audit_id, marketplace_name, api_key) VALUES (?, ?, ?)").bind(aid, mkt, key).run();
            imported++;
          }
          return Response.redirect(url.origin + SECRET_ADMIN_PATH + "?pass=" + ADMIN_PASSWORD, 302);
        } catch (e) {
          return new Response("Error: " + e.message, { status: 500 });
        }
      }

      return new Response(`<!DOCTYPE html><html><head>${brandHead}</head><body>
<div class="wrap" style="display:flex; justify-content:center; align-items:center; min-height:100vh;">
  <div class="card" style="width:440px;">
    <a class="logo" href="#">Bot<span>Rev</span></a>
    <div style="font-family:var(--font-mono); font-size:0.6rem; letter-spacing:2px; color:var(--muted); margin: 8px 0 24px; text-transform:uppercase;">Fleet Onboarding</div>
    <p style="font-size:0.8rem; color:var(--muted); margin-bottom:20px; line-height:1.6;">
      Upload a CSV. First 6 columns required, last 2 optional:<br>
      <code>NetworkID, AuditID, Domain, Marketplace, APIKey, AccessKey, IntegrationType, OriginServer</code><br><br>
      <b style="color:var(--text);">IntegrationType:</b> B (Standard — CNAME Proxy) or C (Snippet — JS Tag). Defaults to B.<br>
      <b style="color:var(--text);">OriginServer:</b> Required for Option B only. The publisher's real origin hostname (e.g. <code>mysite.wpengine.com</code>).
    </p>
    <form method="POST" enctype="multipart/form-data">
      <input type="file" name="csv_file" class="input" accept=".csv" required style="margin-bottom:12px;">
      <button class="btn btn-primary" style="width:100%;">Execute Bulk Import</button>
    </form>
    <a href="${SECRET_ADMIN_PATH}?pass=${ADMIN_PASSWORD}" class="btn btn-ghost" style="width:100%; margin-top:10px; justify-content:center;">← Back to Fleet Command</a>
  </div>
</div></body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // 11. MAIN PUBLISHER DASHBOARD
    // ============================================================
    if (path === "/dashboard") {
      const eId    = (url.searchParams.get("entity") || "").toLowerCase();
      const tab    = url.searchParams.get("tab") || "audit";
      const range  = url.searchParams.get("range") || "all";
      const isAdmin = url.searchParams.get("mode") === "admin";

      const { results: domains } = await env.DB.prepare(
        "SELECT * FROM publisher_entities WHERE LOWER(pub_user_id) = ?"
      ).bind(eId).all();
      if (domains.length === 0) return new Response("Access Denied", { status: 403 });

      const dateFilter = range === "7" ? "AND timestamp > datetime('now','-7 days')" : range === "30" ? "AND timestamp > datetime('now','-30 days')" : "";
      const filterBar  = `
        <div style="display:flex; gap:8px; margin-bottom:32px;">
          ${["7","30","all"].map(v => `<a href="?entity=${eId}&tab=${tab}&range=${v}" class="btn btn-ghost btn-sm ${range===v?'btn-primary':''}">${v==='all'?'All Time':v+' Days'}</a>`).join('')}
        </div>`;

      let tabContent = "";

      // ---- AUDIT TAB ----
      if (tab === "audit") {
        const stats = await env.DB.prepare(
          `SELECT SUM(CASE WHEN is_bot=1 THEN 1 ELSE 0 END) as tB, SUM(CASE WHEN is_stealth=1 THEN 1 ELSE 0 END) as tS, SUM(CASE WHEN is_bot=1 THEN cpm_value ELSE 0 END) as tRev FROM bot_logs WHERE audit_id IN (${domains.map(()=>'?').join(',')}) ${dateFilter}`
        ).bind(...domains.map(d=>d.audit_id)).first();

        const tierBreak = await env.DB.prepare(
          `SELECT tier, COUNT(*) as c, SUM(cpm_value) as rev FROM bot_logs WHERE is_bot=1 ${dateFilter} AND audit_id IN (${domains.map(()=>'?').join(',')}) GROUP BY tier`
        ).bind(...domains.map(d=>d.audit_id)).all();

        const totalHits = stats?.tB || 0;
        const tierData  = Object.fromEntries((tierBreak.results || []).map(r => [r.tier, r]));
        const tierLabels = { 1: "Premium AI", 2: "Headless", 3: "Search", 4: "Utility" };

        const domainCards = await Promise.all(domains.map(async d => {
          const active = await env.DB.prepare("SELECT timestamp FROM bot_logs WHERE audit_id = ? AND is_bot = 1 LIMIT 1").bind(d.audit_id).first();
          const dnsLive = !!active;
          const dnsStatusColor  = dnsLive ? 'var(--green)' : '#f59e0b';
          const dnsStatusBorder = dnsLive ? 'var(--green)' : 'var(--border)';
          const dnsStatusBg     = dnsLive ? 'rgba(0,229,160,0.05)' : 'transparent';
          const dnsStatusLabel  = dnsLive ? 'DNS Active' : 'DNS Pending';
          const dnsStatusDot    = dnsLive ? 'dot-green' : 'dot-gray';

          return `
          <div class="card ${dnsLive ? 'sniffer-live' : ''}">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px;">
              <div>
                <div style="font-weight:700; font-size:1.05rem;">${d.domain_name}</div>
                <div style="font-family:var(--font-mono); font-size:0.6rem; color:var(--muted); margin-top:3px;">${d.audit_id}</div>
                ${isAdmin ? `<div style="font-family:var(--font-mono); font-size:0.58rem; margin-top:5px; display:inline-block; padding:2px 8px; border-radius:10px; background:${d.integration_type==='C'?'rgba(245,158,11,0.1)':'rgba(0,229,160,0.07)'}; color:${d.integration_type==='C'?'#f59e0b':'var(--green)'};">${d.integration_type==='C'?'Snippet':'Standard'}</div>` : ''}
              </div>
              <div style="display:flex; align-items:center; gap:6px; padding:5px 12px; border-radius:20px; border:1px solid ${dnsStatusBorder}; background:${dnsStatusBg};">
                <span class="dot ${dnsStatusDot}"></span>
                <span style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; color:${dnsStatusColor};">${dnsStatusLabel}</span>
              </div>
            </div>
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
              <a href="/domain-drilldown?audit_id=${d.audit_id}&range=${range}" class="btn btn-primary btn-sm">View Audit Log →</a>
              ${isAdmin ? `` : ''}
            </div>
            
          </div>`;
        }));

        tabContent = `
          ${filterBar}
          <div class="grid-3" style="margin-bottom:24px;">
            <div class="card card-lit"><div class="stat-label">Total Bot Hits</div><div class="stat-val">${totalHits.toLocaleString()}</div></div>
            <div class="card card-lit"><div class="stat-label">Est. Recovery Potential</div><div class="stat-val" style="color:var(--green);">$${(stats?.tRev||0).toFixed(4)}</div></div>
            <div class="card card-lit"><div class="stat-label">Stealth Crawlers</div><div class="stat-val" style="color:var(--amber);">${(stats?.tS||0).toLocaleString()}</div></div>
          </div>
          <div class="card" style="margin-bottom:24px;">
            <div class="stat-label" style="margin-bottom:16px;">Tier Breakdown</div>
            <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:16px;">
              ${[1,2,3,4].map(t => {
                const d = tierData[t] || { c: 0, rev: 0 };
                const pct = totalHits > 0 ? (d.c / totalHits * 100) : 0;
                const colors = { 1: 'var(--green)', 2: 'var(--blue)', 3: 'var(--amber)', 4: 'var(--muted)' };
                return `<div>
                  <div style="font-family:var(--font-mono); font-size:0.58rem; text-transform:uppercase; letter-spacing:1px; color:${colors[t]}; margin-bottom:4px;">T${t} · ${tierLabels[t]}</div>
                  <div style="font-family:var(--font-mono); font-size:1.1rem; font-weight:500;">${d.c.toLocaleString()}</div>
                  <div style="font-family:var(--font-mono); font-size:0.65rem; color:var(--muted);">$${(d.rev||0).toFixed(4)}</div>
                  <div class="tier-bar"><div class="tier-fill" style="width:${pct.toFixed(1)}%; background:${colors[t]};"></div></div>
                </div>`;
              }).join('')}
            </div>
          </div>
          ${domainCards.join('')}`;


      // ---- MARKETS TAB ----
      } else if (tab === "market") {
        const markets = ['TollBit', 'Dappier', 'ProRata', 'Microsoft', 'Amazon'];
        const allMarketData = await Promise.all(domains.map(d =>
          Promise.all(markets.map(m => getMarketplaceDetails(d.audit_id, m, range)))
        ));
        let gNet = 0;
        allMarketData.forEach(dm => dm.forEach(m => { gNet += m.net; }));

        const mktColors = { TollBit: "var(--green)", Dappier: "var(--blue)", ProRata: "var(--amber)", Microsoft: "#00a4ef", Amazon: "#ff9900" };

        tabContent = `
          ${filterBar}
          <div class="card card-lit" style="max-width:380px; margin:0 0 28px; border:1px solid var(--green);">
            <div class="stat-label">Total Network Net Revenue</div>
            <div class="stat-val" style="color:var(--green); font-size:3rem;">$${gNet.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2})}</div>
          </div>
          ${(await Promise.all(domains.map(async (d, idx) => {
            const stats = allMarketData[idx];
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

      // ---- RESOURCES TAB ----
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
                    <div style="color:var(--muted); line-height:1.6; font-size:0.75rem;">Publisher adds one CNAME record pointing <code>www</code> to <code>proxy.botrev.com</code>. Works on any host — Cloudflare, Squarespace, Wix, WordPress, Namecheap, all of it. Full headless + stealth detection. <b style="color:var(--text);">This is the default for all new publishers.</b></div>
                  </div>
                  <div style="background:rgba(245,158,11,0.05); border:1px solid rgba(245,158,11,0.2); border-radius:8px; padding:14px;">
                    <div style="font-family:var(--font-mono); font-size:0.6rem; color:#f59e0b; letter-spacing:1px; margin-bottom:8px;">SNIPPET · FALLBACK</div>
                    <div style="font-weight:700; color:var(--text); margin-bottom:6px;">JS Tag</div>
                    <div style="color:var(--muted); line-height:1.6; font-size:0.75rem;">Publisher pastes a single script tag in their site header. No DNS changes needed. Captures JS-executing bots (T1 AI crawlers) but misses headless scrapers. Best as a quick audit start — migrate to Standard once they're comfortable.</div>
                  </div>
                </div>
              </div>

            </div>
            <div class="card" style="margin-bottom:16px;">
              <div class="stat-label" style="margin-bottom:16px;">CPM Recovery Matrix</div>
              <table>
                <thead><tr><th>Tier</th><th>Bot Class</th><th>Example Agents</th><th style="text-align:right;">CPM</th></tr></thead>
                <tbody>
                  <tr><td><span class="badge badge-t1">T1</span></td><td style="font-weight:700;">Premium AI</td><td style="font-size:0.75rem; color:var(--muted);">OpenAI, Claude, AppleBot, Perplexity, ByteSpider</td><td style="text-align:right; font-family:var(--font-mono); color:var(--green);">~$20.00 est.</td></tr>
                  <tr><td><span class="badge badge-t2">T2</span></td><td style="font-weight:700;">Headless Scrapers</td><td style="font-size:0.75rem; color:var(--muted);">Puppeteer, Playwright, Selenium, HeadlessChrome</td><td style="text-align:right; font-family:var(--font-mono); color:var(--blue);">~$10.00 est.</td></tr>
                  <tr><td><span class="badge badge-t3">T3</span></td><td style="font-weight:700;">Verified Search</td><td style="font-size:0.75rem; color:var(--muted);">Googlebot, Bingbot, DuckDuckBot, Baidu</td><td style="text-align:right; font-family:var(--font-mono); color:var(--amber);">~$5.00 est.</td></tr>
                  <tr><td><span class="badge badge-t4">T4</span></td><td style="font-weight:700;">Utility Bots</td><td style="font-size:0.75rem; color:var(--muted);">General crawlers, scrapers, unidentified agents</td><td style="text-align:right; font-family:var(--font-mono); color:var(--muted);">~$1.00 est.</td></tr>
                </tbody>
              </table>
            </div>
            <div class="card">
              <div class="stat-label" style="margin-bottom:16px;">How BotRev Works</div>
              <div style="font-size:0.85rem; color:var(--muted); line-height:1.9;">
                BotRev sits between AI crawlers and your origin server, classifying every bot request in real time and routing verified AI agents to your marketplace partners.<br><br>
                <b style="color:var(--text);">Traffic Layer:</b> One CNAME record — BotRev handles everything else.<br>
                <b style="color:var(--text);">Tier Classification:</b> Every bot is scored T1–T4 by identity and intent.<br>
                <b style="color:var(--text);">Marketplace Routing:</b> Verified AI hits are billed via TollBit, Dappier, and partners.<br>
                <b style="color:var(--text);">Revenue Reporting:</b> Real-time earnings tracked per domain, per marketplace.
              </div>
            </div>
          </div>`;

      // ---- ACCOUNT TAB ----
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

<script>
// copySnip removed — sniffer runs via publisher CNAME record, no script installation needed
</script>
</body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // 12. LOGIN
    // ============================================================
    if (path === "/login") {
      if (request.method === "POST") {
        const d = await request.formData();
        const u = (d.get("user") || "").trim().toLowerCase();
        const p = (d.get("pass") || "").trim();
        if (p === ADMIN_PASSWORD) return Response.redirect(url.origin + SECRET_ADMIN_PATH + "?pass=" + p, 302);
        const auth = await env.DB.prepare("SELECT pub_user_id FROM publisher_entities WHERE LOWER(pub_user_id) = ? AND password = ? LIMIT 1").bind(u, p).first();
        if (auth) return Response.redirect(url.origin + "/dashboard?entity=" + auth.pub_user_id.toLowerCase(), 302);
        return new Response(`<!DOCTYPE html><html><head>${brandHead}</head><body>
<div style="display:flex; justify-content:center; align-items:center; min-height:100vh; background: linear-gradient(135deg, #1E3A5F 0%, #2D5A8E 50%, #1E3A5F 100%);">
  <div class="card" style="width:360px; text-align:center; box-shadow: 0 20px 60px rgba(30,58,95,0.3);">
    <a class="logo" href="#" style="font-size:1.6rem;">Bot<span>Rev</span></a>
    <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--red); margin:12px 0;">Invalid credentials</div>
    <form method="POST" style="text-align:left;">
      <label class="stat-label">Network ID</label>
      <input name="user" class="input" style="margin:6px 0 14px;" required>
      <label class="stat-label">Access Key</label>
      <input name="pass" type="password" class="input" style="margin:6px 0 20px;" required>
      <button class="btn btn-primary" style="width:100%;">Sign In</button>
    </form>
  </div>
</div></body></html>`, { headers: { "Content-Type": "text/html" } });
      }

      return new Response(`<!DOCTYPE html><html><head>${brandHead}</head><body>
<div style="display:flex; justify-content:center; align-items:center; min-height:100vh; background: linear-gradient(135deg, #1E3A5F 0%, #2D5A8E 50%, #1E3A5F 100%);">
  <div class="card" style="width:360px; text-align:center; box-shadow: 0 20px 60px rgba(30,58,95,0.3);">
    <a class="logo" href="#" style="font-size:1.6rem;">Bot<span>Rev</span></a>
    <div style="font-family:var(--font-mono); font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin:8px 0 24px;">Publisher Portal</div>
    <form method="POST" style="text-align:left;">
      <label class="stat-label">Network ID</label>
      <input name="user" class="input" style="margin:6px 0 14px;" required>
      <label class="stat-label">Access Key</label>
      <input name="pass" type="password" class="input" style="margin:6px 0 20px;" required>
      <button class="btn btn-primary" style="width:100%;">Sign In</button>
    </form>
  </div>
</div></body></html>`, { headers: { "Content-Type": "text/html" } });
    }

    // ============================================================
    // 13. MISC API
    // ============================================================
    if (path === "/api/update-account" && request.method === "POST") {
      const eId = url.searchParams.get("entity");
      const pa  = url.searchParams.get("pass");
      await env.DB.prepare("UPDATE publisher_entities SET password = ? WHERE LOWER(pub_user_id) = ?").bind(pa, eId.toLowerCase()).run();
      return new Response("OK");
    }

    // ============================================================
    // 14. DELETE PUBLISHER — POST /api/admin/delete-publisher
    // ============================================================
    if (path === "/api/admin/delete-publisher" && request.method === "POST") {
      const pass    = url.searchParams.get("pass");
      const auditId = url.searchParams.get("audit_id");

      if (pass !== ADMIN_PASSWORD) {
        return Response.json({ ok: false, error: "Unauthorized" }, { status: 401 });
      }
      if (!auditId) {
        return Response.json({ ok: false, error: "Missing audit_id" }, { status: 400 });
      }

      try {
        // Delete from all D1 tables
        await env.DB.prepare("DELETE FROM bot_logs              WHERE audit_id = ?").bind(auditId).run();
        await env.DB.prepare("DELETE FROM publisher_marketplaces WHERE audit_id = ?").bind(auditId).run();
        await env.DB.prepare("DELETE FROM publisher_entities    WHERE audit_id = ?").bind(auditId).run();

        return Response.json({ ok: true, deleted: auditId });
      } catch (err) {
        return Response.json({ ok: false, error: err.message }, { status: 500 });
      }
    }

    // ============================================================
    // 15. GET PUBLISHER DETAIL — GET /api/admin/publisher-detail
    // ============================================================
    if (path === "/api/admin/publisher-detail") {
      const pass    = url.searchParams.get("pass");
      const auditId = url.searchParams.get("audit_id");
      if (pass !== ADMIN_PASSWORD) return Response.json({ ok: false, error: "Unauthorized" }, { status: 401 });
      if (!auditId)               return Response.json({ ok: false, error: "Missing audit_id" }, { status: 400 });

      const publisher = await env.DB
        .prepare("SELECT * FROM publisher_entities WHERE audit_id = ? LIMIT 1")
        .bind(auditId).first();
      if (!publisher) return Response.json({ ok: false, error: "Publisher not found" }, { status: 404 });

      const markets = ['TollBit', 'Dappier', 'ProRata', 'Microsoft', 'Amazon'];
      const keyRows = await env.DB
        .prepare("SELECT marketplace_name, api_key FROM publisher_marketplaces WHERE audit_id = ?")
        .bind(auditId).all();
      const keys = {};
      markets.forEach(m => { keys[m] = ""; });
      (keyRows.results || []).forEach(r => { keys[r.marketplace_name] = r.api_key || ""; });

      return Response.json({ ok: true, publisher, keys });
    }

    // ============================================================
    // 16. UPDATE PUBLISHER — POST /api/admin/update-publisher
    // ============================================================
    if (path === "/api/admin/update-publisher" && request.method === "POST") {
      const pass = url.searchParams.get("pass");
      if (pass !== ADMIN_PASSWORD) return Response.json({ ok: false, error: "Unauthorized" }, { status: 401 });

      let body;
      try { body = await request.json(); } catch { return Response.json({ ok: false, error: "Invalid JSON" }, { status: 400 }); }

      const { original_audit_id, pub_user_id, audit_id, domain_name, email, password, integration_type, origin_server, keys } = body;
      if (!original_audit_id || !pub_user_id || !audit_id || !domain_name) {
        return Response.json({ ok: false, error: "Missing required fields" }, { status: 400 });
      }

      try {
        const auditIdChanged = audit_id !== original_audit_id;

        // 1. Update publisher_entities
        await env.DB.prepare(
          "UPDATE publisher_entities SET pub_user_id=?, audit_id=?, domain_name=?, email=?, password=?, integration_type=?, origin_server=? WHERE audit_id=?"
        ).bind(
          pub_user_id.toLowerCase(), audit_id, domain_name,
          email || null, password || null,
          integration_type || "B", origin_server || null,
          original_audit_id
        ).run();

        // 2. If audit_id changed, cascade to related tables
        if (auditIdChanged) {
          await env.DB.prepare("UPDATE bot_logs SET audit_id=? WHERE audit_id=?").bind(audit_id, original_audit_id).run();
          await env.DB.prepare("UPDATE publisher_marketplaces SET audit_id=? WHERE audit_id=?").bind(audit_id, original_audit_id).run();
        }

        // 3. Upsert marketplace keys
        const markets = ['TollBit', 'Dappier', 'ProRata', 'Microsoft', 'Amazon'];
        for (const m of markets) {
          const apiKey = (keys && keys[m]) ? keys[m].trim() : "";
          if (apiKey) {
            await env.DB.prepare(
              "INSERT INTO publisher_marketplaces (audit_id, marketplace_name, api_key) VALUES (?, ?, ?) ON CONFLICT(audit_id, marketplace_name) DO UPDATE SET api_key=excluded.api_key"
            ).bind(audit_id, m, apiKey).run();
          }
        }

        return Response.json({ ok: true, audit_id });
      } catch (err) {
        return Response.json({ ok: false, error: err.message }, { status: 500 });
      }
    }

    return fetch(request);
  },
};
