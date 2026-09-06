/**
 * Email Data Metrics - Backend API (v3)
 *
 * What changed vs v2
 * ------------------
 * 1. ALIGNMENT-AWARE SUPPRESSION ENGINE
 *    Every check now emits a *candidate signal* that is passed through a
 *    suppression layer before it is ever shown to the user. Suppressed signals
 *    are not deleted - they are returned in `suppressedSignals` with the reason
 *    they were dismissed, so the technical tab can still show "we checked this,
 *    here's why it's fine". This kills the large majority of false positives
 *    (mailing lists, ESPs, internal forwarding, subdomain senders) with zero
 *    AI cost, deterministically.
 *
 * 2. ORGANISATIONAL-DOMAIN COMPARISON
 *    v2 compared domains with `!==`, so mail.example.com vs example.com was a
 *    "mismatch". v3 compares eTLD+1 (with a Gulf/Commonwealth-aware multi-part
 *    TLD list), matching how DMARC relaxed alignment actually works.
 *
 * 3. WEIGHTED RISK SCORING
 *    v2: any single warning => "Medium". v3: signals carry confidence, and a
 *    single low-confidence soft signal can no longer drag a clean email to
 *    Medium.
 *
 * 4. AI ADJUDICATION (optional, pluggable, fail-open)
 *    Grey-area signals only are sent to a small LLM as a compact JSON *signal
 *    packet* (domains + verdicts, never the message body). The model may
 *    downgrade or dismiss soft signals, and may escalate anything, but it can
 *    never overrule a hard/objective signal such as DMARC=fail. If the AI is
 *    disabled, slow, erroring, or returns junk, the deterministic verdict is
 *    used unchanged.
 *
 * POST /api/analyze
 *   headers: { 'x-api-key': '<API_KEY>' }
 *   body: { from, to, cc, replyTo, subject, rawHeaders, selectedDomain?, userEmail? }
 */

const express = require('express');
const cheerio = require('cheerio');
const crypto = require('crypto');
const dns = require('dns').promises;

const app = express();
app.use(express.json({ limit: '5mb' }));

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || null;

/************ AI CONFIG ************/
const AI = {
  enabled: String(process.env.AI_ENABLED || 'true').toLowerCase() !== 'false',
  provider: (process.env.AI_PROVIDER || 'gemini').toLowerCase(), // gemini | anthropic | openai | none
  apiKey: process.env.AI_API_KEY || '',
  model: process.env.AI_MODEL || '', // resolved per-provider below
  timeoutMs: parseInt(process.env.AI_TIMEOUT_MS || '7000', 10),
  includeSubject: String(process.env.AI_INCLUDE_SUBJECT || 'true').toLowerCase() !== 'false',
  maxCallsPerMin: parseInt(process.env.AI_MAX_CALLS_PER_MIN || '60', 10)
};
const DEFAULT_MODELS = {
  gemini: 'gemini-3.1-flash-lite',
  anthropic: 'claude-haiku-4-5-20251001',
  openai: 'gpt-4.1-mini'
};
function aiModel() { return AI.model || DEFAULT_MODELS[AI.provider] || ''; }
function aiUsable() { return AI.enabled && AI.provider !== 'none' && !!AI.apiKey; }

/************ AUTH MIDDLEWARE ************/
app.use('/api', (req, res, next) => {
  if (!API_KEY) return res.status(500).json({ error: 'Server misconfigured: API_KEY env var not set.' });
  const provided = req.header('x-api-key');
  if (!provided || provided !== API_KEY) return res.status(401).json({ error: 'Missing or invalid API key.' });
  next();
});

/************ CACHE ************/
const CACHE = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000;
const AI_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
function cacheGet(key, ttl) {
  const hit = CACHE.get(key);
  if (!hit) return undefined;
  if (Date.now() - hit.time > (ttl || CACHE_TTL_MS)) { CACHE.delete(key); return undefined; }
  return hit.value;
}
function cacheSet(key, value) {
  CACHE.set(key, { value, time: Date.now() });
  if (CACHE.size > 5000) { // crude bound so a long-lived Render dyno can't grow forever
    const cutoff = Date.now() - AI_CACHE_TTL_MS;
    for (const [k, v] of CACHE) if (v.time < cutoff) CACHE.delete(k);
  }
}

/************ GENERIC HELPERS ************/
function extractEmail(full) {
  if (!full) return '';
  const m = full.match(/<([^>]+)>/);
  if (m) return m[1].trim();
  return full.split(' ')[0].trim();
}
function extractDisplayName(full) {
  if (!full) return '';
  const m = full.match(/^"?([^"<]*)"?\s*</);
  return m ? m[1].trim() : '';
}
function getDomain(email) {
  const p = (email || '').split('@');
  return p.length === 2 ? p[1].toLowerCase().trim().replace(/[>\s]/g, '') : '';
}
function getUniqueDomains(str) {
  const emails = (str || '').match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+)/g) || [];
  return Array.from(new Set(emails.map(getDomain))).filter(Boolean);
}
function isAscii(str) { return /^[\x00-\x7F]*$/.test(str); }

// Multi-part public suffixes we care about. Not the full PSL (that would be a
// dependency + megabytes); this covers the GCC, Commonwealth and major markets,
// which is where Gulf Infotech's clients actually live.
const MULTI_PART_TLDS = new Set([
  'com.om', 'net.om', 'org.om', 'edu.om', 'gov.om', 'co.om',
  'com.ae', 'net.ae', 'org.ae', 'gov.ae', 'ac.ae', 'sch.ae',
  'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa', 'med.sa',
  'com.kw', 'com.qa', 'com.bh', 'com.eg', 'com.jo', 'com.lb', 'com.ye',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'co.za', 'co.in', 'net.in', 'org.in', 'co.ke', 'com.ng', 'com.gh',
  'co.jp', 'or.jp', 'ne.jp', 'co.kr', 'com.cn', 'com.hk', 'com.tw', 'com.sg',
  'com.my', 'com.ph', 'com.vn', 'co.th', 'co.id', 'com.pk', 'com.bd',
  'com.br', 'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.tr', 'com.ua',
  'co.il', 'com.cy', 'com.mt', 'com.pl', 'com.ru', 'com.gr'
]);
function orgDomain(d) {
  if (!d) return '';
  const parts = String(d).toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(last2)) return parts.slice(-3).join('.');
  return last2;
}
function sameOrg(a, b) { return !!a && !!b && orgDomain(a) === orgDomain(b); }
function domainCoreName(d) {
  if (!d) return '';
  return orgDomain(d).split('.')[0].toLowerCase();
}

// Consumer mailbox providers - never treat two of these as "look-alikes" of
// each other, and never treat their presence as impersonation evidence.
const PUBLIC_MAILBOX_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'yahoo.com', 'ymail.com', 'icloud.com', 'me.com', 'aol.com', 'proton.me',
  'protonmail.com', 'zoho.com', 'gmx.com', 'mail.com', 'yandex.com', 'qq.com'
]);

// Bulk-mail / relay infrastructure. A bounce (Return-Path) or DKIM domain here
// is normal ESP behaviour, not evidence of spoofing.
const KNOWN_ESP_DOMAINS = [
  'sendgrid.net', 'sendgrid.com', 'mailgun.org', 'mailgun.net', 'amazonses.com',
  'mcsv.net', 'mcdlv.net', 'mailchimpapp.net', 'rsgsv.net', 'sparkpostmail.com',
  'mandrillapp.com', 'salesforce.com', 'exacttarget.com', 'hubspotemail.net',
  'zoho.com', 'zohomail.com', 'zcsend.net', 'zohocampaigns.com', 'zohoinsights.com',
  'sendinblue.com', 'brevo.com', 'postmarkapp.com', 'mailjet.com', 'customeriomail.com',
  'intercom-mail.com', 'freshemail.io', 'bounce.linkedin.com', 'facebookmail.com',
  'google.com', 'googlegroups.com', 'withgoogle.com', 'microsoft.com', 'office.com'
];
function isKnownEsp(d) {
  if (!d) return false;
  const o = orgDomain(d);
  return KNOWN_ESP_DOMAINS.some(e => o === e || o.endsWith('.' + e) || d.endsWith('.' + e));
}

/************ DNS ************/
async function fetchTXT(name, keyword) {
  const key = 'txt:' + name;
  const cached = cacheGet(key);
  if (cached !== undefined) return matchKeyword(cached, keyword);
  try {
    const records = (await dns.resolveTxt(name)).map(r => r.join(''));
    cacheSet(key, records);
    return matchKeyword(records, keyword);
  } catch (e) { cacheSet(key, []); return null; }
}
function matchKeyword(records, keyword) {
  for (const r of records) if (r.indexOf(keyword) > -1) return r;
  return null;
}
async function fetchMX(domain) {
  const key = 'mx:' + domain;
  const cached = cacheGet(key);
  if (cached !== undefined) return cached;
  try {
    const records = await dns.resolveMx(domain);
    if (!records.length) { cacheSet(key, 'No MX found'); return 'No MX found'; }
    records.sort((a, b) => a.priority - b.priority);
    cacheSet(key, records[0].exchange);
    return records[0].exchange;
  } catch (e) { cacheSet(key, 'No MX found'); return 'No MX found'; }
}
function mapProvider(mxHost) {
  if (!mxHost) return 'Unknown';
  const h = mxHost.toLowerCase();
  const map = {
    'mail.protection.outlook.com': 'Microsoft', '.google.com': 'Google', '.outlook.com': 'Microsoft',
    '.zoho.com': 'Zoho', '.zoho.eu': 'Zoho', '.mimecast.com': 'Mimecast', 'ppe-hosted.com': 'ProofPoint',
    'psmtp.com': 'Postini Legacy', 'yahoodns.net': 'Yahoo', 'spamexperts.com': 'Spam Experts',
    'barracudanetworks.com': 'Barracuda', 'sherwebcloud.com': 'Sherweb', 'spamtitan.com': 'Spam Titan',
    'emailsrvr.com': 'Rackspace', 'mimecast-offshore.com': 'Mimecast', 'messagelabs.com': 'Message Labs',
    'trendmicro.eu': 'TrendMicro', 'secureserver.net': 'GoDaddy', 'registrar-servers.com': 'Namecheap',
    'improvmx.com': 'ImprovMX', 'yandex.net': 'Yandex'
  };
  for (const k in map) if (h.indexOf(k) > -1) return map[k];
  return 'Unknown';
}
function parseDmarcPolicy(record) {
  if (!record) return null;
  const m = record.match(/[;\s]p\s*=\s*(none|quarantine|reject)/i);
  return m ? m[1].toLowerCase() : null;
}
async function getDNSBundle(domain) {
  try {
    const [spf, dmarcOrg, mx] = await Promise.all([
      fetchTXT(domain, 'v=spf1'),
      fetchTXT('_dmarc.' + domain, 'v=DMARC1'),
      fetchMX(domain)
    ]);
    // DMARC is published at the organisational domain; a subdomain sender
    // inherits it. Checking only the exact host produced "No DMARC record"
    // false positives for senders like mail.example.com.
    let dmarc = dmarcOrg;
    const org = orgDomain(domain);
    if (!dmarc && org && org !== domain) dmarc = await fetchTXT('_dmarc.' + org, 'v=DMARC1');
    return {
      spf: spf || 'No SPF record',
      dmarc: dmarc || 'No DMARC record',
      dmarcPolicy: parseDmarcPolicy(dmarc),
      mx,
      provider: mapProvider(mx === 'No MX found' ? null : mx)
    };
  } catch (e) {
    return { spf: 'Error', dmarc: 'Error', dmarcPolicy: null, mx: 'Error', provider: 'Unknown' };
  }
}

/************ AUTH HEADER PARSING ************/
function getAuthBlock(raw) {
  const re = /Authentication-Results:[\s\S]*?(?=\r?\n[A-Za-z-]+:|\r?\n\r?\n|$)/gi;
  const matches = raw ? raw.match(re) : null;
  return matches ? matches.join('\n') : '';
}
function getAuthStatus(block, key) {
  if (!block) return 'Unknown';
  if (new RegExp(key + '\\s*=\\s*pass', 'i').test(block)) return 'Pass';
  if (new RegExp(key + '\\s*=\\s*fail', 'i').test(block)) return 'Fail';
  if (new RegExp(key + '\\s*=\\s*(softfail|permerror|temperror|policy|neutral|none)', 'i').test(block)) return 'Unknown';
  return 'Unknown';
}
// v2 returned only the FIRST dkim=pass header.d. Messages routinely carry several
// signatures (sender + ESP + list); if ANY of them aligns with the From domain the
// message is DKIM-aligned, so we must collect them all.
function getDkimDomains(block) {
  if (!block) return [];
  const out = [];
  const re = /dkim=\s*pass[^;]*?header\.d=([a-zA-Z0-9.-]+)/gi;
  let m;
  while ((m = re.exec(block)) !== null) out.push(m[1].toLowerCase());
  return Array.from(new Set(out));
}
function getSpfDomain(block) {
  if (!block) return null;
  const m = block.match(/spf=\s*pass[^;]*?smtp\.mailfrom=([^\s;]+)/i);
  if (!m) return null;
  const val = m[1].replace(/[<>]/g, '');
  return getDomain(val) || val.toLowerCase();
}
function getHeader(raw, name) {
  if (!raw) return null;
  const re = new RegExp('^' + name + ':[ \\t]*([\\s\\S]*?)(?=\\r?\\n[A-Za-z-]+:|\\r?\\n\\r?\\n)', 'im');
  const m = raw.match(re);
  return m ? m[1].replace(/\r?\n\s+/g, ' ').trim() : null;
}
function getReturnPathDomain(raw) {
  const v = getHeader(raw, 'Return-Path');
  if (!v) return null;
  return getDomain(v.replace(/[<>]/g, '').trim()) || null;
}

/************ MAIL-FLOW CONTEXT ************/
/**
 * Works out HOW the message reached the mailbox. Almost every false positive in
 * v2 came from not knowing this: mailing lists, Google Groups, ESP relays and
 * plain forwarding all legitimately break envelope/SPF alignment.
 */
function detectMailFlow(raw, fromDomain, recipientDomain) {
  const listId = getHeader(raw, 'List-Id');
  const listUnsub = getHeader(raw, 'List-Unsubscribe');
  const precedence = (getHeader(raw, 'Precedence') || '').toLowerCase();
  const groupId = getHeader(raw, 'X-Google-Group-Id') || getHeader(raw, 'Mailing-List');
  const autoSubmitted = (getHeader(raw, 'Auto-Submitted') || '').toLowerCase();
  const senderHeader = getHeader(raw, 'Sender');
  const deliveredTo = getHeader(raw, 'Delivered-To');
  const xForwardedTo = getHeader(raw, 'X-Forwarded-To') || getHeader(raw, 'X-Forwarded-For');
  const arcPresent = /^ARC-Seal:/im.test(raw || '');
  const returnPathDomain = getReturnPathDomain(raw);
  const deliveredToDomain = getDomain((deliveredTo || '').trim());

  const isMailingList = !!(listId || listUnsub || groupId || precedence.indexOf('bulk') > -1 || precedence.indexOf('list') > -1);
  const isGoogleGroup = !!groupId || /googlegroups\.com/i.test(listId || '');
  const relayDomain = returnPathDomain || getDomain(senderHeader || '');

  // The recipient's own infrastructure relayed it (group alias, catch-all,
  // forwarding rule). This is the single biggest source of "envelope mismatch"
  // noise inside a Workspace tenant.
  const forwardedByOwnDomain = !!(recipientDomain && relayDomain && sameOrg(relayDomain, recipientDomain) && !sameOrg(relayDomain, fromDomain));

  return {
    isMailingList,
    isGoogleGroup,
    isAutoGenerated: !!autoSubmitted && autoSubmitted !== 'no',
    forwardedByOwnDomain,
    arcPresent,
    listId: listId || null,
    senderHeaderDomain: getDomain(senderHeader || '') || null,
    deliveredToDomain: deliveredToDomain || null,
    relayDomain: relayDomain || null,
    xForwarded: !!xForwardedTo
  };
}

/************ SIGNAL MODEL ************/
/**
 * signal = {
 *   code, title, severity: info|warning|danger, confidence: low|medium|high,
 *   detail (technical), plain (non-technical), category, hard (bool - AI may not
 *   downgrade), aiEligible (bool - send to AI for adjudication), evidence {}
 * }
 */
const SEVERITY_WEIGHT = {
  danger: { high: 100, medium: 80, low: 60 },
  warning: { high: 30, medium: 18, low: 8 },
  info: { high: 0, medium: 0, low: 0 }
};
function signalWeight(s) {
  return (SEVERITY_WEIGHT[s.severity] || SEVERITY_WEIGHT.info)[s.confidence || 'medium'] || 0;
}
function scoreToRisk(score) {
  if (score >= 60) return 'High';
  if (score >= 25) return 'Medium';
  return 'Low';
}

/************ MIME BODY EXTRACTION ************/
function decodeQuotedPrintable(str) {
  return str.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}
function decodeByEncoding(body, encoding) {
  if (encoding.indexOf('base64') > -1) {
    try { return Buffer.from(body.replace(/\r?\n/g, ''), 'base64').toString('utf8'); } catch (e) { return body; }
  }
  if (encoding.indexOf('quoted-printable') > -1) return decodeQuotedPrintable(body);
  return body;
}
function extractHtmlBody(raw) {
  if (!raw) return null;
  try {
    const ctMatch = raw.match(/^Content-Type:\s*([^;\r\n]+)[\s\S]{0,300}?boundary="?([^"\r\n;]+)"?/im);
    if (!ctMatch) {
      if (/^Content-Type:\s*text\/html/im.test(raw)) {
        const bodyStart = raw.search(/\r?\n\r?\n/);
        const body = bodyStart > -1 ? raw.slice(bodyStart) : raw;
        const cte = (raw.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i) || [])[1] || '7bit';
        return decodeByEncoding(body, cte.trim().toLowerCase());
      }
      return null;
    }
    const boundary = ctMatch[2];
    const parts = raw.split('--' + boundary).slice(1, -1);
    for (const part of parts) {
      if (/Content-Type:\s*multipart\//i.test(part.split(/\r?\n\r?\n/)[0])) {
        const nested = extractHtmlBody(part);
        if (nested) return nested;
        continue;
      }
      if (/Content-Type:\s*text\/html/i.test(part)) {
        const splitIdx = part.search(/\r?\n\r?\n/);
        if (splitIdx === -1) continue;
        const headerBlock = part.slice(0, splitIdx);
        const body = part.slice(splitIdx);
        const cte = (headerBlock.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i) || [])[1] || '7bit';
        return decodeByEncoding(body, cte.trim().toLowerCase());
      }
    }
    return null;
  } catch (e) { return null; }
}

/************ LINK ANALYSIS ************/
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy'];
const RISKY_TLDS = ['.tk', '.top', '.xyz', '.click', '.gq', '.ml', '.cf', '.work', '.zip', '.review', '.country', '.kim', '.mom'];
// Click-tracking / redirect infrastructure. Anchor text showing brand.com while
// the href points at one of these is the *normal* behaviour of every marketing
// platform on earth - it is not a link-masking attack.
const TRACKING_DOMAINS = [
  'list-manage.com', 'sendgrid.net', 'sparkpostmail.com', 'mailgun.org', 'mandrillapp.com',
  'hubspotlinks.com', 'hs-sites.com', 'salesforce.com', 'exct.net', 'clicks.aweber.com',
  'go.pardot.com', 'links.zoho.com', 'zcsend.net', 'campaign-archive.com', 'brevo.com',
  'sendibt2.com', 'r.email', 'click.email', 'email.mg', 'notifications.google.com',
  'awstrack.me', 'ct.sendgrid.net', 'trk.klclick.com', 'url.avanan.click', 'safelinks.protection.outlook.com',
  'urldefense.com', 'protect-us.mimecast.com', 'clicktime.symantec.com', 'linkprotect.cudasvc.com'
];
function isTrackingDomain(d) {
  if (!d) return false;
  return TRACKING_DOMAINS.some(t => d === t || d.endsWith('.' + t) || d.indexOf(t) > -1);
}

function analyzeLinks(rawSource, fromDomain) {
  const flags = [];
  const html = extractHtmlBody(rawSource);
  if (!html) return { flags, linkCount: 0, domains: [], note: 'No HTML body found to scan (plain-text email or unusual MIME structure).' };

  const $ = cheerio.load(html);
  const anchors = $('a[href]');
  const seenDomains = new Set();
  let linkCount = 0;

  anchors.each((_, el) => {
    const href = $(el).attr('href') || '';
    const text = $(el).text().trim();
    if (!/^https?:\/\//i.test(href)) return;
    linkCount++;
    let hrefDomain = '';
    try { hrefDomain = new URL(href).hostname.toLowerCase(); } catch (e) { return; }
    seenDomains.add(hrefDomain);

    // Link text/destination mismatch.
    const textDomainMatch = text.match(/((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})/);
    if (textDomainMatch) {
      const textDomain = textDomainMatch[1].toLowerCase();
      const sameSite = domainCoreName(textDomain) === domainCoreName(hrefDomain) || sameOrg(textDomain, hrefDomain);
      // Redirector that carries the real destination in the query string
      // (?url=, ?u=, target=...) - decode before judging.
      const hrefDecoded = decodeURIComponent(href).toLowerCase();
      const destinationMentioned = hrefDecoded.indexOf(domainCoreName(textDomain)) > -1;

      if (!sameSite) {
        if (isTrackingDomain(hrefDomain) || destinationMentioned) {
          flags.push({
            code: 'LINK_TRACKING_REDIRECT', check: 'Link goes through a tracking redirect',
            severity: 'info', confidence: 'low', aiEligible: true, hard: false,
            detail: `Link text shows "${textDomain}" but the href points at "${hrefDomain}", which looks like click-tracking or a security rewrite rather than link masking.`
          });
        } else {
          flags.push({
            code: 'LINK_TEXT_MISMATCH', check: 'Link text does not match its destination',
            severity: 'danger', confidence: sameOrg(hrefDomain, fromDomain) ? 'low' : 'high',
            aiEligible: true, hard: false,
            detail: `Link text shows "${textDomain}" but it actually points to "${hrefDomain}".`,
            evidence: { textDomain, hrefDomain }
          });
        }
      }
    }

    if (SHORTENERS.some(s => hrefDomain === s || hrefDomain.endsWith('.' + s))) {
      flags.push({
        code: 'LINK_SHORTENER', check: 'Shortened link', severity: 'warning', confidence: 'medium',
        aiEligible: true, hard: false,
        detail: `Link uses a URL shortener (${hrefDomain}), which hides the real destination.`
      });
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hrefDomain) || /^\[[0-9a-f:]+\]$/i.test(hrefDomain)) {
      flags.push({
        code: 'LINK_RAW_IP', check: 'Link to a raw IP address', severity: 'danger', confidence: 'high',
        aiEligible: false, hard: true,
        detail: `Link points directly to an IP address (${hrefDomain}) instead of a domain name.`
      });
    }
    if (RISKY_TLDS.some(tld => hrefDomain.endsWith(tld))) {
      flags.push({
        code: 'LINK_RISKY_TLD', check: 'Link on a high-risk domain ending', severity: 'warning',
        confidence: 'medium', aiEligible: true, hard: false,
        detail: `Link domain "${hrefDomain}" uses a TLD frequently abused for phishing.`
      });
    }
  });

  const seenKeys = new Set();
  const deduped = flags.filter(f => {
    const k = f.code + '|' + f.detail;
    if (seenKeys.has(k)) return false;
    seenKeys.add(k);
    return true;
  });

  return { flags: deduped, linkCount, domains: Array.from(seenDomains) };
}

/************ DOMAIN REPUTATION ************/
function homoglyphChecks(domain) {
  const flags = [];
  if (!domain) return flags;
  if (!isAscii(domain)) {
    flags.push({
      code: 'DOMAIN_NON_ASCII', check: 'Non-ASCII characters in domain', severity: 'danger',
      confidence: 'high', aiEligible: false, hard: true,
      detail: `Domain "${domain}" contains non-ASCII characters, consistent with a homoglyph/look-alike attack.`
    });
  }
  if (domain.split('.').some(l => l.startsWith('xn--'))) {
    flags.push({
      code: 'DOMAIN_PUNYCODE', check: 'Internationalised (punycode) domain', severity: 'warning',
      confidence: 'medium', aiEligible: true, hard: false,
      detail: `Domain "${domain}" is punycode-encoded. Legitimate for some businesses, but worth a second look if unexpected.`
    });
  }
  return flags;
}

async function whoisDomainAge(domain) {
  const key = 'whois:' + domain;
  const cached = cacheGet(key, AI_CACHE_TTL_MS);
  if (cached !== undefined) return cached;
  const result = { ageDays: null, risk: 'Unknown', creationDate: null, source: null };
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const resp = await fetch('https://rdap.org/domain/' + encodeURIComponent(orgDomain(domain)), {
      signal: controller.signal, headers: { Accept: 'application/rdap+json' }
    });
    clearTimeout(timeout);
    if (resp.ok) {
      const data = await resp.json();
      const regEvent = (data.events || []).find(ev => ev.eventAction === 'registration');
      if (regEvent && regEvent.eventDate) {
        const created = new Date(regEvent.eventDate);
        if (!isNaN(created.getTime())) {
          result.ageDays = Math.floor((Date.now() - created.getTime()) / 86400000);
          result.risk = result.ageDays < 30 ? 'High' : result.ageDays < 180 ? 'Medium' : 'Low';
          result.creationDate = regEvent.eventDate;
          result.source = 'rdap';
        }
      }
    }
  } catch (e) { /* unknown TLD, timeout, or blocked - stays Unknown */ }
  cacheSet(key, result);
  return result;
}

/************ LOOK-ALIKE DOMAIN CHECK (tightened) ************/
function levenshtein(a, b) {
  const m = [];
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  for (let i = 0; i <= b.length; i++) m[i] = [i];
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      m[i][j] = Math.min(m[i - 1][j] + 1, m[i][j - 1] + 1, m[i - 1][j - 1] + (b.charAt(i - 1) === a.charAt(j - 1) ? 0 : 1));
    }
  }
  return m[b.length][a.length];
}
/**
 * v2 compared every domain against every other domain with a threshold of
 * max(2, ...), so short unrelated domains ("zoho.com" vs "soho.com", or two
 * different consumer providers) collided constantly. v3:
 *   - compares organisational domains only
 *   - always involves the From domain (that's the identity being impersonated)
 *   - never compares two public mailbox providers
 *   - distance 1 for short names, at most 2 for long ones
 */
function impersonationCheck(domains, fromDomain) {
  const pairs = [];      // near-identical spellings - hard signal
  const embedded = [];   // one name wrapped inside another - AI-reviewable
  if (!fromDomain) return { status: 'Safe', pairs, embedded };
  const fromOrg = orgDomain(fromDomain);
  const fromCore = domainCoreName(fromDomain);
  for (const d of domains) {
    const org = orgDomain(d);
    if (!org || org === fromOrg) continue;
    if (PUBLIC_MAILBOX_DOMAINS.has(org) && PUBLIC_MAILBOX_DOMAINS.has(fromOrg)) continue;
    const core = domainCoreName(d);
    if (!core || !fromCore) continue;

    if (Math.abs(core.length - fromCore.length) <= 2) {
      const dist = levenshtein(core, fromCore);
      const threshold = Math.min(core.length, fromCore.length) <= 6 ? 1 : 2;
      // dist === 0 means the same name on a different TLD (acme.com vs acme.co)
      if (dist <= threshold) { pairs.push(fromOrg + ' vs ' + org); continue; }
    }

    // "gulfinfotech.com" vs "gulfinfotech-support.top": the real name is
    // embedded in a longer one. Skipped for mail platforms and free mailboxes,
    // where this pattern is normal (google.com / googlegroups.com).
    const short = core.length <= fromCore.length ? core : fromCore;
    const long = core.length <= fromCore.length ? fromCore : core;
    if (short.length >= 5 && long.indexOf(short) > -1 &&
        !isKnownEsp(org) && !isKnownEsp(fromOrg) &&
        !PUBLIC_MAILBOX_DOMAINS.has(org) && !PUBLIC_MAILBOX_DOMAINS.has(fromOrg)) {
      embedded.push(fromOrg + ' vs ' + org);
    }
  }
  return {
    status: (pairs.length || embedded.length) ? 'Warning' : 'Safe',
    pairs: Array.from(new Set(pairs)),
    embedded: Array.from(new Set(embedded))
  };
}

/************ IDENTITY / HEADER SIGNALS + SUPPRESSION ************/
const BRAND_KEYWORDS = [
  'paypal', 'microsoft', 'apple', 'amazon', 'docusign', 'dhl', 'fedex', 'netflix',
  'facebook', 'instagram', 'linkedin', 'irs', 'hmrc', 'ups', 'office365', 'onedrive',
  'dropbox', 'adobe', 'wetransfer', 'whatsapp', 'binance', 'coinbase'
];

function buildIdentitySignals(ctx) {
  const signals = [];
  const suppressed = [];
  const keep = s => signals.push(s);
  const drop = (s, reason) => suppressed.push(Object.assign({}, s, { suppressedReason: reason }));

  const {
    fromRaw, fromDomain, replyTo, raw, auth, dkimDomains, spfDomain,
    returnPathDomain, recipientDomain, mailFlow
  } = ctx;

  const dmarcPass = auth.dmarc === 'Pass';
  const dkimAligned = dkimDomains.some(d => sameOrg(d, fromDomain));
  const spfAligned = spfDomain ? sameOrg(spfDomain, fromDomain) : false;

  /* --- 1. Envelope (Return-Path) vs visible From --------------------------- */
  if (returnPathDomain && fromDomain && !sameOrg(returnPathDomain, fromDomain)) {
    const cand = {
      code: 'ENVELOPE_MISMATCH', check: 'Envelope sender mismatch', severity: 'warning',
      confidence: 'low', category: 'identity', aiEligible: true, hard: false,
      detail: `Visible From is "${fromDomain}" but the bounce (Return-Path) domain is "${returnPathDomain}".`,
      evidence: { fromDomain, returnPathDomain }
    };
    if (dmarcPass) drop(cand, 'DMARC passed - the receiving server verified an aligned identifier, so a different bounce domain is normal relay behaviour.');
    else if (dkimAligned) drop(cand, `DKIM is signed by an aligned domain (${dkimDomains.join(', ')}), which proves the From domain authorised this message.`);
    else if (mailFlow.forwardedByOwnDomain) drop(cand, `The bounce domain is your own organisation (${returnPathDomain}) - your mail system forwarded or re-delivered this message.`);
    else if (mailFlow.isMailingList || mailFlow.isGoogleGroup) drop(cand, 'Message was delivered through a mailing list / group, which always rewrites the bounce address.');
    else if (isKnownEsp(returnPathDomain)) drop(cand, `Bounce domain "${returnPathDomain}" belongs to a known bulk-email provider.`);
    else keep(cand);
  }

  /* --- 2. SPF alignment ---------------------------------------------------- */
  if (spfDomain && fromDomain && !spfAligned) {
    const cand = {
      code: 'SPF_ALIGNMENT', check: 'SPF checked a different domain', severity: 'warning',
      confidence: 'low', category: 'auth', aiEligible: true, hard: false,
      detail: `SPF passed for "${spfDomain}", which is not the visible From domain "${fromDomain}".`,
      evidence: { spfDomain, fromDomain }
    };
    if (dmarcPass) drop(cand, 'DMARC passed overall, which means DKIM carried the alignment - unaligned SPF is expected on relayed mail.');
    else if (dkimAligned) drop(cand, 'DKIM is aligned with the From domain, which satisfies DMARC on its own.');
    else if (mailFlow.forwardedByOwnDomain || mailFlow.isMailingList) drop(cand, 'Forwarding and mailing lists always break SPF alignment; this is expected, not evidence of spoofing.');
    else keep(cand);
  }

  /* --- 3. DKIM alignment --------------------------------------------------- */
  if (dkimDomains.length && fromDomain && !dkimAligned) {
    const cand = {
      code: 'DKIM_ALIGNMENT', check: 'DKIM signed by a different domain', severity: 'warning',
      confidence: 'medium', category: 'auth', aiEligible: true, hard: false,
      detail: `DKIM passed for "${dkimDomains.join(', ')}", none of which match the From domain "${fromDomain}".`,
      evidence: { dkimDomains, fromDomain }
    };
    if (dmarcPass) drop(cand, 'DMARC passed, so an aligned identifier was verified regardless of which domain signed.');
    else if (spfAligned) drop(cand, 'SPF is aligned with the From domain, which satisfies DMARC on its own.');
    else if (mailFlow.isMailingList && dkimDomains.some(isKnownEsp)) drop(cand, 'A mailing list re-signed the message with its own key, which is standard list behaviour.');
    else keep(cand);
  }

  /* --- 4. Reply-To pointing elsewhere -------------------------------------- */
  const replyDomains = getUniqueDomains(replyTo || '');
  const unalignedReply = replyDomains.filter(d => !sameOrg(d, fromDomain));
  if (unalignedReply.length && fromDomain) {
    const looksFreeMail = unalignedReply.some(d => PUBLIC_MAILBOX_DOMAINS.has(orgDomain(d)));
    const cand = {
      code: 'REPLY_TO_MISMATCH', check: 'Replies go somewhere else', severity: 'warning',
      confidence: looksFreeMail ? 'high' : 'medium', category: 'identity', aiEligible: true, hard: false,
      detail: `Replies would go to "${unalignedReply.join(', ')}" instead of the visible From domain "${fromDomain}".` +
        (looksFreeMail ? ' Redirecting replies to a free mailbox is a hallmark of business-email-compromise.' : ''),
      evidence: { replyDomains: unalignedReply, fromDomain, looksFreeMail }
    };
    if (mailFlow.isMailingList || mailFlow.isGoogleGroup) drop(cand, 'Mailing lists set Reply-To to the list address by design.');
    else if (unalignedReply.every(d => sameOrg(d, recipientDomain))) drop(cand, 'Replies go back to your own organisation.');
    else if (unalignedReply.every(isKnownEsp)) drop(cand, 'Reply address belongs to the sending platform, not a third party.');
    else keep(cand);
  }

  /* --- 5. Display name referencing a brand --------------------------------- */
  const displayName = extractDisplayName(fromRaw || '');
  const dn = displayName.toLowerCase();
  const viaMatch = dn.match(/^["']?(.*?)["']?\s+via\s+(.+)$/);
  let transparentRelay = false;
  if (viaMatch && fromDomain) {
    const viaPart = viaMatch[2].replace(/[^a-z0-9]/g, '');
    const core = domainCoreName(fromDomain).replace(/[^a-z0-9]/g, '');
    if (viaPart && core && (viaPart.indexOf(core) > -1 || core.indexOf(viaPart) > -1)) transparentRelay = true;
  }
  if (dn && fromDomain && !transparentRelay) {
    for (const brand of BRAND_KEYWORDS) {
      if (dn.indexOf(brand) > -1 && fromDomain.indexOf(brand) === -1) {
        const cand = {
          code: 'DISPLAY_NAME_BRAND', check: 'Display name references another brand', severity: 'warning',
          confidence: 'low', category: 'identity', aiEligible: true, hard: false,
          detail: `Display name "${displayName}" references "${brand}" but the sending domain is "${fromDomain}".`,
          evidence: { displayName, brand, fromDomain }
        };
        if (dmarcPass && isKnownEsp(fromDomain)) drop(cand, 'Sent from a verified bulk-mail platform with DMARC passing - typically a partner or reseller mailing on the brand\'s behalf.');
        else keep(cand);
        break;
      }
    }
  }

  /* --- 6. Hard authentication failures ------------------------------------- */
  if (auth.dmarc === 'Fail') {
    keep({
      code: 'DMARC_FAIL', check: 'Authentication failed (DMARC)', severity: 'danger', confidence: 'high',
      category: 'auth', aiEligible: false, hard: true,
      detail: 'The receiving mail server\'s own DMARC check failed for this message - a strong, objective signal of spoofing or serious misconfiguration.'
    });
  }
  if (auth.spf === 'Fail' && auth.dkim === 'Fail') {
    keep({
      code: 'SPF_DKIM_FAIL', check: 'Authentication failed (SPF + DKIM)', severity: 'danger', confidence: 'high',
      category: 'auth', aiEligible: false, hard: true,
      detail: 'Both SPF and DKIM failed for this message.'
    });
  }

  /* --- 7. Sending domain publishes no protection --------------------------- */
  if (ctx.dnsBundle && ctx.dnsBundle.dmarc === 'No DMARC record' && !dmarcPass) {
    keep({
      code: 'NO_DMARC_RECORD', check: 'Sending domain has no DMARC policy', severity: 'warning',
      confidence: 'low', category: 'auth', aiEligible: true, hard: false,
      detail: `"${ctx.activeDomain}" publishes no DMARC record, so anyone can forge mail from it without being blocked.`
    });
  }

  return { signals, suppressed, context: { dmarcPass, dkimAligned, spfAligned, transparentRelay } };
}

/************ PLAIN-LANGUAGE LAYER (used when AI is off, and as a fallback) ***/
const PLAIN = {
  DMARC_FAIL: { s: 'This email failed the sender\'s own anti-forgery check.', a: 'Treat it as fake unless you can confirm it by phone.' },
  SPF_DKIM_FAIL: { s: 'The sending server could not prove it is allowed to send for this domain.', a: 'Do not act on this email without confirming with the sender directly.' },
  LINK_RAW_IP: { s: 'A link points at a bare server address instead of a website name.', a: 'Do not click the links.' },
  LINK_TEXT_MISMATCH: { s: 'A link shows one website but actually goes somewhere else.', a: 'Do not click - hover a link first and check where it really goes.' },
  DOMAIN_NON_ASCII: { s: 'The sender\'s domain uses look-alike characters to imitate a real one.', a: 'Do not reply or click anything.' },
  DOMAIN_LOOKALIKE: { s: 'A domain in this email closely imitates the sender\'s real domain.', a: 'Check the spelling of the sender address carefully before replying.' },
  DOMAIN_EMBEDDED_NAME: { s: 'The sender\'s web address wraps a company name inside a different one.', a: 'Read the part after the @ carefully - it is not the company\'s real address.' },
  REPLY_TO_MISMATCH: { s: 'If you reply, your reply goes to a different address than the one shown.', a: 'Check with the sender through a known number before replying.' },
  ENVELOPE_MISMATCH: { s: 'The email was actually sent by a different system than the one shown.', a: 'Usually harmless, but be careful if the email asks for money or passwords.' },
  SPF_ALIGNMENT: { s: 'The sending server does not belong to the domain shown in the From line.', a: 'Be careful with attachments and links.' },
  DKIM_ALIGNMENT: { s: 'The digital signature belongs to a different domain than the sender shown.', a: 'Be careful with attachments and links.' },
  DISPLAY_NAME_BRAND: { s: 'The sender name mentions a well-known company that does not match their email address.', a: 'Verify before trusting any request in this email.' },
  NO_DMARC_RECORD: { s: 'This sender\'s domain is not protected against forgery.', a: 'Be a little more careful than usual with this sender.' },
  DOMAIN_NEW: { s: 'The sender\'s domain was registered very recently.', a: 'Be cautious - scammers often use brand-new domains.' },
  DOMAIN_PUNYCODE: { s: 'The sender uses an international character domain.', a: 'Fine if you expected it, suspicious if you did not.' },
  LINK_SHORTENER: { s: 'A link is shortened, so the real destination is hidden.', a: 'Do not click unless you trust the sender.' },
  LINK_RISKY_TLD: { s: 'A link uses a domain ending commonly used by scammers.', a: 'Avoid clicking it.' },
  LINK_TRACKING_REDIRECT: { s: 'Links go through a click-tracking service, which is normal for newsletters.', a: 'No action needed.' }
};
function plainFor(code) { return PLAIN[code] || { s: null, a: null }; }

function buildDeterministicSummary(risk, signals, ctx) {
  const shown = signals.filter(s => s.severity !== 'info');
  if (risk === 'Low' || !shown.length) {
    const who = ctx.fromDomain || 'this sender';
    return {
      headline: 'This email looks legitimate',
      explanation: `We checked who really sent this message and where its links go. The sender's identity was confirmed for ${who} and nothing unusual came up.`,
      action: 'No action needed. As always, only enter passwords or payment details on sites you navigated to yourself.',
      points: [
        { icon: 'ok', text: ctx.dmarcPass ? 'Sender identity verified by the mail provider' : 'No forgery signals found in the message headers' },
        { icon: 'ok', text: ctx.linkCount ? `${ctx.linkCount} link(s) checked - none suspicious` : 'No links to check' },
        { icon: 'ok', text: ctx.domainAge != null ? `Sender domain is ${Math.floor(ctx.domainAge / 365)}+ year(s) old` : 'Sender domain reputation checked' }
      ]
    };
  }
  const top = shown.slice().sort((a, b) => signalWeight(b) - signalWeight(a)).slice(0, 3);
  const points = top.map(s => ({
    icon: s.severity === 'danger' ? 'bad' : 'warn',
    text: plainFor(s.code).s || s.check
  }));
  const actions = top.map(s => plainFor(s.code).a).filter(Boolean);
  return {
    headline: risk === 'High' ? 'Do not trust this email' : 'Check before you act on this email',
    explanation: risk === 'High'
      ? 'This message shows strong signs of being forged or malicious. The sender is very likely not who they claim to be.'
      : 'Most of this email checks out, but one or two things are worth a second look before you reply, click, or pay anything.',
    action: actions[0] || 'Verify with the sender through a channel you already trust.',
    points
  };
}

/************ AI ADJUDICATION ************/
const AI_SYSTEM_PROMPT = `You are an email-security triage analyst inside a Gmail add-on used by non-technical office staff.

You receive a JSON packet of technical signals already computed by a deterministic engine. You NEVER receive the message body. Your job is to decide which of the AMBIGUOUS signals are actually benign (normal mail infrastructure) versus genuinely suspicious, and to write a short, calm, plain-English explanation for a non-technical reader.

Key domain knowledge you must apply:
- Mailing lists, Google Groups, forwarding rules, ESPs and security gateways routinely break SPF alignment and rewrite the Return-Path. With DMARC or aligned DKIM passing, these are NOT suspicious.
- Newsletters and marketing platforms almost always wrap links in click-tracking redirects. That is normal.
- Legitimate resellers, partners and news digests reference other companies' brand names honestly.
- Genuine phishing indicators: unaligned authentication combined with an urgent financial or credential request, reply-to pointing at a free mailbox, look-alike domains, link text that masks a different destination, brand-new domains.
- Absence of evidence is not evidence of attack. When signals are explainable by ordinary mail routing, say so plainly.

Return ONLY a JSON object, no markdown, no commentary:
{
  "verdict": "safe" | "caution" | "danger",
  "confidence": 0.0-1.0,
  "headline": "max 7 words, plain English, no jargon",
  "explanation": "2-3 short sentences a non-technical person understands. Never use the words SPF, DKIM, DMARC, envelope, alignment or header.",
  "action": "one short sentence telling the reader what to do",
  "signals": [ { "code": "<signal code from input>", "assessment": "expected" | "suspicious", "severity": "info" | "warning" | "danger", "reason": "one short technical sentence for the details tab" } ]
}
Include every ambiguous signal code from the input in "signals". Use "expected" + "info" for signals fully explained by normal mail routing.`;

let aiCallTimestamps = [];
function aiRateLimitOk() {
  const now = Date.now();
  aiCallTimestamps = aiCallTimestamps.filter(t => now - t < 60000);
  if (aiCallTimestamps.length >= AI.maxCallsPerMin) return false;
  aiCallTimestamps.push(now);
  return true;
}

function buildSignalPacket(ctx, ambiguous) {
  return {
    sender: {
      domain: ctx.fromDomain,
      displayName: extractDisplayName(ctx.fromRaw || '') || null,
      isNoReplyAddress: /^(no-?reply|donotreply|notifications?|mailer|bounce)/i.test((ctx.fromEmail || '').split('@')[0] || '')
    },
    subject: AI.includeSubject ? (ctx.subject || null) : null,
    routing: {
      returnPathDomain: ctx.returnPathDomain,
      replyToDomains: getUniqueDomains(ctx.replyTo || ''),
      recipientDomain: ctx.recipientDomain,
      deliveredViaMailingList: ctx.mailFlow.isMailingList,
      deliveredViaGoogleGroup: ctx.mailFlow.isGoogleGroup,
      forwardedByRecipientOrg: ctx.mailFlow.forwardedByOwnDomain,
      arcPresent: ctx.mailFlow.arcPresent
    },
    authentication: {
      spf: ctx.auth.spf, dkim: ctx.auth.dkim, dmarc: ctx.auth.dmarc,
      dkimSigningDomains: ctx.dkimDomains,
      spfDomain: ctx.spfDomain,
      dmarcPolicy: ctx.dnsBundle.dmarcPolicy,
      mailProvider: ctx.dnsBundle.provider
    },
    domain: {
      ageDays: ctx.domainAge,
      hasSpfRecord: ctx.dnsBundle.spf !== 'No SPF record',
      hasDmarcRecord: ctx.dnsBundle.dmarc !== 'No DMARC record'
    },
    links: { count: ctx.linkCount, uniqueDomains: (ctx.linkDomains || []).slice(0, 15) },
    hardSignals: ctx.hardSignals.map(s => ({ code: s.code, detail: s.detail })),
    ambiguousSignals: ambiguous.map(s => ({ code: s.code, severity: s.severity, detail: s.detail })),
    suppressedByEngine: ctx.suppressed.map(s => ({ code: s.code, reason: s.suppressedReason }))
  };
}

async function callAiProvider(packet) {
  const model = aiModel();
  const userText = 'Analyse this signal packet:\n' + JSON.stringify(packet);
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), AI.timeoutMs);
  try {
    let url, options;
    if (AI.provider === 'gemini') {
      url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(AI.apiKey)}`;
      options = {
        method: 'POST', signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: AI_SYSTEM_PROMPT }] },
          contents: [{ role: 'user', parts: [{ text: userText }] }],
          generationConfig: { temperature: 0.1, maxOutputTokens: 900, responseMimeType: 'application/json' }
        })
      };
    } else if (AI.provider === 'anthropic') {
      url = 'https://api.anthropic.com/v1/messages';
      options = {
        method: 'POST', signal: controller.signal,
        headers: { 'Content-Type': 'application/json', 'x-api-key': AI.apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({
          model, max_tokens: 900, temperature: 0.1,
          system: AI_SYSTEM_PROMPT,
          messages: [{ role: 'user', content: userText }]
        })
      };
    } else if (AI.provider === 'openai') {
      url = 'https://api.openai.com/v1/chat/completions';
      options = {
        method: 'POST', signal: controller.signal,
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + AI.apiKey },
        body: JSON.stringify({
          model, temperature: 0.1, response_format: { type: 'json_object' },
          messages: [{ role: 'system', content: AI_SYSTEM_PROMPT }, { role: 'user', content: userText }]
        })
      };
    } else {
      return null;
    }

    const resp = await fetch(url, options);
    clearTimeout(t);
    if (!resp.ok) { console.error('AI provider error', resp.status, (await resp.text()).slice(0, 300)); return null; }
    const data = await resp.json();

    let text = '';
    if (AI.provider === 'gemini') text = (((data.candidates || [])[0] || {}).content || {}).parts?.map(p => p.text || '').join('') || '';
    else if (AI.provider === 'anthropic') text = (data.content || []).filter(c => c.type === 'text').map(c => c.text).join('');
    else text = (((data.choices || [])[0] || {}).message || {}).content || '';

    const clean = text.replace(/```json/gi, '').replace(/```/g, '').trim();
    return JSON.parse(clean);
  } catch (e) {
    clearTimeout(t);
    console.error('AI call failed:', e.message);
    return null;
  }
}

async function adjudicate(ctx, signals, force) {
  const ambiguous = signals.filter(s => s.aiEligible && !s.hard);
  const hard = signals.filter(s => s.hard);

  if (!aiUsable()) return { used: false, available: false, reason: 'not-configured', verdict: null };
  // AI is on-demand: the user presses "Ask AI to review" in the add-on.
  if (!force) return { used: false, available: true, reason: 'not-requested', verdict: null };

  // When explicitly requested we run even with nothing ambiguous, so the button
  // always returns an answer rather than silently doing nothing.
  const packet = buildSignalPacket(Object.assign({}, ctx, { hardSignals: hard }), ambiguous.length ? ambiguous : signals);
  const key = 'ai:' + crypto.createHash('sha256').update(JSON.stringify(packet)).digest('hex');
  const cached = cacheGet(key, AI_CACHE_TTL_MS);
  if (cached !== undefined) return { used: true, available: true, cached: true, verdict: cached };

  if (!aiRateLimitOk()) return { used: false, available: true, reason: 'rate-limited', verdict: null };

  const verdict = await callAiProvider(packet);
  if (!verdict || typeof verdict !== 'object' || !verdict.verdict) {
    return { used: false, available: true, reason: 'ai-error', verdict: null };
  }
  cacheSet(key, verdict);
  return { used: true, available: true, cached: false, verdict };
}

/**
 * Applies the AI verdict under strict guardrails:
 *  - hard signals are immutable (AI can never dismiss DMARC=fail, raw-IP links,
 *    homoglyph domains or look-alike domains)
 *  - AI may downgrade soft signals to info, or escalate any signal
 *  - the final risk can be raised by the AI but never lowered below what hard
 *    signals require
 */
function applyAiVerdict(signals, ai) {
  if (!ai || !ai.verdict) return { signals, notes: [] };
  const bySeverity = { info: 'info', warning: 'warning', danger: 'danger' };
  const map = new Map();
  (ai.verdict.signals || []).forEach(s => { if (s && s.code) map.set(s.code, s); });

  const notes = [];
  const out = signals.map(sig => {
    const judged = map.get(sig.code);
    if (!judged) return sig;
    if (sig.hard) {
      notes.push({ code: sig.code, note: 'AI review recorded but not applied - this is an objective check.' });
      return sig;
    }
    let newSev = bySeverity[judged.severity] || sig.severity;
    // Some signals are AI-reviewable but may not be dismissed entirely.
    if (sig.minSeverity) {
      const rank = { info: 0, warning: 1, danger: 2 };
      if (rank[newSev] < rank[sig.minSeverity]) newSev = sig.minSeverity;
    }
    if (newSev !== sig.severity) {
      notes.push({ code: sig.code, from: sig.severity, to: newSev, reason: judged.reason || '' });
    }
    return Object.assign({}, sig, {
      severity: newSev,
      aiAssessment: judged.assessment || null,
      aiReason: judged.reason || null
    });
  });
  return { signals: out, notes };
}

/************ ROUTE ************/
app.post('/api/analyze', async (req, res) => {
  try {
    const {
      from = '', to = '', cc = '', replyTo = '', subject = '',
      rawHeaders = '', selectedDomain = null, userEmail = '', aiReview = false
    } = req.body || {};

    const fromEmail = extractEmail(from);
    const fromDomain = getDomain(fromEmail);

    const allDomains = getUniqueDomains([from, to, cc, replyTo].join(','));
    if (fromDomain && allDomains.indexOf(fromDomain) === -1) allDomains.unshift(fromDomain);

    const activeDomain = selectedDomain && allDomains.indexOf(selectedDomain) > -1 ? selectedDomain : fromDomain;

    // Who received this? Needed to recognise "my own server forwarded it".
    const deliveredTo = getHeader(rawHeaders, 'Delivered-To');
    const recipientDomain = getDomain(userEmail) || getDomain((deliveredTo || '').trim()) || getDomain(extractEmail(to));

    const dnsBundle = activeDomain
      ? await getDNSBundle(activeDomain)
      : { spf: 'N/A', dmarc: 'N/A', dmarcPolicy: null, mx: 'N/A', provider: 'Unknown' };

    const authBlock = getAuthBlock(rawHeaders);
    const auth = {
      spf: getAuthStatus(authBlock, 'spf'),
      dkim: getAuthStatus(authBlock, 'dkim'),
      dmarc: getAuthStatus(authBlock, 'dmarc')
    };
    const dkimDomains = getDkimDomains(authBlock);
    const spfDomain = getSpfDomain(authBlock);
    const returnPathDomain = getReturnPathDomain(rawHeaders);
    const mailFlow = detectMailFlow(rawHeaders, fromDomain, recipientDomain);

    const linkAnalysis = analyzeLinks(rawHeaders, fromDomain);
    const whoisInfo = activeDomain ? await whoisDomainAge(activeDomain) : { ageDays: null, risk: 'Unknown', creationDate: null };

    const ctxBase = {
      fromRaw: from, fromEmail, fromDomain, replyTo, subject, raw: rawHeaders,
      auth, dkimDomains, spfDomain, returnPathDomain, recipientDomain, mailFlow,
      dnsBundle, activeDomain, domainAge: whoisInfo.ageDays,
      linkCount: linkAnalysis.linkCount, linkDomains: linkAnalysis.domains
    };

    const identity = buildIdentitySignals(ctxBase);
    const suppressed = identity.suppressed.slice();

    // Domain reputation
    const repSignals = homoglyphChecks(activeDomain);
    if (whoisInfo.risk === 'High' || whoisInfo.risk === 'Medium') {
      repSignals.push({
        code: 'DOMAIN_NEW', check: 'Newly registered domain',
        severity: whoisInfo.risk === 'High' ? 'warning' : 'info',
        confidence: whoisInfo.risk === 'High' ? 'high' : 'low',
        category: 'domain', aiEligible: true, hard: false,
        detail: `Domain "${activeDomain}" was registered about ${whoisInfo.ageDays} day(s) ago. Freshly registered domains are disproportionately used in phishing.`
      });
    }

    // Look-alike domains inside this message
    const imp = impersonationCheck(allDomains, fromDomain);
    const impSignals = [];
    if (imp.pairs.length) {
      impSignals.push({
        code: 'DOMAIN_LOOKALIKE', check: 'Look-alike domain', severity: 'danger', confidence: 'high',
        category: 'domain', aiEligible: false, hard: true,
        detail: `Look-alike domains found among this message's own addresses: ${imp.pairs.join(', ')}.`
      });
    }
    if (imp.embedded.length) {
      impSignals.push({
        code: 'DOMAIN_EMBEDDED_NAME', check: 'Domain wraps another company name', severity: 'danger',
        confidence: 'medium', category: 'domain', aiEligible: true, hard: false, minSeverity: 'warning',
        detail: `One domain contains another's name: ${imp.embedded.join(', ')}. Attackers register names like this to look like a company's support or billing arm.`
      });
    }

    let signals = [...identity.signals, ...linkAnalysis.flags, ...repSignals, ...impSignals];

    // --- AI adjudication (only when the user asked for it) ------------------
    const aiResult = await adjudicate(
      Object.assign({}, ctxBase, { suppressed, hardSignals: signals.filter(s => s.hard) }),
      signals,
      aiReview === true || aiReview === 'true'
    );
    const applied = applyAiVerdict(signals, aiResult);
    signals = applied.signals;

    // --- Risk ---------------------------------------------------------------
    const deterministicScore = signals.reduce((n, s) => n + signalWeight(s), 0);
    let overallRisk = scoreToRisk(deterministicScore);

    // AI may escalate, never de-escalate below the hard-signal floor.
    const hardFloor = signals.some(s => s.hard && s.severity === 'danger') ? 'High' : null;
    if (aiResult.used && aiResult.verdict) {
      const aiRisk = aiResult.verdict.verdict === 'danger' ? 'High' : aiResult.verdict.verdict === 'caution' ? 'Medium' : 'Low';
      const order = { Low: 0, Medium: 1, High: 2 };
      // Take the higher of deterministic vs AI, then enforce the hard floor.
      overallRisk = order[aiRisk] > order[overallRisk] ? aiRisk : overallRisk;
      // Allow the AI to soften only when nothing hard is firing and it is confident.
      if (!hardFloor && (aiResult.verdict.confidence == null || aiResult.verdict.confidence >= 0.7) && order[aiRisk] < order[overallRisk]) {
        overallRisk = aiRisk;
      }
    }
    if (hardFloor) overallRisk = 'High';

    // --- Simple (non-technical) block --------------------------------------
    const fallback = buildDeterministicSummary(overallRisk, signals, Object.assign({}, ctxBase, { dmarcPass: identity.context.dmarcPass }));
    const simple = (aiResult.used && aiResult.verdict)
      ? {
        headline: aiResult.verdict.headline || fallback.headline,
        explanation: aiResult.verdict.explanation || fallback.explanation,
        action: aiResult.verdict.action || fallback.action,
        points: fallback.points,
        source: 'ai'
      }
      : Object.assign({}, fallback, { source: 'rules' });

    const decorated = signals.map(s => Object.assign({}, s, {
      plain: plainFor(s.code).s || s.check,
      plainAction: plainFor(s.code).a || null
    }));
    const visibleSignals = decorated.filter(s => s.severity !== 'info');
    const infoSignals = decorated.filter(s => s.severity === 'info');

    res.json({
      // --- v2-compatible fields (so an older Code.gs keeps working) ---
      fromEmail, fromDomain, activeDomain,
      domains: allDomains,
      impersonation: imp,
      dns: dnsBundle,
      auth,
      headerSpoofing: visibleSignals.filter(s => s.category === 'identity' || s.category === 'auth').map(s => ({ check: s.check, severity: s.severity, detail: s.detail })),
      linkAnalysis: { linkCount: linkAnalysis.linkCount, flags: visibleSignals.filter(s => s.code.startsWith('LINK_')).map(s => ({ check: s.check, severity: s.severity, detail: s.detail })), note: linkAnalysis.note || null },
      domainReputation: { whois: whoisInfo, flags: visibleSignals.filter(s => s.code.startsWith('DOMAIN_')).map(s => ({ check: s.check, severity: s.severity, detail: s.detail })) },
      overallRisk,

      // --- v3 fields ---
      version: 3,
      simple,
      signals: visibleSignals,
      infoSignals,
      suppressedSignals: suppressed,
      mailFlow,
      alignment: identity.context,
      riskScore: deterministicScore,
      ai: {
        available: aiResult.available !== false,
        used: aiResult.used,
        cached: !!aiResult.cached,
        reason: aiResult.reason || null,
        provider: aiResult.used ? AI.provider : null,
        model: aiResult.used ? aiModel() : null,
        verdict: aiResult.used && aiResult.verdict ? {
          verdict: aiResult.verdict.verdict,
          confidence: aiResult.verdict.confidence,
          headline: aiResult.verdict.headline,
          explanation: aiResult.verdict.explanation,
          action: aiResult.verdict.action
        } : null,
        adjustments: applied.notes
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error analyzing email', details: err.message });
  }
});

app.get('/health', (req, res) => res.json({
  ok: true, version: 3,
  ai: { enabled: AI.enabled, provider: AI.provider, model: aiModel(), keyConfigured: !!AI.apiKey }
}));

app.listen(PORT, () => console.log(`Email Data Metrics API v3 listening on port ${PORT}`));
module.exports = app;
