/**
 * Email Data Metrics - Backend API (v2)
 * Adds: API key auth, header-spoofing checks (envelope mismatch, display-name,
 * reply-to, DMARC alignment awareness), link/URL analysis in the HTML body,
 * and domain reputation (WHOIS age + homoglyph/punycode detection).
 *
 * POST /api/analyze
 *   headers: { 'x-api-key': '<your key>' }
 *   body: {
 *     from, to, cc, replyTo: string,
 *     rawHeaders: string,   // full raw message source (headers + body)
 *     selectedDomain?: string
 *   }
 */

const express = require('express');
const cheerio = require('cheerio');

const app = express();
app.use(express.json({ limit: '5mb' }));

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || null;

/************ AUTH MIDDLEWARE ************/
app.use('/api', (req, res, next) => {
  if (!API_KEY) {
    // No key configured on the server - refuse to run wide open in production.
    return res.status(500).json({ error: 'Server misconfigured: API_KEY env var not set.' });
  }
  const provided = req.header('x-api-key');
  if (!provided || provided !== API_KEY) {
    return res.status(401).json({ error: 'Missing or invalid API key.' });
  }
  next();
});

/************ CACHE ************/
const CACHE = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000;
function cacheGet(key) {
  const hit = CACHE.get(key);
  if (!hit) return undefined;
  if (Date.now() - hit.time > CACHE_TTL_MS) { CACHE.delete(key); return undefined; }
  return hit.value;
}
function cacheSet(key, value) { CACHE.set(key, { value, time: Date.now() }); }

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
  return p.length === 2 ? p[1].toLowerCase().trim() : '';
}
function getUniqueDomains(str) {
  const emails = (str || '').match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+)/g) || [];
  return Array.from(new Set(emails.map(getDomain)));
}
function isAscii(str) { return /^[\x00-\x7F]*$/.test(str); }

/************ DNS (native) ************/
const dns = require('dns').promises;
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
    '.google.com': 'Google', '.outlook.com': 'Microsoft', '.zoho.com': 'Zoho',
    '.mimecast.com': 'Mimecast', 'ppe-hosted.com': 'ProofPoint', 'psmtp.com': 'Postini Legacy',
    'yahoodns.net': 'Yahoo', 'spamexperts.com': 'Spam Experts', 'barracudanetworks.com': 'Barracuda',
    'sherwebcloud.com': 'Sherweb', 'spamtitan.com': 'Spam Titan', 'emailsrvr.com': 'Network Solutions',
    'mimecast-offshore.com': 'Mimecast', 'messagelabs.com': 'Message Labs', 'trendmicro.eu': 'TrendMicro',
    'mail.protection.outlook.com': 'Microsoft'
  };
  for (const k in map) if (h.indexOf(k) > -1) return map[k];
  return 'Unknown';
}
async function getDNSBundle(domain) {
  try {
    const [spf, dmarc, mx] = await Promise.all([
      fetchTXT(domain, 'v=spf1'),
      fetchTXT('_dmarc.' + domain, 'v=DMARC1'),
      fetchMX(domain)
    ]);
    return { spf: spf || 'No SPF record', dmarc: dmarc || 'No DMARC record', mx, provider: mapProvider(mx === 'No MX found' ? null : mx) };
  } catch (e) { return { spf: 'Error', dmarc: 'Error', mx: 'Error', provider: 'Unknown' }; }
}

/************ AUTH HEADER PARSING (with alignment) ************/
function getAuthBlock(raw) {
  const re = /Authentication-Results:[\s\S]*?(?=\r?\n[A-Za-z-]+:|\r?\n\r?\n|$)/gi;
  const matches = raw ? raw.match(re) : null;
  return matches ? matches.join('\n') : '';
}
function getAuthStatus(block, key) {
  if (!block) return 'Unknown';
  if (new RegExp(key + '\\s*=\\s*pass', 'i').test(block)) return 'Pass';
  if (new RegExp(key + '\\s*=\\s*fail', 'i').test(block)) return 'Fail';
  return 'Unknown';
}
// Extract the domain each mechanism actually authenticated (for alignment checks)
function getAuthDomain(block, mechanism) {
  if (!block) return null;
  if (mechanism === 'dkim') {
    const m = block.match(/dkim=\s*pass[^;]*header\.d=([a-zA-Z0-9.-]+)/i);
    return m ? m[1].toLowerCase() : null;
  }
  if (mechanism === 'spf') {
    const m = block.match(/spf=\s*pass[^;]*smtp\.mailfrom=([^\s;]+)/i);
    if (!m) return null;
    const val = m[1].replace(/[<>]/g, '');
    return getDomain(val) || val.toLowerCase();
  }
  return null;
}
function getReturnPathDomain(raw) {
  if (!raw) return null;
  const m = raw.match(/^Return-Path:\s*<?([^>\r\n]+)>?/im);
  if (!m) return null;
  return getDomain(m[1].trim()) || null;
}

/************ HEADER SPOOFING CHECKS ************/
const BRAND_KEYWORDS = [
  'paypal', 'microsoft', 'apple', 'amazon', 'google', 'docusign', 'dhl', 'fedex',
  'bank', 'netflix', 'facebook', 'instagram', 'linkedin', 'irs', 'hmrc', 'ups',
  'office365', 'outlook', 'onedrive', 'dropbox', 'adobe', 'wetransfer'
];

function headerSpoofingChecks({ fromRaw, fromEmail, fromDomain, replyTo, rawSource, authBlock }) {
  const flags = [];

  // 1. Envelope (Return-Path) vs visible From domain
  const returnPathDomain = getReturnPathDomain(rawSource);
  if (returnPathDomain && fromDomain && returnPathDomain !== fromDomain) {
    flags.push({
      check: 'Envelope sender mismatch',
      severity: 'warning',
      detail: `Visible From is "${fromDomain}" but the actual sending (Return-Path) domain is "${returnPathDomain}". This can be legitimate (mailing lists, some ESPs) but is also a common spoofing pattern.`
    });
  }

  // 2. Display name impersonating a brand not matching the domain
  const displayName = extractDisplayName(fromRaw || '').toLowerCase();
  if (displayName && fromDomain) {
    for (const brand of BRAND_KEYWORDS) {
      if (displayName.indexOf(brand) > -1 && fromDomain.indexOf(brand) === -1) {
        flags.push({
          check: 'Display name / domain mismatch',
          severity: 'danger',
          detail: `Sender display name references "${brand}" but the email domain is "${fromDomain}", which does not match. Classic brand-impersonation pattern.`
        });
        break;
      }
    }
  }

  // 3. Reply-To silently pointing elsewhere
  const replyDomains = getUniqueDomains(replyTo || '');
  if (replyDomains.length && fromDomain && replyDomains.indexOf(fromDomain) === -1) {
    flags.push({
      check: 'Reply-To mismatch',
      severity: 'warning',
      detail: `Replies would go to "${replyDomains.join(', ')}", not the visible From domain "${fromDomain}". Common in business-email-compromise (BEC) attacks.`
    });
  }

  // 4. SPF/DKIM alignment awareness (useful especially when DMARC is missing/none)
  const dkimDomain = getAuthDomain(authBlock, 'dkim');
  const spfDomain = getAuthDomain(authBlock, 'spf');
  if (fromDomain && dkimDomain && dkimDomain !== fromDomain) {
    flags.push({
      check: 'DKIM alignment',
      severity: 'warning',
      detail: `DKIM passed for "${dkimDomain}", which differs from the visible From domain "${fromDomain}". A pass here does not guarantee the visible sender is legitimate.`
    });
  }
  if (fromDomain && spfDomain && spfDomain !== fromDomain) {
    flags.push({
      check: 'SPF alignment',
      severity: 'warning',
      detail: `SPF passed for "${spfDomain}", which differs from the visible From domain "${fromDomain}".`
    });
  }

  return flags;
}

/************ MIME BODY EXTRACTION + LINK ANALYSIS ************/
function decodeQuotedPrintable(str) {
  return str
    .replace(/=\r?\n/g, '')
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function extractHtmlBody(raw) {
  if (!raw) return null;
  try {
    const ctMatch = raw.match(/^Content-Type:\s*([^;\r\n]+)[\s\S]{0,300}?boundary="?([^"\r\n;]+)"?/im);
    if (!ctMatch) {
      // Not multipart at top level - maybe a direct text/html message
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
  } catch (e) {
    return null;
  }
}
function decodeByEncoding(body, encoding) {
  if (encoding.indexOf('base64') > -1) {
    try { return Buffer.from(body.replace(/\r?\n/g, ''), 'base64').toString('utf8'); }
    catch (e) { return body; }
  }
  if (encoding.indexOf('quoted-printable') > -1) return decodeQuotedPrintable(body);
  return body;
}

const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly'];
const RISKY_TLDS = ['.tk', '.top', '.xyz', '.click', '.gq', '.ml', '.cf', '.work', '.click', '.zip', '.review'];

function analyzeLinks(rawSource, fromDomain) {
  const flags = [];
  const html = extractHtmlBody(rawSource);
  if (!html) {
    return { flags, linkCount: 0, note: 'No HTML body found to scan for links (plain-text email, or unusual MIME structure).' };
  }
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

    // Anchor text displays a different domain than the actual destination
    const textDomainMatch = text.match(/([a-zA-Z0-9-]+\.[a-zA-Z]{2,})/);
    if (textDomainMatch) {
      const textDomain = textDomainMatch[1].toLowerCase();
      if (hrefDomain.indexOf(textDomain) === -1 && textDomain.indexOf(hrefDomain) === -1) {
        flags.push({
          check: 'Link text/destination mismatch',
          severity: 'danger',
          detail: `Link text shows "${textDomain}" but actually points to "${hrefDomain}".`
        });
      }
    }

    if (SHORTENERS.some(s => hrefDomain === s || hrefDomain.endsWith('.' + s))) {
      flags.push({ check: 'Shortened URL', severity: 'warning', detail: `Link uses a URL shortener (${hrefDomain}), which hides the real destination.` });
    }
    if (RISKY_TLDS.some(tld => hrefDomain.endsWith(tld))) {
      flags.push({ check: 'High-risk TLD', severity: 'warning', detail: `Link domain "${hrefDomain}" uses a TLD frequently abused for phishing.` });
    }
    if (fromDomain && hrefDomain && hrefDomain.indexOf(fromDomain) === -1 && fromDomain.indexOf(hrefDomain) === -1) {
      // Informational only - most emails legitimately link off-domain (unsubscribe, socials, etc.)
    }
  });

  return { flags, linkCount, domains: Array.from(seenDomains) };
}

/************ DOMAIN REPUTATION: homoglyph/punycode + WHOIS age ************/
function homoglyphChecks(domain) {
  const flags = [];
  if (!domain) return flags;
  if (!isAscii(domain)) {
    flags.push({ check: 'Non-ASCII domain characters', severity: 'danger', detail: `Domain "${domain}" contains non-ASCII characters, consistent with a homoglyph/lookalike attack.` });
  }
  if (domain.split('.').some(label => label.startsWith('xn--'))) {
    flags.push({ check: 'Punycode (IDN) domain', severity: 'warning', detail: `Domain "${domain}" is internationalized (punycode). Legitimate for some businesses, but worth a second look if unexpected.` });
  }
  return flags;
}

// Uses RDAP (the modern, HTTPS-based successor to WHOIS) instead of raw port-43
// WHOIS queries, which are frequently blocked on cloud hosts (Render, etc.).
async function whoisDomainAge(domain) {
  const key = 'whois:' + domain;
  const cached = cacheGet(key);
  if (cached !== undefined) return cached;

  const result = { ageDays: null, risk: 'Unknown', creationDate: null, source: null };

  // rdap.org is a public bootstrap proxy that resolves the correct
  // registry RDAP server for any TLD and returns a unified JSON response.
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const resp = await fetch('https://rdap.org/domain/' + encodeURIComponent(domain), {
      signal: controller.signal,
      headers: { Accept: 'application/rdap+json' }
    });
    clearTimeout(timeout);

    if (resp.ok) {
      const data = await resp.json();
      const events = data.events || [];
      const regEvent = events.find(ev => ev.eventAction === 'registration');
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
  } catch (e) {
    // Leave result as Unknown - network failure, timeout, or unsupported TLD.
  }

  cacheSet(key, result);
  return result;
}

/************ RISK AGGREGATION ************/
function computeOverallRisk(allFlags) {
  if (allFlags.some(f => f.severity === 'danger')) return 'High';
  if (allFlags.some(f => f.severity === 'warning')) return 'Medium';
  return 'Low';
}

/************ IMPERSONATION (domain-vs-domain, unchanged) ************/
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
function impersonationCheck(domains) {
  const pairs = [];
  for (let i = 0; i < domains.length; i++) {
    for (let j = i + 1; j < domains.length; j++) {
      const d1 = domains[i], d2 = domains[j];
      const dist = levenshtein(d1, d2);
      const threshold = Math.max(2, Math.floor(Math.min(d1.length, d2.length) * 0.2));
      if (dist > 0 && dist <= threshold) pairs.push(d1 + ' vs ' + d2);
    }
  }
  return { status: pairs.length ? 'Warning' : 'Safe', pairs };
}

/************ ROUTE ************/
app.post('/api/analyze', async (req, res) => {
  try {
    const { from = '', to = '', cc = '', replyTo = '', rawHeaders = '', selectedDomain = null } = req.body || {};

    const fromEmail = extractEmail(from);
    const fromDomain = getDomain(fromEmail);

    const allAddrStr = [from, to, cc, replyTo].join(',');
    const allDomains = getUniqueDomains(allAddrStr);
    if (fromDomain && allDomains.indexOf(fromDomain) === -1) allDomains.unshift(fromDomain);

    const activeDomain = selectedDomain && allDomains.indexOf(selectedDomain) > -1 ? selectedDomain : fromDomain;

    const imp = impersonationCheck(allDomains);
    const dnsBundle = activeDomain ? await getDNSBundle(activeDomain) : { spf: 'N/A', dmarc: 'N/A', mx: 'N/A', provider: 'Unknown' };

    const authBlock = getAuthBlock(rawHeaders);
    const auth = {
      spf: getAuthStatus(authBlock, 'spf'),
      dkim: getAuthStatus(authBlock, 'dkim'),
      dmarc: getAuthStatus(authBlock, 'dmarc')
    };

    const spoofingFlags = headerSpoofingChecks({ fromRaw: from, fromEmail, fromDomain, replyTo, rawSource: rawHeaders, authBlock });
    const linkAnalysis = analyzeLinks(rawHeaders, fromDomain);
    const reputationFlags = homoglyphChecks(activeDomain);
    const whoisInfo = activeDomain ? await whoisDomainAge(activeDomain) : { ageDays: null, risk: 'Unknown', creationDate: null };
    if (whoisInfo.risk === 'High' || whoisInfo.risk === 'Medium') {
      reputationFlags.push({
        check: 'Newly registered domain',
        severity: whoisInfo.risk === 'High' ? 'danger' : 'warning',
        detail: `Domain "${activeDomain}" was registered ~${whoisInfo.ageDays} day(s) ago. Freshly-registered domains are disproportionately used in phishing.`
      });
    }

    const allFlags = [...spoofingFlags, ...linkAnalysis.flags, ...reputationFlags];
    const overallRisk = computeOverallRisk(allFlags);

    res.json({
      fromEmail, fromDomain, activeDomain,
      domains: allDomains,
      impersonation: imp,
      dns: dnsBundle,
      auth,
      headerSpoofing: spoofingFlags,
      linkAnalysis: { linkCount: linkAnalysis.linkCount, flags: linkAnalysis.flags, note: linkAnalysis.note || null },
      domainReputation: { whois: whoisInfo, flags: reputationFlags },
      overallRisk,
      allFlags
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error analyzing email', details: err.message });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Email Data Metrics API listening on port ${PORT}`));
module.exports = app;
