/**
 * Email Data Metrics - Backend API
 * Ports the DNS / impersonation / auth-header logic out of the
 * Gmail Apps Script so it can be shared by Gmail, Outlook, or anything else.
 *
 * Endpoints:
 *   POST /api/analyze
 *     body: {
 *       from: string,        // "Name <user@domain.com>"
 *       to: string,          // comma-separated addresses
 *       cc: string,          // comma-separated addresses
 *       replyTo: string,     // comma-separated addresses
 *       rawHeaders: string,  // raw email source / headers (for Authentication-Results)
 *       selectedDomain?: string // optional - which domain's DNS to look up
 *     }
 *     returns: {
 *       fromEmail, fromDomain, activeDomain,
 *       domains: string[],
 *       impersonation: { status: 'Safe'|'Warning', pairs: string[] },
 *       dns: { mx, provider, dmarc, spf },
 *       auth: { spf, dkim, dmarc }
 *     }
 */

const express = require('express');
const dns = require('dns').promises;

const app = express();
app.use(express.json({ limit: '2mb' })); // raw email source can be large

const PORT = process.env.PORT || 3000;

// Simple in-memory cache so repeated lookups of the same domain
// don't re-hit DNS every time (this was a noted gap in the Apps Script version).
const DNS_CACHE = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function cacheGet(key) {
  const hit = DNS_CACHE.get(key);
  if (!hit) return null;
  if (Date.now() - hit.time > CACHE_TTL_MS) {
    DNS_CACHE.delete(key);
    return null;
  }
  return hit.value;
}

function cacheSet(key, value) {
  DNS_CACHE.set(key, { value, time: Date.now() });
}

/************ GENERIC HELPERS (ported as-is from Code.gs) ************/

function extractEmail(full) {
  if (!full) return '';
  const m = full.match(/<([^>]+)>/);
  if (m) return m[1];
  return full.split(' ')[0].trim();
}

function getDomain(email) {
  const p = (email || '').split('@');
  return p.length === 2 ? p[1].toLowerCase() : '';
}

function getUniqueDomains(str) {
  const emails = (str || '').match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+)/g) || [];
  const out = new Set();
  for (const e of emails) out.add(getDomain(e));
  return Array.from(out);
}

/************ DNS LOOKUPS (native Node dns module, no external HTTP hop needed) ************/

async function fetchTXT(name, keyword) {
  const cacheKey = 'txt:' + name;
  const cached = cacheGet(cacheKey);
  if (cached !== null) return matchKeyword(cached, keyword);

  try {
    const records = await dns.resolveTxt(name); // string[][]
    const flat = records.map((r) => r.join(''));
    cacheSet(cacheKey, flat);
    return matchKeyword(flat, keyword);
  } catch (err) {
    cacheSet(cacheKey, []);
    return null;
  }
}

function matchKeyword(records, keyword) {
  for (const rec of records) {
    if (rec.indexOf(keyword) > -1) return rec;
  }
  return null;
}

async function fetchMX(domain) {
  const cacheKey = 'mx:' + domain;
  const cached = cacheGet(cacheKey);
  if (cached !== null) return cached;

  try {
    const records = await dns.resolveMx(domain); // [{exchange, priority}]
    if (!records.length) {
      cacheSet(cacheKey, 'No MX found');
      return 'No MX found';
    }
    records.sort((a, b) => a.priority - b.priority);
    const top = records[0].exchange;
    cacheSet(cacheKey, top);
    return top;
  } catch (err) {
    cacheSet(cacheKey, 'No MX found');
    return 'No MX found';
  }
}

function mapProvider(mxHost) {
  if (!mxHost) return 'Unknown';
  const h = mxHost.toLowerCase();
  const map = {
    '.google.com': 'Google',
    '.outlook.com': 'Microsoft',
    '.zoho.com': 'Zoho',
    '.mimecast.com': 'Mimecast',
    'ppe-hosted.com': 'ProofPoint',
    'psmtp.com': 'Postini Legacy',
    'yahoodns.net': 'Yahoo',
    'spamexperts.com': 'Spam Experts',
    'barracudanetworks.com': 'Barracuda',
    'sherwebcloud.com': 'Sherweb',
    'spamtitan.com': 'Spam Titan',
    'emailsrvr.com': 'Network Solutions',
    'mimecast-offshore.com': 'Mimecast',
    'messagelabs.com': 'Message Labs',
    'trendmicro.eu': 'TrendMicro',
    'mail.protection.outlook.com': 'Microsoft',
  };
  for (const key in map) {
    if (h.indexOf(key) > -1) return map[key];
  }
  return 'Unknown';
}

async function getDNSBundle(domain) {
  try {
    const [spf, dmarc, mx] = await Promise.all([
      fetchTXT(domain, 'v=spf1'),
      fetchTXT('_dmarc.' + domain, 'v=DMARC1'),
      fetchMX(domain),
    ]);
    const provider = mapProvider(mx === 'No MX found' ? null : mx);
    return {
      spf: spf || 'No SPF record',
      dmarc: dmarc || 'No DMARC record',
      mx,
      provider,
    };
  } catch (err) {
    return { spf: 'Error', dmarc: 'Error', mx: 'Error', provider: 'Unknown' };
  }
}

/************ AUTH HEADER HELPERS (ported as-is) ************/

function getAuthBlock(raw) {
  const re = /Authentication-Results:[\s\S]*?(?=\r?\n[A-Za-z-]+:|\r?\n\r?\n|$)/gi;
  const matches = raw ? raw.match(re) : null;
  return matches ? matches.join('\n') : '';
}

function getAuthStatus(block, key) {
  if (!block) return 'Unknown';
  const passRe = new RegExp(key + '\\s*=\\s*pass', 'i');
  const failRe = new RegExp(key + '\\s*=\\s*fail', 'i');
  if (passRe.test(block)) return 'Pass';
  if (failRe.test(block)) return 'Fail';
  return 'Unknown';
}

/************ IMPERSONATION CHECK (ported as-is) ************/

function levenshtein(a, b) {
  const m = [];
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  for (let i = 0; i <= b.length; i++) m[i] = [i];
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      m[i][j] = Math.min(
        m[i - 1][j] + 1,
        m[i][j - 1] + 1,
        m[i - 1][j - 1] + (b.charAt(i - 1) === a.charAt(j - 1) ? 0 : 1)
      );
    }
  }
  return m[b.length][a.length];
}

function impersonationCheck(domains) {
  const pairs = [];
  for (let i = 0; i < domains.length; i++) {
    for (let j = i + 1; j < domains.length; j++) {
      const d1 = domains[i];
      const d2 = domains[j];
      const dist = levenshtein(d1, d2);
      const threshold = Math.max(2, Math.floor(Math.min(d1.length, d2.length) * 0.2));
      if (dist > 0 && dist <= threshold) {
        pairs.push(d1 + ' vs ' + d2);
      }
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

    const activeDomain =
      selectedDomain && allDomains.indexOf(selectedDomain) > -1 ? selectedDomain : fromDomain;

    const imp = impersonationCheck(allDomains);

    const dnsBundle = activeDomain
      ? await getDNSBundle(activeDomain)
      : { spf: 'N/A', dmarc: 'N/A', mx: 'N/A', provider: 'Unknown' };

    const authBlock = getAuthBlock(rawHeaders);
    const auth = {
      spf: getAuthStatus(authBlock, 'spf'),
      dkim: getAuthStatus(authBlock, 'dkim'),
      dmarc: getAuthStatus(authBlock, 'dmarc'),
    };

    res.json({
      fromEmail,
      fromDomain,
      activeDomain,
      domains: allDomains,
      impersonation: imp,
      dns: dnsBundle,
      auth,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error analyzing email', details: err.message });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Email Data Metrics API listening on port ${PORT}`);
});

module.exports = app; // useful for testing
