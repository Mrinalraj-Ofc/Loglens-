/**
 * geoip.js — LogLens GeoIP Lookup
 * ─────────────────────────────────
 * Maps IP addresses to geographic locations.
 *
 * Uses ip-api.com — free for non-commercial use, no API key needed.
 * Rate limit: 45 requests/minute (we batch and cache to stay under).
 *
 * For production: use MaxMind GeoLite2 (local database, no rate limit,
 * but requires free registration). The local file approach is ~200× faster.
 *
 * Private/reserved IPs (10.x.x.x, 192.168.x.x, etc.) are not
 * looked up — they will never have geolocation data.
 */

// ─── In-Memory Cache ──────────────────────────────────────────────────────────

const cache = new Map();  // ip → geo result
const TTL   = 24 * 60 * 60 * 1000;  // 24-hour cache TTL

// ─── Private IP Ranges ────────────────────────────────────────────────────────

const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^::1$/,
  /^fc00:/,
  /^169\.254\./,
];

function isPrivateIP(ip) {
  return PRIVATE_RANGES.some((rx) => rx.test(ip));
}

// ─── GeoIP Lookup ─────────────────────────────────────────────────────────────

/**
 * Look up the geographic location of an IP address.
 *
 * @param {string} ip
 * @returns {Promise<GeoResult|null>}
 *
 * @typedef {Object} GeoResult
 * @property {string} country
 * @property {string} countryCode  — ISO 3166-1 alpha-2 (e.g. "US")
 * @property {string} city
 * @property {string} region
 * @property {number} lat
 * @property {number} lon
 * @property {string} isp
 * @property {boolean} proxy       — is this a known proxy/VPN/Tor exit?
 */
export async function lookupIP(ip) {
  if (!ip || isPrivateIP(ip)) {
    return { country: 'Private Network', countryCode: 'LO', city: 'localhost', region: '', lat: 0, lon: 0, isp: 'internal', proxy: false };
  }

  // Check cache
  const cached = cache.get(ip);
  if (cached && Date.now() - cached.ts < TTL) {
    return cached.data;
  }

  try {
    const url      = `http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,proxy,hosting`;
    const res      = await fetch(url, { signal: AbortSignal.timeout(5000) });
    const data     = await res.json();

    if (data.status !== 'success') return null;

    const result = {
      country:     data.country,
      countryCode: data.countryCode,
      city:        data.city,
      region:      data.regionName,
      lat:         data.lat,
      lon:         data.lon,
      isp:         data.isp,
      proxy:       data.proxy || data.hosting,
    };

    cache.set(ip, { ts: Date.now(), data: result });
    return result;

  } catch (err) {
    // Network failure or timeout — return null, don't crash
    console.warn(`[GEOIP] Lookup failed for ${ip}: ${err.message}`);
    return null;
  }
}

/**
 * Batch lookup multiple IPs with rate limiting.
 * ip-api.com allows 45 req/min = 1 per ~1.33 seconds.
 * We add a 1.4s delay between requests to stay safe.
 *
 * @param {string[]} ips
 * @returns {Promise<Map<string, GeoResult|null>>}
 */
export async function batchLookupIPs(ips) {
  const results  = new Map();
  const unique   = [...new Set(ips)].filter((ip) => ip && !isPrivateIP(ip));

  for (const ip of unique) {
    results.set(ip, await lookupIP(ip));
    // Rate limit delay — skip if cached (cache hits don't count against rate limit)
    if (!cache.has(ip)) {
      await new Promise((r) => setTimeout(r, 1400));
    }
  }

  return results;
}
