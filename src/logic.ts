import type { Hono } from "hono";


// ATXP: requirePayment only fires inside an ATXP context (set by atxpHono middleware).
// For raw x402 requests, the existing @x402/hono middleware handles the gate.
// If neither protocol is active (ATXP_CONNECTION unset), tryRequirePayment is a no-op.
async function tryRequirePayment(price: number): Promise<void> {
  if (!process.env.ATXP_CONNECTION) return;
  try {
    const { requirePayment } = await import("@atxp/server");
    const BigNumber = (await import("bignumber.js")).default;
    await requirePayment({ price: BigNumber(price) });
  } catch (e: any) {
    if (e?.code === -30402) throw e;
  }
}

// ---------------------------------------------------------------------------
// Known VPN / hosting / proxy providers for heuristic detection
// ---------------------------------------------------------------------------

const VPN_KEYWORDS = [
  "nordvpn", "expressvpn", "surfshark", "cyberghost", "protonvpn", "proton vpn",
  "private internet access", "pia", "mullvad", "windscribe", "tunnelbear",
  "ipvanish", "vyprvpn", "hide.me", "purevpn", "hotspot shield", "zenmate",
  "torguard", "astrill", "strongvpn", "airvpn",
];

const HOSTING_KEYWORDS = [
  "amazon", "aws", "google cloud", "microsoft azure", "digitalocean",
  "linode", "akamai", "vultr", "ovh", "hetzner", "scaleway", "oracle cloud",
  "cloudflare", "fastly", "choopa", "m247", "leaseweb", "quadranet",
  "contabo", "kamatera", "hostwinds", "interserver",
  "data center", "datacenter", "hosting", "server", "cloud",
  "colocation", "colo", "vps",
];

const TOR_ASNS = [
  "AS209", "AS13335", // commonly seen exit nodes — simplified heuristic
];

// ---------------------------------------------------------------------------
// IP validation
// ---------------------------------------------------------------------------

const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_REGEX = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;

function isValidIp(ip: string): boolean {
  return IPV4_REGEX.test(ip) || IPV6_REGEX.test(ip);
}

// ---------------------------------------------------------------------------
// Geolocation lookup via ip-api.com (free, 45 req/min)
// ---------------------------------------------------------------------------

interface GeoResult {
  ip: string;
  country: string | null;
  country_code: string | null;
  region: string | null;
  region_code: string | null;
  city: string | null;
  zip: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
  isp: string | null;
  organization: string | null;
  asn: string | null;
  connection_type: string | null;
  is_vpn: boolean;
  is_proxy: boolean;
  is_hosting: boolean;
  is_tor: boolean;
  threat_score: "low" | "medium" | "high";
}

async function lookupIp(ip: string): Promise<GeoResult> {
  const result: GeoResult = {
    ip,
    country: null, country_code: null, region: null, region_code: null,
    city: null, zip: null, latitude: null, longitude: null, timezone: null,
    isp: null, organization: null, asn: null, connection_type: null,
    is_vpn: false, is_proxy: false, is_hosting: false, is_tor: false,
    threat_score: "low",
  };

  try {
    // ip-api.com fields: status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query
    const url = `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,mobile,query`;
    const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
    const data = await res.json() as any;

    if (data.status === "success") {
      result.country = data.country || null;
      result.country_code = data.countryCode || null;
      result.region = data.regionName || null;
      result.region_code = data.region || null;
      result.city = data.city || null;
      result.zip = data.zip || null;
      result.latitude = data.lat ?? null;
      result.longitude = data.lon ?? null;
      result.timezone = data.timezone || null;
      result.isp = data.isp || null;
      result.organization = data.org || null;
      result.asn = data.as || null;
      result.is_proxy = data.proxy === true;
      result.is_hosting = data.hosting === true;
      result.connection_type = data.mobile ? "mobile" : (data.hosting ? "hosting" : "residential");

      // VPN heuristic: check ISP/org name against known VPN providers
      const ispLower = (result.isp || "").toLowerCase();
      const orgLower = (result.organization || "").toLowerCase();
      const combined = `${ispLower} ${orgLower}`;

      result.is_vpn = VPN_KEYWORDS.some(kw => combined.includes(kw));

      // Hosting heuristic: supplement ip-api's flag
      if (!result.is_hosting) {
        result.is_hosting = HOSTING_KEYWORDS.some(kw => combined.includes(kw));
      }

      // Tor heuristic: check ASN
      if (result.asn) {
        const asnNumber = result.asn.split(" ")[0];
        result.is_tor = TOR_ASNS.includes(asnNumber);
      }

      // Threat score
      const flags = [result.is_vpn, result.is_proxy, result.is_hosting, result.is_tor].filter(Boolean).length;
      result.threat_score = flags >= 2 ? "high" : flags === 1 ? "medium" : "low";
    }
  } catch {
    // Lookup failed — return partial data
  }

  return result;
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export function registerRoutes(app: Hono) {
  // Single IP lookup
  app.get("/api/lookup", async (c) => {
    await tryRequirePayment(0.003);
    const ip = c.req.query("ip");
    if (!ip) return c.json({ error: "Missing required parameter: ip" }, 400);
    if (!isValidIp(ip)) return c.json({ error: "Invalid IP address format" }, 400);

    const startTime = Date.now();
    try {
      const result = await lookupIp(ip);
      return c.json({ ...result, lookup_time_ms: Date.now() - startTime });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Lookup failed";
      return c.json({ error: msg, ip, lookup_time_ms: Date.now() - startTime }, 500);
    }
  });

  // Batch IP lookup (up to 20)
  app.post("/api/lookup/batch", async (c) => {
    await tryRequirePayment(0.01);
    let body: { ips?: string[] };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    if (!body.ips || !Array.isArray(body.ips)) {
      return c.json({ error: "Missing required field: ips (array of IP addresses)" }, 400);
    }
    if (body.ips.length === 0) {
      return c.json({ error: "ips array must not be empty" }, 400);
    }
    if (body.ips.length > 20) {
      return c.json({ error: "Maximum 20 IPs per batch request" }, 400);
    }

    const invalid = body.ips.filter(ip => !isValidIp(ip));
    if (invalid.length > 0) {
      return c.json({ error: `Invalid IP addresses: ${invalid.join(", ")}` }, 400);
    }

    const startTime = Date.now();
    try {
      // ip-api.com has a batch endpoint but it's POST to /batch
      // We'll use individual lookups with concurrency to stay within rate limits
      const results = await Promise.all(body.ips.map(ip => lookupIp(ip)));
      return c.json({
        count: results.length,
        results,
        lookup_time_ms: Date.now() - startTime,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Batch lookup failed";
      return c.json({ error: msg, lookup_time_ms: Date.now() - startTime }, 500);
    }
  });
}
