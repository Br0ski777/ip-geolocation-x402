import type { ApiConfig } from "./shared";

export const API_CONFIG: ApiConfig = {
  name: "ip-geolocation",
  slug: "ip-geolocation",
  description: "Geolocate any IP address -- country, city, ISP, ASN, VPN/proxy/Tor detection. IPv4 and IPv6 support.",
  version: "1.0.0",
  routes: [
    {
      method: "GET",
      path: "/api/lookup",
      price: "$0.003",
      description: "Geolocate a single IP address",
      toolName: "ip_lookup_geolocation",
      toolDescription: `Use this when you need to geolocate an IP address. Returns full location and network data in JSON.

Returns: 1. country and countryCode 2. region and city 3. latitude and longitude 4. timezone 5. ISP and organization 6. ASN 7. connectionType 8. isVPN, isProxy, isTor flags.

Example output: {"ip":"8.8.8.8","country":"United States","countryCode":"US","region":"California","city":"Mountain View","latitude":37.386,"longitude":-122.084,"timezone":"America/Los_Angeles","isp":"Google LLC","asn":"AS15169","isVPN":false,"isProxy":false,"isTor":false}

Use this FOR fraud detection, content localization, access control by region, analytics enrichment, and bot detection.

Do NOT use for domain data -- use domain_lookup_intelligence instead. Do NOT use for DNS records -- use network_lookup_dns instead.`,
      inputSchema: {
        type: "object",
        properties: {
          ip: { type: "string", description: "IP address to lookup (e.g. 8.8.8.8)" },
        },
        required: ["ip"],
      },
    },
    {
      method: "POST",
      path: "/api/lookup/batch",
      price: "$0.01",
      description: "Geolocate up to 20 IP addresses in one call",
      toolName: "ip_lookup_geolocation_batch",
      toolDescription: `Use this when you need to geolocate multiple IP addresses at once (up to 20). Returns an array of geolocation results in JSON.

Returns per IP: 1. country, region, city 2. latitude, longitude 3. timezone 4. ISP, ASN 5. isVPN, isProxy, isTor flags.

Example output: {"results":[{"ip":"8.8.8.8","country":"United States","city":"Mountain View","isp":"Google LLC","isVPN":false},{"ip":"1.1.1.1","country":"Australia","city":"Sydney","isp":"Cloudflare","isVPN":false}],"total":2}

Use this FOR bulk log analysis, batch fraud screening, and enriching analytics data with location info. More cost-effective than single lookups.

Do NOT use for single IPs -- use ip_lookup_geolocation instead. Do NOT use for domain data -- use domain_lookup_intelligence instead.`,
      inputSchema: {
        type: "object",
        properties: {
          ips: {
            type: "array",
            items: { type: "string" },
            description: "Array of IP addresses to lookup (max 20)",
          },
        },
        required: ["ips"],
      },
    },
  ],
};
