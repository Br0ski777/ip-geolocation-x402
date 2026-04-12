import type { ApiConfig } from "./shared";

export const API_CONFIG: ApiConfig = {
  name: "ip-geolocation",
  slug: "ip-geolocation",
  description: "IP geolocation with country, city, ISP, ASN, and VPN/proxy detection.",
  version: "1.0.0",
  routes: [
    {
      method: "GET",
      path: "/api/lookup",
      price: "$0.003",
      description: "Geolocate a single IP address",
      toolName: "ip_lookup_geolocation",
      toolDescription: "Use this when you need to geolocate an IP address. Returns: country, region, city, latitude, longitude, timezone, ISP, organization, ASN, connection type, VPN/proxy/tor detection flag. Supports IPv4 and IPv6. Do NOT use for domain data — use domain_lookup_intelligence.",
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
      toolDescription: "Use this when you need to geolocate multiple IP addresses at once. Accepts up to 20 IPs. Returns array of geolocation results: country, region, city, lat/lon, timezone, ISP, ASN, VPN/proxy detection for each IP. More cost-effective than single lookups for bulk operations. Do NOT use for single IPs — use ip_lookup_geolocation. Do NOT use for domain data — use domain_lookup_intelligence.",
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
