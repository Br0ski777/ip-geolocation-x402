# IP Geolocation API

[![MCP Server](https://img.shields.io/badge/MCP-server-blue)](https://ip-geolocation.api.klymax402.com/mcp)
[![x402](https://img.shields.io/badge/payments-x402-6E56CF)](https://x402.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Geolocate any IP address -- country, city, ISP, ASN, VPN/proxy/Tor detection. IPv4 and IPv6 support. Pay-per-call via [x402](https://x402.org) (USDC on Base L2) -- no API key, no signup, no rate-limit wall.

Part of the [klymax402](https://klymax402.com) marketplace -- 100 x402 micropayment APIs for AI agents, one wallet, USDC on Base.

## Quickstart -- MCP

Add to your MCP client config (Claude Desktop, Cursor, ElizaOS, etc.):

```json
{
  "mcpServers": {
    "ip-geolocation": {
      "url": "https://ip-geolocation.api.klymax402.com/mcp"
    }
  }
}
```

## Quickstart -- HTTP (x402)

```bash
curl "https://ip-geolocation.api.klymax402.com/api/lookup?ip=..."
# -> 402 Payment Required, with an x402 payment challenge in the response body
```

Any x402-aware client ([`@x402/fetch`](https://www.npmjs.com/package/@x402/fetch), [`x402-agent-tools`](https://www.npmjs.com/package/x402-agent-tools), ATXP) handles the 402 -> sign -> retry cycle automatically.

## Tools

| Tool | Method | Path | Price | Description |
|---|---|---|---|---|
| `ip_lookup_geolocation` | GET | `/api/lookup` | $0.003 | Geolocate a single IP address |
| `ip_lookup_geolocation_batch` | POST | `/api/lookup/batch` | $0.01 | Geolocate up to 20 IP addresses in one call |

### `ip_lookup_geolocation`

Use this when you need to geolocate an IP address. Returns full location and network data in JSON.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `ip` | string | yes | IP address to lookup (e.g. 8.8.8.8) |

Example response:

```json
{"ip":"8.8.8.8","country":"United States","countryCode":"US","region":"California","city":"Mountain View","latitude":37.386,"longitude":-122.084,"timezone":"America/Los_Angeles","isp":"Google LLC","asn":"AS15169","isVPN":false,"isProxy":false,"isTor":false}
```

**When to use**: fraud detection, content localization, access control by region, analytics enrichment, and bot detection.

**Not for**: domain data (use `domain_lookup_intelligence`), DNS records (use `network_lookup_dns`).

### `ip_lookup_geolocation_batch`

Use this when you need to geolocate multiple IP addresses at once (up to 20). Returns an array of geolocation results in JSON.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `ips` | array | yes | Array of IP addresses to lookup (max 20) |

Example response:

```json
{"results":[{"ip":"8.8.8.8","country":"United States","city":"Mountain View","isp":"Google LLC","isVPN":false},{"ip":"1.1.1.1","country":"Australia","city":"Sydney","isp":"Cloudflare","isVPN":false}],"total":2}
```

**When to use**: bulk log analysis, batch fraud screening, and enriching analytics data with location info. More cost-effective than single lookups.

**Not for**: single IPs (use `ip_lookup_geolocation`), domain data (use `domain_lookup_intelligence`).

## Example agent prompts

- "Geolocate an IP address"
- "Geolocate multiple IP addresses at once (up to 20)"

## Payment

- Protocol: [x402](https://x402.org) -- HTTP-native pay-per-call, no signup, no API key
- Network: Base L2 (`eip155:8453`)
- Asset: USDC
- Facilitator: Coinbase CDP (primary), PayAI (fallback)
- Also reachable via [ATXP](https://atxp.ai) (OAuth-wrapped x402, RFC 9728 protected-resource metadata)

## Part of klymax402

100 x402 micropayment APIs for AI agents -- one wallet, USDC on Base, zero signup.

- Catalog: https://klymax402.com/llms.txt
- Full API reference: https://klymax402.com/llms-full.txt
- Live stats: https://klymax402.com/stats

## License

MIT
