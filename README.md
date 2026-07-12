# Domain & Company Intel MCP — by SelfLabbs

Domain and company intelligence for AI agents. Give an agent a domain or email address and it can vet the company, qualify the lead, or map the target — all from free public data, no API keys.

## Tools

| Tool | What it does | Source |
|---|---|---|
| `domain_intel` | Registrar, creation/expiry dates, domain age, EPP status, nameservers, DNSSEC, abuse contact | RDAP |
| `dns_lookup` | A, AAAA, MX, NS, TXT, CNAME, SOA records | Cloudflare DoH |
| `email_deliverability` | MX presence, SPF/DMARC posture, free vs. disposable provider, verdict | Cloudflare DoH |
| `tech_stack` | Web server, CMS/framework, CDN, analytics, security headers, page title | Live fetch |
| `subdomains` | Subdomain discovery from Certificate Transparency logs | crt.sh |
| `domain_report` | One call returns a full dossier: registration + DNS + email deliverability + tech stack, combined | all-in-one |

No API keys required for any tool.

## Quick start (hosted)

**Claude Code**
```bash
claude mcp add --transport http domain-intel https://domain-intel-mcp.greenfield1775.workers.dev/mcp
```

**Claude Desktop / other clients**
```json
{
  "mcpServers": {
    "domain-intel": {
      "command": "npx",
      "args": ["mcp-remote", "https://domain-intel-mcp.greenfield1775.workers.dev/mcp"]
    }
  }
}
```

## Example agent workflows

- *"Is acme.com a real, established business? When was it registered?"* → `domain_intel`
- *"This lead's email is @acme.io — can it receive mail, is it a throwaway?"* → `email_deliverability`
- *"What's competitor.com built on?"* → `tech_stack`
- *"Map the public subdomains of target.com"* → `subdomains`

## Pricing

The hosted endpoint is **freemium**:

- **Free** — all six tools work, results capped at 10 items per call. No key required.
- **Builder — $19/mo** — uncapped results, 5,000 tool calls/mo, priority endpoint.
- **Team — $49/mo** — uncapped results, 25,000 tool calls/mo, usage dashboard.

**[Subscribe →](https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf)** — one subscription unlocks Pro on every SelfLabbs server.

### Using your Pro key

After subscribing you receive a license key beginning with `SELFLABBS-`. Pass it as a Bearer token and the free-tier caps are removed:

```bash
claude mcp add --transport http --header "Authorization: Bearer SELFLABBS-XXXX-XXXX" domain-intel https://domain-intel-mcp.greenfield1775.workers.dev/mcp
```

The key is validated against Polar on each request (cached briefly). Cancel anytime — access reverts to the free tier automatically.

## Self-host (Cloudflare Workers, free tier)

Create a Worker, paste `worker.js`, deploy. Optional `SERVER_API_KEY` env var gates access behind `Authorization: Bearer <key>`. No other configuration needed.

## License

MIT. Data from RDAP, Cloudflare DNS, and crt.sh under their respective terms.
