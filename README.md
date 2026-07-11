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

## Self-host (Cloudflare Workers, free tier)

Create a Worker, paste `worker.js`, deploy. Optional `SERVER_API_KEY` env var gates access behind `Authorization: Bearer <key>`. No other configuration needed.

## License

MIT. Data from RDAP, Cloudflare DNS, and crt.sh under their respective terms.
