/**
 * SelfLabbs Domain & Company Intel MCP Server
 * Remote MCP server (Streamable HTTP, stateless) for Cloudflare Workers.
 * Zero dependencies, zero API keys. All data from free public sources.
 *
 * Tools:
 *   domain_intel        — registration data via RDAP (registrar, dates, status, nameservers, age)
 *   dns_lookup          — A/AAAA/MX/NS/TXT/CNAME/SOA via Cloudflare DoH
 *   email_deliverability— MX presence + SPF/DMARC posture, free/disposable detection
 *   tech_stack          — homepage fingerprint: server, CMS/framework, CDN, analytics
 *   subdomains          — certificate-transparency subdomain discovery (crt.sh)
 */

const SERVER_INFO = { name: "selflabbs-domain-intel", version: "1.0.0" };
const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const TOOLS = [
  {
    name: "domain_intel",
    description:
      "Registration intelligence for a domain via RDAP (the modern WHOIS). Returns registrar, creation/expiration/last-changed dates, domain age in years, EPP status codes, nameservers, DNSSEC state, and abuse contact. Use to vet a company, assess a lead, or judge how established a domain is.",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name, e.g. stripe.com (no scheme)" } },
      required: ["domain"],
    },
  },
  {
    name: "dns_lookup",
    description:
      "Look up DNS records for a domain via Cloudflare DNS-over-HTTPS. Returns A, AAAA, MX, NS, TXT, CNAME, and SOA records. Use to see where a domain is hosted, who runs its mail and DNS, and what verification/policy TXT records it publishes.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Domain name, e.g. stripe.com" },
        types: {
          type: "array",
          items: { type: "string" },
          description: "Optional subset of record types, e.g. [\"MX\",\"TXT\"]. Defaults to all common types.",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "email_deliverability",
    description:
      "Assess whether a domain (or the domain of an email address) can receive mail and how strong its sender authentication is. Returns MX presence, SPF and DMARC policy, whether it's a free consumer provider (gmail, etc.) or a known disposable/temp-mail provider, and an overall verdict. Use to qualify leads and flag throwaway signups.",
    inputSchema: {
      type: "object",
      properties: {
        domain_or_email: { type: "string", description: "A domain (stripe.com) or an email address (a@stripe.com)" },
      },
      required: ["domain_or_email"],
    },
  },
  {
    name: "tech_stack",
    description:
      "Fingerprint the technology behind a website by fetching its homepage. Detects web server, CMS/framework (WordPress, Shopify, Next.js, etc.), CDN, analytics, and returns the page title, final URL after redirects, and key response headers. Use for competitive research and lead enrichment.",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain or full URL, e.g. shopify.com" } },
      required: ["domain"],
    },
  },
  {
    name: "subdomains",
    description:
      "Discover subdomains of a domain from public Certificate Transparency logs (crt.sh). Useful for mapping a company's public surface (app., api., staging., etc.). Best-effort: crt.sh can be slow; returns a note if unavailable.",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Registrable domain, e.g. stripe.com" } },
      required: ["domain"],
    },
  },
];

class UserError extends Error {}

const FREE_PROVIDERS = new Set([
  "gmail.com","googlemail.com","yahoo.com","ymail.com","outlook.com","hotmail.com","live.com","msn.com",
  "aol.com","icloud.com","me.com","mac.com","proton.me","protonmail.com","gmx.com","gmx.net","mail.com",
  "zoho.com","yandex.com","yandex.ru","fastmail.com","tutanota.com","hey.com",
]);
const DISPOSABLE_PROVIDERS = new Set([
  "mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com","temp-mail.org","throwawaymail.com",
  "yopmail.com","getnada.com","trashmail.com","sharklasers.com","dispostable.com","maildrop.cc","fakeinbox.com",
  "mohmal.com","emailondeck.com","mintemail.com","spamgourmet.com","tempr.email","moakt.com",
]);

function cleanDomain(input) {
  let d = String(input || "").trim().toLowerCase();
  if (d.includes("@")) d = d.split("@").pop();
  d = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:.*$/, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) throw new UserError("Invalid domain: " + input);
  return d;
}

async function doh(name, type) {
  const url = "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=" + type;
  const res = await fetch(url, { headers: { accept: "application/dns-json" } });
  if (!res.ok) throw new UserError("DNS query failed (HTTP " + res.status + ")");
  const data = await res.json();
  return (data.Answer || []).map(function (a) { return a.data; });
}

async function domainIntel(args) {
  const domain = cleanDomain(args.domain);
  const res = await fetch("https://rdap.org/domain/" + encodeURIComponent(domain), {
    headers: { Accept: "application/rdap+json", "User-Agent": "selflabbs-domain-intel-mcp" },
    redirect: "follow",
  });
  if (res.status === 404) return { domain: domain, found: false, note: "No RDAP record found. Domain may be unregistered or use a TLD without RDAP." };
  if (!res.ok) throw new UserError("RDAP lookup failed (HTTP " + res.status + ")");
  const d = await res.json();
  const events = {};
  for (const e of d.events || []) events[e.eventAction] = e.eventDate;
  let registrar = null, abuse = null;
  for (const ent of d.entities || []) {
    if ((ent.roles || []).indexOf("registrar") !== -1) {
      const fn = (ent.vcardArray && ent.vcardArray[1] || []).find(function (x) { return x[0] === "fn"; });
      if (fn) registrar = fn[3];
      for (const sub of ent.entities || []) {
        if ((sub.roles || []).indexOf("abuse") !== -1) {
          const em = (sub.vcardArray && sub.vcardArray[1] || []).find(function (x) { return x[0] === "email"; });
          if (em) abuse = em[3];
        }
      }
    }
  }
  const created = events.registration;
  let ageYears = null;
  if (created) ageYears = Math.floor((Date.now() - new Date(created).getTime()) / (365.25 * 24 * 3600 * 1000));
  return {
    domain: domain,
    found: true,
    registrar: registrar,
    created: created || null,
    expires: events.expiration || null,
    last_changed: events["last changed"] || null,
    age_years: ageYears,
    status: d.status || [],
    nameservers: (d.nameservers || []).map(function (n) { return (n.ldhName || "").toLowerCase(); }),
    dnssec_signed: Boolean(d.secureDNS && d.secureDNS.delegationSigned),
    abuse_contact: abuse,
  };
}

async function dnsLookup(args) {
  const domain = cleanDomain(args.domain);
  const all = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
  const types = Array.isArray(args.types) && args.types.length
    ? args.types.map(function (t) { return String(t).toUpperCase(); }).filter(function (t) { return all.indexOf(t) !== -1; })
    : all;
  const out = {};
  await Promise.all(types.map(async function (t) {
    try { out[t] = await doh(domain, t); } catch (e) { out[t] = []; }
  }));
  return { domain: domain, records: out };
}

async function emailDeliverability(args) {
  const domain = cleanDomain(args.domain_or_email);
  const [mx, txt, dmarcTxt] = await Promise.all([
    doh(domain, "MX").catch(function () { return []; }),
    doh(domain, "TXT").catch(function () { return []; }),
    doh("_dmarc." + domain, "TXT").catch(function () { return []; }),
  ]);
  const spf = txt.map(function (t) { return t.replace(/"/g, ""); }).find(function (t) { return t.toLowerCase().indexOf("v=spf1") === 0; }) || null;
  const dmarc = dmarcTxt.map(function (t) { return t.replace(/"/g, ""); }).find(function (t) { return t.toLowerCase().indexOf("v=dmarc1") === 0; }) || null;
  let dmarcPolicy = null;
  if (dmarc) { const m = dmarc.match(/p=([a-z]+)/i); dmarcPolicy = m ? m[1].toLowerCase() : null; }
  const isFree = FREE_PROVIDERS.has(domain);
  const isDisposable = DISPOSABLE_PROVIDERS.has(domain);
  const hasMx = mx.length > 0;
  let verdict;
  if (isDisposable) verdict = "disposable";
  else if (!hasMx) verdict = "cannot_receive_mail";
  else if (isFree) verdict = "free_consumer_provider";
  else verdict = "business_domain";
  return {
    domain: domain,
    can_receive_mail: hasMx,
    mx_hosts: mx.map(function (r) { return r.split(" ").pop(); }),
    spf: spf,
    dmarc_policy: dmarcPolicy,
    dmarc_record: dmarc,
    is_free_provider: isFree,
    is_disposable: isDisposable,
    auth_posture: hasMx ? ((spf ? 1 : 0) + (dmarc ? 1 : 0) === 2 ? "strong" : (spf || dmarc) ? "partial" : "none") : "n/a",
    verdict: verdict,
  };
}

const TECH_SIGNATURES = [
  { name: "WordPress", test: function (h, b) { return /wp-content|wp-includes/i.test(b) || /wordpress/i.test(h.generator || ""); } },
  { name: "Shopify", test: function (h, b) { return /cdn\.shopify\.com|x-shopid/i.test(b + JSON.stringify(h)); } },
  { name: "Wix", test: function (h, b) { return /static\.wixstatic\.com|X-Wix/i.test(b + JSON.stringify(h)); } },
  { name: "Squarespace", test: function (h, b) { return /squarespace/i.test(b) || /Squarespace/i.test(h.server || ""); } },
  { name: "Webflow", test: function (h, b) { return /webflow/i.test(b) || /Webflow/i.test(h.generator || ""); } },
  { name: "Next.js", test: function (h, b) { return /_next\/static|__NEXT_DATA__/i.test(b) || "x-nextjs-cache" in h; } },
  { name: "Nuxt", test: function (h, b) { return /__NUXT__|_nuxt\//i.test(b); } },
  { name: "React", test: function (h, b) { return /data-reactroot|react\./i.test(b); } },
  { name: "Vue", test: function (h, b) { return /data-v-|vue(\.min)?\.js/i.test(b); } },
  { name: "Gatsby", test: function (h, b) { return /gatsby/i.test(b); } },
  { name: "HubSpot", test: function (h, b) { return /hs-scripts|hubspot/i.test(b); } },
  { name: "Drupal", test: function (h, b) { return /Drupal/i.test(b) || "x-drupal-cache" in h; } },
  { name: "Ghost", test: function (h, b) { return /ghost/i.test(h.generator || "") || /content=\"Ghost/i.test(b); } },
];
const ANALYTICS_SIGNATURES = [
  { name: "Google Analytics", re: /google-analytics\.com|gtag\(|googletagmanager\.com/i },
  { name: "Plausible", re: /plausible\.io/i },
  { name: "Segment", re: /cdn\.segment\.com/i },
  { name: "Mixpanel", re: /mixpanel/i },
  { name: "Hotjar", re: /hotjar/i },
  { name: "Meta Pixel", re: /connect\.facebook\.net|fbq\(/i },
];

async function techStack(args) {
  let target = String(args.domain || "").trim();
  if (!/^https?:\/\//i.test(target)) target = "https://" + cleanDomain(target);
  const controller = new AbortController();
  const timer = setTimeout(function () { controller.abort(); }, 8000);
  let res;
  try {
    res = await fetch(target, { redirect: "follow", signal: controller.signal, headers: { "User-Agent": "Mozilla/5.0 (compatible; selflabbs-domain-intel/1.0)" } });
  } catch (e) {
    clearTimeout(timer);
    throw new UserError("Could not fetch site: " + (e.name === "AbortError" ? "timed out" : e.message));
  }
  clearTimeout(timer);
  const headers = {};
  res.headers.forEach(function (v, k) { headers[k.toLowerCase()] = v; });
  let body = "";
  try { body = (await res.text()).slice(0, 200000); } catch (e) {}
  const genMatch = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  const generator = genMatch ? genMatch[1] : null;
  const titleMatch = body.match(/<title[^>]*>([^<]{0,200})<\/title>/i);
  const hdrForSig = Object.assign({ generator: generator }, headers);
  const tech = TECH_SIGNATURES.filter(function (s) { return s.test(hdrForSig, body); }).map(function (s) { return s.name; });
  const analytics = ANALYTICS_SIGNATURES.filter(function (s) { return s.re.test(body); }).map(function (s) { return s.name; });
  return {
    url: res.url,
    status: res.status,
    title: titleMatch ? titleMatch[1].trim() : null,
    server: headers["server"] || null,
    powered_by: headers["x-powered-by"] || null,
    cdn: headers["cf-ray"] ? "Cloudflare" : (headers["x-served-by"] ? "Fastly" : (headers["x-amz-cf-id"] ? "CloudFront" : null)),
    generator: generator,
    technologies: tech,
    analytics: analytics,
    security_headers: {
      hsts: Boolean(headers["strict-transport-security"]),
      csp: Boolean(headers["content-security-policy"]),
      x_frame_options: headers["x-frame-options"] || null,
    },
  };
}

async function subdomains(args) {
  const domain = cleanDomain(args.domain);
  const controller = new AbortController();
  const timer = setTimeout(function () { controller.abort(); }, 9000);
  let res;
  try {
    res = await fetch("https://crt.sh/?q=%25." + encodeURIComponent(domain) + "&output=json", { signal: controller.signal, headers: { "User-Agent": "selflabbs-domain-intel-mcp" } });
  } catch (e) {
    clearTimeout(timer);
    return { domain: domain, available: false, note: "Certificate Transparency source (crt.sh) unavailable or timed out. Try again shortly." };
  }
  clearTimeout(timer);
  if (!res.ok) return { domain: domain, available: false, note: "crt.sh returned HTTP " + res.status };
  let rows;
  try { rows = await res.json(); } catch (e) { return { domain: domain, available: false, note: "crt.sh returned no parseable data." }; }
  const set = new Set();
  for (const r of rows || []) {
    String(r.name_value || "").split("\n").forEach(function (n) {
      n = n.trim().toLowerCase();
      if (n && !n.startsWith("*.") && (n === domain || n.endsWith("." + domain))) set.add(n);
    });
  }
  const list = Array.from(set).sort();
  return { domain: domain, available: true, count: list.length, subdomains: list.slice(0, 200), truncated: list.length > 200 };
}

const TOOL_IMPLS = {
  domain_intel: domainIntel,
  dns_lookup: dnsLookup,
  email_deliverability: emailDeliverability,
  tech_stack: techStack,
  subdomains: subdomains,
};

function rpcResult(id, result) { return { jsonrpc: "2.0", id: id, result: result }; }
function rpcError(id, code, message) { return { jsonrpc: "2.0", id: id, error: { code: code, message: message } }; }

async function handleRpc(msg, env) {
  const id = msg.id, method = msg.method, params = msg.params;
  if (id === undefined || id === null) return null;
  switch (method) {
    case "initialize": {
      const requested = params && params.protocolVersion;
      return rpcResult(id, {
        protocolVersion: PROTOCOL_VERSIONS.indexOf(requested) !== -1 ? requested : PROTOCOL_VERSIONS[0],
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
        instructions: "Domain and company intelligence tools for AI agents: registration data (RDAP), DNS records, email deliverability, website tech-stack fingerprinting, and subdomain discovery. Use for lead qualification, competitive research, and reconnaissance.",
      });
    }
    case "ping": return rpcResult(id, {});
    case "tools/list": return rpcResult(id, { tools: TOOLS });
    case "tools/call": {
      const name = params && params.name;
      const impl = TOOL_IMPLS[name];
      if (!impl) return rpcError(id, -32602, "Unknown tool: " + name);
      try {
        const out = await impl((params && params.arguments) || {}, env);
        return rpcResult(id, { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] });
      } catch (e) {
        const message = e instanceof UserError ? e.message : "Internal error: " + e.message;
        return rpcResult(id, { content: [{ type: "text", text: message }], isError: true });
      }
    }
    case "resources/list": return rpcResult(id, { resources: [] });
    case "prompts/list": return rpcResult(id, { prompts: [] });
    default: return rpcError(id, -32601, "Method not found: " + method);
  }
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version",
  "Access-Control-Expose-Headers": "Mcp-Session-Id",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (url.pathname === "/" && request.method === "GET") {
      return new Response(JSON.stringify({
        service: SERVER_INFO.name, version: SERVER_INFO.version, mcp_endpoint: "/mcp",
        docs: "https://selflabbs.com", tools: TOOLS.map(function (t) { return t.name; }),
      }, null, 2), { headers: Object.assign({ "Content-Type": "application/json" }, CORS) });
    }
    if (url.pathname !== "/mcp") return new Response("Not found", { status: 404, headers: CORS });
    if (env && env.SERVER_API_KEY) {
      const auth = request.headers.get("Authorization") || "";
      if (auth !== "Bearer " + env.SERVER_API_KEY)
        return new Response(JSON.stringify(rpcError(null, -32000, "Unauthorized: missing or invalid API key")), { status: 401, headers: Object.assign({ "Content-Type": "application/json" }, CORS) });
    }
    if (request.method === "GET") return new Response(null, { status: 405, headers: Object.assign({ Allow: "POST" }, CORS) });
    if (request.method === "DELETE") return new Response(null, { status: 200, headers: CORS });
    if (request.method !== "POST") return new Response(null, { status: 405, headers: Object.assign({ Allow: "POST" }, CORS) });
    let body;
    try { body = await request.json(); } catch (e) {
      return new Response(JSON.stringify(rpcError(null, -32700, "Parse error")), { status: 400, headers: Object.assign({ "Content-Type": "application/json" }, CORS) });
    }
    const messages = Array.isArray(body) ? body : [body];
    const settled = await Promise.all(messages.map(function (m) { return handleRpc(m, env); }));
    const responses = settled.filter(function (r) { return r !== null; });
    if (responses.length === 0) return new Response(null, { status: 202, headers: CORS });
    const payload = Array.isArray(body) ? responses : responses[0];
    return new Response(JSON.stringify(payload), { headers: Object.assign({ "Content-Type": "application/json" }, CORS) });
  },
};
