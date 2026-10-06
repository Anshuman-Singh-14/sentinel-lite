# Role 1: Backend & Security

**Owner:** Member 1
**Files:** `backend/app.py`, `config.py`, `db.py`, `models.py`, `auth.py`, `cli.py`, `validation.py`,
`admin.py`, `guard.py`, and the tests `test_auth.py`, `test_guard.py`, `test_admin.py`.

My part is everything that decides **who** can use Sentinel Lite and **what** they are allowed to do:
logging in, admin-only pages, which hosts may be scanned, how often, and the record of who did what.

## 1. What happens when someone logs in

1. The browser sends `POST /api/auth/login` with `{"username": ..., "password": ...}`.
   Pydantic checks the body first (the username can be at most 32 characters, the password at most 200).
2. `guard.check_login_rate()` counts login attempts from the client's IP address. After 5 in one
   minute it answers **429 Too Many Requests**. This slows down password-guessing bots.
3. We look the username up in the `users` table.
4. `bcrypt.checkpw()` compares the typed password with the stored **bcrypt hash**. We never store
   the password itself, only the hash, and bcrypt is deliberately slow so stolen hashes are hard
   to crack.
5. If the username doesn't exist, we still run bcrypt against a dummy hash. That way a wrong
   username takes as long as a wrong password, and an attacker can't tell from the response time
   which usernames are real. The error message is also the same: "Wrong username or password".
6. If the check fails or the account is deactivated, we answer **401** and record a
   `login_failed` entry in the activity log.
7. On success we clear any old session, put the user's id into the session
   (`request.session["user_id"] = user.id`), record a `login` entry, and return the user's
   name and role.

After that, every protected route uses the `current_user` dependency. It reads the user id from
the session cookie and loads the user **from the database on every request**. So if an admin
deactivates someone, their very next request is refused, even though their cookie still exists.
Admin routes add `require_admin`, which answers **403** to normal users.

## 2. How `check_target` decides whether a scan may run

The port scan and the website check send traffic to another computer, so they must only hit
systems we are allowed to test. Before connecting, both call `guard.check_target(db, host)`:

1. **Is it approved?** The host must be in the `allowed_targets` table, which only admins can
   change (Admin page → Approved scan targets). If not: **403** "not an approved target".
2. **What is its IP address?** If the host is already an IPv4 address we use it as-is. Otherwise
   we ask the public DNS resolvers 1.1.1.1 and 8.8.8.8, with a 3-second timeout. We use public
   resolvers because laptop DNS settings often point at VPN servers that don't answer.
3. **Production only: is it an internal address?** When `APP_ENV=prod`, we refuse:
   - addresses that aren't normal public internet hosts: localhost (127.x), private networks
     (10.x, 172.16–31.x, 192.168.x), link-local, reserved and multicast (`is_internal_ip`);
   - the server's own public IP, found by looking up our own `DOMAIN`.

   This applies **even if an admin approved the host**. It protects against a mistake, or a
   domain whose DNS was changed to point inside our network. Without it, someone could use our
   server to scan the private network it sits in (a type of attack called SSRF).
4. If everything passes, we return the IP address, and the port scanner connects to **that exact
   IP**. It doesn't look the name up again.

In development (`APP_ENV=dev`) step 3 is skipped, so the team can approve `127.0.0.1` and scan
their own laptop for the demo.

## 3. Why the session cookie is httpOnly, Secure and SameSite=Lax

After login the browser stores a cookie called `sentinel_session`. It holds only the user id,
**signed** with `SECRET_KEY` (Starlette's `SessionMiddleware`). Anyone can read a signed cookie,
but changing it breaks the signature, so a user can't edit it to become someone else.

| Setting | What it does | What it protects against |
|---|---|---|
| **httpOnly** | JavaScript on the page cannot read the cookie | If an attacker ever injects a script (XSS), it still can't steal the session |
| **Secure** (production only) | The cookie is only sent over HTTPS | Someone on the same Wi-Fi can't read it from plain HTTP traffic. It is off in development because `http://localhost` has no HTTPS |
| **SameSite=Lax** | The browser doesn't send the cookie on POST requests that come from other websites | Cross-site request forgery (CSRF): a malicious page can't submit a form to our API that runs a scan or creates a user as the logged-in person. This is why we don't need CSRF tokens |
| **max_age 8 hours** | The session expires after 8 hours | A forgotten logged-in browser doesn't stay usable forever |

## 4. Rate limits and the activity log

- **Rate limits** (`RateLimiter` in `guard.py`) keep a list of recent timestamps per user (scans:
  10 per minute) or per IP (logins: 5 per minute). Each time, timestamps older than 60 seconds
  are removed. If the list is still full, the request gets **429**. A lock makes this safe when
  FastAPI handles several requests at once.
- **Activity log**: `log_activity()` writes a row (`username`, `action`, `detail`, time) for every
  login, failed login, logout, scan and admin change. Admins see the newest 200 on the Admin page.

## 5. Known limitations

- The rate limits live in memory, so they reset when the server restarts, and they assume a
  single server process. The systemd service runs exactly one, so this holds in production.
- The website check looks the hostname up again when it connects. If a domain's DNS changed in
  the milliseconds between our check and the request (DNS rebinding), the private-IP block could
  be bypassed. The port scanner doesn't have this problem because it connects to the checked IP.

## 6. How it is tested

`tests/test_auth.py`, `test_guard.py` and `test_admin.py` check, among other things, that:

- a wrong username and a wrong password look identical;
- unapproved targets are refused;
- private IPs and the server's own IP are refused in production;
- the 11th scan in a minute is refused;
- an admin can't remove their own admin rights;
- the activity log records logins and admin actions.

Run them with `python -m pytest`.