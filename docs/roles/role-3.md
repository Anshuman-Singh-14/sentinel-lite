# Role 3: Frontend & UX

**Owner:** Member 3
**Files:** everything in `frontend/`: pages, layout, the browser-only tools and the results display.

My part is what the user sees: the login screen, the sidebar, a page for every tool, the
explained findings, scan history, the admin page, and three tools that run only in the browser.
It is built with **React + Vite** in plain JavaScript and plain CSS.

## 1. How a page talks to the backend (`api.js`)

Every call to the server goes through one small function, `api(path, options)`:

1. It sends the request with `fetch()`. For JSON it sets `Content-Type: application/json`. For the
   log upload it sends a `FormData` object, and the browser builds the multipart body itself.
2. It reads the JSON answer.
3. If the status is an error (400, 401, 403, 429, ...), it throws an `ApiError` with the server's
   message. FastAPI sends either `{"detail": "text"}` or, for invalid input, a list of problems;
   `api.js` turns both into one readable sentence for the page to show.

Each tool page keeps track of its request with the `useRequest()` hook (`useRequest.js`), which
holds three things: `busy` (show "Working…"), `data` (the finished scan) and `error` (the message
to show in red). `ToolPage.jsx` is the shared frame: title, intro text, the tool's form, then
either the error or the result.

A finished scan is shown by `ScanResult.jsx`:

- a short **summary table** for that tool (open ports, DNS records, security headers or top IPs);
- the **findings**, one card each (`FindingsList.jsx`) with a coloured severity badge, the
  explanation and the fix;
- links to **Download CSV** and the **Printable report**;
- the raw data, folded away for advanced users.

## 2. How the app knows whether you are logged in

The login itself is stored in an **httpOnly session cookie** set by the server. JavaScript cannot
read it, which protects it from malicious scripts, but the browser sends it automatically with
every request to our own site.

So `App.jsx` simply asks the server when the app starts:

1. While waiting, `user` is `undefined` and the page shows "Loading…".
2. It calls `GET /api/auth/me`. If the answer is a user, `user` becomes that object and the app
   shows the sidebar and pages. If the answer is **401**, `user` becomes `null` and the app shows
   the **login page** instead.
3. After a successful login, the login page passes the returned user up to `App`.
4. "Log out" calls `POST /api/auth/logout` and sets `user` back to `null`.

The **Admin** link and page only appear for users whose role is `admin`. This is only for
convenience: the real protection is on the server, where every `/api/admin/...` route answers
**403** to normal users, whatever the browser does.

## 3. Why the browser-only tools never import `api.js`

The password checker, hash generator and encoder handle things people should not share, such as
real passwords and private text. Their logic lives in `src/browser-tools/`:

| File | What it uses | What it does |
|---|---|---|
| `password.js` | plain JavaScript | Scores length, character types, common passwords, repeats and sequences, and estimates the time to crack |
| `hash.js` | the browser's built-in **Web Crypto** (`crypto.subtle.digest`) | SHA-1, SHA-256, SHA-384 and SHA-512 |
| `encoder.js` | `TextEncoder`, `btoa`/`atob`, `encodeURIComponent` | Base64 and URL encoding and decoding |

None of these files, and none of their pages, import `api.js`, so there is **no code path** that
could send the input to the server. Each page shows a notice saying so. You can prove it in the
demo: open the browser's DevTools → **Network** tab, type into the password box, and no request
appears.

## 4. Smaller details worth knowing

- **Safe display:** React escapes all text it shows, and we never use `dangerouslySetInnerHTML`.
  A scan target like `<script>` is therefore shown as text, not run.
- **Checks in the browser are only for convenience.** The page checks the 5 MB file limit and the
  port list (max 100) to give quick messages, but the server checks everything again, because a
  browser can be bypassed.
- **Times:** the server stores times in UTC. `format.js` shows them in the user's local time.
- **Build:** `npm run build` turns `src/` into plain files in `frontend/dist/`, which FastAPI
  serves. During development `npm run dev` serves the pages on port 5173 and forwards `/api`
  calls to the backend on port 8000.

## 5. Manual test cases

The frontend has no automated tests (CI runs `eslint` on it), so I checked these by hand.

| # | Tool | Input | Expected result | Actual result |
|---|---|---|---|---|
| 1 | Password strength | `password123` | Rated "Very weak", with a tip saying it contains a common password | |
| 2 | Encoder (URL) | Encode `hello world`, then decode `hello%20world` | `hello%20world`, then `hello world` | |
| 3 | Hash generator | `abc` | SHA-256 starts with `ba7816bf` | |
