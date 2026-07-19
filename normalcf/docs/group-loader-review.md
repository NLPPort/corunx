# group.html Loader & Assets Review

**Scope:** `normalcf/static/group.html`, stage modules, `payloads/`, Workers static routing  
**Date:** 2026-07-19  
**Status:** Asset/path gaps largely resolved; base-URL helper still fragile; exploit success remains device/WebKit-dependent

---

## 1. Summary

| Area | Verdict |
|------|---------|
| Access-log beacon → `POST /lab/access-logs` | Works (public route; IP filled server-side) |
| Static file serving (`/Stage*`, `/other/*`, `/payloads/*`) | No `src/` changes needed — Cloudflare Assets already covers them |
| Stage module discovery (root + `other/`) | Wired; previously missing modules now load from `other/` |
| Payload blob loading (`payloads/`) | Complete for Stage3 `buildContainer` path |
| `Ot(fqMaGkNg())` module base URL | Still broken by design; accidentally falls back to site root |
| End-to-end `triggerExploit` success | Not guaranteed (version gates, WebKit, `reportResult` undefined) |

---

## 2. Access logs (`/lab/access-logs`)

### Client (`group.html`)

On page load (before the iOS gate), a beacon posts:

```json
{
  "user_agent": "<navigator.userAgent>",
  "platform": "<navigator.platform>",
  "path": "<location.pathname or /group.html>",
  "method": "GET",
  "referer": "<document.referrer or null>"
}
```

- Preferred: `navigator.sendBeacon` with `Blob` `application/json`
- Fallback: `fetch` POST with `keepalive: true`

### Server

- Public: `POST /lab` + `/access-logs` on `misc.public_router` (no admin token)
- Admin-only: `GET /lab/access-logs` for listing
- Worker routes all `/lab*` to FastAPI (`worker.py` `_is_api_path`)
- Schema: `AccessLogBeaconIn` — matches the beacon fields
- IP is taken from request headers (`cf-connecting-ip` / etc.), not the body
- `platform` is appended into `user_agent` as `[platform=…]`

**Caveats:** failures are silent on the client; listing logs requires admin auth; D1 migrations (`0001_lab`, `0002_lab_gap` for `referer`) must be applied.

---

## 3. Static routing — do `src/` changes need updates?

**No.**

- `wrangler.jsonc` binds `./static` as `ASSETS` with `run_worker_first: true`
- FastAPI only claims `/`, `/health`, `/lab*`, `/docs`, `/hello/`
- Everything else (including `/payloads/*`, `/other/*`, `Stage*.js`) is served by Assets

| Client URL | File on disk |
|------------|--------------|
| `/group.html` | `static/group.html` |
| `/Stage3_VariantB.js` | `static/Stage3_VariantB.js` |
| `/other/Stage3_VariantA.js` | `static/other/Stage3_VariantA.js` |
| `/payloads/bootstrap.dylib` | `static/payloads/bootstrap.dylib` |
| `/payloads/manifest.json` | `static/payloads/manifest.json` |

---

## 4. `triggerExploit` chain

### Flow

1. iOS UA gate (non‑iOS aborts before stage scripts run meaningfully)
2. `platformModule.init` + lockdown / version / simulator checks
3. Stage1 WASM primitive (version-flag selected module)
4. Runtime detect (`lr`) + optional Stage2 PAC bypass
5. Stage3 Variant A or B (`lA`) — sandbox escape + payload feed

### Module path updates (current)

Modules that live only under `static/other/` are loaded with an `other/` prefix:

| Module ID in loader | Served path |
|---------------------|-------------|
| `other/Stage3_VariantA` | `/other/Stage3_VariantA.js` |
| `other/Stage2_13.0_14.x_breezy` | `/other/Stage2_13.0_14.x_breezy.js` |
| `other/Stage1_13.0_15.1.1_buffout` | `/other/Stage1_13.0_15.1.1_buffout.js` |

Root-resident modules keep plain names (`Stage1_16.6_…`, `Stage3_VariantB`, etc.).

### Remaining non-asset blockers

1. **iOS ≥ 17.3** — version flags can leave no Stage1 match → early `1001`
2. **`reportResult` is called but not defined** under `static/` — may throw in the entry try/catch
3. **Outer IP-sync block (~line 510)** — leave commented; it posts IP to `8df9.cc`, not needed for lab (`access-logs` already records IP)
4. **Device/WebKit** — stage1/2/3 still require a vulnerable Safari build; assets alone do not guarantee success

---

## 5. `Ot(fqMaGkNg())` base-URL issue

### Intended behavior

```js
fqMaGkNg() → https://<host>/downloaded/7a7d990….min.js
Ot(...) → resolve URL
slice to directory → https://<host>/downloaded/
setBaseUrl → load Stage*.js from /downloaded/
```

### Actual behavior

`Ot` = `resolveUrl` → first runs `decodeString` / `utf16Encode`, which inserts NULs after ASCII bytes and truncates at the first NUL. A plain `https://…` URL collapses to `"h"`, then resolves as a relative path, and after directory slicing the base becomes approximately:

```text
https://<host>/
```

So modules load from **site root** (and `other/…` prefixes), not from `/downloaded/`. That accidental root base is why the current layout works.

### Related file for `fqMaGkNg`

| Expected | Found |
|----------|--------|
| `static/downloaded/7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.min.js` | **Missing** |
| `static/other/7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.js` | Present (same hash, wrong path/extension) |
| `static/payloads/7a7d990…/raw.bin` | Present (used by Stage3 payload builder) |

### Recommended fix (conceptual)

Set an explicit base without `Ot` on plain ASCII URLs, e.g. `location.origin + "/"`, and only use `Ot`/`decodeString` for packed/encoded strings. Optionally fix or drop the `/downloaded/7a7d990….min.js` URL if nothing fetches that JS file anymore.

---

## 6. Payload loading status

Stage3 VariantB loads payloads as follows:

1. Sync: `payloads/bootstrap.dylib`
2. Async: `payloads/manifest.json`
3. Per hash: `payloads/<hash>/<entry files>` → rebuild F00DBEEF container (`buildContainer`)
4. First metadata hash from `fixedMachOVal1` / `fqMaGkNg()` name: `7a7d990…` → `payloads/7a7d990…/raw.bin`

### Completeness check (2026-07-19)

| Check | Result |
|-------|--------|
| `payloads/bootstrap.dylib` | Present |
| `payloads/manifest.json` | Present |
| Manifest hash dirs (20) | All present |
| Manifest entry files | All present |
| `7a7d990…/raw.bin` size | Matches manifest (2192) |

**No missing payload blobs** for the current Stage3 path.

### Minor issues (non-blocking for HTTP 200)

- **14×** `entry3_type0x07.bin`: on-disk size **49** vs manifest **44** (stale size metadata; loader uses actual buffer length)
- Manifest hashes **without** a matching `downloaded/<hash>.min.js`:
  - `7a7d99099b035b2c6512b6ebeeea6df1ede70fbb`
  - `377bed7460f7538f96bbad7bdc2b8294bdc54599`
  - `38af3c8ba461079a0edc83585023f76843066dcf`  
  (Stage3 `download()` strips to hash and uses `payloads/`; these `.min.js` stubs are optional unless something still GETs them directly)

---

## 7. Directory map (relevant)

```text
static/
  group.html                 # loader + beacon + triggerExploit
  platform_module.js
  utility_module.js
  Stage1_*.js / Stage2_*.js  # version variants at root
  Stage3_VariantB.js
  other/
    Stage3_VariantA.js
    Stage2_13.0_14.x_breezy.js
    Stage1_13.0_15.1.1_buffout.js
    7a7d990….js              # hash JS (not under downloaded/)
    …
  downloaded/                # hashed *.min.js (no 7a7d990…min.js)
  payloads/
    bootstrap.dylib
    manifest.json
    <hash>/entry*.{dylib,bin} | raw.bin
```

---

## 8. Recommendations

1. **Keep** the `other/` prefixes for modules that only exist under `static/other/`.
2. **Do not** uncomment the IP-sync block (~line 510); rely on `/lab/access-logs` for visitor IP.
3. **Define or remove** `reportResult` so the entry try/catch does not call an undefined function.
4. **Replace** `Ot(fqMaGkNg())` base setup with an explicit `location.origin + "/"` (or document that the Ot quirk is intentional).
5. **Optional:** add `downloaded/7a7d990….min.js` (copy/symlink from `other/7a7d990….js`) if you want the coded URL to resolve; not required for `payloads/` loading.
6. **Optional:** refresh manifest `size` fields for the 14× `entry3_type0x07.bin` mismatches.
7. **Test** on real iOS Safari in the supported version window; treat simulator / lockdown / ≥17.3 as expected early exits.

---

## 9. Quick test checklist

- [ ] Load `/group.html` on device Safari → row appears in admin `GET /lab/access-logs`
- [ ] Network: `200` for selected Stage1/2/3 JS (including `/other/…` when applicable)
- [ ] Network: `200` for `/payloads/bootstrap.dylib`, `/payloads/manifest.json`, `/payloads/7a7d990…/raw.bin`
- [ ] Confirm page log lines for stage selection / PAC / Stage3 without module 404s
- [ ] Confirm `reportResult` does not throw (define stub or wire to lab API)
