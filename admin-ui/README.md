# normalcf admin UI

React + Bun + Vite console for the `normalcf` lab API.

Production build is emitted into **`normalcf/static/console`** and served by the Worker at **`/console/`**.

## Dev (hot reload)

```bash
# terminal 1 — API
cd normalcf && npx wrangler dev

# terminal 2 — UI
cd admin-ui
bun install
bun dev
```

Open http://127.0.0.1:5173/console/

Vite proxies `/lab` and `/health` to `http://127.0.0.1:8787` (`VITE_API_PROXY` to override).

## Build into normalcf

```bash
cd admin-ui
bun run build
```

Output: `normalcf/static/console/` (`index.html` + `assets/`).

Then run / deploy the worker:

```bash
cd normalcf
npx wrangler dev
# open http://127.0.0.1:8787/console/
```

Same-origin: UI calls `/lab/...` with no `VITE_API_BASE`.

## Auth

Default console login (override via `normalcf/wrangler.jsonc` `vars`):

- user: `admin`
- pass: `123123admin`

All `/lab/*` routes require `Authorization: Bearer <token>` except `POST /lab/auth/login`.

## Pages

| Route | Purpose |
| --- | --- |
| `/console/login` | Sign in |
| `/console/` | Overview + stats |
| `/console/devices` | Device list |
| `/console/devices/:uuid` | Detail + notes |
| `/console/jobs` | List + enqueue |
| `/console/artifacts` | Capture index |
| `/console/events` | Event timeline |
