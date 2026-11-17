# Nova: storefront, API and admin

Stack: **FastAPI + SQLite** (no external database to set up). One server serves everything:

| URL | What |
|---|---|
| `/` | Customer storefront (`storefront/index.html`) |
| `/admin/` | Admin dashboard (`admin/index.html`) |
| `/api/...` | JSON API |
| `/docs` | Interactive API docs (auto-generated) |

## Run it

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export NOVA_ADMIN_USER=admin
export NOVA_ADMIN_PASSWORD='use-a-long-password'       # first start creates the admin from this
export NOVA_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"

uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000/` for the shop and `http://localhost:8000/admin/` for the admin.
If you skip `NOVA_ADMIN_PASSWORD`, the admin password is `nova-admin-change-me`. Change it right away from the admin sidebar.

Docker: `docker build -t nova . && docker run -p 8000:8000 -v nova-data:/data -e NOVA_ADMIN_PASSWORD=... nova`

Data lives in `data/` (`nova.db`, `uploads/`, `secret.key`). Back that folder up.

## How orders work (no prices on the storefront)

1. Customer builds a design or picks a ready-made one and checks out. Order status starts as `new`.
2. In **Admin > Orders** you review items and uploaded images, enter a **quoted amount**, and move the status through
   `new > quoted > confirmed > printing > shipped > delivered` (or `cancelled`).
3. Customers can check progress with `GET /api/orders/track?code=NV-XXXXXX&email=...` (a tracking page for the storefront is not built yet).

## Admin features

Dashboard stats, order search/filter by status, order detail with customer uploads, quote and internal notes,
CSV export, product create/edit/hide/delete (changes show in the store immediately), subscriber list, password change.

## API summary

Public: `GET /api/products`, `POST /api/orders`, `GET /api/orders/track`, `POST /api/subscribe`

Admin (Bearer token from `POST /api/admin/login`): `GET /api/admin/stats`, `GET /api/admin/orders`,
`GET|PATCH|DELETE /api/admin/orders/{id}`, `GET /api/admin/orders/export.csv`, `GET /api/admin/uploads/{file}`,
`GET|POST /api/admin/products`, `PUT|DELETE /api/admin/products/{id}`, `GET /api/admin/subscribers`,
`DELETE /api/admin/subscribers/{id}`, `POST /api/admin/password`

## Security notes

- Passwords are hashed with scrypt; admin sessions are signed tokens that expire after 12 hours; login is limited to 5 failed attempts per IP per 15 minutes.
- Customer uploads are verified by file signature (PNG, JPG, GIF, WEBP, max 5 MB) and are only downloadable by a signed-in admin.
- Put the app behind HTTPS (Caddy, Nginx or your host's TLS) before going live. Behind a proxy, run uvicorn with `--proxy-headers` so the login limiter sees real client IPs.
- Not included yet: emailing customers on new orders or status changes, online payment, and multiple admin accounts. Orders are stored; you contact customers yourself for now.
- The failed-login limiter is in memory, so it resets on restart and is per process.
- To host the storefront on another domain, set `NOVA_CORS=https://your-shop-domain`.
