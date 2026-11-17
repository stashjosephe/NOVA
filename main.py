"""Nova backend: FastAPI + SQLite. Run with: uvicorn main:app --reload"""
import base64, csv, hashlib, hmac, io, json, os, re, secrets, sqlite3, time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).parent
DATA = Path(os.getenv("NOVA_DATA", BASE / "data"))
UPLOADS = DATA / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA / "nova.db"
STATUSES = ["new", "quoted", "confirmed", "printing", "shipped", "delivered", "cancelled"]


# ---------- security helpers ----------
def _secret() -> bytes:
    if os.getenv("NOVA_SECRET"):
        return os.environ["NOVA_SECRET"].encode()
    f = DATA / "secret.key"
    if not f.exists():
        f.write_text(secrets.token_hex(32))
    return f.read_text().strip().encode()


SECRET = _secret()


def hash_pw(pw: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + ":" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def check_pw(pw: str, stored: str) -> bool:
    salt, _ = stored.split(":")
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(salt)), stored)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_token(user: str) -> str:
    p = _b64(json.dumps({"u": user, "exp": int(time.time()) + 12 * 3600}).encode())
    return p + "." + _b64(hmac.new(SECRET, p.encode(), hashlib.sha256).digest())


def read_token(t: str) -> Optional[str]:
    try:
        p, s = t.split(".")
        if not hmac.compare_digest(s, _b64(hmac.new(SECRET, p.encode(), hashlib.sha256).digest())):
            return None
        d = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        return d["u"] if d["exp"] > time.time() else None
    except Exception:
        return None


def admin(authorization: Optional[str] = Header(None)) -> str:
    user = read_token(authorization[7:]) if authorization and authorization.startswith("Bearer ") else None
    if not user:
        raise HTTPException(401, "Not authenticated")
    return user


FAILS: dict = {}


def throttle(ip: str):
    now = time.time()
    FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 900]
    if len(FAILS[ip]) >= 5:
        raise HTTPException(429, "Too many attempts. Try again in 15 minutes.")


# ---------- database ----------
@contextmanager
def db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


SEED = [
    ("Mini Memory Set", "Polaroids", "9 custom prints, white border", "Bestseller", "", "#FF8A3D", "#FF4F9A"),
    ("Retro Border Prints", "Polaroids", "12 prints, film-strip borders", "", "", "#59C9FF", "#7A5CFF"),
    ("Neon Caption Pack", "Polaroids", "6 prints with handwritten captions", "", "", "#FFE45C", "#FF8A3D"),
    ("Film Roll Set", "Polaroids", "10 prints, vintage film edge", "", "", "#7CF2C4", "#59C9FF"),
    ("Midnight Skyline", "Posters", "A3 matte, 300 gsm", "New", "", "#1D1342", "#FF4F9A"),
    ("Soft Sunset Waves", "Posters", "A2 matte, 300 gsm", "", "", "#FFB36B", "#FF4F9A"),
    ("Retro Gamer Grid", "Posters", "A3 gloss, pixel art", "", "", "#59C9FF", "#1D1342"),
    ("Cherry Cola Poster", "Posters", "A3 gloss, bold typography", "New", "", "#FF4F9A", "#FFE45C"),
    ("Laptop Chaos Pack", "Stickers", "12 waterproof vinyl decals", "Bestseller", "\U0001FAA9", "#FFE45C", "#59C9FF"),
    ("Bottle Buddies", "Stickers", "6 dishwasher-safe decals", "", "\U0001F353", "#FF4F9A", "#FFE45C"),
    ("Phone Glow Decals", "Stickers", "8 slim decals for cases", "", "\u2728", "#7A5CFF", "#59C9FF"),
    ("Cosmic Cat Decals", "Stickers", "10 holographic decals", "", "\U0001F431", "#1D1342", "#7A5CFF"),
]


def init_db():
    with db() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
          description TEXT DEFAULT '', tag TEXT DEFAULT '', emoji TEXT DEFAULT '', color1 TEXT DEFAULT '#FF8A3D',
          color2 TEXT DEFAULT '#FF4F9A', active INTEGER DEFAULT 1, sort INTEGER DEFAULT 0, created_at TEXT);
        CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT, phone TEXT,
          email TEXT, address TEXT, city TEXT, pincode TEXT, delivery TEXT, payment TEXT, note TEXT DEFAULT '',
          status TEXT DEFAULT 'new', amount REAL, admin_note TEXT DEFAULT '', created_at TEXT, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id)
          ON DELETE CASCADE, product_id INTEGER, name TEXT, details TEXT DEFAULT '', qty INTEGER, image TEXT);
        CREATE TABLE IF NOT EXISTS subscribers(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, created_at TEXT);
        CREATE TABLE IF NOT EXISTS admins(username TEXT PRIMARY KEY, pw_hash TEXT NOT NULL);
        """)
        if not c.execute("SELECT 1 FROM products").fetchone():
            for i, p in enumerate(SEED):
                c.execute("INSERT INTO products(name,category,description,tag,emoji,color1,color2,sort,created_at) "
                          "VALUES(?,?,?,?,?,?,?,?,?)", (*p, i, now()))
        if not c.execute("SELECT 1 FROM admins").fetchone():
            user = os.getenv("NOVA_ADMIN_USER", "admin")
            pw = os.getenv("NOVA_ADMIN_PASSWORD")
            if not pw:
                pw = "nova-admin-change-me"
                print("WARNING: using the default admin password. Set NOVA_ADMIN_PASSWORD before going live.")
            c.execute("INSERT INTO admins VALUES(?,?)", (user, hash_pw(pw)))


# ---------- schemas ----------
EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class ItemIn(BaseModel):
    product_id: Optional[int] = None
    name: str = Field(min_length=1, max_length=120)
    details: str = Field(default="", max_length=300)
    qty: int = Field(ge=1, le=99)
    image_data: Optional[str] = Field(default=None, max_length=7_000_000)


class OrderIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    phone: str = Field(pattern=r"^[0-9+\-\s()]{7,20}$")
    email: str = Field(pattern=EMAIL, max_length=120)
    address: str = Field(min_length=1, max_length=300)
    city: str = Field(min_length=1, max_length=80)
    pincode: str = Field(pattern=r"^\d{6}$")
    delivery: str = Field(max_length=40)
    payment: Literal["UPI", "Card", "Cash on delivery"]
    note: str = Field(default="", max_length=500)
    items: list[ItemIn] = Field(min_length=1, max_length=30)


class OrderPatch(BaseModel):
    status: Optional[str] = None
    amount: Optional[float] = Field(default=None, ge=0, le=10_000_000)
    admin_note: Optional[str] = Field(default=None, max_length=1000)


class ProductIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    category: Literal["Polaroids", "Posters", "Stickers"]
    description: str = Field(default="", max_length=200)
    tag: str = Field(default="", max_length=20)
    emoji: str = Field(default="", max_length=8)
    color1: str = Field(default="#FF8A3D", pattern=r"^#[0-9a-fA-F]{6}$")
    color2: str = Field(default="#FF4F9A", pattern=r"^#[0-9a-fA-F]{6}$")
    active: bool = True
    sort: int = 0


class Login(BaseModel):
    username: str = Field(max_length=60)
    password: str = Field(max_length=200)


class PwChange(BaseModel):
    current: str
    new: str = Field(min_length=10, max_length=200)


class Sub(BaseModel):
    email: str = Field(pattern=EMAIL, max_length=120)


# ---------- uploads ----------
MAGIC = [(b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif")]


def save_image(data_url: str) -> str:
    m = re.match(r"^data:image/[a-z+.-]+;base64,(.+)$", data_url, re.S)
    if not m:
        raise HTTPException(400, "Invalid image upload")
    try:
        raw = base64.b64decode(m.group(1), validate=True)
    except Exception:
        raise HTTPException(400, "Invalid image upload")
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(413, "Images must be under 5 MB")
    ext = next((e for sig, e in MAGIC if raw.startswith(sig)), None)
    if not ext and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        ext = "webp"
    if not ext:
        raise HTTPException(400, "Only PNG, JPG, GIF or WEBP images are allowed")
    name = f"{secrets.token_hex(16)}.{ext}"
    (UPLOADS / name).write_bytes(raw)
    return name


def rm_file(name: Optional[str]):
    if name and re.fullmatch(r"[a-f0-9]{32}\.(png|jpg|gif|webp)", name):
        (UPLOADS / name).unlink(missing_ok=True)


# ---------- app ----------
@asynccontextmanager
async def lifespan(_):
    init_db()
    yield


app = FastAPI(title="Nova API", lifespan=lifespan)
if os.getenv("NOVA_CORS"):
    app.add_middleware(CORSMiddleware, allow_origins=os.environ["NOVA_CORS"].split(","),
                       allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"], allow_headers=["*"])


@app.middleware("http")
async def headers(request: Request, call_next):
    r = await call_next(request)
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "same-origin"
    if request.url.path.startswith("/admin"):
        r.headers["X-Frame-Options"] = "DENY"
    return r


# ----- public API -----
@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/products")
def products():
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT id,name,category,description,tag,emoji,color1,color2 FROM products WHERE active=1 ORDER BY sort,id")]


@app.post("/api/orders", status_code=201)
def create_order(o: OrderIn):
    saved: list = []
    try:
        with db() as c:
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            while True:
                code = "NV-" + "".join(secrets.choice(alphabet) for _ in range(6))
                if not c.execute("SELECT 1 FROM orders WHERE code=?", (code,)).fetchone():
                    break
            t = now()
            oid = c.execute(
                "INSERT INTO orders(code,name,phone,email,address,city,pincode,delivery,payment,note,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (code, o.name, o.phone, o.email.lower(), o.address, o.city, o.pincode, o.delivery, o.payment,
                 o.note, t, t)).lastrowid
            for it in o.items:
                img = save_image(it.image_data) if it.image_data else None
                if img:
                    saved.append(img)
                pid = it.product_id if it.product_id and c.execute(
                    "SELECT 1 FROM products WHERE id=?", (it.product_id,)).fetchone() else None
                c.execute("INSERT INTO order_items(order_id,product_id,name,details,qty,image) VALUES(?,?,?,?,?,?)",
                          (oid, pid, it.name, it.details, it.qty, img))
        return {"code": code, "status": "new"}
    except Exception:
        for f in saved:
            rm_file(f)
        raise


@app.get("/api/orders/track")
def track(code: str, email: str):
    with db() as c:
        o = c.execute("SELECT * FROM orders WHERE code=?", (code.strip().upper(),)).fetchone()
        if not o or not hmac.compare_digest(o["email"], email.strip().lower()):
            raise HTTPException(404, "No order found for that code and email")
        items = [dict(r) for r in c.execute("SELECT name,details,qty FROM order_items WHERE order_id=?", (o["id"],))]
    return {"code": o["code"], "status": o["status"], "amount": o["amount"], "updated_at": o["updated_at"], "items": items}


@app.post("/api/subscribe", status_code=201)
def subscribe(s: Sub):
    with db() as c:
        c.execute("INSERT OR IGNORE INTO subscribers(email,created_at) VALUES(?,?)", (s.email.lower(), now()))
    return {"ok": True}


# ----- admin API -----
@app.post("/api/admin/login")
def login(b: Login, request: Request):
    ip = request.client.host if request.client else "?"
    throttle(ip)
    with db() as c:
        row = c.execute("SELECT pw_hash FROM admins WHERE username=?", (b.username,)).fetchone()
    if not row or not check_pw(b.password, row["pw_hash"]):
        FAILS.setdefault(ip, []).append(time.time())
        raise HTTPException(401, "Wrong username or password")
    return {"token": make_token(b.username)}


r = APIRouter(prefix="/api/admin", dependencies=[Depends(admin)])


@r.post("/password")
def change_pw(b: PwChange, user: str = Depends(admin)):
    with db() as c:
        row = c.execute("SELECT pw_hash FROM admins WHERE username=?", (user,)).fetchone()
        if not row or not check_pw(b.current, row["pw_hash"]):
            raise HTTPException(400, "Current password is wrong")
        c.execute("UPDATE admins SET pw_hash=? WHERE username=?", (hash_pw(b.new), user))
    return {"ok": True}


@r.get("/stats")
def stats():
    with db() as c:
        by = {s: 0 for s in STATUSES}
        for row in c.execute("SELECT status, COUNT(*) n FROM orders GROUP BY status"):
            by[row["status"]] = row["n"]
        q = lambda s, *a: c.execute(s, a).fetchone()[0]
        return {
            "by_status": by,
            "orders": q("SELECT COUNT(*) FROM orders"),
            "today": q("SELECT COUNT(*) FROM orders WHERE substr(created_at,1,10)=?", now()[:10]),
            "quoted_value": q("SELECT COALESCE(SUM(amount),0) FROM orders WHERE status NOT IN ('cancelled','new')"),
            "subscribers": q("SELECT COUNT(*) FROM subscribers"),
            "products": q("SELECT COUNT(*) FROM products WHERE active=1"),
        }


def order_filter(status: str, q: str):
    w, a = [], []
    if status in STATUSES:
        w.append("o.status=?"); a.append(status)
    if q:
        w.append("(o.code LIKE ? OR o.name LIKE ? OR o.email LIKE ? OR o.phone LIKE ?)")
        a += [f"%{q}%"] * 4
    return ("WHERE " + " AND ".join(w)) if w else "", a


@r.get("/orders")
def orders(status: str = "", q: str = "", limit: int = 100, offset: int = 0):
    where, a = order_filter(status, q.strip())
    with db() as c:
        rows = c.execute(f"SELECT o.*, (SELECT COALESCE(SUM(qty),0) FROM order_items WHERE order_id=o.id) AS item_count "
                         f"FROM orders o {where} ORDER BY o.id DESC LIMIT ? OFFSET ?",
                         (*a, min(limit, 500), max(offset, 0))).fetchall()
        total = c.execute(f"SELECT COUNT(*) FROM orders o {where}", a).fetchone()[0]
    return {"total": total, "orders": [dict(x) for x in rows]}


def load_order(c, oid: int):
    o = c.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not o:
        raise HTTPException(404, "Order not found")
    d = dict(o)
    d["items"] = [dict(x) for x in c.execute("SELECT * FROM order_items WHERE order_id=?", (oid,))]
    return d


@r.get("/orders/export.csv")
def export_csv(status: str = "", q: str = ""):
    where, a = order_filter(status, q.strip())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["code", "created", "status", "amount", "name", "phone", "email", "address", "city", "pincode",
                "delivery", "payment", "items", "customer_note", "admin_note"])
    with db() as c:
        for o in c.execute(f"SELECT o.* FROM orders o {where} ORDER BY o.id DESC", a).fetchall():
            items = "; ".join(f"{i['qty']}x {i['name']} ({i['details']})" for i in
                              c.execute("SELECT * FROM order_items WHERE order_id=?", (o["id"],)))
            w.writerow([o["code"], o["created_at"], o["status"], o["amount"] if o["amount"] is not None else "",
                        o["name"], o["phone"], o["email"], o["address"], o["city"], o["pincode"], o["delivery"],
                        o["payment"], items, o["note"], o["admin_note"]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=nova-orders.csv"})


@r.get("/orders/{oid}")
def order_detail(oid: int):
    with db() as c:
        return load_order(c, oid)


@r.patch("/orders/{oid}")
def update_order(oid: int, b: OrderPatch):
    if b.status is not None and b.status not in STATUSES:
        raise HTTPException(400, "Unknown status")
    sets, a = ["updated_at=?"], [now()]
    if b.status is not None:
        sets.append("status=?"); a.append(b.status)
    if "amount" in b.model_fields_set:
        sets.append("amount=?"); a.append(b.amount)
    if b.admin_note is not None:
        sets.append("admin_note=?"); a.append(b.admin_note)
    with db() as c:
        load_order(c, oid)
        c.execute(f"UPDATE orders SET {','.join(sets)} WHERE id=?", (*a, oid))
        return load_order(c, oid)


@r.delete("/orders/{oid}", status_code=204)
def delete_order(oid: int):
    with db() as c:
        o = load_order(c, oid)
        c.execute("DELETE FROM orders WHERE id=?", (oid,))
    for i in o["items"]:
        rm_file(i["image"])


@r.get("/uploads/{name}")
def upload(name: str):
    if not re.fullmatch(r"[a-f0-9]{32}\.(png|jpg|gif|webp)", name) or not (UPLOADS / name).exists():
        raise HTTPException(404, "Not found")
    return FileResponse(UPLOADS / name)


@r.get("/products")
def admin_products():
    with db() as c:
        return [dict(x) for x in c.execute("SELECT * FROM products ORDER BY sort,id")]


@r.post("/products", status_code=201)
def add_product(p: ProductIn):
    with db() as c:
        pid = c.execute("INSERT INTO products(name,category,description,tag,emoji,color1,color2,active,sort,created_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (p.name, p.category, p.description, p.tag, p.emoji, p.color1, p.color2, int(p.active), p.sort, now())).lastrowid
        return dict(c.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone())


@r.put("/products/{pid}")
def edit_product(pid: int, p: ProductIn):
    with db() as c:
        if not c.execute("SELECT 1 FROM products WHERE id=?", (pid,)).fetchone():
            raise HTTPException(404, "Product not found")
        c.execute("UPDATE products SET name=?,category=?,description=?,tag=?,emoji=?,color1=?,color2=?,active=?,sort=? WHERE id=?",
                  (p.name, p.category, p.description, p.tag, p.emoji, p.color1, p.color2, int(p.active), p.sort, pid))
        return dict(c.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone())


@r.delete("/products/{pid}", status_code=204)
def delete_product(pid: int):
    with db() as c:
        c.execute("DELETE FROM products WHERE id=?", (pid,))


@r.get("/subscribers")
def subscribers():
    with db() as c:
        return [dict(x) for x in c.execute("SELECT * FROM subscribers ORDER BY id DESC")]


@r.delete("/subscribers/{sid}", status_code=204)
def delete_sub(sid: int):
    with db() as c:
        c.execute("DELETE FROM subscribers WHERE id=?", (sid,))


app.include_router(r)
app.mount("/admin", StaticFiles(directory=BASE / "admin", html=True), name="admin")
app.mount("/", StaticFiles(directory=BASE / "storefront", html=True), name="storefront")
