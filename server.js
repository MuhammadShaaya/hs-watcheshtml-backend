/**
 * H&S Watches — Backend
 * One file. JSON-file database. No ORM, no build step.
 *
 * Run locally:   npm install   then   npm start
 * Deploy:        Railway / Render / any Node host. Set env vars below.
 *
 * Env vars (all optional, sane defaults provided):
 *   PORT           - defaults to 4000
 *   ADMIN_USER     - defaults to "admin"
 *   ADMIN_PASS     - #$W@TC#E$13579
 *   AUTH_SECRET    - #$W@TC#E$13579
 *   CORS_ORIGIN    - https://hswatches.shop/
 */

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");

const PORT = process.env.PORT || 4000;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "#$W@TC#E$13579";
const AUTH_SECRET = process.env.AUTH_SECRET || "#$W@TC#E$13579";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "https://hswatches.shop";

const DB_FILE = path.join(__dirname, "db.json");

// ---------- tiny JSON "database" ----------

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const seed = require("./seed.json");
    fs.writeFileSync(DB_FILE, JSON.stringify(seed, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function nextId(list) {
  return list.length ? Math.max(...list.map((i) => i.id)) + 1 : 1;
}

// ---------- app setup ----------

const app = express();
app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json({ limit: "2mb" }));

// ---------- image uploads (stored on disk, served statically) ----------

const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use("/uploads", express.static(UPLOAD_DIR));

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname || "").toLowerCase() || ".jpg";
      const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
      cb(null, `${unique}${ext}`);
    },
  }),
  limits: { fileSize: 8 * 1024 * 1024, files: 20 },
  fileFilter: (req, file, cb) => {
    if (/^image\//.test(file.mimetype)) cb(null, true);
    else cb(new Error("Only image files are allowed"));
  },
});

// ---------- stateless admin auth ----------
// The token is a deterministic HMAC of the admin credentials + secret.
// No sessions to store, so it survives server restarts (useful on free hosting
// tiers that sleep/restart), while still requiring the correct password to obtain.

function computeToken() {
  return crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(`${ADMIN_USER}:${ADMIN_PASS}`)
    .digest("hex");
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token || token !== computeToken()) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    return res.json({ token: computeToken() });
  }
  res.status(401).json({ error: "Invalid username or password" });
});

// Accepts one or more files under the field name "images".
// Returns { urls: [...] } — paste these straight into a product's image list.
app.post("/api/admin/upload", requireAdmin, (req, res) => {
  upload.array("images", 20)(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    const base = `${req.protocol}://${req.get("host")}`;
    const urls = (req.files || []).map((f) => `${base}/uploads/${f.filename}`);
    res.json({ urls });
  });
});

// ---------- products (public read, admin write) ----------

app.get("/api/products", (req, res) => {
  const db = loadDB();
  res.json(db.products);
});

app.get("/api/products/:id", (req, res) => {
  const db = loadDB();
  const product = db.products.find((p) => p.id === Number(req.params.id));
  if (!product) return res.status(404).json({ error: "Product not found" });
  res.json(product);
});

app.post("/api/admin/products", requireAdmin, (req, res) => {
  const db = loadDB();
  const product = { id: nextId(db.products), ...req.body };
  db.products.push(product);
  saveDB(db);
  res.status(201).json(product);
});

app.put("/api/admin/products/:id", requireAdmin, (req, res) => {
  const db = loadDB();
  const idx = db.products.findIndex((p) => p.id === Number(req.params.id));
  if (idx === -1) return res.status(404).json({ error: "Product not found" });
  db.products[idx] = { ...db.products[idx], ...req.body, id: db.products[idx].id };
  saveDB(db);
  res.json(db.products[idx]);
});

app.delete("/api/admin/products/:id", requireAdmin, (req, res) => {
  const db = loadDB();
  const before = db.products.length;
  db.products = db.products.filter((p) => p.id !== Number(req.params.id));
  saveDB(db);
  if (db.products.length === before) return res.status(404).json({ error: "Product not found" });
  res.json({ ok: true });
});

// ---------- orders (public create, admin read/update) ----------

app.post("/api/orders", (req, res) => {
  const db = loadDB();
  const order = {
    id: nextId(db.orders),
    status: "Pending",
    createdAt: new Date().toISOString(),
    ...req.body,
  };
  db.orders.push(order);
  saveDB(db);
  res.status(201).json(order);
});

app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.orders.slice().reverse());
});

app.put("/api/admin/orders/:id", requireAdmin, (req, res) => {
  const db = loadDB();
  const idx = db.orders.findIndex((o) => o.id === Number(req.params.id));
  if (idx === -1) return res.status(404).json({ error: "Order not found" });
  db.orders[idx] = { ...db.orders[idx], ...req.body, id: db.orders[idx].id };
  saveDB(db);
  res.json(db.orders[idx]);
});

app.delete("/api/admin/orders/:id", requireAdmin, (req, res) => {
  const db = loadDB();
  db.orders = db.orders.filter((o) => o.id !== Number(req.params.id));
  saveDB(db);
  res.json({ ok: true });
});

// ---------- contact messages (public create, admin read/update/delete) ----------

app.post("/api/messages", (req, res) => {
  const db = loadDB();
  const message = {
    id: nextId(db.messages),
    read: false,
    createdAt: new Date().toISOString(),
    ...req.body,
  };
  db.messages.push(message);
  saveDB(db);
  res.status(201).json(message);
});

app.get("/api/admin/messages", requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.messages.slice().reverse());
});

app.put("/api/admin/messages/:id", requireAdmin, (req, res) => {
  const db = loadDB();
  const idx = db.messages.findIndex((m) => m.id === Number(req.params.id));
  if (idx === -1) return res.status(404).json({ error: "Message not found" });
  db.messages[idx] = { ...db.messages[idx], ...req.body, id: db.messages[idx].id };
  saveDB(db);
  res.json(db.messages[idx]);
});

app.delete("/api/admin/messages/:id", requireAdmin, (req, res) => {
  const db = loadDB();
  db.messages = db.messages.filter((m) => m.id !== Number(req.params.id));
  saveDB(db);
  res.json({ ok: true });
});

// ---------- admin dashboard summary ----------

app.get("/api/admin/summary", requireAdmin, (req, res) => {
  const db = loadDB();
  res.json({
    productCount: db.products.length,
    orderCount: db.orders.length,
    pendingOrders: db.orders.filter((o) => o.status === "Pending").length,
    unreadMessages: db.messages.filter((m) => !m.read).length,
    revenue: db.orders.reduce((sum, o) => sum + (o.total || 0), 0),
  });
});

app.get("/", (req, res) => {
  res.send("H&S Watches API is running.");
});

app.listen(PORT, () => {
  console.log(`H&S Watches API listening on port ${PORT}`);
});
