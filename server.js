/**
 * H&S Watches — Backend
 * One file. Data lives in MongoDB Atlas (free forever tier) instead of a
 * local JSON file, so it survives host restarts/redeploys. Product images
 * are uploaded to Cloudinary's free tier for the same reason.
 *
 * Run locally:   npm install   then   npm start
 *
 * Required env vars:
 *   MONGODB_URI          - mongodb+srv://shaayaeducational_db_user:MSlOT911168@cluster0.jcaepwe.mongodb.net/?appName=Cluster0
 *   wftgq5ud, 577552561947961, JDJfDWKglXAm31Vvd5Tdidj46Aw
 *                          - from your Cloudinary dashboard
 *
 * Optional env vars (sane defaults provided):
 *   PORT           - defaults to 4000
 *   MONGODB_DB     - defaults to "hswatches"
 *   ADMIN_USER     - defaults to "admin"
 *   ADMIN_PASS     - #$W@TC#E$13579
 *   AUTH_SECRET    - #$W@TC#E$135793216987
 *   CORS_ORIGIN    - defaults to "*"
 */

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const multer = require("multer");
const { MongoClient } = require("mongodb");
const cloudinary = require("cloudinary").v2;

const PORT = process.env.PORT || 4000;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "#$W@TC#E$13579";
const AUTH_SECRET = process.env.AUTH_SECRET || "#$W@TC#E$135793216987";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || "hswatches";

// Cloudinary can be configured either via a single CLOUDINARY_URL variable
// (what you get from Render/Cloudinary integrations) or three separate
// variables — support both so either setup works without extra steps.
if (process.env.CLOUDINARY_URL) {
  cloudinary.config(); // SDK reads CLOUDINARY_URL from process.env automatically
} else {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
}

// ---------- MongoDB connection ----------

let db;

async function connectDB() {
  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI is not set. Add it to your environment variables.");
  }
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db(MONGODB_DB);
  await seedIfEmpty();
  console.log("Connected to MongoDB.");
}

async function seedIfEmpty() {
  const count = await db.collection("products").countDocuments();
  if (count === 0) {
    const seed = require("./seed.json");
    if (seed.products && seed.products.length) {
      await db.collection("products").insertMany(seed.products);
      const maxId = Math.max(...seed.products.map((p) => p.id));
      await db.collection("counters").updateOne(
        { _id: "ids" },
        { $set: { product: maxId } },
        { upsert: true }
      );
      console.log(`Seeded ${seed.products.length} starter products.`);
    }
  }
}

async function nextId(field) {
  const result = await db.collection("counters").findOneAndUpdate(
    { _id: "ids" },
    { $inc: { [field]: 1 } },
    { returnDocument: "after", upsert: true }
  );
  return result.value[field];
}

const noId = { projection: { _id: 0 } };

// ---------- app setup ----------

const app = express();
app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json({ limit: "2mb" }));

// ---------- image uploads → Cloudinary ----------

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 20 },
  fileFilter: (req, file, cb) => {
    if (/^image\//.test(file.mimetype)) cb(null, true);
    else cb(new Error("Only image files are allowed"));
  },
});

function uploadBufferToCloudinary(buffer) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: "hs-watches" },
      (err, result) => (err ? reject(err) : resolve(result.secure_url))
    );
    stream.end(buffer);
  });
}

// ---------- stateless admin auth ----------

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

app.post("/api/admin/upload", requireAdmin, (req, res) => {
  upload.array("images", 20)(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });
    try {
      const urls = await Promise.all(
        (req.files || []).map((f) => uploadBufferToCloudinary(f.buffer))
      );
      res.json({ urls });
    } catch (e) {
      res.status(500).json({ error: `Cloudinary upload failed: ${e.message}` });
    }
  });
});

// ---------- products (public read, admin write) ----------

app.get("/api/products", async (req, res) => {
  const products = await db.collection("products").find({}, noId).toArray();
  res.json(products);
});

app.get("/api/products/:id", async (req, res) => {
  const product = await db.collection("products").findOne({ id: Number(req.params.id) }, noId);
  if (!product) return res.status(404).json({ error: "Product not found" });
  res.json(product);
});

app.post("/api/admin/products", requireAdmin, async (req, res) => {
  const id = await nextId("product");
  const product = { ...req.body, id };
  await db.collection("products").insertOne(product);
  delete product._id;
  res.status(201).json(product);
});

app.put("/api/admin/products/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const update = { ...req.body };
  delete update.id;
  const result = await db.collection("products").findOneAndUpdate(
    { id },
    { $set: update },
    { returnDocument: "after", projection: { _id: 0 } }
  );
  if (!result.value) return res.status(404).json({ error: "Product not found" });
  res.json(result.value);
});

app.delete("/api/admin/products/:id", requireAdmin, async (req, res) => {
  const result = await db.collection("products").deleteOne({ id: Number(req.params.id) });
  if (result.deletedCount === 0) return res.status(404).json({ error: "Product not found" });
  res.json({ ok: true });
});

// ---------- orders (public create, admin read/update) ----------

app.post("/api/orders", async (req, res) => {
  const id = await nextId("order");
  const order = {
    ...req.body,
    id,
    status: "Pending",
    createdAt: new Date().toISOString(),
  };
  await db.collection("orders").insertOne(order);
  delete order._id;
  res.status(201).json(order);
});

app.get("/api/admin/orders", requireAdmin, async (req, res) => {
  const orders = await db.collection("orders").find({}, noId).sort({ id: -1 }).toArray();
  res.json(orders);
});

app.put("/api/admin/orders/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const update = { ...req.body };
  delete update.id;
  const result = await db.collection("orders").findOneAndUpdate(
    { id },
    { $set: update },
    { returnDocument: "after", projection: { _id: 0 } }
  );
  if (!result.value) return res.status(404).json({ error: "Order not found" });
  res.json(result.value);
});

app.delete("/api/admin/orders/:id", requireAdmin, async (req, res) => {
  await db.collection("orders").deleteOne({ id: Number(req.params.id) });
  res.json({ ok: true });
});

// ---------- contact messages ----------

app.post("/api/messages", async (req, res) => {
  const id = await nextId("message");
  const message = {
    ...req.body,
    id,
    read: false,
    createdAt: new Date().toISOString(),
  };
  await db.collection("messages").insertOne(message);
  delete message._id;
  res.status(201).json(message);
});

app.get("/api/admin/messages", requireAdmin, async (req, res) => {
  const messages = await db.collection("messages").find({}, noId).sort({ id: -1 }).toArray();
  res.json(messages);
});

app.put("/api/admin/messages/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const update = { ...req.body };
  delete update.id;
  const result = await db.collection("messages").findOneAndUpdate(
    { id },
    { $set: update },
    { returnDocument: "after", projection: { _id: 0 } }
  );
  if (!result.value) return res.status(404).json({ error: "Message not found" });
  res.json(result.value);
});

app.delete("/api/admin/messages/:id", requireAdmin, async (req, res) => {
  await db.collection("messages").deleteOne({ id: Number(req.params.id) });
  res.json({ ok: true });
});

// ---------- admin dashboard summary ----------

app.get("/api/admin/summary", requireAdmin, async (req, res) => {
  const [productCount, orderCount, pendingOrders, unreadMessages, orders] = await Promise.all([
    db.collection("products").countDocuments(),
    db.collection("orders").countDocuments(),
    db.collection("orders").countDocuments({ status: "Pending" }),
    db.collection("messages").countDocuments({ read: false }),
    db.collection("orders").find({}, { projection: { _id: 0, total: 1 } }).toArray(),
  ]);
  res.json({
    productCount,
    orderCount,
    pendingOrders,
    unreadMessages,
    revenue: orders.reduce((sum, o) => sum + (o.total || 0), 0),
  });
});

app.get("/", (req, res) => {
  res.send("H&S Watches API is running.");
});

connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`H&S Watches API listening on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to start:", err.message);
    process.exit(1);
  });
