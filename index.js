import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";

/* ======================
   __dirname (ESM)
====================== */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ======================
   APP
====================== */
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

/* ======================
   ENV
====================== */
const {
  JWT_SECRET,
  MYSQLHOST,
  MYSQLUSER,
  MYSQLPASSWORD,
  MYSQLDATABASE,
  MYSQLPORT
} = process.env;

/* ======================
   DB
====================== */
const db = await mysql.createPool({
  host: MYSQLHOST,
  user: MYSQLUSER,
  password: MYSQLPASSWORD,
  database: MYSQLDATABASE,
  port: MYSQLPORT || 3306,
});

/* ======================
   AUTH MIDDLEWARE
====================== */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) {
    return res.status(401).json({ success: false });
  }

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ success: false });
  }
}

/* ======================
   ROUTES
====================== */

/* ---------- LOGIN PAGE ---------- */
app.get("/", (_, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ---------- REGISTER ---------- */
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ success: false, message: "Completa todo" });
  }

  const [exists] = await db.query(
    "SELECT id FROM users WHERE email=?",
    [email]
  );

  if (exists.length > 0) {
    return res.json({ success: false, message: "Correo ya registrado" });
  }

  const hash = await bcrypt.hash(password, 10);

  await db.query(
    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
    [name, email, hash]
  );

  res.json({ success: true });
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM users WHERE email=?",
    [email]
  );

  if (rows.length === 0) {
    return res.json({ success: false, message: "No existe" });
  }

  const ok = await bcrypt.compare(password, rows[0].password);
  if (!ok) {
    return res.json({ success: false, message: "Contraseña incorrecta" });
  }

  const token = jwt.sign(
    { id: rows[0].id },
    JWT_SECRET,
    { expiresIn: "2h" }
  );

  res.json({ success: true, token });
});

/* ======================
   POSTS
====================== */

/* ---------- CREATE POST ---------- */
app.post("/create-post", auth, async (req, res) => {
  const { text } = req.body;

  if (!text) {
    return res.json({ success: false });
  }

  await db.query(
    "INSERT INTO posts (user_id, text) VALUES (?, ?)",
    [req.userId, text]
  );

  res.json({ success: true });
});

/* ---------- GET POSTS ---------- */
app.get("/get-posts", auth, async (_, res) => {
  const [posts] = await db.query(`
    SELECT 
      p.id,
      p.text,
      p.created_at,
      u.name,
      COUNT(l.id) AS likes
    FROM posts p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN likes l ON l.post_id = p.id
    GROUP BY p.id
    ORDER BY p.created_at DESC
  `);

  res.json(posts);
});

/* ======================
   LIKES
====================== */

/* ---------- TOGGLE LIKE ---------- */
app.post("/like/:postId", auth, async (req, res) => {
  const postId = req.params.postId;

  const [exists] = await db.query(
    "SELECT id FROM likes WHERE user_id=? AND post_id=?",
    [req.userId, postId]
  );

  if (exists.length > 0) {
    await db.query(
      "DELETE FROM likes WHERE user_id=? AND post_id=?",
      [req.userId, postId]
    );
    return res.json({ liked: false });
  }

  await db.query(
    "INSERT INTO likes (user_id, post_id) VALUES (?, ?)",
    [req.userId, postId]
  );

  res.json({ liked: true });
});

/* ======================
   COMMENTS
====================== */

/* ---------- ADD COMMENT ---------- */
app.post("/comment/:postId", auth, async (req, res) => {
  const { text } = req.body;
  const postId = req.params.postId;

  if (!text) return res.json({ success: false });

  await db.query(
    "INSERT INTO comments (user_id, post_id, text) VALUES (?, ?, ?)",
    [req.userId, postId, text]
  );

  res.json({ success: true });
});

/* ---------- GET COMMENTS ---------- */
app.get("/comments/:postId", auth, async (req, res) => {
  const postId = req.params.postId;

  const [comments] = await db.query(`
    SELECT c.text, c.created_at, u.name
    FROM comments c
    JOIN users u ON u.id = c.user_id
    WHERE c.post_id=?
    ORDER BY c.created_at ASC
  `, [postId]);

  res.json(comments);
});

/* ======================
   SERVER
====================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("?? MiniFacebook corriendo en puerto", PORT);
});
