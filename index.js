import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sgMail from "@sendgrid/mail";
import multer from "multer";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

/* ======================
   __dirname FIX (ESM)
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
   UPLOADS FOLDER (Render-safe)
====================== */
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}
app.use("/uploads", express.static(uploadsDir));

/* ======================
   ENV
====================== */
const {
  BASE_URL,
  SENDGRID_API_KEY,
  MAIL_FROM,
  JWT_SECRET,
  MYSQLHOST,
  MYSQLUSER,
  MYSQLPASSWORD,
  MYSQLDATABASE,
  MYSQLPORT,
} = process.env;

/* ======================
   SENDGRID
====================== */
sgMail.setApiKey(SENDGRID_API_KEY);

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
   MULTER CONFIG
====================== */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage });

/* ======================
   MIDDLEWARE JWT
====================== */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) {
    return res.status(401).json({ message: "Token requerido" });
  }

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ message: "Token inválido" });
  }
}

/* ======================
   ROUTES
====================== */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* -------- CREATE POST -------- */
app.post("/create-post", auth, upload.single("image"), async (req, res) => {
  try {
    const text = req.body.text || null;
    const image = req.file ? `/uploads/${req.file.filename}` : null;

    if (!text && !image) {
      return res.status(400).json({ message: "Post vacío" });
    }

    await db.query(
      "INSERT INTO posts (user_id, text, image) VALUES (?, ?, ?)",
      [req.userId, text, image]
    );

    res.json({ success: true, message: "Post creado exitosamente" });
  } catch (err) {
    console.error("? Error create-post:", err);
    res.status(500).json({ message: "Error al crear post" });
  }
});

/* -------- GET POSTS -------- */
app.get("/get-posts", auth, async (req, res) => {
  try {
    const [posts] = await db.query(
      `SELECT p.text, p.image, p.created_at, u.name
       FROM posts p
       JOIN users u ON u.id = p.user_id
       ORDER BY p.created_at DESC`
    );

    res.json(posts);
  } catch (err) {
    console.error("? Error get-posts:", err);
    res.status(500).json({ message: "Error al obtener posts" });
  }
});

/* ======================
   SERVER
====================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`?? API corriendo en puerto ${PORT}`);
});
