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
   UPLOADS (Render-safe)
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
   MULTER
====================== */
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadsDir),
  filename: (_, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname),
});
const upload = multer({ storage });

/* ======================
   JWT MIDDLEWARE
====================== */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) {
    return res.status(401).json({ success: false, message: "Token requerido" });
  }

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ success: false, message: "Token inválido" });
  }
}

/* ======================
   ROUTES
====================== */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* -------- REGISTER -------- */
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.json({ success: false, message: "Completa todos los campos" });
    }

    const [existing] = await db.query(
      "SELECT verified, verify_token FROM users WHERE email=?",
      [email]
    );

    if (existing.length > 0 && !existing[0].verified) {
      const link = `${BASE_URL}/verify?token=${existing[0].verify_token}`;

      await sgMail.send({
        to: email,
        from: MAIL_FROM,
        subject: "Verifica tu cuenta",
        html: `<a href="${link}">Verificar cuenta</a>`,
      });

      return res.json({
        success: true,
        message: "Correo ya registrado. Se reenvi´o verificación.",
      });
    }

    if (existing.length > 0) {
      return res.json({ success: false, message: "Correo ya registrado" });
    }

    const hash = await bcrypt.hash(password, 10);
    const verifyToken = uuidv4();

    await db.query(
      "INSERT INTO users (name, email, password, verify_token, verified) VALUES (?, ?, ?, ?, 0)",
      [name, email, hash, verifyToken]
    );

    const link = `${BASE_URL}/verify?token=${verifyToken}`;

    await sgMail.send({
      to: email,
      from: MAIL_FROM,
      subject: "Bienvenido a MiniFacebook",
      html: `<a href="${link}">Verificar cuenta</a>`,
    });

    res.json({
      success: true,
      message: "Registro exitoso. Revisa tu correo.",
    });
  } catch (err) {
    console.error("? Register:", err);
    res.status(500).json({ success: false, message: "Error al registrar" });
  }
});

/* -------- VERIFY -------- */
app.get("/verify", async (req, res) => {
  const { token } = req.query;

  const [result] = await db.query(
    "UPDATE users SET verified=1, verify_token=NULL WHERE verify_token=?",
    [token]
  );

  if (result.affectedRows === 0) {
    return res.send("? Token inválido o expirado");
  }

  res.send("? Cuenta verificada. Ya puedes iniciar sesión.");
});

/* -------- LOGIN -------- */
app.post("/login", async (req, res) => {
  try {
    const email = req.body.email?.trim();
    const password = req.body.password?.trim();

    const [rows] = await db.query(
      "SELECT * FROM users WHERE email=?",
      [email]
    );

    if (rows.length === 0) {
      return res.json({ success: false, message: "Usuario no existe" });
    }

    if (!rows[0].verified) {
      return res.json({
        success: false,
        message: "Verifica tu correo primero",
      });
    }

    const ok = await bcrypt.compare(password, rows[0].password);
    if (!ok) {
      return res.json({
        success: false,
        message: "Contraseña incorrecta",
      });
    }

    const token = jwt.sign(
      { id: rows[0].id },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      success: true,
      message: "Login exitoso",
      token,
    });
  } catch (err) {
    console.error("? Login:", err);
    res.status(500).json({ success: false, message: "Error login" });
  }
});

/* -------- CREATE POST -------- */
app.post("/create-post", auth, upload.single("image"), async (req, res) => {
  try {
    const text = req.body.text || null;
    const image = req.file ? `/uploads/${req.file.filename}` : null;

    if (!text && !image) {
      return res.json({ success: false, message: "Post vacío" });
    }

    await db.query(
      "INSERT INTO posts (user_id, text, image) VALUES (?, ?, ?)",
      [req.userId, text, image]
    );

    res.json({ success: true, message: "Post creado" });
  } catch (err) {
    console.error("? Create post:", err);
    res.status(500).json({ success: false, message: "Error post" });
  }
});

/* -------- GET POSTS -------- */
app.get("/get-posts", auth, async (req, res) => {
  const [posts] = await db.query(
    `SELECT p.text, p.image, p.created_at, u.name
     FROM posts p
     JOIN users u ON u.id = p.user_id
     ORDER BY p.created_at DESC`
  );

  res.json(posts);
});

/* ======================
   SERVER
====================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`?? API corriendo en puerto ${PORT}`);
});
