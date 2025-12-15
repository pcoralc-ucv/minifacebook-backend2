import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sgMail from "@sendgrid/mail";
import multer from "multer";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import { v2 as cloudinary } from "cloudinary";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import { fileURLToPath } from "url";

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
  CLOUDINARY_CLOUD_NAME,
  CLOUDINARY_API_KEY,
  CLOUDINARY_API_SECRET,
} = process.env;

/* ======================
   VALIDACIÓN ENV (CLAVE)
====================== */
if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
  console.error("? Cloudinary ENV no configurado");
  process.exit(1);
}

/* ======================
   SENDGRID
====================== */
sgMail.setApiKey(SENDGRID_API_KEY);

/* ======================
   CLOUDINARY
====================== */
cloudinary.config({
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key: CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET,
});

/* ======================
   MULTER + CLOUDINARY
====================== */
const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    return {
      folder: "minifacebook",
      format: file.mimetype.split("/")[1], // jpg, png
      public_id: Date.now() + "-" + file.originalname
    };
  },
});

const upload = multer({ storage });

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
app.get("/", (_, res) => {
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

    if (existing.length && !existing[0].verified) {
      const link = `${BASE_URL}/verify?token=${existing[0].verify_token}`;
      await sgMail.send({
        to: email,
        from: MAIL_FROM,
        subject: "Verifica tu cuenta",
        html: `<a href="${link}">Verificar cuenta</a>`,
      });
      return res.json({ success: true, message: "Revisa tu correo" });
    }

    if (existing.length) {
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

    res.json({ success: true, message: "Registro exitoso" });
  } catch (err) {
    console.error("? Register:", err);
    res.status(500).json({ success: false });
  }
});

/* -------- LOGIN -------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await db.query("SELECT * FROM users WHERE email=?", [email]);
  if (!rows.length)
    return res.json({ success: false, message: "Usuario no existe" });

  if (!rows[0].verified)
    return res.json({ success: false, message: "Verifica tu correo" });

  const ok = await bcrypt.compare(password, rows[0].password);
  if (!ok)
    return res.json({ success: false, message: "Contraseña incorrecta" });

  const token = jwt.sign({ id: rows[0].id }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ success: true, token });
});

/* -------- CREATE POST -------- */
app.post("/create-post", auth, upload.single("image"), async (req, res) => {
  try {
    const text = req.body.text || null;

    // ?? AQUÍ ESTABA EL ERROR
    const image = req.file ? req.file.secure_url : null;

    console.log("FILE:", req.file); // 

    if (!text && !image) {
      return res.json({ success: false, message: "Post vacío" });
    }

    await db.query(
      "INSERT INTO posts (user_id, text, image) VALUES (?, ?, ?)",
      [req.userId, text, image]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("CREATE POST ERROR:", err);
    res.status(500).json({ success: false });
  }
});

/* -------- GET POSTS -------- */
app.get("/get-posts", auth, async (_, res) => {
  const [posts] = await db.query(`
    SELECT p.text, p.image, p.created_at, u.name
    FROM posts p
    JOIN users u ON u.id = p.user_id
    ORDER BY p.created_at DESC
  `);
  res.json(posts);
});

/* ======================
   SERVER
====================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("? MiniFacebook corriendo en puerto", PORT);
});
