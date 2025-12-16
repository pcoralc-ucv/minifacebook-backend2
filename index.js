import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sgMail from "@sendgrid/mail";
import { v4 as uuidv4 } from "uuid";
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

/* 🔥 ESTO ARREGLA EL UNDEFINED 🔥 */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

/* ======================
   ENV
====================== */
const {
  SENDGRID_API_KEY,
  MAIL_FROM,
  JWT_SECRET,
  MYSQLHOST,
  MYSQLUSER,
  MYSQLPASSWORD,
  MYSQLDATABASE,
  MYSQLPORT,
} = process.env;

if (SENDGRID_API_KEY) {
  sgMail.setApiKey(SENDGRID_API_KEY);
}

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
  if (!header) return res.status(401).json({ message: "Token requerido" });

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ message: "Token inválido" });
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
  console.log("REGISTER BODY:", req.body); // 👈 DEBUG

  const { name, email, password } = req.body || {};

  if (!name || !email || !password) {
    return res.json({
      success: false,
      message: "Completa todos los campos",
    });
  }

  const [exists] = await db.query(
    "SELECT id FROM users WHERE email=?",
    [email]
  );

  if (exists.length) {
    return res.json({
      success: false,
      message: "Correo ya registrado",
    });
  }

  const hash = await bcrypt.hash(password, 10);

  await db.query(
    "INSERT INTO users (name,email,password,verified) VALUES (?,?,?,1)",
    [name, email, hash]
  );

  res.json({
    success: true,
    message: "Registro exitoso, ya puedes iniciar sesión",
  });
});

/* -------- LOGIN -------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const [u] = await db.query("SELECT * FROM users WHERE email=?", [email]);
  if (!u.length)
    return res.json({ success: false, message: "Usuario no existe" });

  const ok = await bcrypt.compare(password, u[0].password);
  if (!ok)
    return res.json({ success: false, message: "Contraseña incorrecta" });

  const token = jwt.sign({ id: u[0].id }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ success: true, token });
});

/* ======================
   SERVER
====================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log("✅ MiniFacebook backend corriendo en puerto", PORT)
);
