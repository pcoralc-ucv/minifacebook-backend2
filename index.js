import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
app.use(express.json());

// 📌 Conexión MySQL (Railway)
const db = await mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

// 📌 Ruta raíz — evita el "Cannot GET /"
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// 📌 Registro
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const hashedPass = await bcrypt.hash(password, 10);
  const token = uuidv4();

  await db.query(
    "INSERT INTO users (name, email, password, verify_token) VALUES (?, ?, ?, ?)",
    [name, email, hashedPass, token]
  );

  res.json({ msg: "Usuario registrado. Verifica tu correo." });
});

// 📌 Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await db.query("SELECT * FROM users WHERE email=?", [email]);

  if (rows.length === 0) return res.status(400).json({ error: "No existe" });

  const ok = await bcrypt.compare(password, rows[0].password);
  if (!ok) return res.status(400).json({ error: "Contraseña incorrecta" });

  const token = jwt.sign({ id: rows[0].id }, process.env.JWT_SECRET);

  res.json({ token });
});

// 📌 Iniciar servidor (Render usa process.env.PORT)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🔥 API CORRIENDO EN PUERTO ${PORT}`));
