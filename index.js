import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sgMail from "@sendgrid/mail";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import { fileURLToPath } from "url";

/* ======================
   PATH CONFIG
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
   ENV VARIABLES (MATCH RENDER)
====================== */
const BASE_URL = process.env.BASE_URL;
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const MAIL_FROM = process.env.MAIL_FROM;
const JWT_SECRET = process.env.JWT_SECRET;

const MYSQLHOST = process.env.MYSQLHOST;
const MYSQLUSER = process.env.MYSQLUSER;
const MYSQLPASSWORD = process.env.MYSQLPASSWORD;
const MYSQLDATABASE = process.env.MYSQLDATABASE;
const MYSQLPORT = process.env.MYSQLPORT || 3306;

/* ======================
   ENV VALIDATION
====================== */
if (
  !BASE_URL ||
  !SENDGRID_API_KEY ||
  !MAIL_FROM ||
  !JWT_SECRET ||
  !MYSQLHOST ||
  !MYSQLUSER ||
  !MYSQLPASSWORD ||
  !MYSQLDATABASE
) {
  console.error("? Faltan variables de entorno críticas");
  console.log({
    BASE_URL,
    SENDGRID_API_KEY: SENDGRID_API_KEY ? "OK" : "MISSING",
    MAIL_FROM,
    MYSQLHOST,
    MYSQLUSER,
    MYSQLDATABASE,
  });
  process.exit(1);
}

/* ======================
   SENDGRID
====================== */
sgMail.setApiKey(SENDGRID_API_KEY);

/* ======================
   DATABASE
====================== */
const db = await mysql.createPool({
  host: MYSQLHOST,
  user: MYSQLUSER,
  password: MYSQLPASSWORD,
  database: MYSQLDATABASE,
  port: MYSQLPORT,
  waitForConnections: true,
  connectionLimit: 10,
});

/* ======================
   ROUTES
====================== */

// Home ? Login
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* -------- REGISTER -------- */
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.json({
        success: false,
        message: "Completa todos los campos",
      });
    }

    const [existing] = await db.query(
      "SELECT verified, verify_token FROM users WHERE email=?",
      [email]
    );

    // Usuario existe pero no verificado ? reenviar correo
    if (existing.length > 0 && !existing[0].verified) {
      const link = `${BASE_URL}/verify?token=${existing[0].verify_token}`;

      await sgMail.send({
        to: email,
        from: MAIL_FROM,
        subject: "Verifica tu cuenta",
        html: `
          <h2>Verificación pendiente</h2>
          <p>Haz clic para verificar tu cuenta:</p>
          <a href="${link}">Verificar cuenta</a>
        `,
      });

      return res.json({
        success: true,
        message:
          "El correo ya estaba registrado. Se reenvi´o el correo de verificación.",
      });
    }

    // Usuario ya verificado
    if (existing.length > 0) {
      return res.json({
        success: false,
        message: "El correo ya está registrado",
      });
    }

    // Crear usuario nuevo
    const hashedPassword = await bcrypt.hash(password, 10);
    const verifyToken = uuidv4();

    await db.query(
      "INSERT INTO users (name, email, password, verify_token, verified) VALUES (?, ?, ?, ?, 0)",
      [name, email, hashedPassword, verifyToken]
    );

    const link = `${BASE_URL}/verify?token=${verifyToken}`;

    await sgMail.send({
      to: email,
      from: MAIL_FROM,
      subject: "Bienvenido a MiniFacebook",
      html: `
        <h2>Bienvenido a MiniFacebook</h2>
        <p>Haz clic para verificar tu cuenta:</p>
        <a href="${link}">Verificar cuenta</a>
      `,
    });

    return res.json({
      success: true,
      message: "Registro exitoso. Revisa tu correo para validar tu cuenta.",
    });
  } catch (err) {
    console.error("? Error register:", err.response?.body || err);
    return res.json({
      success: false,
      message: "Error interno del servidor",
    });
  }
});

/* -------- VERIFY -------- */
app.get("/verify", async (req, res) => {
  try {
    const { token } = req.query;

    const [result] = await db.query(
      "UPDATE users SET verified=1, verify_token=NULL WHERE verify_token=?",
      [token]
    );

    if (result.affectedRows === 0) {
      return res.send("? Token inválido o expirado");
    }

    res.send("? Cuenta verificada. Ya puedes iniciar sesión.");
  } catch (err) {
    console.error("? Error verify:", err);
    res.send("? Error al verificar la cuenta");
  }
});

/* -------- LOGIN -------- */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await db.query(
      "SELECT * FROM users WHERE email=?",
      [email]
    );

    if (rows.length === 0) {
      return res.json({
        success: false,
        message: "Usuario no existe",
      });
    }

    if (!rows[0].verified) {
      return res.json({
        success: false,
        message: "Verifica tu correo primero",
      });
    }

    const match = await bcrypt.compare(password, rows[0].password);
    if (!match) {
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

    return res.json({
      success: true,
      message: "Login exitoso",
      token,
    });
  } catch (err) {
    console.error("? Error login:", err);
    return res.json({
      success: false,
      message: "Error interno del servidor",
    });
  }
});

/* ======================
   SERVER
====================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`?? API corriendo en puerto ${PORT}`);
});
