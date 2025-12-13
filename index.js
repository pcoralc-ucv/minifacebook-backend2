const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());
app.use(express.static("public"));

/* ======================
   CONFIGURACIÓN MYSQL
====================== */
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "123456", // 🔴 CAMBIA ESTO
  database: "facebook",
});

db.connect(err => {
  if (err) {
    console.error("❌ Error MySQL:", err);
  } else {
    console.log("✅ Conectado a MySQL");
  }
});

/* ======================
   CONFIGURACIÓN MAIL
====================== */
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "minifacebookucv@gmail.com",        // 🔴 CAMBIA
    pass: "littzwhjmaqlwgxf"         // 🔴 CAMBIA
  }
});

/* ======================
   REGISTER
====================== */
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ error: "Completa todos los campos" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const token = uuidv4();

  db.query(
    "INSERT INTO users (name, email, password, verify_token) VALUES (?, ?, ?, ?)",
    [name, email, hashedPassword, token],
    async (err) => {
      if (err) {
        return res.json({ error: "Correo ya registrado" });
      }

      const link = `http://192.168.139.130:3000/verify?token=${token}`;

      await transporter.sendMail({
        from: "MiniFacebook <tucorreo@gmail.com>",
        to: email,
        subject: "Verifica tu cuenta",
        html: `
          <h2>Bienvenido a MiniFacebook</h2>
          <p>Haz clic para verificar tu cuenta:</p>
          <a href="${link}">Verificar cuenta</a>
        `
      });

      res.json({
        message: "✅ Se envió un correo para validar tu cuenta"
      });
    }
  );
});

/* ======================
   VERIFY EMAIL
====================== */
app.get("/verify", (req, res) => {
  const { token } = req.query;

  db.query(
    "UPDATE users SET verified = 1, verify_token = NULL WHERE verify_token = ?",
    [token],
    (err, result) => {
      if (result.affectedRows === 0) {
        return res.send("❌ Token inválido o expirado");
      }
      res.send("✅ Cuenta verificada, ya puedes iniciar sesión");
    }
  );
});

/* ======================
   LOGIN
====================== */
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (results.length === 0) {
        return res.json({ error: "Usuario no existe" });
      }

      const user = results[0];

      if (!user.verified) {
        return res.json({ error: "Verifica tu correo primero" });
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.json({ error: "Contraseña incorrecta" });
      }

      const token = jwt.sign(
        { id: user.id },
        "minifacebook_jwt_saucedo",
        { expiresIn: "1h" }
      );

      res.json({
        message: "Login exitoso",
        token
      });
    }
  );
});

/* ======================
   SERVER
====================== */
app.listen(3000, () => {
  console.log("🔥 API CORRIENDO EN PUERTO 3000");
});
