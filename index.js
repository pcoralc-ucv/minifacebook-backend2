import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sgMail from "@sendgrid/mail";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";

// Configuración de almacenamiento de imágenes (para multer)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Guardar en carpeta "uploads"
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage: storage });

// Configuración de Express
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static("uploads")); // Para servir imágenes desde /uploads

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

const db = await mysql.createPool({
  host: MYSQLHOST,
  user: MYSQLUSER,
  password: MYSQLPASSWORD,
  database: MYSQLDATABASE,
  port: MYSQLPORT || 3306,
});

// Ruta para subir un post (con texto o imagen)
app.post("/create-post", upload.single("image"), async (req, res) => {
  try {
    const { text } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : null;
    const userId = jwt.verify(req.headers.authorization.split(" ")[1], JWT_SECRET).id;

    const [result] = await db.query(
      "INSERT INTO posts (user_id, text, image) VALUES (?, ?, ?)",
      [userId, text, image]
    );

    res.json({ success: true, message: "Post creado exitosamente" });
  } catch (err) {
    console.error("Error creating post:", err);
    res.status(500).json({ success: false, message: "Error al crear el post" });
  }
});

// Ruta para obtener los posts
app.get("/get-posts", async (req, res) => {
  try {
    const userId = jwt.verify(req.headers.authorization.split(" ")[1], JWT_SECRET).id;

    const [posts] = await db.query("SELECT text, image FROM posts WHERE user_id = ?", [userId]);

    res.json(posts);
  } catch (err) {
    console.error("Error fetching posts:", err);
    res.status(500).json({ message: "Error al obtener los posts" });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API corriendo en puerto ${PORT}`);
});
