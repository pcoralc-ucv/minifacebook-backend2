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
  CLOUDINARY_API_SECRET
} = process.env;

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
   MULTER → CLOUDINARY
====================== */
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "minifacebook",
    allowed_formats: ["jpg", "jpeg", "png", "webp"],
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
app.get("/", (_, res) =>
  res.sendFile(path.join(__dirname, "public", "login.html"))
);

/* -------- REGISTER -------- */
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.json({ success: false, message: "Campos incompletos" });

  const [exists] = await db.query(
    "SELECT verified, verify_token FROM users WHERE email=?",
    [email]
  );

  if (exists.length && !exists[0].verified) {
    const link = `${BASE_URL}/verify?token=${exists[0].verify_token}`;
    await sgMail.send({
      to: email,
      from: MAIL_FROM,
      subject: "Verifica tu cuenta",
      html: `<a href="${link}">Verificar cuenta</a>`,
    });
    return res.json({ success: true, message: "Revisa tu correo" });
  }

  if (exists.length)
    return res.json({ success: false, message: "Correo ya registrado" });

  const hash = await bcrypt.hash(password, 10);
  const token = uuidv4();

  await db.query(
    "INSERT INTO users (name,email,password,verify_token,verified) VALUES (?,?,?,?,0)",
    [name, email, hash, token]
  );

  const link = `${BASE_URL}/verify?token=${token}`;
  await sgMail.send({
    to: email,
    from: MAIL_FROM,
    subject: "Bienvenido a MiniFacebook",
    html: `<a href="${link}">Verificar cuenta</a>`,
  });

  res.json({ success: true });
});

/* -------- VERIFY -------- */
app.get("/verify", async (req, res) => {
  const { token } = req.query;
  const [r] = await db.query(
    "UPDATE users SET verified=1, verify_token=NULL WHERE verify_token=?",
    [token]
  );
  if (!r.affectedRows) return res.send("Token inválido");
  res.send("Cuenta verificada");
});

/* -------- LOGIN -------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const [u] = await db.query("SELECT * FROM users WHERE email=?", [email]);

  if (!u.length) return res.json({ success: false });
  if (!u[0].verified) return res.json({ success: false });

  const ok = await bcrypt.compare(password, u[0].password);
  if (!ok) return res.json({ success: false });

  const token = jwt.sign({ id: u[0].id }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ success: true, token });
});

/* -------- CREATE POST (IMAGEN DESDE PC) -------- */
app.post("/create-post", auth, upload.single("image"), async (req, res) => {
  const text = req.body.text || null;
  const image = req.file ? req.file.path : null; // URL Cloudinary

  if (!text && !image)
    return res.json({ success: false, message: "Post vacío" });

  await db.query(
    "INSERT INTO posts (user_id,text,image) VALUES (?,?,?)",
    [req.userId, text, image]
  );

  res.json({ success: true });
});

/* -------- GET POSTS -------- */
app.get("/get-posts", auth, async (req, res) => {
  const [posts] = await db.query(
    `
    SELECT 
      p.id,p.text,p.image,p.created_at,u.name,
      (SELECT COUNT(*) FROM likes WHERE post_id=p.id) AS likes,
      EXISTS(
        SELECT 1 FROM likes 
        WHERE post_id=p.id AND user_id=?
      ) AS liked
    FROM posts p
    JOIN users u ON u.id=p.user_id
    ORDER BY p.created_at DESC
    `,
    [req.userId]
  );
  res.json(posts);
});

/* -------- LIKE -------- */
app.post("/like/:postId", auth, async (req, res) => {
  const { postId } = req.params;

  const [e] = await db.query(
    "SELECT id FROM likes WHERE user_id=? AND post_id=?",
    [req.userId, postId]
  );

  if (e.length) {
    await db.query("DELETE FROM likes WHERE id=?", [e[0].id]);
    return res.json({ liked: false });
  }

  await db.query("INSERT INTO likes (user_id,post_id) VALUES (?,?)", [
    req.userId,
    postId,
  ]);
  res.json({ liked: true });
});

/* -------- COMMENTS -------- */
app.get("/comments/:postId", auth, async (req, res) => {
  const [c] = await db.query(
    `
    SELECT c.text,c.created_at,u.name
    FROM comments c
    JOIN users u ON u.id=c.user_id
    WHERE c.post_id=?
    ORDER BY c.created_at
    `,
    [req.params.postId]
  );
  res.json(c);
});

app.post("/comment", auth, async (req, res) => {
  const { postId, text } = req.body;
  await db.query(
    "INSERT INTO comments (user_id,post_id,text) VALUES (?,?,?)",
    [req.userId, postId, text]
  );
  res.json({ success: true });
});

/* ======================
   SERVER
====================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log("MiniFacebook backend listo en puerto", PORT)
);
