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
   SENDGRID
====================== */
sgMail.setApiKey(SENDGRID_API_KEY);

/* ======================
   CLOUDINARY CONFIG
====================== */
cloudinary.config({
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key: CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET,
});

/* ======================
   MULTER CLOUDINARY (CORRECTO)
====================== */
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "minifacebook",
    resource_type: "image",
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
   AUTH
====================== */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ success: false });

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ success: false });
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
  const { name, email, password } = req.body;
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
    subject: "Verifica tu cuenta",
    html: `<a href="${link}">Verificar cuenta</a>`,
  });

  res.json({ success: true });
});

/* -------- VERIFY -------- */
app.get("/verify", async (req, res) => {
  const { token } = req.query;
  await db.query(
    "UPDATE users SET verified=1, verify_token=NULL WHERE verify_token=?",
    [token]
  );
  res.send("Cuenta verificada");
});

/* -------- LOGIN -------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const [u] = await db.query("SELECT * FROM users WHERE email=?", [email]);
  if (!u.length) return res.json({ success: false });

  const ok = await bcrypt.compare(password, u[0].password);
  if (!ok) return res.json({ success: false });

  const token = jwt.sign({ id: u[0].id }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ success: true, token });
});

/* -------- CREATE POST -------- */
app.post("/create-post", auth, upload.single("image"), async (req, res) => {
  console.log("FILE:", req.file);

  const text = req.body.text || null;
  const image = req.file?.path || null; // ?? CLOUDINARY URL

  if (!text && !image) {
    return res.json({ success: false });
  }

  await db.query(
    "INSERT INTO posts (user_id,text,image) VALUES (?,?,?)",
    [req.userId, text, image]
  );

  res.json({ success: true });
});

/* -------- GET POSTS -------- */
app.get("/get-posts", auth, async (req, res) => {
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
app.listen(process.env.PORT || 3000, () =>
  console.log("?? MiniFacebook listo")
);
