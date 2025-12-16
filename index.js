import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sgMail from "@sendgrid/mail";
import multer from "multer";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import { v2 as cloudinary } from "cloudinary";
import path from "path";
import { fileURLToPath } from "url";

/* ===== dirname ===== */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ===== APP ===== */
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

/* ===== ENV ===== */
const {
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

/* ===== CLOUDINARY ===== */
cloudinary.config({
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key: CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET
});

/* ===== MULTER CLOUDINARY ===== */
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "minifacebook",
    allowed_formats: ["jpg","jpeg","png","webp"]
  }
});
const upload = multer({ storage });

/* ===== DB ===== */
const db = await mysql.createPool({
  host: MYSQLHOST,
  user: MYSQLUSER,
  password: MYSQLPASSWORD,
  database: MYSQLDATABASE,
  port: MYSQLPORT || 3306
});

/* ===== AUTH ===== */
function auth(req,res,next){
  const header = req.headers.authorization;
  if(!header) return res.status(401).json({error:"Token requerido"});
  try{
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  }catch{
    res.status(401).json({error:"Token inválido"});
  }
}

/* ===== CREATE POST ===== */
app.post(
  "/create-post",
  auth,
  upload.single("image"),
  async (req,res)=>{
    console.log("FILE:", req.file); // 👈 DEBUG

    const text = req.body.text || null;
    const image = req.file ? req.file.path : null;

    if(!text && !image){
      return res.json({success:false,message:"Post vacío"});
    }

    await db.query(
      "INSERT INTO posts (user_id,text,image) VALUES (?,?,?)",
      [req.userId,text,image]
    );

    res.json({success:true});
  }
);

/* ===== GET POSTS ===== */
app.get("/get-posts", auth, async (req,res)=>{
  const [rows] = await db.query(`
    SELECT p.id,p.text,p.image,p.created_at,u.name
    FROM posts p
    JOIN users u ON u.id=p.user_id
    ORDER BY p.created_at DESC
  `);
  res.json(rows);
});

/* ===== SERVER ===== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log("🔥 Server ON",PORT));
