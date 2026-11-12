require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const smtpPort=Number(process.env.SMTP_PORT||587);
const resetMailer=process.env.SMTP_HOST&&process.env.SMTP_FROM&&Number.isInteger(smtpPort)
  ? nodemailer.createTransport({
      host:process.env.SMTP_HOST,
      port:smtpPort,
      secure:process.env.SMTP_SECURE==="true",
      auth:process.env.SMTP_USER?{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS||""}:undefined
    })
  : null;
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) {
  console.error("Set JWT_SECRET in .env to a random string of at least 32 characters.");
  process.exit(1);
}

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
const db = new Database(path.join(dataDir, "bondhu-bitto.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  phone TEXT DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','member')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER NOT NULL REFERENCES users(id),
  amount REAL NOT NULL CHECK(amount > 0),
  kisti_month TEXT NOT NULL,
  paid_date TEXT NOT NULL,
  method TEXT DEFAULT 'Cash',
  reference TEXT DEFAULT '',
  note TEXT DEFAULT '',
  recorded_by INTEGER REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'approved' CHECK(status IN ('pending','approved')),
  approved_by INTEGER REFERENCES users(id),
  approved_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_payments_member ON payments(member_id);
CREATE INDEX IF NOT EXISTS idx_payments_month ON payments(kisti_month);
CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);
CREATE TABLE IF NOT EXISTS notices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  image_mime TEXT,
  image_data BLOB,
  file_name TEXT,
  file_mime TEXT,
  file_data BLOB,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS emergency_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL DEFAULT '',
  image_mime TEXT,
  image_data BLOB,
  file_name TEXT,
  file_mime TEXT,
  file_data BLOB,
  status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','resolved')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at TEXT,
  resolved_by INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_notices_created ON notices(created_at);
CREATE INDEX IF NOT EXISTS idx_emergency_status ON emergency_messages(status,created_at);
`);
const userColumns = new Set(db.pragma("table_info(users)").map(column => column.name));
for (const [column, definition] of [
  ["account_no", "TEXT"],
  ["father_name", "TEXT NOT NULL DEFAULT ''"],
  ["mother_name", "TEXT NOT NULL DEFAULT ''"],
  ["nominee_name", "TEXT NOT NULL DEFAULT ''"],
  ["nid", "TEXT NOT NULL DEFAULT ''"],
  ["nominee_nid", "TEXT NOT NULL DEFAULT ''"],
  ["profile_photo", "TEXT NOT NULL DEFAULT ''"],
  ["nid_photo", "TEXT NOT NULL DEFAULT ''"],
  ["nominee_nid_photo", "TEXT NOT NULL DEFAULT ''"],
  ["own_signature", "TEXT NOT NULL DEFAULT ''"],
  ["nominee_signature", "TEXT NOT NULL DEFAULT ''"]
]) {
  if (!userColumns.has(column)) db.exec(`ALTER TABLE users ADD COLUMN ${column} ${definition}`);
}
const memberAccountNo = id => `BB-${String(id).padStart(6,"0")}`;
const membersWithoutAccountNo=db.prepare("SELECT id FROM users WHERE role='member' AND (account_no IS NULL OR account_no='')").all();
const saveAccountNo=db.prepare("UPDATE users SET account_no=? WHERE id=?");
for(const member of membersWithoutAccountNo) saveAccountNo.run(memberAccountNo(member.id),member.id);
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_account_no ON users(account_no) WHERE account_no IS NOT NULL");
const paymentColumns = new Set(db.pragma("table_info(payments)").map(column => column.name));
for (const [column, definition] of [
  ["status", "TEXT NOT NULL DEFAULT 'approved'"],
  ["approved_by", "INTEGER REFERENCES users(id)"],
  ["approved_at", "TEXT"]
]) {
  if (!paymentColumns.has(column)) db.exec(`ALTER TABLE payments ADD COLUMN ${column} ${definition}`);
}

const adminEmail = process.env.ADMIN_EMAIL || "admin@bondhubitto.local";
const adminPassword = process.env.ADMIN_PASSWORD;
if (!adminPassword || adminPassword.length < 10) {
  console.error("Set ADMIN_PASSWORD in .env (minimum 10 characters).");
  process.exit(1);
}
const existingAdmin = db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
    .run(process.env.ADMIN_NAME || "BonDhu Bitto Admin", adminEmail, hash);
  console.log("Initial administrator created:", adminEmail);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "12mb" }));
app.use(cookieParser());
app.use("/image", express.static(path.join(__dirname, "image")));
app.use(express.static(path.join(__dirname, "public")));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const passwordResetLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });
const emergencyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 3, standardHeaders: true, legacyHeaders: false });
function auth(req, res, next) {
  const token = req.cookies.bb_session;
  if (!token) return res.status(401).json({ error: "Please sign in." });
  try {
    const payload = jwt.verify(token, SECRET);
    const user = db.prepare("SELECT id,name,email,phone,role,active,account_no FROM users WHERE id=?").get(payload.id);
    if (!user || !user.active) return res.status(401).json({ error: "Account unavailable." });
    req.user = user;
    next();
  } catch { res.status(401).json({ error: "Session expired. Please sign in again." }); }
}
const adminOnly = (req,res,next) => req.user.role === "admin" ? next() : res.status(403).json({error:"Administrator access required."});
const clean = (v, max=200) => String(v ?? "").trim().slice(0,max);
const validMonth = v => /^\d{4}-(0[1-9]|1[0-2])$/.test(String(v));
const validDate = v => /^\d{4}-\d{2}-\d{2}$/.test(String(v)) && !Number.isNaN(Date.parse(v));
const emailOk = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const imageMimes = new Set(["image/jpeg","image/png","image/webp"]);
const fileMimes = new Set(["application/pdf","text/plain","application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document"]);
const parseDataUpload = (data, allowedMimes, maxBytes) => {
  if(!data) return null;
  const match=String(data).match(/^data:([\w.+-]+\/[\w.+-]+);base64,([A-Za-z0-9+/]+={0,2})$/);
  if(!match||!allowedMimes.has(match[1])) return null;
  const buffer=Buffer.from(match[2],"base64");
  if(buffer.length>maxBytes||buffer.toString("base64")!==match[2]) return null;
  return {mime:match[1],buffer};
};
const safeFilename = value => clean(value,120).replace(/[\\/\r\n\0]/g,"_")||"attachment";
const parseProfileImage = value => {
  if (value === "") return "";
  const match=String(value).match(/^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/);
  if (!match) return null;
  const image=Buffer.from(match[1],"base64");
  return image.length<=650*1024 && image.toString("base64")===match[1] ? value : null;
};

app.post("/api/login", loginLimiter, (req,res) => {
  const email = clean(req.body.email,254).toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || !user.active || !bcrypt.compareSync(password,user.password_hash))
    return res.status(401).json({error:"Email or password is incorrect."});
  const token = jwt.sign({id:user.id}, SECRET, {expiresIn:"12h"});
  res.cookie("bb_session", token, {httpOnly:true, sameSite:"strict", secure:process.env.NODE_ENV==="production", maxAge:12*60*60*1000});
  res.json({user:{id:user.id,name:user.name,email:user.email,role:user.role,account_no:user.account_no}});
});
app.post("/api/password/forgot", passwordResetLimiter, (req,res) => {
  if(!resetMailer) return res.status(503).json({error:"Password recovery email is not configured. Please contact the administrator."});
  const email=clean(req.body?.email,254).toLowerCase();
  if(!emailOk(email)) return res.status(400).json({error:"Enter a valid email address."});
  const user=db.prepare("SELECT id,name,email FROM users WHERE email=? AND active=1").get(email);
  if(user){
    const now=Date.now(), token=crypto.randomBytes(32).toString("hex");
    const tokenHash=crypto.createHash("sha256").update(token).digest("hex");
    const expiresAt=now+30*60*1000;
    db.prepare("DELETE FROM password_resets WHERE user_id=? OR expires_at<=?").run(user.id,now);
    db.prepare("INSERT INTO password_resets(user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)").run(user.id,tokenHash,expiresAt,now);
    let resetUrl;
    try{
      resetUrl=new URL(process.env.APP_URL||`http://localhost:${PORT}`);
      resetUrl.searchParams.set("reset",token);
    }catch{
      db.prepare("DELETE FROM password_resets WHERE token_hash=?").run(tokenHash);
      return res.status(503).json({error:"Password recovery is not available. Please contact the administrator."});
    }
    const message={
      from:process.env.SMTP_FROM,
      to:user.email,
      subject:"Reset your BonDhu Bitto password",
      text:`Hello ${user.name},\n\nUse this link to reset your password. It expires in 30 minutes:\n${resetUrl}\n\nIf you did not request this, you can ignore this email.`,
      html:`<p>Hello,</p><p>Use this link to reset your BonDhu Bitto password. It expires in 30 minutes.</p><p><a href="${resetUrl.toString()}">Reset password</a></p><p>If you did not request this, you can ignore this email.</p>`
    };
    resetMailer.sendMail(message).catch(error=>{
      db.prepare("DELETE FROM password_resets WHERE token_hash=?").run(tokenHash);
      console.error("Password reset email delivery failed:",error.message);
    });
  }
  res.json({message:"If an active account matches that email, a password reset link will be sent."});
});
app.post("/api/password/reset", passwordResetLimiter, (req,res) => {
  const token=clean(req.body?.token,128), password=String(req.body?.password||"");
  if(password.length<10) return res.status(400).json({error:"Password must be at least 10 characters."});
  const tokenHash=crypto.createHash("sha256").update(token).digest("hex"), now=Date.now();
  const changePassword=db.transaction(()=>{
    const reset=db.prepare("SELECT user_id FROM password_resets WHERE token_hash=? AND expires_at>? AND used_at IS NULL").get(tokenHash,now);
    if(!reset) return false;
    const hash=bcrypt.hashSync(password,12);
    const updated=db.prepare("UPDATE users SET password_hash=? WHERE id=? AND active=1").run(hash,reset.user_id);
    if(!updated.changes) return false;
    db.prepare("DELETE FROM password_resets WHERE user_id=?").run(reset.user_id);
    return true;
  });
  if(!changePassword()) return res.status(400).json({error:"This password reset link is invalid or has expired."});
  res.json({ok:true});
});
app.post("/api/logout", (req,res) => { res.clearCookie("bb_session",{httpOnly:true,sameSite:"strict",secure:process.env.NODE_ENV==="production"}); res.json({ok:true}); });
app.get("/api/me", auth, (req,res) => res.json({user:req.user}));
app.get("/api/profile", auth, (req,res) => {
  const profile=db.prepare("SELECT id,name,email,phone,account_no,father_name,mother_name,nominee_name,nid,nominee_nid,profile_photo,nid_photo,nominee_nid_photo,own_signature,nominee_signature FROM users WHERE id=?").get(req.user.id);
  res.json({profile});
});
app.patch("/api/profile", auth, (req,res) => {
  const body=req.body||{};
  const name=clean(body.name,100), fatherName=clean(body.fatherName,100), motherName=clean(body.motherName,100);
  const nomineeName=clean(body.nomineeName,100), nid=clean(body.nid,30), nomineeNid=clean(body.nomineeNid,30);
  const profilePhoto=body.profilePhoto===undefined||body.profilePhoto===null?null:parseProfileImage(body.profilePhoto);
  const nidPhoto=body.nidPhoto===undefined||body.nidPhoto===null?null:parseProfileImage(body.nidPhoto);
  const nomineeNidPhoto=body.nomineeNidPhoto===undefined||body.nomineeNidPhoto===null?null:parseProfileImage(body.nomineeNidPhoto);
  const ownSignature=body.ownSignature===undefined||body.ownSignature===null?null:parseProfileImage(body.ownSignature);
  const nomineeSignature=body.nomineeSignature===undefined||body.nomineeSignature===null?null:parseProfileImage(body.nomineeSignature);
  if (body.profilePhoto!==undefined && body.profilePhoto!==null && profilePhoto===null ||
      body.nidPhoto!==undefined && body.nidPhoto!==null && nidPhoto===null ||
      body.nomineeNidPhoto!==undefined && body.nomineeNidPhoto!==null && nomineeNidPhoto===null ||
      body.ownSignature!==undefined && body.ownSignature!==null && ownSignature===null ||
      body.nomineeSignature!==undefined && body.nomineeSignature!==null && nomineeSignature===null)
    return res.status(400).json({error:"Profile photos, NID images and signatures must be JPEG images smaller than 650 KB each."});
  if (!name) return res.status(400).json({error:"Enter your full name."});
  db.prepare("UPDATE users SET name=?,father_name=?,mother_name=?,nominee_name=?,nid=?,nominee_nid=?,profile_photo=COALESCE(?,profile_photo),nid_photo=COALESCE(?,nid_photo),nominee_nid_photo=COALESCE(?,nominee_nid_photo),own_signature=COALESCE(?,own_signature),nominee_signature=COALESCE(?,nominee_signature) WHERE id=?")
    .run(name,fatherName,motherName,nomineeName,nid,nomineeNid,profilePhoto,nidPhoto,nomineeNidPhoto,ownSignature,nomineeSignature,req.user.id);
  const profile=db.prepare("SELECT id,name,email,phone,account_no,father_name,mother_name,nominee_name,nid,nominee_nid,profile_photo,nid_photo,nominee_nid_photo,own_signature,nominee_signature FROM users WHERE id=?").get(req.user.id);
  res.json({profile});
});

app.get("/api/contact-info", auth, (req,res) => {
  res.json({whatsappNumber:clean(process.env.WHATSAPP_NUMBER,30).replace(/\D/g,"")});
});
app.get("/api/notices", auth, (req,res) => {
  const notices=db.prepare(`SELECT n.id,n.title,n.body,n.file_name,n.created_at,u.name created_by,
    (n.image_data IS NOT NULL) has_image,(n.file_data IS NOT NULL) has_file
    FROM notices n JOIN users u ON u.id=n.created_by ORDER BY n.created_at DESC,n.id DESC`).all();
  res.json({notices});
});
app.post("/api/notices", auth, adminOnly, (req,res) => {
  const title=clean(req.body?.title,120), body=clean(req.body?.body,4000);
  const image=req.body?.image?parseDataUpload(req.body.image,imageMimes,2*1024*1024):null;
  const file=req.body?.file?parseDataUpload(req.body.file,fileMimes,4*1024*1024):null;
  if(!title) return res.status(400).json({error:"Enter a notice title."});
  if(!body&&!req.body?.image&&!req.body?.file) return res.status(400).json({error:"Add notice text, an image, or a file."});
  if(req.body?.image&&!image) return res.status(400).json({error:"Notice image must be JPEG, PNG or WebP under 2 MB."});
  if(req.body?.file&&!file) return res.status(400).json({error:"File must be PDF, TXT, DOC or DOCX under 4 MB."});
  const fileName=file?safeFilename(req.body.fileName):null;
  const info=db.prepare("INSERT INTO notices(title,body,image_mime,image_data,file_name,file_mime,file_data,created_by) VALUES(?,?,?,?,?,?,?,?)")
    .run(title,body,image?.mime||null,image?.buffer||null,fileName,file?.mime||null,file?.buffer||null,req.user.id);
  res.status(201).json({id:info.lastInsertRowid});
});
app.get("/api/notices/:id/image", auth, (req,res) => {
  const notice=db.prepare("SELECT image_mime,image_data FROM notices WHERE id=?").get(Number(req.params.id));
  if(!notice?.image_data) return res.status(404).json({error:"Notice image not found."});
  res.setHeader("Content-Type",notice.image_mime);
  res.setHeader("Cache-Control","private, no-store");
  res.setHeader("X-Content-Type-Options","nosniff");
  res.send(notice.image_data);
});
app.get("/api/notices/:id/file", auth, (req,res) => {
  const notice=db.prepare("SELECT file_name,file_mime,file_data FROM notices WHERE id=?").get(Number(req.params.id));
  if(!notice?.file_data) return res.status(404).json({error:"Notice file not found."});
  res.setHeader("Content-Type",notice.file_mime);
  res.setHeader("Content-Disposition",`attachment; filename*=UTF-8''${encodeURIComponent(notice.file_name)}`);
  res.setHeader("Cache-Control","private, no-store");
  res.setHeader("X-Content-Type-Options","nosniff");
  res.send(notice.file_data);
});
app.delete("/api/notices/:id", auth, adminOnly, (req,res) => {
  const info=db.prepare("DELETE FROM notices WHERE id=?").run(Number(req.params.id));
  if(!info.changes) return res.status(404).json({error:"Notice not found."});
  res.json({ok:true});
});
app.post("/api/emergency", auth, emergencyLimiter, (req,res) => {
  if(req.user.role!=='member') return res.status(403).json({error:"Only member accounts can send emergency messages."});
  const body=clean(req.body?.body,2000);
  const image=req.body?.image?parseDataUpload(req.body.image,imageMimes,2*1024*1024):null;
  const file=req.body?.file?parseDataUpload(req.body.file,fileMimes,4*1024*1024):null;
  if(!body&&!req.body?.image&&!req.body?.file) return res.status(400).json({error:"Write a message or attach a file."});
  if(req.body?.image&&!image) return res.status(400).json({error:"Image must be JPEG, PNG or WebP under 2 MB."});
  if(req.body?.file&&!file) return res.status(400).json({error:"File must be PDF, TXT, DOC or DOCX under 4 MB."});
  const info=db.prepare("INSERT INTO emergency_messages(member_id,body,image_mime,image_data,file_name,file_mime,file_data) VALUES(?,?,?,?,?,?,?)")
    .run(req.user.id,body,image?.mime||null,image?.buffer||null,file?safeFilename(req.body.fileName):null,file?.mime||null,file?.buffer||null);
  res.status(201).json({id:info.lastInsertRowid,status:"new"});
});
app.get("/api/emergency", auth, adminOnly, (req,res) => {
  const messages=db.prepare(`SELECT e.id,e.body,e.status,e.created_at,e.resolved_at,e.file_name,
    (e.image_data IS NOT NULL) has_image,(e.file_data IS NOT NULL) has_file,
    u.id member_id,u.name member_name,u.account_no,u.email,u.phone
    FROM emergency_messages e JOIN users u ON u.id=e.member_id
    ORDER BY CASE e.status WHEN 'new' THEN 0 ELSE 1 END,e.created_at DESC,e.id DESC`).all();
  res.json({messages});
});
app.get("/api/emergency/:id/image", auth, adminOnly, (req,res) => {
  const message=db.prepare("SELECT image_mime,image_data FROM emergency_messages WHERE id=?").get(Number(req.params.id));
  if(!message?.image_data) return res.status(404).json({error:"Emergency image not found."});
  res.setHeader("Content-Type",message.image_mime);res.setHeader("Cache-Control","private, no-store");res.setHeader("X-Content-Type-Options","nosniff");res.send(message.image_data);
});
app.get("/api/emergency/:id/file", auth, adminOnly, (req,res) => {
  const message=db.prepare("SELECT file_name,file_mime,file_data FROM emergency_messages WHERE id=?").get(Number(req.params.id));
  if(!message?.file_data) return res.status(404).json({error:"Emergency file not found."});
  res.setHeader("Content-Type",message.file_mime);res.setHeader("Content-Disposition",`attachment; filename*=UTF-8''${encodeURIComponent(message.file_name)}`);res.setHeader("Cache-Control","private, no-store");res.setHeader("X-Content-Type-Options","nosniff");res.send(message.file_data);
});
app.patch("/api/emergency/:id/resolve", auth, adminOnly, (req,res) => {
  const info=db.prepare("UPDATE emergency_messages SET status='resolved',resolved_at=?,resolved_by=? WHERE id=? AND status='new'")
    .run(new Date().toISOString(),req.user.id,Number(req.params.id));
  if(!info.changes) return res.status(404).json({error:"New emergency message not found."});
  res.json({ok:true});
});

app.get("/api/dashboard", auth, (req,res) => {
  if (req.user.role === "member") {
    const total = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE member_id=? AND status='approved'").get(req.user.id).total;
    const current = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE member_id=? AND kisti_month=? AND status='approved'").get(req.user.id,new Date().toISOString().slice(0,7)).total;
    const communityTotal = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE status='approved'").get().total;
    const members = db.prepare("SELECT COUNT(*) count FROM users WHERE role='member' AND active=1").get().count;
    const payments = db.prepare("SELECT * FROM payments WHERE member_id=? ORDER BY paid_date DESC,id DESC LIMIT 100").all(req.user.id);
    return res.json({member:true,total,current,communityTotal,members,payments});
  }
  const total = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE status='approved'").get().total;
  const current = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE kisti_month=? AND status='approved'").get(new Date().toISOString().slice(0,7)).total;
  const members = db.prepare("SELECT COUNT(*) count FROM users WHERE role='member' AND active=1").get().count;
  const profileFields=["name","email","phone","father_name","mother_name","nominee_name","nid","nominee_nid","has_profile_photo","has_nid_photo","has_nominee_nid_photo","has_own_signature","has_nominee_signature"];
  const profileRows=db.prepare(`SELECT id,name,email,active,phone,father_name,mother_name,nominee_name,nid,nominee_nid,
    LENGTH(profile_photo)>0 has_profile_photo,LENGTH(nid_photo)>0 has_nid_photo,
    LENGTH(nominee_nid_photo)>0 has_nominee_nid_photo,LENGTH(own_signature)>0 has_own_signature,
    LENGTH(nominee_signature)>0 has_nominee_signature FROM users WHERE role='member' ORDER BY name COLLATE NOCASE`).all();
  const profileCompletion=profileRows.map(member=>{
    const completed=profileFields.filter(field=>Boolean(member[field])).length;
    return {id:member.id,name:member.name,active:Boolean(member.active),completed,total:profileFields.length,percentage:Math.round(completed*100/profileFields.length)};
  });
  const recent = db.prepare(`SELECT p.*,u.name member_name FROM payments p JOIN users u ON u.id=p.member_id WHERE p.status='approved' ORDER BY p.paid_date DESC,p.id DESC LIMIT 8`).all();
  res.json({member:false,total,current,members,average:members?total/members:0,recent,profileCompletion});
});

app.get("/api/members", auth, adminOnly, (req,res) => {
  const rows = db.prepare(`SELECT u.id,u.account_no,u.name,u.email,u.phone,u.active,u.created_at,
    COALESCE(SUM(CASE WHEN p.status='approved' THEN p.amount ELSE 0 END),0) total_saved FROM users u LEFT JOIN payments p ON p.member_id=u.id
    WHERE u.role='member' GROUP BY u.id ORDER BY u.name COLLATE NOCASE`).all();
  res.json({members:rows});
});
app.get("/api/members/:id/profile", auth, adminOnly, (req,res) => {
  const profile=db.prepare("SELECT id,account_no,name,email,phone,father_name,mother_name,nominee_name,nid,nominee_nid,profile_photo,nid_photo,nominee_nid_photo,own_signature,nominee_signature FROM users WHERE id=? AND role='member'").get(Number(req.params.id));
  if(!profile) return res.status(404).json({error:"Member not found."});
  res.json({profile});
});
app.get("/api/members/:id/ledger", auth, adminOnly, (req,res) => {
  const memberId=Number(req.params.id);
  if(!Number.isInteger(memberId)||memberId<1) return res.status(400).json({error:"Invalid member account."});
  const member=db.prepare("SELECT id,account_no,name,email,phone,active,father_name,mother_name,nominee_name,nid,nominee_nid FROM users WHERE id=? AND role='member'").get(memberId);
  if(!member) return res.status(404).json({error:"Member not found."});
  const payments=db.prepare("SELECT id,kisti_month,paid_date,amount,method,reference,note,status,created_at,approved_at FROM payments WHERE member_id=? ORDER BY kisti_month DESC,paid_date DESC,id DESC").all(memberId);
  const approvedTotal=payments.filter(payment=>payment.status==='approved').reduce((total,payment)=>total+payment.amount,0);
  const pendingTotal=payments.filter(payment=>payment.status==='pending').reduce((total,payment)=>total+payment.amount,0);
  res.json({member,payments,approvedTotal,pendingTotal});
});
app.patch("/api/members/:id/profile", auth, adminOnly, (req,res) => {
  const body=req.body||{}, memberId=Number(req.params.id);
  const name=clean(body.name,100), email=clean(body.email,254).toLowerCase(), phone=clean(body.phone,30);
  const fatherName=clean(body.fatherName,100), motherName=clean(body.motherName,100), nomineeName=clean(body.nomineeName,100);
  const nid=clean(body.nid,30), nomineeNid=clean(body.nomineeNid,30);
  const images={
    profilePhoto:body.profilePhoto,
    nidPhoto:body.nidPhoto,
    nomineeNidPhoto:body.nomineeNidPhoto,
    ownSignature:body.ownSignature,
    nomineeSignature:body.nomineeSignature
  };
  for(const [field,value] of Object.entries(images)){
    if(value!==undefined&&value!==null){
      images[field]=parseProfileImage(value);
      if(images[field]===null) return res.status(400).json({error:"Profile photos, NID images and signatures must be JPEG images smaller than 650 KB each."});
    }else images[field]=null;
  }
  if(!Number.isInteger(memberId)||memberId<1||!name||!emailOk(email)) return res.status(400).json({error:"Enter a member name and valid email."});
  try{
    const info=db.prepare("UPDATE users SET name=?,email=?,phone=?,father_name=?,mother_name=?,nominee_name=?,nid=?,nominee_nid=?,profile_photo=COALESCE(?,profile_photo),nid_photo=COALESCE(?,nid_photo),nominee_nid_photo=COALESCE(?,nominee_nid_photo),own_signature=COALESCE(?,own_signature),nominee_signature=COALESCE(?,nominee_signature) WHERE id=? AND role='member'")
      .run(name,email,phone,fatherName,motherName,nomineeName,nid,nomineeNid,images.profilePhoto,images.nidPhoto,images.nomineeNidPhoto,images.ownSignature,images.nomineeSignature,memberId);
    if(!info.changes) return res.status(404).json({error:"Member not found."});
    const profile=db.prepare("SELECT id,account_no,name,email,phone,father_name,mother_name,nominee_name,nid,nominee_nid,profile_photo,nid_photo,nominee_nid_photo,own_signature,nominee_signature FROM users WHERE id=?").get(memberId);
    res.json({profile});
  }catch(error){
    if(error.code==="SQLITE_CONSTRAINT_UNIQUE") return res.status(409).json({error:"This email is already registered."});
    throw error;
  }
});
app.post("/api/members", auth, adminOnly, (req,res) => {
  const name=clean(req.body.name,100), email=clean(req.body.email,254).toLowerCase();
  const phone=clean(req.body.phone,30), password=String(req.body.password||"");
  if (!name || !emailOk(email) || password.length<10) return res.status(400).json({error:"Enter a name, valid email and a password of at least 10 characters."});
  try {
    const hash=bcrypt.hashSync(password,12);
    const createMember=db.transaction(()=>{
      const info=db.prepare("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,'member')").run(name,email,phone,hash);
      const accountNo=memberAccountNo(info.lastInsertRowid);
      db.prepare("UPDATE users SET account_no=? WHERE id=?").run(accountNo,info.lastInsertRowid);
      return {id:info.lastInsertRowid,accountNo};
    });
    res.status(201).json(createMember());
  } catch(e) { res.status(409).json({error:e.code==="SQLITE_CONSTRAINT_UNIQUE"?"This email is already registered.":"Could not create member."}); }
});
app.patch("/api/members/:id/status", auth, adminOnly, (req,res) => {
  const active=req.body.active ? 1 : 0;
  const info=db.prepare("UPDATE users SET active=? WHERE id=? AND role='member'").run(active,Number(req.params.id));
  if (!info.changes) return res.status(404).json({error:"Member not found."});
  res.json({ok:true});
});
app.get("/api/payments", auth, (req,res) => {
  const sql=`SELECT p.*,u.name member_name,u.email member_email,u.phone member_phone FROM payments p JOIN users u ON u.id=p.member_id`;
  const rows=req.user.role==="admin"
    ? db.prepare(sql+" ORDER BY p.paid_date DESC,p.id DESC LIMIT 500").all()
    : db.prepare(sql+" WHERE p.member_id=? ORDER BY p.paid_date DESC,p.id DESC LIMIT 500").all(req.user.id);
  res.json({payments:rows});
});
app.post("/api/payments", auth, (req,res) => {
  const memberId=req.user.role==="admin" ? Number(req.body.memberId) : req.user.id;
  const amount=Number(req.body.amount);
  const month=clean(req.body.month,7), date=clean(req.body.date,10);
  const method=clean(req.body.method,30)||"Cash", reference=clean(req.body.reference,80), note=clean(req.body.note,250);
  const member=db.prepare("SELECT id FROM users WHERE id=? AND role='member' AND active=1").get(memberId);
  if (!member || !Number.isFinite(amount) || amount<=0 || amount>100000000 || !validMonth(month) || !validDate(date))
    return res.status(400).json({error:"Check member, amount, kisti month and payment date."});
  const status=req.user.role==="admin"?"approved":"pending";
  const info=db.prepare("INSERT INTO payments(member_id,amount,kisti_month,paid_date,method,reference,note,recorded_by,status,approved_by,approved_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
    .run(memberId,amount,month,date,method,reference,note,req.user.id,status,status==="approved"?req.user.id:null,status==="approved"?new Date().toISOString():null);
  res.status(201).json({id:info.lastInsertRowid,status});
});
app.post("/api/payments/:id/approve", auth, adminOnly, (req,res) => {
  const paymentId=Number(req.params.id);
  if(!Number.isInteger(paymentId)||paymentId<1) return res.status(400).json({error:"Invalid payment record."});
  const info=db.prepare("UPDATE payments SET status='approved',approved_by=?,approved_at=? WHERE id=? AND status='pending'")
    .run(req.user.id,new Date().toISOString(),paymentId);
  if(!info.changes) return res.status(404).json({error:"Pending payment not found."});
  res.json({ok:true,status:"approved"});
});
app.patch("/api/payments/:id", auth, adminOnly, (req,res) => {
  const paymentId=Number(req.params.id), memberId=Number(req.body.memberId), amount=Number(req.body.amount);
  const month=clean(req.body.month,7), date=clean(req.body.date,10);
  const method=clean(req.body.method,30)||"Cash", reference=clean(req.body.reference,80), note=clean(req.body.note,250);
  const member=db.prepare("SELECT id FROM users WHERE id=? AND role='member'").get(memberId);
  if (!Number.isInteger(paymentId) || paymentId<1 || !member || !Number.isFinite(amount) || amount<=0 || amount>100000000 || !validMonth(month) || !validDate(date))
    return res.status(400).json({error:"Check member, amount, kisti month and payment date."});
  const info=db.prepare("UPDATE payments SET member_id=?,amount=?,kisti_month=?,paid_date=?,method=?,reference=?,note=? WHERE id=?")
    .run(memberId,amount,month,date,method,reference,note,paymentId);
  if(!info.changes) return res.status(404).json({error:"Payment not found."});
  res.json({ok:true});
});
app.delete("/api/payments/:id", auth, adminOnly, (req,res) => {
  const info=db.prepare("DELETE FROM payments WHERE id=?").run(Number(req.params.id));
  if(!info.changes) return res.status(404).json({error:"Payment not found."});
  res.json({ok:true});
});
app.get("/api/report.csv", auth, adminOnly, (req,res) => {
  const rows=db.prepare(`SELECT u.name,u.email,u.phone,p.kisti_month,p.paid_date,p.amount,p.method,p.reference,p.note
    FROM payments p JOIN users u ON u.id=p.member_id WHERE p.status='approved' ORDER BY p.paid_date DESC,p.id DESC`).all();
  const q=v=>'"'+String(v??"").replace(/"/g,'""')+'"';
  const csv=[["Member","Email","Phone","Kisti month","Paid date","Amount BDT","Method","Reference","Note"],...rows.map(r=>[r.name,r.email,r.phone,r.kisti_month,r.paid_date,r.amount,r.method,r.reference,r.note])]
    .map(row=>row.map(q).join(",")).join("\r\n");
  res.setHeader("Content-Type","text/csv; charset=utf-8");
  res.setHeader("Content-Disposition",'attachment; filename="bondhu-bitto-report.csv"');
  res.send("\ufeff"+csv);
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`BonDhu Bitto running at http://localhost:${PORT}`));
