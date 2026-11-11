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
`);
const userColumns = new Set(db.pragma("table_info(users)").map(column => column.name));
for (const [column, definition] of [
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
app.use(express.json({ limit: "6mb" }));
app.use(cookieParser());
app.use("/image", express.static(path.join(__dirname, "image")));
app.use(express.static(path.join(__dirname, "public")));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const passwordResetLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });
function auth(req, res, next) {
  const token = req.cookies.bb_session;
  if (!token) return res.status(401).json({ error: "Please sign in." });
  try {
    const payload = jwt.verify(token, SECRET);
    const user = db.prepare("SELECT id,name,email,phone,role,active FROM users WHERE id=?").get(payload.id);
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
  res.json({user:{id:user.id,name:user.name,email:user.email,role:user.role}});
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
  const profile=db.prepare("SELECT id,name,email,phone,father_name,mother_name,nominee_name,nid,nominee_nid,profile_photo,nid_photo,nominee_nid_photo,own_signature,nominee_signature FROM users WHERE id=?").get(req.user.id);
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
  const profile=db.prepare("SELECT id,name,email,phone,father_name,mother_name,nominee_name,nid,nominee_nid,profile_photo,nid_photo,nominee_nid_photo,own_signature,nominee_signature FROM users WHERE id=?").get(req.user.id);
  res.json({profile});
});

app.get("/api/dashboard", auth, (req,res) => {
  if (req.user.role === "member") {
    const total = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE member_id=?").get(req.user.id).total;
    const current = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE member_id=? AND kisti_month=?").get(req.user.id,new Date().toISOString().slice(0,7)).total;
    const members = db.prepare("SELECT COUNT(*) count FROM users WHERE role='member' AND active=1").get().count;
    const payments = db.prepare("SELECT * FROM payments WHERE member_id=? ORDER BY paid_date DESC,id DESC LIMIT 100").all(req.user.id);
    return res.json({member:true,total,current,members,payments});
  }
  const total = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments").get().total;
  const current = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE kisti_month=?").get(new Date().toISOString().slice(0,7)).total;
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
  const recent = db.prepare(`SELECT p.*,u.name member_name FROM payments p JOIN users u ON u.id=p.member_id ORDER BY p.paid_date DESC,p.id DESC LIMIT 8`).all();
  res.json({member:false,total,current,members,average:members?total/members:0,recent,profileCompletion});
});

app.get("/api/members", auth, adminOnly, (req,res) => {
  const rows = db.prepare(`SELECT u.id,u.name,u.email,u.phone,u.active,u.created_at,
    COALESCE(SUM(p.amount),0) total_saved FROM users u LEFT JOIN payments p ON p.member_id=u.id
    WHERE u.role='member' GROUP BY u.id ORDER BY u.name COLLATE NOCASE`).all();
  res.json({members:rows});
});
app.get("/api/members/:id/profile", auth, adminOnly, (req,res) => {
  const profile=db.prepare("SELECT id,name,email,phone,father_name,mother_name,nominee_name,nid,nominee_nid,profile_photo,nid_photo,nominee_nid_photo,own_signature,nominee_signature FROM users WHERE id=? AND role='member'").get(Number(req.params.id));
  if(!profile) return res.status(404).json({error:"Member not found."});
  res.json({profile});
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
    const profile=db.prepare("SELECT id,name,email,phone,father_name,mother_name,nominee_name,nid,nominee_nid,profile_photo,nid_photo,nominee_nid_photo,own_signature,nominee_signature FROM users WHERE id=?").get(memberId);
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
    const info=db.prepare("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,'member')").run(name,email,phone,hash);
    res.status(201).json({id:info.lastInsertRowid});
  } catch(e) { res.status(409).json({error:e.code==="SQLITE_CONSTRAINT_UNIQUE"?"This email is already registered.":"Could not create member."}); }
});
app.patch("/api/members/:id/status", auth, adminOnly, (req,res) => {
  const active=req.body.active ? 1 : 0;
  const info=db.prepare("UPDATE users SET active=? WHERE id=? AND role='member'").run(active,Number(req.params.id));
  if (!info.changes) return res.status(404).json({error:"Member not found."});
  res.json({ok:true});
});
app.get("/api/payments", auth, (req,res) => {
  const sql=`SELECT p.*,u.name member_name FROM payments p JOIN users u ON u.id=p.member_id`;
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
  const info=db.prepare("INSERT INTO payments(member_id,amount,kisti_month,paid_date,method,reference,note,recorded_by) VALUES(?,?,?,?,?,?,?,?)")
    .run(memberId,amount,month,date,method,reference,note,req.user.id);
  res.status(201).json({id:info.lastInsertRowid});
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
    FROM payments p JOIN users u ON u.id=p.member_id ORDER BY p.paid_date DESC,p.id DESC`).all();
  const q=v=>'"'+String(v??"").replace(/"/g,'""')+'"';
  const csv=[["Member","Email","Phone","Kisti month","Paid date","Amount BDT","Method","Reference","Note"],...rows.map(r=>[r.name,r.email,r.phone,r.kisti_month,r.paid_date,r.amount,r.method,r.reference,r.note])]
    .map(row=>row.map(q).join(",")).join("\r\n");
  res.setHeader("Content-Type","text/csv; charset=utf-8");
  res.setHeader("Content-Disposition",'attachment; filename="bondhu-bitto-report.csv"');
  res.send("\ufeff"+csv);
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`BonDhu Bitto running at http://localhost:${PORT}`));
