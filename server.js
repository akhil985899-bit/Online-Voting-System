require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const crypto = require("crypto");

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET to a random value at least 32 characters long in .env");
  process.exit(1);
}

const app = express();
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 250, standardHeaders: true, legacyHeaders: false }));

const { Schema } = mongoose;
const userSchema = new Schema({
  admissionNo: { type: String, unique: true, sparse: true, trim: true, uppercase: true },
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["admin", "representative", "voter"], default: "voter" },
  approved: { type: Boolean, default: false }
}, { timestamps: true });

const electionSchema = new Schema({
  title: { type: String, required: true, trim: true, maxlength: 120 },
  description: { type: String, trim: true, maxlength: 500 },
  status: { type: String, enum: ["draft", "active", "closed"], default: "draft" },
  startsAt: Date, endsAt: Date,
  startedBy: { type: Schema.Types.ObjectId, ref: "User" }
}, { timestamps: true });

const candidateSchema = new Schema({
  election: { type: Schema.Types.ObjectId, ref: "Election", required: true },
  user: { type: Schema.Types.ObjectId, ref: "User", required: true },
  manifesto: { type: String, trim: true, maxlength: 1000, default: "" },
  department: { type: String, trim: true, maxlength: 100 },
  position: { type: String, trim: true, maxlength: 100, default: "Student Representative" }
}, { timestamps: true });
candidateSchema.index({ election: 1, user: 1 }, { unique: true });

/*
  Privacy design for this student project:
  - Vote records contain election + candidate + random receipt only.
  - They do NOT contain voter ID, admission number, email, or account ID.
  - A separate VoteReceipt collection maps a voter to an election and a hash
    of a random receipt, so the system can enforce one vote per account without
    storing the selected candidate alongside the voter's identity.
  - This reduces casual access to choices, but is NOT a formally audited
    anonymous voting protocol. A real election needs independent security review.
*/
const voteSchema = new Schema({
  election: { type: Schema.Types.ObjectId, ref: "Election", required: true },
  candidate: { type: Schema.Types.ObjectId, ref: "Candidate", required: true },
  receiptHash: { type: String, required: true, unique: true }
}, { timestamps: true });
voteSchema.index({ election: 1, receiptHash: 1 });

const receiptSchema = new Schema({
  election: { type: Schema.Types.ObjectId, ref: "Election", required: true },
  voter: { type: Schema.Types.ObjectId, ref: "User", required: true },
  receiptHash: { type: String, required: true, unique: true }
}, { timestamps: true });
receiptSchema.index({ election: 1, voter: 1 }, { unique: true });

const User = mongoose.model("User", userSchema);
const Election = mongoose.model("Election", electionSchema);
const Candidate = mongoose.model("Candidate", candidateSchema);
const Vote = mongoose.model("Vote", voteSchema);
const VoteReceipt = mongoose.model("VoteReceipt", receiptSchema);

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const emailOf = x => String(x || "").trim().toLowerCase();
const safeUser = u => ({ id: u._id, name: u.name, email: u.email, admissionNo: u.admissionNo, role: u.role, approved: u.approved });
const hashReceipt = receipt => crypto.createHash("sha256").update(receipt).digest("hex");

function setSession(res, user) {
  const token = jwt.sign({ sub: String(user._id) }, process.env.JWT_SECRET, { expiresIn: "8h" });
  res.cookie("campus_token", token, {
    httpOnly: true, sameSite: "strict",
    secure: process.env.NODE_ENV === "production", maxAge: 8 * 60 * 60 * 1000
  });
}
const auth = asyncRoute(async (req, res, next) => {
  try {
    if (!req.cookies.campus_token) return res.status(401).json({ error: "Please sign in first." });
    const payload = jwt.verify(req.cookies.campus_token, process.env.JWT_SECRET);
    req.user = await User.findById(payload.sub);
    if (!req.user) return res.status(401).json({ error: "Account not found." });
    next();
  } catch {
    return res.status(401).json({ error: "Session expired. Please sign in again." });
  }
});
const allow = (...roles) => (req, res, next) =>
  req.user && roles.includes(req.user.role) ? next() : res.status(403).json({ error: "You do not have permission to do that." });

async function seedAdmin() {
  const email = emailOf(process.env.ADMIN_EMAIL);
  const password = process.env.ADMIN_PASSWORD || "";
  if (!email || password.length < 12) {
    console.warn("Set ADMIN_EMAIL and ADMIN_PASSWORD (12+ characters) in .env to create the admin account.");
    return;
  }
  if (!(await User.findOne({ email }))) {
    await User.create({
      name: process.env.ADMIN_NAME || "Administrator", email,
      passwordHash: await bcrypt.hash(password, 12), role: "admin", approved: true
    });
    console.log("Initial admin account created:", email);
  }
}

app.get("/api/health", (req, res) => res.json({ ok: true, service: "CampusVote" }));

// Registration has no OTP. Admin approval is required before voting.
app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const admissionNo = String(req.body.admissionNo || "").trim().toUpperCase();
  const email = emailOf(req.body.email);
  const password = String(req.body.password || "");
  if (name.length < 2 || !/^[A-Z0-9/-]{3,30}$/.test(admissionNo) ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8) {
    return res.status(400).json({ error: "Enter your name, valid admission number, email, and password of at least 8 characters." });
  }
  const domains = (process.env.ALLOWED_EMAIL_DOMAINS || "").split(",").map(x => x.trim().toLowerCase()).filter(Boolean);
  if (domains.length && !domains.some(d => email.endsWith("@" + d))) {
    return res.status(400).json({ error: "Use your official college email address." });
  }
  if (await User.findOne({ $or: [{ email }, { admissionNo }] })) {
    return res.status(409).json({ error: "This email or admission number is already registered." });
  }
  const user = await User.create({
    name, admissionNo, email, passwordHash: await bcrypt.hash(password, 12),
    role: "voter", approved: false
  });
  res.status(201).json({ message: "Registration complete. Wait for admin approval before voting.", user: safeUser(user) });
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const user = await User.findOne({ email: emailOf(req.body.email) });
  if (!user || !(await bcrypt.compare(String(req.body.password || ""), user.passwordHash))) {
    return res.status(401).json({ error: "Invalid email or password." });
  }
  setSession(res, user);
  res.json({ user: safeUser(user) });
}));
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("campus_token", { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production" });
  res.json({ message: "Signed out." });
});
app.get("/api/auth/me", auth, (req, res) => res.json({ user: safeUser(req.user) }));

app.get("/api/elections", asyncRoute(async (req, res) =>
  res.json({ elections: await Election.find().sort({ createdAt: -1 }).lean() })));

app.post("/api/admin/elections", auth, allow("admin"), asyncRoute(async (req, res) => {
  const title = String(req.body.title || "").trim();
  if (title.length < 3) return res.status(400).json({ error: "Election title must be at least 3 characters." });
  const election = await Election.create({ title, description: String(req.body.description || "").trim() });
  res.status(201).json({ election });
}));
app.post("/api/admin/elections/:id/start", auth, allow("admin"), asyncRoute(async (req, res) => {
  const election = await Election.findById(req.params.id);
  if (!election) return res.status(404).json({ error: "Election not found." });
  if (election.status !== "draft") return res.status(400).json({ error: "Only draft elections can be started." });
  if (!(await Candidate.exists({ election: election._id }))) return res.status(400).json({ error: "Add at least one candidate before starting." });
  election.status = "active"; election.startedBy = req.user._id; election.startsAt = new Date();
  await election.save();
  res.json({ election });
}));
app.post("/api/admin/elections/:id/close", auth, allow("admin"), asyncRoute(async (req, res) => {
  const election = await Election.findOneAndUpdate(
    { _id: req.params.id, status: "active" }, { status: "closed", endsAt: new Date() }, { new: true }
  );
  if (!election) return res.status(404).json({ error: "Active election not found." });
  res.json({ election });
}));
app.get("/api/admin/users/pending", auth, allow("admin"), asyncRoute(async (req, res) => {
  const users = await User.find({ role: "voter", approved: false })
    .select("name email admissionNo createdAt").sort({ createdAt: 1 }).lean();
  res.json({ users });
}));
app.post("/api/admin/users/:id/approve", auth, allow("admin"), asyncRoute(async (req, res) => {
  const user = await User.findOneAndUpdate({ _id: req.params.id, role: "voter" }, { approved: true }, { new: true });
  if (!user) return res.status(404).json({ error: "Student account not found." });
  res.json({ user: safeUser(user) });
}));
app.post("/api/admin/users/:id/representative", auth, allow("admin"), asyncRoute(async (req, res) => {
  const user = await User.findOneAndUpdate(
    { _id: req.params.id, role: { $in: ["voter", "representative"] } },
    { role: "representative", approved: true }, { new: true }
  );
  if (!user) return res.status(404).json({ error: "Student account not found." });
  res.json({ user: safeUser(user) });
}));

// Admin can directly add an approved representative to a draft election.
app.get("/api/admin/representatives", auth, allow("admin"), asyncRoute(async (req, res) => {
  const users = await User.find({ role: "representative", approved: true })
    .select("name email admissionNo").sort({ name: 1 }).lean();
  res.json({ representatives: users.map(u => ({ id: u._id, name: u.name, email: u.email, admissionNo: u.admissionNo })) });
}));
app.post("/api/admin/elections/:id/candidates", auth, allow("admin"), asyncRoute(async (req, res) => {
  const election = await Election.findById(req.params.id);
  if (!election) return res.status(404).json({ error: "Election not found." });
  if (election.status !== "draft") return res.status(400).json({ error: "Representatives can only be added before voting starts. Close and recreate the election if the candidate list must change after voting has opened." });
  const user = await User.findOne({ _id: req.body.userId, role: "representative", approved: true });
  if (!user) return res.status(400).json({ error: "Choose an approved representative account first. Use Make representative in the admin dashboard." });
  if (await Candidate.exists({ election: election._id, user: user._id })) return res.status(409).json({ error: "This representative is already added to this election." });
  const candidate = await Candidate.create({
    election: election._id, user: user._id,
    position: String(req.body.position || "Student Representative").trim().slice(0, 100),
    department: String(req.body.department || "").trim().slice(0, 100),
    manifesto: String(req.body.manifesto || "").trim().slice(0, 1000)
  });
  res.status(201).json({ candidate: { id: candidate._id, name: user.name, position: candidate.position, department: candidate.department, manifesto: candidate.manifesto } });
}));

// Candidate application: one candidate profile per account and election.
app.post("/api/representative/apply", auth, allow("representative"), asyncRoute(async (req, res) => {
  const election = await Election.findById(req.body.electionId);
  if (!election || election.status !== "draft") return res.status(400).json({ error: "Applications are only allowed before the election starts." });
  if (await Candidate.exists({ election: election._id, user: req.user._id })) {
    return res.status(409).json({ error: "You have already applied to this election." });
  }
  const candidate = await Candidate.create({
    election: election._id, user: req.user._id,
    manifesto: String(req.body.manifesto || "").slice(0, 1000),
    department: String(req.body.department || "").slice(0, 100),
    position: String(req.body.position || "Student Representative").slice(0, 100)
  });
  res.status(201).json({ candidate });
}));
app.get("/api/elections/:id/candidates", asyncRoute(async (req, res) => {
  const candidates = await Candidate.find({ election: req.params.id }).populate("user", "name").lean();
  res.json({ candidates: candidates.map(c => ({
    id: c._id, name: c.user.name, position: c.position,
    department: c.department, manifesto: c.manifesto
  })) });
}));

// Vote and identity receipt are written separately; unique index enforces one vote per voter/election.
app.post("/api/vote/submit", auth, allow("voter"), asyncRoute(async (req, res) => {
  if (!req.user.approved) return res.status(403).json({ error: "Your student account is awaiting admin approval." });
  const election = await Election.findOne({ _id: req.body.electionId, status: "active" });
  if (!election) return res.status(400).json({ error: "This election is not active." });
  const candidate = await Candidate.findOne({ _id: req.body.candidateId, election: election._id });
  if (!candidate) return res.status(400).json({ error: "Choose a valid candidate for this election." });

  const receipt = crypto.randomBytes(32).toString("hex");
  const receiptHash = hashReceipt(receipt);
  // Separate writes; for production use a MongoDB transaction on a replica set.
  try {
    await VoteReceipt.create({ election: election._id, voter: req.user._id, receiptHash });
    await Vote.create({ election: election._id, candidate: candidate._id, receiptHash });
  } catch (err) {
    await VoteReceipt.deleteOne({ election: election._id, voter: req.user._id, receiptHash }).catch(() => {});
    if (err.code === 11000) return res.status(409).json({ error: "You have already voted in this election." });
    throw err;
  }
  res.json({ message: "Your vote has been recorded. Your identity is not stored in the vote record." });
}));

// Admin-only results, and only after closing the election.
app.get("/api/admin/elections/:id/results", auth, allow("admin"), asyncRoute(async (req, res) => {
  const election = await Election.findById(req.params.id).lean();
  if (!election) return res.status(404).json({ error: "Election not found." });
  if (election.status !== "closed") return res.status(400).json({ error: "Results are available only after the election is closed." });
  const candidates = await Candidate.find({ election: election._id }).populate("user", "name").lean();
  const counts = await Vote.aggregate([
    { $match: { election: election._id } },
    { $group: { _id: "$candidate", votes: { $sum: 1 } } }
  ]);
  const countMap = new Map(counts.map(x => [String(x._id), x.votes]));
  res.json({ election, results: candidates.map(c => ({
    candidateId: c._id, name: c.user.name, position: c.position,
    department: c.department, votes: countMap.get(String(c._id)) || 0
  })).sort((a, b) => b.votes - a.votes) });
}));

app.use("/api", (req, res) => res.status(404).json({ error: "API endpoint not found." }));
app.use((err, req, res, next) => {
  console.error(err);
  if (err.code === 11000) return res.status(409).json({ error: "This record already exists." });
  if (err.name === "CastError") return res.status(400).json({ error: "Invalid record ID." });
  res.status(500).json({ error: "Something went wrong. Check the server terminal." });
});

const port = Number(process.env.PORT || 3000);
mongoose.connect(process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/campusvote")
  .then(async () => {
    console.log("Connected to MongoDB");
    await seedAdmin();
    app.listen(port, () => console.log(`CampusVote running at http://localhost:${port}`));
  })
  .catch(err => { console.error("MongoDB connection failed:", err.message); process.exit(1); });
