// ═══════════════════════════════════════════════════════════════
//  HordBox Railway Backend — server.js
//  Stack: Node.js + Express + PostgreSQL + JWT + bcrypt
//  Deploy to: railway.app (attach a PostgreSQL plugin)
// ═══════════════════════════════════════════════════════════════

const express  = require("express");
const cors     = require("cors");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const { Pool } = require("pg");

const app  = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ── Middleware ──────────────────────────────────────────────────
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || "*",   // set your Vercel/Netlify URL
  credentials: true,
}));
app.use(express.json());

// ── DB Init — run once on startup ──────────────────────────────
const initDB = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      VARCHAR(50)  UNIQUE NOT NULL,
      email         VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at    TIMESTAMPTZ  DEFAULT NOW(),
      avatar_char   VARCHAR(2)   DEFAULT '',
      watchlist     JSONB        DEFAULT '[]',
      watchlist_ids JSONB        DEFAULT '[]',
      liked         JSONB        DEFAULT '[]',
      liked_ids     JSONB        DEFAULT '[]',
      ratings       JSONB        DEFAULT '{}',
      settings      JSONB        DEFAULT '{}'
    );
  `);
  console.log("✓ DB ready");
};
initDB().catch(console.error);

// ── JWT helpers ─────────────────────────────────────────────────
const SECRET = process.env.JWT_SECRET || "dev-secret-change-in-production";

const signToken = (userId) =>
  jwt.sign({ userId }, SECRET, { expiresIn: "30d" });

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.userId = jwt.verify(token, SECRET).userId;
    next();
  } catch {
    res.status(401).json({ error: "Token invalid or expired" });
  }
};

// ── ROUTES ─────────────────────────────────────────────────────

// Health check
app.get("/", (req, res) => res.json({ status: "HordBox API running" }));

// ── POST /auth/register ─────────────────────────────────────────
app.post("/auth/register", async (req, res) => {
  const { username, email, password } = req.body ?? {};

  if (!username?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: "username, email and password are required." });

  if (username.trim().length < 3)
    return res.status(400).json({ error: "Username must be at least 3 characters." });

  if (password.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters." });

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()))
    return res.status(400).json({ error: "Please enter a valid email address." });

  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      `INSERT INTO users (username, email, password_hash, avatar_char)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, email, created_at`,
      [
        username.trim(),
        email.toLowerCase().trim(),
        hash,
        username.trim()[0].toUpperCase(),
      ]
    );

    const token = signToken(rows[0].id);
    res.status(201).json({ token, user: rows[0] });

  } catch (err) {
    if (err.code === "23505") {
      const field = err.detail?.includes("email") ? "email" : "username";
      return res.status(409).json({
        error: field === "email"
          ? "This email address is already registered."
          : "That username is already taken.",
      });
    }
    console.error("Register error:", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// ── POST /auth/login ────────────────────────────────────────────
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};

  if (!email?.trim() || !password)
    return res.status(400).json({ error: "Email and password are required." });

  try {
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );

    if (!rows[0])
      return res.status(401).json({ error: "Invalid email or password." });

    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid)
      return res.status(401).json({ error: "Invalid email or password." });

    const { password_hash, ...user } = rows[0];
    const token = signToken(user.id);
    res.json({ token, user });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// ── GET /auth/me ────────────────────────────────────────────────
app.get("/auth/me", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, email, created_at, avatar_char,
              watchlist_ids, liked_ids, ratings, settings
       FROM users WHERE id = $1`,
      [req.userId]
    );
    if (!rows[0]) return res.status(404).json({ error: "User not found." });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch user." });
  }
});

// ── PUT /user/sync ──────────────────────────────────────────────
// Call this from the frontend to persist watchlist/liked/ratings
app.put("/user/sync", authMiddleware, async (req, res) => {
  const { watchlist_ids, liked_ids, ratings, settings } = req.body ?? {};
  try {
    await pool.query(
      `UPDATE users
       SET watchlist_ids = COALESCE($1, watchlist_ids),
           liked_ids     = COALESCE($2, liked_ids),
           ratings       = COALESCE($3, ratings),
           settings      = COALESCE($4, settings)
       WHERE id = $5`,
      [
        watchlist_ids ? JSON.stringify(watchlist_ids) : null,
        liked_ids     ? JSON.stringify(liked_ids)     : null,
        ratings       ? JSON.stringify(ratings)       : null,
        settings      ? JSON.stringify(settings)      : null,
        req.userId,
      ]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Sync error:", err);
    res.status(500).json({ error: "Sync failed." });
  }
});

// ── DELETE /auth/account ────────────────────────────────────────
app.delete("/auth/account", authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id = $1", [req.userId]);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Could not delete account." });
  }
});

// ── Start ───────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`HordBox API → http://localhost:${PORT}`)
);
