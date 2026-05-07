// ═══════════════════════════════════════════════════════════════
//  HordBox Railway Backend — server.js
//  Stack: Node.js + Express + PostgreSQL + JWT + bcrypt
//  Deploy to: railway.app (attach a PostgreSQL plugin)
//  Stage 4 additions: followers table, activity feed
// ═══════════════════════════════════════════════════════════════

const express    = require("express");
const cors       = require("cors");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const { Pool }   = require("pg");

const app  = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ── Middleware ──────────────────────────────────────────────────
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || "*",
  credentials: true,
}));
app.use(express.json());

// ── DB Init — run once on startup ──────────────────────────────
const initDB = async () => {
  // ── Original users table ────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id                SERIAL PRIMARY KEY,
      username          VARCHAR(50)  UNIQUE NOT NULL,
      email             VARCHAR(255) UNIQUE NOT NULL,
      password_hash     VARCHAR(255) NOT NULL,
      created_at        TIMESTAMPTZ  DEFAULT NOW(),
      avatar_char       VARCHAR(2)   DEFAULT '',
      watchlist         JSONB        DEFAULT '[]',
      watchlist_ids     JSONB        DEFAULT '[]',
      liked             JSONB        DEFAULT '[]',
      liked_ids         JSONB        DEFAULT '[]',
      ratings           JSONB        DEFAULT '{}',
      settings          JSONB        DEFAULT '{}'
    );
  `);
  // Add columns if they don't exist yet (safe to run repeatedly)
  for (const col of [
    `ADD COLUMN IF NOT EXISTS reminders         JSONB DEFAULT '{}'`,
    `ADD COLUMN IF NOT EXISTS continue_watching JSONB DEFAULT '{}'`,
    `ADD COLUMN IF NOT EXISTS search_history    JSONB DEFAULT '[]'`,
    `ADD COLUMN IF NOT EXISTS security_question VARCHAR(255) DEFAULT ''`,
    `ADD COLUMN IF NOT EXISTS security_answer_hash VARCHAR(255) DEFAULT ''`,
  ]) {
    await pool.query(`ALTER TABLE users ${col};`);
  }

  // ── Stage 4: followers table ────────────────────────────────
  // Each row = "follower_id follows followee_id"
  await pool.query(`
    CREATE TABLE IF NOT EXISTS followers (
      id           SERIAL PRIMARY KEY,
      follower_id  INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      followee_id  INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at   TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (follower_id, followee_id)
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_followers_follower ON followers(follower_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_followers_followee ON followers(followee_id);`);

  // ── Stage 4: activity table ─────────────────────────────────
  // Records user actions for the social feed.
  // action_type: 'liked' | 'watchlist' | 'rated' | 'watched'
  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity (
      id               SERIAL PRIMARY KEY,
      actor_id         INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      action_type      VARCHAR(30) NOT NULL,
      item_id          INT,
      item_title       VARCHAR(255),
      item_media_type  VARCHAR(10),
      item_poster      VARCHAR(255),
      meta             JSONB DEFAULT '{}',
      created_at       TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_activity_actor ON activity(actor_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_activity_created ON activity(created_at DESC);`);

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

// Optional auth — attaches userId if present but doesn't block the request
const optionalAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (token) {
    try { req.userId = jwt.verify(token, SECRET).userId; } catch {}
  }
  next();
};

// ── ROUTES ─────────────────────────────────────────────────────

// Health check
app.get("/", (req, res) => res.json({ status: "HordBox API running" }));

// ── POST /auth/register ─────────────────────────────────────────
app.post("/auth/register", async (req, res) => {
  const { username, email, password, security_question, security_answer } = req.body ?? {};

  if (!username?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: "username, email and password are required." });
  if (username.trim().length < 3)
    return res.status(400).json({ error: "Username must be at least 3 characters." });
  if (password.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()))
    return res.status(400).json({ error: "Please enter a valid email address." });
  if (!security_question?.trim() || !security_answer?.trim())
    return res.status(400).json({ error: "Please choose a security question and provide an answer." });
  if (security_answer.trim().length < 2)
    return res.status(400).json({ error: "Security answer must be at least 2 characters." });

  try {
    const hash       = await bcrypt.hash(password, 12);
    const answerHash = await bcrypt.hash(security_answer.trim().toLowerCase(), 12);
    const { rows } = await pool.query(
      `INSERT INTO users (username, email, password_hash, avatar_char, security_question, security_answer_hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, username, email, created_at`,
      [
        username.trim(),
        email.toLowerCase().trim(),
        hash,
        username.trim()[0].toUpperCase(),
        security_question.trim(),
        answerHash,
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
    if (!rows[0]) return res.status(401).json({ error: "Invalid email or password." });
    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid)  return res.status(401).json({ error: "Invalid email or password." });
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
  } catch {
    res.status(500).json({ error: "Failed to fetch user." });
  }
});

// ── POST /auth/get-security-question ────────────────────────────
app.post("/auth/get-security-question", async (req, res) => {
  const { email } = req.body ?? {};
  if (!email?.trim()) return res.status(400).json({ error: "Email is required." });
  try {
    const { rows } = await pool.query(
      "SELECT security_question FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );
    if (!rows[0] || !rows[0].security_question)
      return res.status(404).json({ error: "No account found with that email address." });
    res.json({ question: rows[0].security_question });
  } catch (err) {
    console.error("Get security question error:", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// ── POST /auth/reset-password ────────────────────────────────────
app.post("/auth/reset-password", async (req, res) => {
  const { email, security_answer, new_password } = req.body ?? {};
  if (!email?.trim() || !security_answer?.trim() || !new_password)
    return res.status(400).json({ error: "Email, security answer, and new password are required." });
  if (new_password.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters." });
  try {
    const { rows } = await pool.query(
      "SELECT id, security_answer_hash FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );
    if (!rows[0]) return res.status(404).json({ error: "No account found with that email address." });
    const valid = await bcrypt.compare(security_answer.trim().toLowerCase(), rows[0].security_answer_hash);
    if (!valid)  return res.status(401).json({ error: "Incorrect answer. Please try again." });
    const hash = await bcrypt.hash(new_password, 12);
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [hash, rows[0].id]);
    res.json({ success: true });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// ── GET /user/data ──────────────────────────────────────────────
app.get("/user/data", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT watchlist_ids, watchlist, liked_ids, liked,
              reminders, continue_watching, settings, search_history
       FROM users WHERE id = $1`,
      [req.userId]
    );
    if (!rows[0]) return res.status(404).json({ error: "User not found." });
    res.json({
      library: {
        watchlist_ids:     rows[0].watchlist_ids      || [],
        watchlist_items:   rows[0].watchlist          || [],
        liked_ids:         rows[0].liked_ids          || [],
        liked_items:       rows[0].liked              || [],
        continue_watching: rows[0].continue_watching  || {},
      },
      reminders:      rows[0].reminders      || {},
      settings:       rows[0].settings       || {},
      search_history: rows[0].search_history || [],
    });
  } catch (err) {
    console.error("Data fetch error:", err);
    res.status(500).json({ error: "Failed to fetch user data." });
  }
});

// ── PUT /user/sync ──────────────────────────────────────────────
app.put("/user/sync", authMiddleware, async (req, res) => {
  const {
    watchlist_ids, watchlist_items, liked_ids, liked_items,
    reminders, ratings, settings, continue_watching, search_history,
  } = req.body ?? {};
  try {
    await pool.query(
      `UPDATE users
       SET watchlist_ids     = COALESCE($1,  watchlist_ids),
           watchlist         = COALESCE($2,  watchlist),
           liked_ids         = COALESCE($3,  liked_ids),
           liked             = COALESCE($4,  liked),
           reminders         = COALESCE($5,  reminders),
           ratings           = COALESCE($6,  ratings),
           settings          = COALESCE($7,  settings),
           continue_watching = COALESCE($8,  continue_watching),
           search_history    = COALESCE($9,  search_history)
       WHERE id = $10`,
      [
        watchlist_ids     ? JSON.stringify(watchlist_ids)     : null,
        watchlist_items   ? JSON.stringify(watchlist_items)   : null,
        liked_ids         ? JSON.stringify(liked_ids)         : null,
        liked_items       ? JSON.stringify(liked_items)       : null,
        reminders         ? JSON.stringify(reminders)         : null,
        ratings           ? JSON.stringify(ratings)           : null,
        settings          ? JSON.stringify(settings)          : null,
        continue_watching ? JSON.stringify(continue_watching) : null,
        search_history    ? JSON.stringify(search_history)    : null,
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

// ════════════════════════════════════════════════════════════════
//  STAGE 4 — SOCIAL ROUTES
// ════════════════════════════════════════════════════════════════

// ── GET /users/:username — public profile ────────────────────────
// Returns public stats for any user. If the requester is logged in,
// also returns whether they are already following this user.
app.get("/users/:username", optionalAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, created_at, liked, watchlist_ids
       FROM users WHERE username = $1`,
      [req.params.username]
    );
    if (!rows[0]) return res.status(404).json({ error: "User not found." });

    const u = rows[0];

    // Follower / following counts
    const [{ rows: fwRows }, { rows: fgRows }] = await Promise.all([
      pool.query("SELECT COUNT(*) FROM followers WHERE followee_id = $1", [u.id]),
      pool.query("SELECT COUNT(*) FROM followers WHERE follower_id = $1", [u.id]),
    ]);

    // Is the current requester following this user?
    let is_following = false;
    if (req.userId && req.userId !== u.id) {
      const { rows: chk } = await pool.query(
        "SELECT 1 FROM followers WHERE follower_id = $1 AND followee_id = $2",
        [req.userId, u.id]
      );
      is_following = chk.length > 0;
    }

    // Recent liked items (last 10, public)
    const liked = u.liked || [];
    const recent_liked = liked.slice(-10).reverse();

    res.json({
      user: {
        id:              u.id,
        username:        u.username,
        created_at:      u.created_at,
        liked_count:     liked.length,
        watchlist_count: (u.watchlist_ids || []).length,
        follower_count:  parseInt(fwRows[0].count, 10),
        following_count: parseInt(fgRows[0].count, 10),
        recent_liked,
      },
      is_following,
    });
  } catch (err) {
    console.error("Public profile error:", err);
    res.status(500).json({ error: "Failed to load profile." });
  }
});

// ── POST /social/follow/:userId — follow / unfollow toggle ───────
app.post("/social/follow/:userId", authMiddleware, async (req, res) => {
  const followeeId = parseInt(req.params.userId, 10);
  if (isNaN(followeeId)) return res.status(400).json({ error: "Invalid user id." });
  if (followeeId === req.userId) return res.status(400).json({ error: "You cannot follow yourself." });

  try {
    // Check if already following
    const { rows } = await pool.query(
      "SELECT id FROM followers WHERE follower_id = $1 AND followee_id = $2",
      [req.userId, followeeId]
    );

    if (rows.length > 0) {
      // Unfollow
      await pool.query(
        "DELETE FROM followers WHERE follower_id = $1 AND followee_id = $2",
        [req.userId, followeeId]
      );
      return res.json({ following: false });
    } else {
      // Follow
      await pool.query(
        "INSERT INTO followers (follower_id, followee_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        [req.userId, followeeId]
      );
      // Log a "follow" activity (optional — could be shown in their own feed)
      await pool.query(
        `INSERT INTO activity (actor_id, action_type) VALUES ($1, 'followed')`,
        [req.userId]
      ).catch(() => {}); // non-critical
      return res.json({ following: true });
    }
  } catch (err) {
    console.error("Follow error:", err);
    res.status(500).json({ error: "Failed to update follow status." });
  }
});

// ── GET /social/followers/:userId — list followers ───────────────
app.get("/social/followers/:userId", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.created_at
       FROM followers f
       JOIN users u ON u.id = f.follower_id
       WHERE f.followee_id = $1
       ORDER BY f.created_at DESC
       LIMIT 100`,
      [req.params.userId]
    );
    res.json({ followers: rows });
  } catch {
    res.status(500).json({ error: "Failed to fetch followers." });
  }
});

// ── GET /social/following/:userId — list who this user follows ───
app.get("/social/following/:userId", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.created_at
       FROM followers f
       JOIN users u ON u.id = f.followee_id
       WHERE f.follower_id = $1
       ORDER BY f.created_at DESC
       LIMIT 100`,
      [req.params.userId]
    );
    res.json({ following: rows });
  } catch {
    res.status(500).json({ error: "Failed to fetch following list." });
  }
});

// ── GET /social/feed — activity feed ────────────────────────────
// Returns the 50 most recent activity entries from all users
// that the requesting user follows.
app.get("/social/feed", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         a.id,
         a.action_type,
         a.item_id,
         a.item_title,
         a.item_media_type,
         a.item_poster,
         a.meta,
         EXTRACT(EPOCH FROM a.created_at) * 1000  AS created_at,
         u.username  AS actor_username,
         u.id        AS actor_id
       FROM activity a
       JOIN users u ON u.id = a.actor_id
       JOIN followers f ON f.followee_id = a.actor_id
       WHERE f.follower_id = $1
         AND a.action_type IN ('liked','watchlist','rated','watched')
       ORDER BY a.created_at DESC
       LIMIT 50`,
      [req.userId]
    );
    res.json({ feed: rows });
  } catch (err) {
    console.error("Feed error:", err);
    res.status(500).json({ error: "Failed to fetch feed." });
  }
});

// ── POST /social/activity — record a user action ─────────────────
// Called by the frontend whenever a user likes, saves, or rates.
// Body: { action_type, item_id, item_title, item_media_type, item_poster, meta }
app.post("/social/activity", authMiddleware, async (req, res) => {
  const { action_type, item_id, item_title, item_media_type, item_poster, meta } = req.body ?? {};
  const ALLOWED = ["liked", "watchlist", "rated", "watched"];
  if (!ALLOWED.includes(action_type))
    return res.status(400).json({ error: "Invalid action_type." });
  try {
    await pool.query(
      `INSERT INTO activity (actor_id, action_type, item_id, item_title, item_media_type, item_poster, meta)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        req.userId,
        action_type,
        item_id   || null,
        item_title || null,
        item_media_type || null,
        item_poster || null,
        meta ? JSON.stringify(meta) : "{}",
      ]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Activity post error:", err);
    res.status(500).json({ error: "Failed to record activity." });
  }
});

// ── Start ───────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`HordBox API → http://localhost:${PORT}`)
);
