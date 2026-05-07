// ═══════════════════════════════════════════════════════════════
//  HordBox Railway Backend — server.js
//  Stack: Node.js + Express + PostgreSQL + JWT + bcrypt
//  Deploy to: railway.app (attach a PostgreSQL plugin)
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id                    SERIAL PRIMARY KEY,
      username              VARCHAR(50)  UNIQUE NOT NULL,
      email                 VARCHAR(255) UNIQUE NOT NULL,
      password_hash         VARCHAR(255) NOT NULL,
      created_at            TIMESTAMPTZ  DEFAULT NOW(),
      avatar_char           VARCHAR(2)   DEFAULT '',
      watchlist             JSONB        DEFAULT '[]',
      watchlist_ids         JSONB        DEFAULT '[]',
      liked                 JSONB        DEFAULT '[]',
      liked_ids             JSONB        DEFAULT '[]',
      ratings               JSONB        DEFAULT '{}',
      settings              JSONB        DEFAULT '{}'
    );
  `);

  // Safe incremental column additions
  const alterCols = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS reminders              JSONB   DEFAULT '{}'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS continue_watching      JSONB   DEFAULT '{}'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS search_history         JSONB   DEFAULT '[]'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS security_question_1       VARCHAR(255) DEFAULT ''`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS security_answer_hash_1    VARCHAR(255) DEFAULT ''`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS security_question_2       VARCHAR(255) DEFAULT ''`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS security_answer_hash_2    VARCHAR(255) DEFAULT ''`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS bio                    TEXT    DEFAULT ''`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_public              BOOLEAN DEFAULT TRUE`,
  ];
  for (const q of alterCols) await pool.query(q).catch(() => {});

  // ── Social: followers ───────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS followers (
      follower_id   INT REFERENCES users(id) ON DELETE CASCADE,
      following_id  INT REFERENCES users(id) ON DELETE CASCADE,
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (follower_id, following_id)
    );
  `);

  // ── Social: activity feed ───────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity (
      id           SERIAL PRIMARY KEY,
      user_id      INT REFERENCES users(id) ON DELETE CASCADE,
      type         VARCHAR(30) NOT NULL,
      item_id      INT,
      item_title   VARCHAR(255),
      item_poster  VARCHAR(255),
      media_type   VARCHAR(10),
      rating       INT,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_activity_user      ON activity(user_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_activity_created   ON activity(created_at DESC);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_followers_follower  ON followers(follower_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_followers_following ON followers(following_id);`);

  console.log("✓ DB ready (incl. social tables + dual security questions)");
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

// ── Helper: safely serialize a value for JSONB ──────────────────
// Fixes the core data-loss bug: empty arrays [] and empty objects {}
// are falsy in JS, so the old "value ? JSON.stringify(value) : null"
// pattern sent null for empty collections, causing COALESCE to keep
// stale data instead of saving the intended empty state.
const toJson = (v) => (v !== undefined && v !== null ? JSON.stringify(v) : null);

// ── ROUTES ─────────────────────────────────────────────────────

// Health check
app.get("/", (req, res) => res.json({ status: "HordBox API running" }));

// ── POST /auth/register ─────────────────────────────────────────
app.post("/auth/register", async (req, res) => {
  const {
    username,
    email,
    password,
    security_question_1,
    security_answer_1,
    security_question_2,
    security_answer_2,
  } = req.body ?? {};

  if (!username?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: "username, email and password are required." });

  if (username.trim().length < 3)
    return res.status(400).json({ error: "Username must be at least 3 characters." });

  if (password.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters." });

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()))
    return res.status(400).json({ error: "Please enter a valid email address." });

  if (!security_question_1?.trim() || !security_answer_1?.trim())
    return res.status(400).json({ error: "Please choose a security question and provide an answer." });

  if (security_answer_1.trim().length < 2)
    return res.status(400).json({ error: "Security answer 1 must be at least 2 characters." });

  if (!security_question_2?.trim() || !security_answer_2?.trim())
    return res.status(400).json({ error: "Please choose a second security question and provide an answer." });

  if (security_answer_2.trim().length < 2)
    return res.status(400).json({ error: "Security answer 2 must be at least 2 characters." });

  if (security_question_1.trim() === security_question_2.trim())
    return res.status(400).json({ error: "Please choose two different security questions." });

  try {
    const hash        = await bcrypt.hash(password, 12);
    const answerHash1 = await bcrypt.hash(security_answer_1.trim().toLowerCase(), 12);
    const answerHash2 = await bcrypt.hash(security_answer_2.trim().toLowerCase(), 12);

    const { rows } = await pool.query(
      `INSERT INTO users (
         username, email, password_hash, avatar_char,
         security_question_1, security_answer_hash_1,
         security_question_2, security_answer_hash_2
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, username, email, created_at`,
      [
        username.trim(),
        email.toLowerCase().trim(),
        hash,
        username.trim()[0].toUpperCase(),
        security_question_1.trim(),
        answerHash1,
        security_question_2.trim(),
        answerHash2,
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

// ── POST /auth/get-security-question ────────────────────────────
app.post("/auth/get-security-question", async (req, res) => {
  const { email } = req.body ?? {};
  if (!email?.trim())
    return res.status(400).json({ error: "Email is required." });

  try {
    const { rows } = await pool.query(
      "SELECT security_question_1, security_question_2 FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );

    if (!rows[0] || (!rows[0].security_question_1 && !rows[0].security_question_2))
      return res.status(404).json({ error: "No account found with that email address." });

    res.json({
      question_1: rows[0].security_question_1 || "",
      question_2: rows[0].security_question_2 || "",
    });
  } catch (err) {
    console.error("Get security question error:", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// ── POST /auth/reset-password ────────────────────────────────────
app.post("/auth/reset-password", async (req, res) => {
  const { email, security_answer_1, security_answer_2, new_password } = req.body ?? {};

  if (!email?.trim() || !security_answer_1?.trim() || !security_answer_2?.trim() || !new_password)
    return res.status(400).json({ error: "Email, both security answers, and a new password are required." });

  if (new_password.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters." });

  try {
    const { rows } = await pool.query(
      "SELECT id, security_answer_hash_1, security_answer_hash_2 FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );

    if (!rows[0])
      return res.status(404).json({ error: "No account found with that email address." });

    const valid1 = await bcrypt.compare(
      security_answer_1.trim().toLowerCase(),
      rows[0].security_answer_hash_1
    );
    if (!valid1)
      return res.status(401).json({ error: "Incorrect answer to question 1. Please try again." });

    const valid2 = await bcrypt.compare(
      security_answer_2.trim().toLowerCase(),
      rows[0].security_answer_hash_2
    );
    if (!valid2)
      return res.status(401).json({ error: "Incorrect answer to question 2. Please try again." });

    const hash = await bcrypt.hash(new_password, 12);
    await pool.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [hash, rows[0].id]
    );

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
// FIX: replaced "value ? JSON.stringify(value) : null" with toJson(value)
// so that empty arrays [] and empty objects {} are saved correctly instead
// of being treated as falsy and falling through to COALESCE's fallback,
// which was silently keeping stale data on the backend.
app.put("/user/sync", authMiddleware, async (req, res) => {
  const {
    watchlist_ids, watchlist_items, liked_ids, liked_items,
    reminders, ratings, settings, continue_watching, search_history,
  } = req.body ?? {};

  try {
    await pool.query(
      `UPDATE users
       SET watchlist_ids     = COALESCE($1::jsonb,  watchlist_ids),
           watchlist         = COALESCE($2::jsonb,  watchlist),
           liked_ids         = COALESCE($3::jsonb,  liked_ids),
           liked             = COALESCE($4::jsonb,  liked),
           reminders         = COALESCE($5::jsonb,  reminders),
           ratings           = COALESCE($6::jsonb,  ratings),
           settings          = COALESCE($7::jsonb,  settings),
           continue_watching = COALESCE($8::jsonb,  continue_watching),
           search_history    = COALESCE($9::jsonb,  search_history)
       WHERE id = $10`,
      [
        toJson(watchlist_ids),
        toJson(watchlist_items),
        toJson(liked_ids),
        toJson(liked_items),
        toJson(reminders),
        toJson(ratings),
        toJson(settings),
        toJson(continue_watching),
        toJson(search_history),
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
// SOCIAL ROUTES
// ════════════════════════════════════════════════════════════════

// ── GET /users/search?q=username ────────────────────────────────
app.get("/users/search", authMiddleware, async (req, res) => {
  const q = (req.query.q || "").trim();
  if (q.length < 2)
    return res.status(400).json({ error: "Search query must be at least 2 characters." });

  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.avatar_char, u.created_at,
              (SELECT COUNT(*) FROM followers WHERE following_id = u.id)::INT AS followers_count,
              EXISTS(SELECT 1 FROM followers WHERE follower_id = $2 AND following_id = u.id) AS you_follow
       FROM users u
       WHERE u.username ILIKE $1 AND u.id != $2
       LIMIT 20`,
      [`%${q}%`, req.userId]
    );
    res.json({ users: rows });
  } catch (err) {
    console.error("User search error:", err);
    res.status(500).json({ error: "Search failed." });
  }
});

// ── GET /users/:username ─────────────────────────────────────────
app.get("/users/:username", async (req, res) => {
  const { username } = req.params;
  let viewerId = null;
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (token) viewerId = jwt.verify(token, SECRET).userId;
  } catch {}

  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.avatar_char, u.created_at, u.bio,
              (SELECT COUNT(*) FROM followers WHERE following_id = u.id)::INT  AS followers_count,
              (SELECT COUNT(*) FROM followers WHERE follower_id  = u.id)::INT  AS following_count,
              COALESCE(jsonb_array_length(u.liked_ids), 0)     AS liked_count,
              COALESCE(jsonb_array_length(u.watchlist_ids), 0) AS watchlist_count,
              CASE WHEN $2::INT IS NOT NULL
                THEN EXISTS(SELECT 1 FROM followers WHERE follower_id=$2 AND following_id=u.id)
                ELSE FALSE
              END AS you_follow
       FROM users u
       WHERE u.username = $1`,
      [username, viewerId]
    );
    if (!rows[0]) return res.status(404).json({ error: "User not found." });
    res.json(rows[0]);
  } catch (err) {
    console.error("Public profile error:", err);
    res.status(500).json({ error: "Failed to fetch profile." });
  }
});

// ── POST /social/follow/:userId ──────────────────────────────────
app.post("/social/follow/:userId", authMiddleware, async (req, res) => {
  const followingId = parseInt(req.params.userId);
  if (isNaN(followingId) || followingId === req.userId)
    return res.status(400).json({ error: "Invalid target user." });

  try {
    await pool.query(
      "INSERT INTO followers (follower_id, following_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [req.userId, followingId]
    );
    res.json({ success: true, action: "followed" });
  } catch (err) {
    console.error("Follow error:", err);
    res.status(500).json({ error: "Failed to follow user." });
  }
});

// ── DELETE /social/follow/:userId ────────────────────────────────
app.delete("/social/follow/:userId", authMiddleware, async (req, res) => {
  const followingId = parseInt(req.params.userId);
  if (isNaN(followingId))
    return res.status(400).json({ error: "Invalid target user." });

  try {
    await pool.query(
      "DELETE FROM followers WHERE follower_id = $1 AND following_id = $2",
      [req.userId, followingId]
    );
    res.json({ success: true, action: "unfollowed" });
  } catch (err) {
    console.error("Unfollow error:", err);
    res.status(500).json({ error: "Failed to unfollow user." });
  }
});

// ── GET /social/status/:userId ───────────────────────────────────
app.get("/social/status/:userId", authMiddleware, async (req, res) => {
  const targetId = parseInt(req.params.userId);
  try {
    const { rows } = await pool.query(
      "SELECT 1 FROM followers WHERE follower_id = $1 AND following_id = $2",
      [req.userId, targetId]
    );
    res.json({ following: rows.length > 0 });
  } catch {
    res.status(500).json({ error: "Failed to check follow status." });
  }
});

// ── GET /social/followers ────────────────────────────────────────
app.get("/social/followers", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.avatar_char, f.created_at AS followed_at,
              EXISTS(SELECT 1 FROM followers WHERE follower_id=$1 AND following_id=u.id) AS you_follow
       FROM followers f
       JOIN users u ON f.follower_id = u.id
       WHERE f.following_id = $1
       ORDER BY f.created_at DESC`,
      [req.userId]
    );
    res.json({ followers: rows });
  } catch (err) {
    console.error("Followers error:", err);
    res.status(500).json({ error: "Failed to fetch followers." });
  }
});

// ── GET /social/following ────────────────────────────────────────
app.get("/social/following", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.avatar_char, f.created_at AS followed_at
       FROM followers f
       JOIN users u ON f.following_id = u.id
       WHERE f.follower_id = $1
       ORDER BY f.created_at DESC`,
      [req.userId]
    );
    res.json({ following: rows });
  } catch (err) {
    console.error("Following error:", err);
    res.status(500).json({ error: "Failed to fetch following list." });
  }
});

// ── GET /social/feed ─────────────────────────────────────────────
app.get("/social/feed", authMiddleware, async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit  || "50"), 100);
  const offset = parseInt(req.query.offset || "0");

  try {
    const { rows } = await pool.query(
      `SELECT a.id, a.type, a.item_id, a.item_title, a.item_poster,
              a.media_type, a.rating, a.created_at,
              u.username, u.avatar_char
       FROM activity a
       JOIN users u ON a.user_id = u.id
       WHERE a.user_id IN (
         SELECT following_id FROM followers WHERE follower_id = $1
       )
       ORDER BY a.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.userId, limit, offset]
    );
    res.json({ feed: rows, hasMore: rows.length === limit });
  } catch (err) {
    console.error("Feed error:", err);
    res.status(500).json({ error: "Failed to fetch feed." });
  }
});

// ── POST /social/activity ────────────────────────────────────────
app.post("/social/activity", authMiddleware, async (req, res) => {
  const { type, item_id, item_title, item_poster, media_type, rating } = req.body ?? {};

  const VALID_TYPES = ["liked", "watchlisted", "rated", "watched", "unliked", "removed_watchlist"];
  if (!type || !VALID_TYPES.includes(type))
    return res.status(400).json({ error: "Invalid activity type." });

  try {
    const positiveTypes = ["liked", "watchlisted", "rated", "watched"];
    if (!positiveTypes.includes(type)) {
      if (item_id) {
        const reverseType = type === "unliked" ? "liked" : "watchlisted";
        await pool.query(
          "DELETE FROM activity WHERE user_id=$1 AND type=$2 AND item_id=$3",
          [req.userId, reverseType, item_id]
        );
      }
      return res.json({ success: true });
    }

    await pool.query(
      `INSERT INTO activity (user_id, type, item_id, item_title, item_poster, media_type, rating)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT DO NOTHING`,
      [req.userId, type, item_id || null, item_title || null, item_poster || null, media_type || null, rating || null]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Activity log error:", err);
    res.status(500).json({ error: "Failed to log activity." });
  }
});

// Deduplicate activity rows
pool.query(`
  CREATE UNIQUE INDEX IF NOT EXISTS idx_activity_dedup
  ON activity (user_id, type, item_id)
  WHERE item_id IS NOT NULL
`).catch(() => {});

// ── PUT /auth/change-password ───────────────────────────────────
app.put("/auth/change-password", authMiddleware, async (req, res) => {
  const { current_password, new_password } = req.body ?? {};

  if (!current_password || !new_password)
    return res.status(400).json({ error: "Current and new password are required." });

  if (new_password.length < 8)
    return res.status(400).json({ error: "New password must be at least 8 characters." });

  try {
    const { rows } = await pool.query(
      "SELECT password_hash FROM users WHERE id = $1",
      [req.userId]
    );
    if (!rows[0]) return res.status(404).json({ error: "User not found." });

    const valid = await bcrypt.compare(current_password, rows[0].password_hash);
    if (!valid)
      return res.status(401).json({ error: "Current password is incorrect." });

    // ── FIX: block same password on the backend too ─────────────
    const same = await bcrypt.compare(new_password, rows[0].password_hash);
    if (same)
      return res.status(400).json({ error: "New password must be different from your current password." });

    const hash = await bcrypt.hash(new_password, 12);
    await pool.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [hash, req.userId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ error: "Failed to change password." });
  }
});

// ── PUT /auth/change-profile ────────────────────────────────────
app.put("/auth/change-profile", authMiddleware, async (req, res) => {
  const { username, email, password } = req.body ?? {};

  if (!username?.trim() || username.trim().length < 3)
    return res.status(400).json({ error: "Username must be at least 3 characters." });

  if (!email?.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()))
    return res.status(400).json({ error: "Please enter a valid email address." });

  if (!password)
    return res.status(400).json({ error: "Current password is required to confirm changes." });

  try {
    const { rows } = await pool.query(
      "SELECT username, email, password_hash FROM users WHERE id = $1",
      [req.userId]
    );
    if (!rows[0]) return res.status(404).json({ error: "User not found." });

    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid)
      return res.status(401).json({ error: "Password is incorrect." });

    // ── FIX: block identical profile update on the backend too ──
    if (
      username.trim() === rows[0].username &&
      email.trim().toLowerCase() === rows[0].email
    ) {
      return res.status(400).json({ error: "No changes detected. Please update your username or email before saving." });
    }

    const { rows: updated } = await pool.query(
      `UPDATE users
       SET username = $1, email = $2
       WHERE id = $3
       RETURNING id, username, email`,
      [username.trim(), email.trim().toLowerCase(), req.userId]
    );

    res.json({ success: true, user: updated[0] });
  } catch (err) {
    if (err.code === "23505") {
      const field = err.detail?.includes("email") ? "email" : "username";
      return res.status(409).json({
        error: field === "email"
          ? "That email is already in use."
          : "That username is already taken.",
      });
    }
    console.error("Change profile error:", err);
    res.status(500).json({ error: "Failed to update profile." });
  }
});

// ── Start ───────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`HordBox API → http://localhost:${PORT}`)
);
