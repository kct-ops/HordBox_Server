// ═══════════════════════════════════════════════════════════════
//  HordBox Railway Backend — server.js
//  Stack: Node.js + Express + PostgreSQL + JWT + bcrypt
//  Deploy to: railway.app (attach a PostgreSQL plugin)
// ═══════════════════════════════════════════════════════════════

const express  = require("express");
const cors     = require("cors");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const cron     = require("node-cron"); // ✅ NEW: npm install node-cron
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
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS reminders         JSONB DEFAULT '{}';
  `);
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS continue_watching JSONB DEFAULT '{}';
  `);
  // ✅ NEW: search history column
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS search_history    JSONB DEFAULT '[]';
  `);
  // ✅ NEW: global app cache table (stores upcoming movie IDs, refreshed daily)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_cache (
      key        VARCHAR(100) PRIMARY KEY,
      value      JSONB        NOT NULL,
      updated_at TIMESTAMPTZ  DEFAULT NOW()
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

// ── UPCOMING IDS — fetch from TMDB and cache ────────────────────
// ✅ NEW: Hits TMDB /movie/upcoming pages 1–5, keeps only future-dated
// movie IDs, and upserts into app_cache. Called on startup + daily cron.
// Requires TMDB_KEY env var on Railway (same key used in the frontend).
const refreshUpcomingIds = async () => {
  const TMDB_KEY = process.env.TMDB_KEY;
  if (!TMDB_KEY) {
    console.warn("⚠  TMDB_KEY not set — skipping upcoming IDs refresh");
    return null;
  }
  try {
    const today  = new Date().toISOString().split("T")[0];
    let   allIds = [];

    for (let page = 1; page <= 5; page++) {
      const url = new URL("https://api.themoviedb.org/3/movie/upcoming");
      url.searchParams.set("api_key", TMDB_KEY);
      url.searchParams.set("region",  "US");
      url.searchParams.set("page",    page);

      const res  = await fetch(url.toString());
      if (!res.ok) break;

      const data = await res.json();
      const ids  = (data.results || [])
        .filter(m => m.release_date && m.release_date > today)
        .map(m => m.id);

      allIds = [...allIds, ...ids];
      if (page >= (data.total_pages || 1)) break;
    }

    const unique = [...new Set(allIds)];

    await pool.query(
      `INSERT INTO app_cache (key, value, updated_at)
       VALUES ('upcoming_ids', $1, NOW())
       ON CONFLICT (key) DO UPDATE
         SET value = $1, updated_at = NOW()`,
      [JSON.stringify(unique)]
    );

    console.log(`✓ upcoming_ids refreshed — ${unique.length} IDs`);
    return unique;
  } catch (err) {
    console.error("upcoming_ids refresh failed:", err);
    return null;
  }
};

// Run 3s after startup (gives initDB time to finish), then daily at 03:00 UTC
setTimeout(() => refreshUpcomingIds(), 3000);
cron.schedule("0 3 * * *", () => {
  console.log("⏰ Cron: refreshing upcoming IDs…");
  refreshUpcomingIds();
});

// ── ROUTES ─────────────────────────────────────────────────────

// Health check
app.get("/", (req, res) => res.json({ status: "HordBox API running" }));

// ── GET /upcoming-ids ───────────────────────────────────────────
// ✅ NEW: Public — no auth needed. Returns the cached upcoming movie IDs.
// On a cold first boot (cache empty) it triggers a live fetch instead.
app.get("/upcoming-ids", async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT value, updated_at FROM app_cache WHERE key = 'upcoming_ids'"
    );
    if (!rows[0]) {
      const ids = await refreshUpcomingIds();
      return res.json({ ids: ids || [], updated_at: new Date() });
    }
    res.json({ ids: rows[0].value, updated_at: rows[0].updated_at });
  } catch (err) {
    console.error("upcoming-ids fetch error:", err);
    res.status(500).json({ error: "Could not fetch upcoming IDs." });
  }
});

// ── POST /upcoming-ids/refresh ──────────────────────────────────
// ✅ NEW: Protected — manually trigger a refresh without waiting for cron.
app.post("/upcoming-ids/refresh", authMiddleware, async (req, res) => {
  const ids = await refreshUpcomingIds();
  if (!ids) return res.status(500).json({ error: "Refresh failed. Check TMDB_KEY." });
  res.json({ success: true, count: ids.length });
});

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

// ── GET /user/data ──────────────────────────────────────────────
// Called on login to restore library, reminders, and watch history
app.get("/user/data", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      // ✅ CHANGED: added search_history to SELECT
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
      search_history: rows[0].search_history || [],  // ✅ NEW
    });
  } catch (err) {
    console.error("Data fetch error:", err);
    res.status(500).json({ error: "Failed to fetch user data." });
  }
});

// ── PUT /user/sync ──────────────────────────────────────────────
// Called automatically (debounced) whenever library, reminders, or watch history changes
app.put("/user/sync", authMiddleware, async (req, res) => {
  const {
    watchlist_ids,
    watchlist_items,
    liked_ids,
    liked_items,
    reminders,
    ratings,
    settings,
    continue_watching,
    search_history,   // ✅ NEW
  } = req.body ?? {};

  try {
    await pool.query(
      // ✅ CHANGED: added search_history to SET, shifted WHERE id to $10
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
        search_history    ? JSON.stringify(search_history)    : null, // ✅ NEW
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
