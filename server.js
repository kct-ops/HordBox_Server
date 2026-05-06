// ═══════════════════════════════════════════════════════════════
//  HordBox Railway Backend — server.js
//  Stack: Node.js + Express + PostgreSQL + JWT + bcrypt
//  Deploy to: railway.app (attach a PostgreSQL plugin)
// ═══════════════════════════════════════════════════════════════

const express    = require("express");
const cors       = require("cors");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const crypto     = require("crypto");           // built-in
const { Pool }   = require("pg");

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
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS search_history    JSONB DEFAULT '[]';
  `);

  // ── Password reset tokens table ─────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token      VARCHAR(64) UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used       BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log("✓ DB ready");
};
initDB().catch(console.error);

// Send email via Resend HTTP API (avoids Railway SMTP port blocks)
const sendResetEmail = async (to, username, resetUrl) => {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from: process.env.SMTP_FROM || 'HordBox <onboarding@resend.dev>',
      to: [to],
      subject: 'Reset your HordBox password',
      html: `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#07090e;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#07090e;padding:40px 0;">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0"
        style="background:#0d1119;border:1px solid #1e2736;border-radius:16px;padding:40px 36px;">
        <tr><td>
          <div style="font-size:22px;font-weight:900;color:#00c2d4;letter-spacing:2px;margin-bottom:28px;">
            HORD<span style="color:#eef2f8;">BOX</span>
          </div>
          <h2 style="color:#eef2f8;font-size:20px;font-weight:800;margin:0 0 10px;">
            Reset your password
          </h2>
          <p style="color:#8ca0b8;font-size:14px;line-height:1.6;margin:0 0 24px;">
            Hi ${username}, we received a request to reset your password.
            Click the button below to choose a new one.
            This link expires in <strong style="color:#eef2f8;">1 hour</strong>.
          </p>
          <a href="${resetUrl}"
            style="display:inline-block;background:#00c2d4;color:#07090e;font-weight:800;
                   font-size:15px;padding:14px 32px;border-radius:10px;text-decoration:none;
                   letter-spacing:0.3px;margin-bottom:24px;">
            Set New Password
          </a>
          <p style="color:#4a5a6e;font-size:12px;line-height:1.6;margin:0;">
            If you didn't request this, you can safely ignore this email.<br><br>
            Or copy this link into your browser:<br>
            <span style="color:#00c2d4;word-break:break-all;">${resetUrl}</span>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
    }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || 'Resend API error');
  }
  return res.json();
};

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

// ── POST /auth/forgot-password ──────────────────────────────────
// Always returns 200 (prevents email enumeration).
// Sends a reset link to the address if it exists in the DB.
app.post("/auth/forgot-password", async (req, res) => {
  // Respond immediately so the frontend never waits on SMTP
  res.json({ success: true });

  const { email } = req.body ?? {};
  if (!email?.trim()) return;

  try {
    const { rows } = await pool.query(
      "SELECT id, username FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );
    if (!rows[0]) return; // silently do nothing — user not found

    const token   = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Invalidate any previous unused tokens for this user
    await pool.query(
      "UPDATE password_reset_tokens SET used = TRUE WHERE user_id = $1 AND used = FALSE",
      [rows[0].id]
    );

    await pool.query(
      `INSERT INTO password_reset_tokens (user_id, token, expires_at)
       VALUES ($1, $2, $3)`,
      [rows[0].id, token, expires]
    );

    const appUrl   = process.env.APP_URL || "https://hordbox.vercel.app";
    const resetUrl = `${appUrl}?reset_token=${token}`;
    const username = rows[0].username;

    await sendResetEmail(email.trim(), username, resetUrl);

    console.log(`✓ Password reset email sent to ${email.trim()}`);
  } catch (err) {
    console.error("Forgot password error:", err);
  }
});

// ── POST /auth/reset-password ───────────────────────────────────
app.post("/auth/reset-password", async (req, res) => {
  const { token, password } = req.body ?? {};

  if (!token || !password)
    return res.status(400).json({ error: "Token and new password are required." });

  if (password.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters." });

  try {
    const { rows } = await pool.query(
      `SELECT * FROM password_reset_tokens
       WHERE token = $1 AND used = FALSE AND expires_at > NOW()`,
      [token]
    );

    if (!rows[0])
      return res.status(400).json({ error: "Reset link is invalid or has expired. Please request a new one." });

    const hash = await bcrypt.hash(password, 12);

    await pool.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [hash, rows[0].user_id]
    );
    await pool.query(
      "UPDATE password_reset_tokens SET used = TRUE WHERE id = $1",
      [rows[0].id]
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
    search_history,
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

// ── Start ───────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`HordBox API → http://localhost:${PORT}`)
);
