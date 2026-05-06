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
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified      BOOLEAN     DEFAULT FALSE;
  `);
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS verification_token  VARCHAR(64) DEFAULT NULL;
  `);
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

// ── Send password-reset email via Brevo ─────────────────────────
const sendResetEmail = async (to, username, resetUrl) => {
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'api-key': process.env.BREVO_API_KEY,
    },
    body: JSON.stringify({
      sender: { name: 'HordBox', email: process.env.BREVO_SENDER_EMAIL },
      to: [{ email: to }],
      subject: 'Reset your HordBox password',
      htmlContent: `<!DOCTYPE html>
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
    throw new Error(JSON.stringify(err) || 'Brevo API error');
  }
  return res.json();
};

// ── Send verification email via Brevo ───────────────────────────
const sendVerificationEmail = async (to, username, verifyUrl) => {
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'api-key': process.env.BREVO_API_KEY,
    },
    body: JSON.stringify({
      sender: { name: 'HordBox', email: process.env.BREVO_SENDER_EMAIL },
      to: [{ email: to }],
      subject: 'Verify your HordBox email',
      htmlContent: `<!DOCTYPE html>
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
            Confirm your email
          </h2>
          <p style="color:#8ca0b8;font-size:14px;line-height:1.6;margin:0 0 24px;">
            Hi ${username}, thanks for joining HordBox!
            Click below to verify your email address and activate your account.
          </p>
          <a href="${verifyUrl}"
            style="display:inline-block;background:#00c2d4;color:#07090e;font-weight:800;
                   font-size:15px;padding:14px 32px;border-radius:10px;text-decoration:none;
                   letter-spacing:0.3px;margin-bottom:24px;">
            Verify Email
          </a>
          <p style="color:#4a5a6e;font-size:12px;line-height:1.6;margin:0;">
            If you didn't create an account, you can safely ignore this email.<br><br>
            Or copy this link into your browser:<br>
            <span style="color:#00c2d4;word-break:break-all;">${verifyUrl}</span>
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
    throw new Error(JSON.stringify(err) || 'Brevo API error');
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

app.get("/", (req, res) => res.json({ status: "HordBox API running" }));

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
    const hash  = await bcrypt.hash(password, 12);
    const token = crypto.randomBytes(32).toString("hex");

    const { rows } = await pool.query(
      `INSERT INTO users (username, email, password_hash, avatar_char, verification_token, email_verified)
       VALUES ($1, $2, $3, $4, $5, FALSE)
       RETURNING id, username, email`,
      [username.trim(), email.toLowerCase().trim(), hash, username.trim()[0].toUpperCase(), token]
    );

    const appUrl    = process.env.APP_URL || "https://hordbox.vercel.app";
    const verifyUrl = `${appUrl}?verify_token=${token}`;
    sendVerificationEmail(email.trim(), username.trim(), verifyUrl).catch(console.error);

    res.status(201).json({ pending: true, email: rows[0].email });

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

    if (!rows[0].email_verified) {
      return res.status(403).json({
        error: "Please verify your email before logging in.",
        unverified: true,
        email: rows[0].email,
      });
    }

    const { password_hash, ...user } = rows[0];
    const token = signToken(user.id);
    res.json({ token, user });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

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

app.post("/auth/forgot-password", async (req, res) => {
  res.json({ success: true });

  const { email } = req.body ?? {};
  if (!email?.trim()) return;

  try {
    const { rows } = await pool.query(
      "SELECT id, username FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );
    if (!rows[0]) return;

    const token   = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 60 * 60 * 1000);

    await pool.query(
      "UPDATE password_reset_tokens SET used = TRUE WHERE user_id = $1 AND used = FALSE",
      [rows[0].id]
    );
    await pool.query(
      `INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)`,
      [rows[0].id, token, expires]
    );

    const appUrl   = process.env.APP_URL || "https://hordbox.vercel.app";
    const resetUrl = `${appUrl}?reset_token=${token}`;

    await sendResetEmail(email.trim(), rows[0].username, resetUrl);
    console.log(`✓ Password reset email sent to ${email.trim()}`);
  } catch (err) {
    console.error("Forgot password error:", err);
  }
});

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
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [hash, rows[0].user_id]);
    await pool.query("UPDATE password_reset_tokens SET used = TRUE WHERE id = $1", [rows[0].id]);

    res.json({ success: true });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

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

app.get("/auth/verify-email", async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: "Token missing." });

  try {
    const { rows } = await pool.query(
      `UPDATE users
       SET email_verified = TRUE, verification_token = NULL
       WHERE verification_token = $1 AND email_verified = FALSE
       RETURNING id, username, email, created_at, avatar_char,
                 watchlist_ids, liked_ids, ratings, settings`,
      [token]
    );

    if (!rows[0])
      return res.status(400).json({ error: "This link is invalid or already used." });

    const jwt_token = signToken(rows[0].id);
    res.json({ token: jwt_token, user: rows[0] });

  } catch (err) {
    console.error("Verify email error:", err);
    res.status(500).json({ error: "Something went wrong." });
  }
});

app.post("/auth/resend-verification", async (req, res) => {
  const { email } = req.body ?? {};
  res.json({ success: true });

  if (!email?.trim()) return;

  try {
    const newToken = crypto.randomBytes(32).toString("hex");
    const { rows } = await pool.query(
      `UPDATE users SET verification_token = $1
       WHERE email = $2 AND email_verified = FALSE
       RETURNING username`,
      [newToken, email.toLowerCase().trim()]
    );
    if (!rows[0]) return;

    const appUrl    = process.env.APP_URL || "https://hordbox.vercel.app";
    const verifyUrl = `${appUrl}?verify_token=${newToken}`;
    await sendVerificationEmail(email.trim(), rows[0].username, verifyUrl);
  } catch (err) {
    console.error("Resend verification error:", err);
  }
});

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
