// Compass — сервер: аккаунты, сохранение анкеты, ссылки для просмотра, AI-прокси.
// Хранилище: Postgres (если задан DATABASE_URL), иначе JSON-файл (для локального запуска).
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");

const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === "production";
const AI_KEY = process.env.ANTHROPIC_API_KEY || "";
const AI_MODEL = process.env.AI_MODEL || "claude-haiku-5-5";
const AI_DAILY_LIMIT = +(process.env.AI_DAILY_LIMIT || 60);
const SESSION_DAYS = 60;

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const rid = (n = 24) => crypto.randomBytes(n).toString("base64url");

function makePgStore(url) {
  const { Pool } = require("pg");
  const pool = new Pool({
    connectionString: url,
    ssl: /render\.com|sslmode=require/.test(url) ? { rejectUnauthorized: false } : undefined,
    max: 5,
  });
  const q = (text, params) => pool.query(text, params);
  return {
    kind: "postgres",
    async init() {
      // Таблицы с префиксом compass_, чтобы спокойно жить в общей базе.
      await q(`CREATE TABLE IF NOT EXISTS compass_users(
        id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pass TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student', state JSONB, share_token TEXT UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
      await q(`CREATE TABLE IF NOT EXISTS compass_sessions(
        token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES compass_users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL)`);
      await q(`CREATE TABLE IF NOT EXISTS compass_ai_usage(
        user_id TEXT NOT NULL, day DATE NOT NULL, n INT NOT NULL DEFAULT 0, PRIMARY KEY(user_id, day))`);
      await q(`DELETE FROM compass_sessions WHERE expires_at < now()`);
    },
    async createUser(u) {
      await q(`INSERT INTO compass_users(id,email,name,pass,role,state) VALUES($1,$2,$3,$4,$5,$6)`,
        [u.id, u.email, u.name, u.pass, u.role, u.state ? JSON.stringify(u.state) : null]);
    },
    async userByEmail(email) { return (await q(`SELECT * FROM compass_users WHERE email=$1`, [email])).rows[0] || null; },
    async userById(id) { return (await q(`SELECT * FROM compass_users WHERE id=$1`, [id])).rows[0] || null; },
    async userByShare(t) { return (await q(`SELECT * FROM compass_users WHERE share_token=$1`, [t])).rows[0] || null; },
    async saveState(id, state) { await q(`UPDATE compass_users SET state=$2, updated_at=now() WHERE id=$1`, [id, JSON.stringify(state)]); },
    async setName(id, name) { await q(`UPDATE compass_users SET name=$2, updated_at=now() WHERE id=$1`, [id, name]); },
    async setPass(id, pass) { await q(`UPDATE compass_users SET pass=$2 WHERE id=$1`, [id, pass]); },
    async setShare(id, t) { await q(`UPDATE compass_users SET share_token=$2 WHERE id=$1`, [id, t]); },
    async deleteUser(id) { await q(`DELETE FROM compass_users WHERE id=$1`, [id]); await q(`DELETE FROM compass_ai_usage WHERE user_id=$1`, [id]); },
    async addSession(hash, userId, exp) { await q(`INSERT INTO compass_sessions VALUES($1,$2,$3)`, [hash, userId, exp]); },
    async sessionUser(hash) {
      return (await q(`SELECT u.* FROM compass_sessions s JOIN compass_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()`, [hash])).rows[0] || null;
    },
    async dropSession(hash) { await q(`DELETE FROM compass_sessions WHERE token_hash=$1`, [hash]); },
    async dropUserSessions(id) { await q(`DELETE FROM compass_sessions WHERE user_id=$1`, [id]); },
    async aiBump(id) {
      const r = await q(`INSERT INTO compass_ai_usage(user_id,day,n) VALUES($1,CURRENT_DATE,1)
        ON CONFLICT(user_id,day) DO UPDATE SET n=compass_ai_usage.n+1 RETURNING n`, [id]);
      return r.rows[0].n;
    },
    async stats() {
      const r = await q(`SELECT count(*)::int AS users, count(share_token)::int AS shared,
        count(*) FILTER (WHERE created_at > now() - interval '7 days')::int AS week FROM compass_users`);
      return r.rows[0];
    },
  };
}

function makeFileStore(file) {
  let db = { users: [], sessions: [], ai: {} };
  try { db = JSON.parse(fs.readFileSync(file, "utf8")); } catch (_) {}
  const flush = () => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(db)); };
  const now = () => Date.now();
  return {
    kind: "file",
    async init() { db.sessions = db.sessions.filter((s) => s.exp > now()); flush(); },
    async createUser(u) { db.users.push({ ...u, share_token: null, created_at: new Date().toISOString() }); flush(); },
    async userByEmail(e) { return db.users.find((u) => u.email === e) || null; },
    async userById(id) { return db.users.find((u) => u.id === id) || null; },
    async userByShare(t) { return db.users.find((u) => u.share_token === t) || null; },
    async saveState(id, s) { const u = db.users.find((x) => x.id === id); if (u) { u.state = s; u.updated_at = new Date().toISOString(); flush(); } },
    async setName(id, n) { const u = db.users.find((x) => x.id === id); if (u) { u.name = n; flush(); } },
    async setPass(id, p) { const u = db.users.find((x) => x.id === id); if (u) { u.pass = p; flush(); } },
    async setShare(id, t) { const u = db.users.find((x) => x.id === id); if (u) { u.share_token = t; flush(); } },
    async deleteUser(id) { db.users = db.users.filter((u) => u.id !== id); db.sessions = db.sessions.filter((s) => s.user !== id); flush(); },
    async addSession(h, user, exp) { db.sessions.push({ h, user, exp: +exp }); flush(); },
    async sessionUser(h) { const s = db.sessions.find((x) => x.h === h && x.exp > now()); return s ? db.users.find((u) => u.id === s.user) || null : null; },
    async dropSession(h) { db.sessions = db.sessions.filter((s) => s.h !== h); flush(); },
    async dropUserSessions(id) { db.sessions = db.sessions.filter((s) => s.user !== id); flush(); },
    async aiBump(id) { const k = id + ":" + new Date().toISOString().slice(0, 10); db.ai[k] = (db.ai[k] || 0) + 1; flush(); return db.ai[k]; },
    async stats() { return { users: db.users.length, shared: db.users.filter((u) => u.share_token).length, week: 0 }; },
  };
}

const store = process.env.DATABASE_URL
  ? makePgStore(process.env.DATABASE_URL)
  : makeFileStore(process.env.DATA_FILE || path.join(__dirname, "data", "compass.json"));

/* ------------------------------------------------------------------ */
/* App                                                                 */
/* ------------------------------------------------------------------ */
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "300kb" }));
app.use((req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "SAMEORIGIN",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
  next();
});

function parseCookies(h) {
  const out = {};
  (h || "").split(";").forEach((p) => { const i = p.indexOf("="); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return out;
}
const COOKIE = "compass_sid";
function setSession(res, token) {
  res.cookie
    ? res.cookie(COOKIE, token, { httpOnly: true, sameSite: "lax", secure: PROD, maxAge: SESSION_DAYS * 864e5, path: "/" })
    : null;
}
async function startSession(res, userId) {
  const token = rid(32);
  await store.addSession(sha(token), userId, new Date(Date.now() + SESSION_DAYS * 864e5));
  setSession(res, token);
}
app.use(async (req, res, next) => {
  req.user = null;
  const t = parseCookies(req.headers.cookie)[COOKIE];
  if (t) { try { req.user = await store.sessionUser(sha(t)); } catch (e) { console.error("session", e.message); } }
  next();
});
const auth = (req, res, next) => (req.user ? next() : res.status(401).json({ error: "Нужно войти в аккаунт" }));
const pub = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, shareToken: u.share_token || null });

// Простая защита от перебора паролей (в памяти).
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  arr.push(now); hits.set(key, arr);
  return arr.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some((t) => now - t < 36e5)) hits.delete(k); }, 6e5).unref();

const cleanEmail = (e) => String(e || "").trim().toLowerCase().slice(0, 200);
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

app.get("/healthz", (req, res) => res.json({ ok: true, store: store.kind, ai: !!AI_KEY }));

app.post("/api/register", async (req, res) => {
  try {
    if (limited("reg:" + req.ip, 10, 36e5)) return res.status(429).json({ error: "Слишком много попыток. Попробуй через час." });
    const name = String(req.body.name || "").trim().slice(0, 60);
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");
    const role = req.body.role === "mentor" ? "mentor" : "student";
    if (!name) return res.status(400).json({ error: "Напиши имя" });
    if (!validEmail(email)) return res.status(400).json({ error: "Проверь email: похоже, в нём ошибка" });
    if (password.length < 8) return res.status(400).json({ error: "Пароль должен быть не короче 8 символов" });
    if (await store.userByEmail(email)) return res.status(409).json({ error: "Аккаунт с таким email уже есть. Попробуй войти." });
    const state = req.body.state && typeof req.body.state === "object" ? req.body.state : null;
    const u = { id: rid(12), email, name, pass: await bcrypt.hash(password, 10), role, state };
    await store.createUser(u);
    await startSession(res, u.id);
    res.json({ user: pub(u), state: u.state });
  } catch (e) { console.error(e); res.status(500).json({ error: "Не получилось создать аккаунт. Попробуй ещё раз." }); }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    if (limited("login:" + req.ip, 20, 9e5) || limited("login:" + email, 8, 9e5))
      return res.status(429).json({ error: "Слишком много попыток входа. Подожди 15 минут." });
    const u = await store.userByEmail(email);
    if (!u || !(await bcrypt.compare(String(req.body.password || ""), u.pass)))
      return res.status(401).json({ error: "Неверный email или пароль" });
    await startSession(res, u.id);
    res.json({ user: pub(u), state: u.state || null });
  } catch (e) { console.error(e); res.status(500).json({ error: "Не получилось войти. Попробуй ещё раз." }); }
});

app.post("/api/logout", async (req, res) => {
  const t = parseCookies(req.headers.cookie)[COOKIE];
  if (t) await store.dropSession(sha(t)).catch(() => {});
  res.clearCookie(COOKIE, { path: "/" });
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  if (!req.user) return res.json({ user: null });
  res.json({ user: pub(req.user), state: req.user.state || null });
});

app.put("/api/state", auth, async (req, res) => {
  const s = req.body.state;
  if (!s || typeof s !== "object") return res.status(400).json({ error: "Пустые данные" });
  await store.saveState(req.user.id, s);
  res.json({ ok: true, savedAt: new Date().toISOString() });
});

app.put("/api/account", auth, async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 60);
  if (name) await store.setName(req.user.id, name);
  if (req.body.newPassword) {
    if (!(await bcrypt.compare(String(req.body.password || ""), req.user.pass))) return res.status(401).json({ error: "Текущий пароль неверный" });
    if (String(req.body.newPassword).length < 8) return res.status(400).json({ error: "Новый пароль должен быть не короче 8 символов" });
    await store.setPass(req.user.id, await bcrypt.hash(String(req.body.newPassword), 10));
  }
  res.json({ user: pub(await store.userById(req.user.id)) });
});

app.delete("/api/account", auth, async (req, res) => {
  if (!(await bcrypt.compare(String(req.body.password || ""), req.user.pass))) return res.status(401).json({ error: "Пароль неверный" });
  await store.dropUserSessions(req.user.id);
  await store.deleteUser(req.user.id);
  res.clearCookie(COOKIE, { path: "/" });
  res.json({ ok: true });
});

app.post("/api/share", auth, async (req, res) => {
  const t = req.user.share_token || rid(9);
  await store.setShare(req.user.id, t);
  res.json({ shareToken: t });
});
app.delete("/api/share", auth, async (req, res) => {
  await store.setShare(req.user.id, null);
  res.json({ shareToken: null });
});
app.get("/api/shared/:token", async (req, res) => {
  const u = await store.userByShare(String(req.params.token).slice(0, 40));
  if (!u) return res.status(404).json({ error: "Ссылка не найдена или её отключили" });
  res.json({ name: u.name, state: u.state || null });
});

app.get("/api/stats", async (req, res) => {
  try { res.json(await store.stats()); } catch (e) { res.json({}); }
});

app.post("/api/ai", auth, async (req, res) => {
  if (!AI_KEY) return res.status(503).json({ code: "ai_off", error: "AI пока не подключён" });
  const prompt = String(req.body.prompt || "").slice(0, 30000);
  if (!prompt) return res.status(400).json({ error: "Пустой запрос" });
  try {
    const n = await store.aiBump(req.user.id);
    if (n > AI_DAILY_LIMIT) return res.status(429).json({ code: "rate_limited", error: "Лимит AI на сегодня исчерпан" });
  } catch (e) { console.error("ai usage", e.message); }
  const tier = req.body.tier === "quick" ? 700 : 1400;
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": AI_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: AI_MODEL,
        max_tokens: tier,
        system: "Ты — ассистент профориентационного сервиса Compass для школьников Казахстана. Отвечай по-русски. Если просят JSON — отвечай только валидным JSON без пояснений.",
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const j = await r.json();
    if (!r.ok) { console.error("anthropic", r.status, JSON.stringify(j).slice(0, 300)); return res.status(502).json({ code: "upstream_error", error: "AI временно недоступен" }); }
    const text = (j.content || []).filter((c) => c.type === "text").map((c) => c.text).join("");
    res.json({ text });
  } catch (e) { console.error("ai", e.message); res.status(502).json({ code: "upstream_error", error: "AI временно недоступен" }); }
});

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"], maxAge: PROD ? "1h" : 0, index: "index.html" }));
// Любой другой путь (например, /r/<код> — ссылка для просмотра) отдаёт приложение.
app.get(/^\/(?!api\/).*/, (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

store.init()
  .then(() => app.listen(PORT, () => console.log(`Compass on :${PORT} · store=${store.kind} · ai=${AI_KEY ? "on" : "off"}`)))
  .catch((e) => { console.error("Storage init failed:", e); process.exit(1); });
