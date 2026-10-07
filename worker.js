/* =====================================================================
   Master Protocol — Ask AI backend (Cloudflare Worker, single file, no build step) · 5.1

   What it does: the app sends a question (plus the data its tools looked up) here; this worker adds the
   secret AI key and forwards it to the AI provider; the answer goes back to the app. It stores nothing and logs
   nothing about the content of requests.

   Set these in Cloudflare → your worker → Settings → Variables and Secrets:
     ANTHROPIC_API_KEY   Secret  your sk-ant-… key (console.anthropic.com)
     APP_ACCESS_CODE     Secret  a long random code you make up (20+ letters and numbers); the same code goes into the app
     ALLOWED_ORIGIN      Text    https://kycullen11-bot.github.io   (comma-separate if you need more than one)
   Optional:
     AI_MODEL            Text    default claude-sonnet-5-5 (or e.g. claude-opus-5-5, claude-haiku-4-5-20251001)
     MAX_OUTPUT_TOKENS   Text    cap on answer length (default 2000)
     DAILY_LIMIT         Text    most AI calls per day (default 300) — needs the USAGE binding below
     USAGE               KV namespace binding (Settings → Bindings → KV namespace) — enables the daily limit
     AI_PROVIDER         Text    anthropic (default) | openai
     OPENAI_API_KEY      Secret  only if AI_PROVIDER = openai
     OPENAI_MODEL        Text    only if AI_PROVIDER = openai (default gpt-4.1)

   Hardening in 5.1 (the access code is the real gate — an Origin header only stops other websites in a browser):
     · only the app's own tools are accepted, by name; the app's instructions sit behind a fixed server-side preamble
     · max_tokens is clamped; message, tool and instruction sizes are capped
     · wrong access codes are throttled per address (5 tries, then a 15-minute lockout)
     · optional daily request limit (KV), on top of the monthly spend limit you set in the Anthropic console
     · CORS: only your app's origin can read /chat responses
     · prompt caching: the unchanging part of each request (tools + fixed instructions + the conversation so far) is
       cached by Anthropic, so repeated parts cost about a tenth

   Endpoints:  GET /health  (checks the access code)   ·   POST /chat  (one model turn; the app runs the tool loop)
   ===================================================================== */

const VERSION = "5.1";
const MAX_BODY_BYTES = 600_000;          // a question + capped tool results; far above normal use
const MAX_MESSAGES = 80, MAX_TOOLS = 20, MAX_SYSTEM_CHARS = 20_000, MAX_TOOL_DESC = 6_000;
const RATE_PER_MINUTE = 40;              // per worker instance — a brake, not a guarantee
const AUTH_FAILS = 5, AUTH_WINDOW = 10 * 60_000, AUTH_LOCK = 15 * 60_000;
const TOOL_ALLOWLIST = new Set(["get_today_context", "get_readiness", "get_logs", "compare_groups", "compare_periods", "get_trend",
  "get_morning_evening_change", "get_recent_sleep", "get_recent_training", "get_recovery_modalities", "get_trends_summary",
  "get_schedule", "get_protocol_rule", "get_needs_review"]);
const PREAMBLE = "This assistant runs only inside Kyle's Master Protocol app, for questions about his own health protocol, logs and plan. " +
  "If asked to do unrelated work (writing code, general tasks, anything not about his protocol, logs or health), decline in one sentence. " +
  "Never recommend changing a medication, hormone, peptide or stimulant dose or schedule — those stay with his clinicians.";
const hits = [], fails = new Map();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim().replace(/\/+$/, "")).filter(Boolean);
    const originOk = allowed.length > 0 && allowed.includes(origin);
    /* Only the allowed origin may read /chat answers. /health replies are readable from anywhere so a wrong
       ALLOWED_ORIGIN shows a clear message in the app during setup — they never contain anything private. */
    const readable = originOk || url.pathname === "/health";
    const cors = {
      "Access-Control-Allow-Origin": readable ? (origin || allowed[0] || "null") : (allowed[0] || "null"),
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
    };
    const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" } });
    const fail = (status, message, type = "error") => json({ error: { type, message } }, status);

    if (request.method === "OPTIONS") return readable ? new Response(null, { status: 204, headers: cors }) : new Response(null, { status: 403 });
    if (!originOk) return fail(403, "This origin is not allowed. Set ALLOWED_ORIGIN on the worker to your app's origin (e.g. https://kycullen11-bot.github.io).", "origin");

    // access code: throttled per address, constant-time comparison
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const now = Date.now();
    const f = fails.get(ip);
    if (f && f.lockedUntil > now) return fail(429, "Too many wrong access codes — try again in " + Math.ceil((f.lockedUntil - now) / 60000) + " min.", "auth_locked");
    const auth = request.headers.get("Authorization") || "";
    const code = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!env.APP_ACCESS_CODE) return fail(500, "APP_ACCESS_CODE is not set on the worker.", "config");
    if (!safeEqual(code, env.APP_ACCESS_CODE)) {
      const rec = f && now - f.first < AUTH_WINDOW ? f : { first: now, n: 0, lockedUntil: 0 };
      rec.n++; if (rec.n >= AUTH_FAILS) { rec.lockedUntil = now + AUTH_LOCK; rec.n = 0; rec.first = now; }
      fails.set(ip, rec); if (fails.size > 5000) fails.clear();
      return fail(401, "Access code not accepted.", "auth");
    }
    if (f) fails.delete(ip);

    // simple per-instance rate brake
    while (hits.length && now - hits[0] > 60_000) hits.shift();
    if (hits.length >= RATE_PER_MINUTE) return fail(429, "Too many requests — wait a minute.", "rate_limit");
    hits.push(now);

    const provider = (env.AI_PROVIDER || "anthropic").toLowerCase();
    const model = provider === "openai" ? (env.OPENAI_MODEL || "gpt-4.1") : (env.AI_MODEL || "claude-sonnet-5-5");

    if (request.method === "GET" && url.pathname === "/health") {
      const keyOk = provider === "openai" ? !!env.OPENAI_API_KEY : !!env.ANTHROPIC_API_KEY;
      if (!keyOk) return fail(500, (provider === "openai" ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY") + " is not set on the worker.", "config");
      const warnings = [];
      if (String(env.APP_ACCESS_CODE).length < 20) warnings.push("APP_ACCESS_CODE is shorter than 20 characters — use a longer random code (change it on the worker and in the app).");
      if (!env.USAGE) warnings.push("No daily limit: add a KV namespace binding named USAGE to cap calls per day (optional — the Anthropic console spend limit is the main cap).");
      return json({ ok: true, provider, model, version: VERSION, warnings });
    }
    if (request.method !== "POST" || url.pathname !== "/chat") return fail(404, "Not found.", "not_found");

    const raw = await request.text();
    if (raw.length > MAX_BODY_BYTES) return fail(413, "Request too large.", "too_large");
    let body;
    try { body = JSON.parse(raw); } catch { return fail(400, "Body must be JSON.", "bad_request"); }
    const err = validate(body);
    if (err) return fail(400, err, "bad_request");

    // optional daily limit (KV binding USAGE)
    if (env.USAGE) {
      const day = new Date().toISOString().slice(0, 10), key = "calls:" + day, limit = Number(env.DAILY_LIMIT) || 300;
      const n = Number(await env.USAGE.get(key)) || 0;
      if (n >= limit) return fail(429, "Daily AI limit reached (" + limit + " calls). It resets at midnight UTC.", "daily_limit");
      await env.USAGE.put(key, String(n + 1), { expirationTtl: 3 * 86400 });
    }

    const cap = Math.max(256, Math.min(Number(env.MAX_OUTPUT_TOKENS) || 2000, 8000));
    const asked = Number.isFinite(Number(body.max_tokens)) ? Math.floor(Number(body.max_tokens)) : 1600;
    const maxOut = Math.max(64, Math.min(asked, cap));
    try {
      const out = provider === "openai"
        ? await callOpenAI(env, model, body, maxOut)
        : await callAnthropic(env, model, body, maxOut);
      return json(out);
    } catch (e) {
      const status = e.status && e.status >= 400 && e.status < 600 ? e.status : 502;
      return fail(status === 401 || status === 403 ? 502 : status, e.message || "AI provider error.", e.type || "provider");
    }
  },
};

function safeEqual(a, b) {
  const x = new TextEncoder().encode(String(a)), y = new TextEncoder().encode(String(b));
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

function validate(b) {
  if (!b || typeof b !== "object") return "Missing body.";
  if (!Array.isArray(b.messages) || !b.messages.length) return "messages must be a non-empty array.";
  if (b.messages.length > MAX_MESSAGES) return "Too many messages.";
  for (const m of b.messages) {
    if (!m || (m.role !== "user" && m.role !== "assistant")) return "Each message needs role user or assistant.";
    if (typeof m.content !== "string" && !Array.isArray(m.content)) return "Each message needs content.";
  }
  if (b.system != null && (typeof b.system !== "string" || b.system.length > MAX_SYSTEM_CHARS)) return "system must be a string (max " + MAX_SYSTEM_CHARS + " characters).";
  if (b.tools != null) {
    if (!Array.isArray(b.tools) || b.tools.length > MAX_TOOLS) return "tools must be an array (max " + MAX_TOOLS + ").";
    for (const t of b.tools) {
      if (!t || !TOOL_ALLOWLIST.has(t.name)) return "Tool not allowed: " + (t && t.name);
      if (typeof t.description !== "string" || t.description.length > MAX_TOOL_DESC) return "Tool description missing or too long: " + t.name;
      if (!t.input_schema || typeof t.input_schema !== "object") return "Tool input_schema missing: " + t.name;
    }
  }
  if (b.tool_choice != null && !(b.tool_choice && (b.tool_choice.type === "auto" || b.tool_choice.type === "none"))) return "tool_choice must be auto or none.";
  return null;
}

/* ---------- Anthropic (Claude) — the neutral format is already Anthropic's ---------- */
const CACHE = { type: "ephemeral" };
async function callAnthropic(env, model, b, maxOut) {
  if (!env.ANTHROPIC_API_KEY) throw Object.assign(new Error("ANTHROPIC_API_KEY is not set on the worker."), { status: 500, type: "config" });
  // system: [fixed preamble + the app's unchanging instructions] (cached) + [today's line] (not cached)
  const sys = typeof b.system === "string" ? b.system : "";
  const cut = b.cache && Number.isInteger(b.cache.static_chars) && b.cache.static_chars > 0 && b.cache.static_chars <= sys.length ? b.cache.static_chars : 0;
  const system = [{ type: "text", text: PREAMBLE + "\n\n" + (cut ? sys.slice(0, cut) : sys), cache_control: CACHE }];
  if (cut && sys.slice(cut).trim()) system.push({ type: "text", text: sys.slice(cut).trim() });
  // messages: copy, and mark the end of the conversation so the next round of the same answer reuses it
  const messages = b.messages.map((m) => ({ role: m.role, content: typeof m.content === "string" ? m.content : m.content.map((c) => ({ ...c })) }));
  const last = messages[messages.length - 1];
  if (typeof last.content === "string") last.content = [{ type: "text", text: last.content }];
  if (last.content.length) last.content[last.content.length - 1].cache_control = CACHE;
  const req = { model, max_tokens: maxOut, system, messages };
  if (b.tools && b.tools.length) {
    req.tools = b.tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.input_schema }));
    req.tools[req.tools.length - 1].cache_control = CACHE;
    if (b.tool_choice) req.tool_choice = { type: b.tool_choice.type };
  }
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify(req),
  });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw providerError(r.status, j && j.error && j.error.message, "Anthropic");
  const u = j.usage || {};
  return {
    provider: "anthropic", model: j.model || model, stop_reason: j.stop_reason,
    content: (j.content || []).filter((c) => c.type === "text" || c.type === "tool_use")
      .map((c) => c.type === "text" ? { type: "text", text: c.text } : { type: "tool_use", id: c.id, name: c.name, input: c.input || {} }),
    usage: { input_tokens: u.input_tokens || 0, output_tokens: u.output_tokens || 0, cache_read_input_tokens: u.cache_read_input_tokens || 0, cache_creation_input_tokens: u.cache_creation_input_tokens || 0 },
  };
}

/* ---------- OpenAI (optional) — translate to / from Chat Completions function calling ---------- */
async function callOpenAI(env, model, b, maxOut) {
  if (!env.OPENAI_API_KEY) throw Object.assign(new Error("OPENAI_API_KEY is not set on the worker."), { status: 500, type: "config" });
  const msgs = [{ role: "system", content: PREAMBLE + (b.system ? "\n\n" + b.system : "") }];
  for (const m of b.messages) {
    if (typeof m.content === "string") { msgs.push({ role: m.role, content: m.content }); continue; }
    if (m.role === "assistant") {
      const text = m.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");
      const calls = m.content.filter((c) => c.type === "tool_use").map((c) => ({ id: c.id, type: "function", function: { name: c.name, arguments: JSON.stringify(c.input || {}) } }));
      msgs.push(calls.length ? { role: "assistant", content: text || null, tool_calls: calls } : { role: "assistant", content: text });
    } else {
      const results = m.content.filter((c) => c.type === "tool_result");
      for (const r of results) msgs.push({ role: "tool", tool_call_id: r.tool_use_id, content: typeof r.content === "string" ? r.content : JSON.stringify(r.content) });
      const text = m.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");
      if (text) msgs.push({ role: "user", content: text });
    }
  }
  const req = { model, max_tokens: maxOut, messages: msgs };
  if (b.tools && b.tools.length) {
    req.tools = b.tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.input_schema } }));
    req.tool_choice = b.tool_choice && b.tool_choice.type === "none" ? "none" : "auto";
  }
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Authorization": "Bearer " + env.OPENAI_API_KEY, "content-type": "application/json" },
    body: JSON.stringify(req),
  });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw providerError(r.status, j && j.error && j.error.message, "OpenAI");
  const ch = (j.choices && j.choices[0]) || {}, msg = ch.message || {};
  const content = [];
  if (msg.content) content.push({ type: "text", text: msg.content });
  for (const tc of msg.tool_calls || []) {
    let input = {};
    try { input = JSON.parse(tc.function.arguments || "{}"); } catch { input = {}; }
    content.push({ type: "tool_use", id: tc.id, name: tc.function.name, input });
  }
  const stop = ch.finish_reason === "tool_calls" ? "tool_use" : ch.finish_reason === "length" ? "max_tokens" : "end_turn";
  return {
    provider: "openai", model: j.model || model, stop_reason: stop, content,
    usage: { input_tokens: (j.usage && j.usage.prompt_tokens) || 0, output_tokens: (j.usage && j.usage.completion_tokens) || 0 },
  };
}

function providerError(status, message, who) {
  const map = {
    400: who + " rejected the request: " + (message || "bad request"),
    401: "The " + who + " API key on the worker is invalid — re-paste it in Variables and Secrets.",
    403: "The " + who + " API key on the worker isn't allowed to use this model.",
    404: "Model not found at " + who + " — check AI_MODEL / OPENAI_MODEL on the worker.",
    429: who + " rate limit or credit limit reached — wait, or check billing.",
    529: who + " is overloaded right now — try again shortly.",
  };
  return Object.assign(new Error(map[status] || (who + " error " + status + (message ? ": " + message : ""))), { status: status === 529 ? 503 : status, type: "provider" });
}
