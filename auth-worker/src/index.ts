export interface Env {
  DB: D1Database;
  SITE_URL: string;
  DISCORD_CLIENT_ID: string;
  DISCORD_CLIENT_SECRET: string;
  ADMIN_DISCORD_ID: string;
  ADMIN_PASSWORD_HASH: string;
  SESSION_SECRET: string;
  KEY_PEPPER: string;
  ADMIN_PHONE: string;
  ADMIN_EMAIL: string;
  TWILIO_ACCOUNT_SID: string;
  TWILIO_AUTH_TOKEN: string;
  TWILIO_FROM: string;
  RESEND_API_KEY: string;
  EMAIL_FROM: string;
}

const corsHeaders = (env: Env) => ({
  "Access-Control-Allow-Origin": env.SITE_URL,
  "Access-Control-Allow-Credentials": "true",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Vary": "Origin",
});

const json = (env: Env, data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders(env) },
  });

const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const unb64url = (value: string) => {
  const s = value.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(s + "=".repeat((4 - s.length % 4) % 4));
  return Uint8Array.from(raw, c => c.charCodeAt(0));
};
const utf8 = (value: string) => new TextEncoder().encode(value);
const sha256 = async (value: string) => b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(value))));
const randomToken = (size = 32) => {
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  return b64url(bytes);
};

async function signToken(env: Env, claims: Record<string, unknown>) {
  const payload = b64url(utf8(JSON.stringify(claims)));
  const key = await crypto.subtle.importKey("raw", utf8(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(payload)));
  return payload + "." + b64url(sig);
}
async function verifyToken(env: Env, token: string | null) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const key = await crypto.subtle.importKey("raw", utf8(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  let valid = false;
  try { valid = await crypto.subtle.verify("HMAC", key, unb64url(parts[1]), utf8(parts[0])); } catch { return null; }
  if (!valid) return null;
  try {
    const claims = JSON.parse(new TextDecoder().decode(unb64url(parts[0])));
    if (!claims.exp || claims.exp < Math.floor(Date.now() / 1000)) return null;
    return claims as Record<string, unknown>;
  } catch { return null; }
}
function bearer(request: Request) {
  const value = request.headers.get("Authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7) : null;
}
function isPasswordHashFormat(value: string) {
  return /^pbkdf2\$\d+\$[^$]+\$[^$]+$/.test(value);
}
async function verifyPassword(password: string, encoded: string) {
  if (!isPasswordHashFormat(encoded)) return false;
  const [, iterations, salt, expected] = encoded.split("$");
  const material = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unb64url(salt), iterations: Number(iterations) }, material, 256));
  return b64url(bits) === expected;
}
async function audit(env: Env, actor: string, action: string, detail = "") {
  await env.DB.prepare("INSERT INTO audit_log (actor_id, action, detail, created_at) VALUES (?, ?, ?, ?)")
    .bind(actor, action, detail.slice(0, 300), Date.now()).run();
}
async function sendSms(env: Env, code: string) {
  const url = `https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`;
  const body = new URLSearchParams({ To: env.ADMIN_PHONE, From: env.TWILIO_FROM, Body: `WARTEX yönetici doğrulama kodun: ${code}. 5 dakika içinde kullan.` });
  const auth = btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`);
  const res = await fetch(url, { method: "POST", headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" }, body });
  if (!res.ok) throw new Error("SMS provider failed");
}
async function sendEmail(env: Env, code: string) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: env.EMAIL_FROM,
      to: [env.ADMIN_EMAIL],
      subject: "WARTEX yönetici doğrulama kodu",
      text: `WARTEX yönetici doğrulama kodun: ${code}. Kod 5 dakika içinde sona erer. Bu işlemi sen başlatmadıysan kodu paylaşma.`,
    }),
  });
  if (!res.ok) throw new Error("Email provider failed");
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(env) });
    if (url.pathname === "/health") return json(env, { ok: true, service: "WARTEX Auth API" });

    if (url.pathname === "/auth/discord") {
      const state = randomToken(24);
      const redirect = new URL("https://discord.com/oauth2/authorize");
      redirect.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
      redirect.searchParams.set("redirect_uri", url.origin + "/auth/callback");
      redirect.searchParams.set("response_type", "code");
      redirect.searchParams.set("scope", "identify");
      redirect.searchParams.set("state", state);
      return new Response(null, { status: 302, headers: {
        Location: redirect.toString(),
        "Set-Cookie": `wartex_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`,
        ...corsHeaders(env),
      }});
    }

    if (url.pathname === "/auth/callback") {
      const stateCookie = request.headers.get("Cookie")?.match(/(?:^|; )wartex_oauth_state=([^;]+)/)?.[1];
      const state = url.searchParams.get("state");
      const code = url.searchParams.get("code");
      if (!state || !stateCookie || state !== stateCookie || !code) return json(env, { error: "OAuth state doğrulaması başarısız." }, 400);
      const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET, grant_type: "authorization_code", code, redirect_uri: url.origin + "/auth/callback" }),
      });
      if (!tokenRes.ok) return json(env, { error: "Discord token alınamadı." }, 401);
      const tokenData = await tokenRes.json() as { access_token?: string };
      if (!tokenData.access_token) return json(env, { error: "Discord token eksik." }, 401);
      const userRes = await fetch("https://discord.com/api/users/@me", { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
      if (!userRes.ok) return json(env, { error: "Discord hesabı doğrulanamadı." }, 401);
      const user = await userRes.json() as { id: string; username?: string; global_name?: string };
      const isAdmin = user.id === env.ADMIN_DISCORD_ID;
      await env.DB.prepare("INSERT INTO user_events (discord_id, event_type, detail, created_at) VALUES (?, ?, ?, ?)")
        .bind(user.id, "discord_login", isAdmin ? "admin_oauth_started" : "user_login", Date.now()).run();
      const oneTime = randomToken(32);
      await env.DB.prepare("INSERT INTO auth_codes (code_hash, discord_id, username, is_admin, expires_at) VALUES (?, ?, ?, ?, ?)")
        .bind(await sha256(oneTime + env.SESSION_SECRET), user.id, user.global_name || user.username || "", isAdmin ? 1 : 0, Date.now() + 120000).run();
      const target = new URL(env.SITE_URL);
      target.searchParams.set("auth_code", oneTime);
      return new Response(null, { status: 302, headers: { Location: target.toString(), "Set-Cookie": "wartex_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0", ...corsHeaders(env) } });
    }

    if (url.pathname === "/auth/exchange" && request.method === "POST") {
      const body = await request.json().catch(() => ({})) as { code?: string };
      if (!body.code || body.code.length > 200) return json(env, { error: "Kod geçersiz." }, 400);
      const hash = await sha256(body.code + env.SESSION_SECRET);
      const row = await env.DB.prepare("SELECT discord_id, username, is_admin, expires_at FROM auth_codes WHERE code_hash = ?").bind(hash).first<{ discord_id: string; username: string; is_admin: number; expires_at: number }>();
      if (!row || row.expires_at < Date.now()) return json(env, { error: "Giriş kodu geçersiz veya süresi dolmuş." }, 401);
      await env.DB.prepare("DELETE FROM auth_codes WHERE code_hash = ?").bind(hash).run();
      if (row.is_admin) {
        const flowToken = await signToken(env, { sub: row.discord_id, name: row.username, scope: "admin_flow", stage: "credentials", exp: Math.floor(Date.now() / 1000) + 600 });
        return json(env, { role: "admin_pending", token: flowToken, username: row.username });
      }
      const token = await signToken(env, { sub: row.discord_id, name: row.username, scope: "user", exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7 });
      await audit(env, row.discord_id, "user_login");
      return json(env, { role: "user", token, username: row.username });
    }

    if (url.pathname === "/admin/verify-credentials" && request.method === "POST") {
      const claims = await verifyToken(env, bearer(request));
      if (!claims || claims.scope !== "admin_flow" || claims.sub !== env.ADMIN_DISCORD_ID || claims.stage !== "credentials") return json(env, { error: "Yönetici doğrulama oturumu geçersiz." }, 401);
      const body = await request.json().catch(() => ({})) as { password?: string; key?: string };
      if (!body.password || !body.key || body.password.length > 256 || body.key.length > 256) return json(env, { error: "Şifre ve yönetici anahtarı gerekli." }, 400);
      const validPassword = await verifyPassword(body.password, env.ADMIN_PASSWORD_HASH);
      const keyHash = await sha256(env.KEY_PEPPER + body.key.trim());
      const keyRow = await env.DB.prepare("SELECT id, expires_at, used_at FROM admin_keys WHERE key_hash = ?").bind(keyHash).first<{ id: number; expires_at: number; used_at: number | null }>();
      if (!validPassword || !keyRow || keyRow.used_at !== null || keyRow.expires_at < Date.now()) {
        await audit(env, String(claims.sub), "admin_credentials_failed");
        return json(env, { error: "Bilgiler geçersiz." }, 401);
      }
      const used = await env.DB.prepare("UPDATE admin_keys SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?").bind(Date.now(), keyRow.id, Date.now()).run();
      if (!used.meta.changes) return json(env, { error: "Bu anahtar kullanılmış veya süresi dolmuş." }, 401);
      const challenge = randomToken(24);
      const smsCode = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
      const emailCode = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
      const exp = Date.now() + 5 * 60 * 1000;
      await env.DB.prepare("INSERT INTO otp_challenges (challenge_hash, discord_id, sms_hash, email_hash, sms_ok, expires_at, attempts) VALUES (?, ?, ?, ?, 0, ?, 0)")
        .bind(await sha256(challenge + env.SESSION_SECRET), String(claims.sub), await sha256(env.KEY_PEPPER + smsCode), await sha256(env.KEY_PEPPER + emailCode), exp).run();
      try {
        await Promise.all([sendSms(env, smsCode), sendEmail(env, emailCode)]);
      } catch {
        await env.DB.prepare("DELETE FROM otp_challenges WHERE challenge_hash = ?").bind(await sha256(challenge + env.SESSION_SECRET)).run();
        await audit(env, String(claims.sub), "otp_delivery_failed");
        return json(env, { error: "Kodlar gönderilemedi. SMS/e-posta sağlayıcı ayarlarını kontrol edin." }, 502);
      }
      await audit(env, String(claims.sub), "admin_otp_sent");
      const next = await signToken(env, { sub: claims.sub, scope: "admin_flow", stage: "sms", challenge, exp: Math.floor(Date.now() / 1000) + 300 });
      return json(env, { ok: true, nextStep: "sms", token: next });
    }

    if ((url.pathname === "/admin/verify-sms" || url.pathname === "/admin/verify-email") && request.method === "POST") {
      const claims = await verifyToken(env, bearer(request));
      const expectedStage = url.pathname.endsWith("verify-sms") ? "sms" : "email";
      if (!claims || claims.scope !== "admin_flow" || claims.sub !== env.ADMIN_DISCORD_ID || claims.stage !== expectedStage || typeof claims.challenge !== "string") return json(env, { error: "Doğrulama oturumu geçersiz." }, 401);
      const body = await request.json().catch(() => ({})) as { code?: string };
      if (!body.code || !/^\d{6}$/.test(body.code)) return json(env, { error: "6 haneli kodu gir." }, 400);
      const ch = await sha256(String(claims.challenge) + env.SESSION_SECRET);
      const row = await env.DB.prepare("SELECT sms_hash, email_hash, sms_ok, expires_at, attempts FROM otp_challenges WHERE challenge_hash = ? AND discord_id = ?")
        .bind(ch, String(claims.sub)).first<{ sms_hash: string; email_hash: string; sms_ok: number; expires_at: number; attempts: number }>();
      if (!row || row.expires_at < Date.now() || row.attempts >= 5) return json(env, { error: "Kodun süresi doldu veya deneme sınırı aşıldı." }, 401);
      const provided = await sha256(env.KEY_PEPPER + body.code);
      if (expectedStage === "sms") {
        if (provided !== row.sms_hash) {
          await env.DB.prepare("UPDATE otp_challenges SET attempts = attempts + 1 WHERE challenge_hash = ?").bind(ch).run();
          return json(env, { error: "SMS kodu hatalı." }, 401);
        }
        await env.DB.prepare("UPDATE otp_challenges SET sms_ok = 1 WHERE challenge_hash = ?").bind(ch).run();
        const next = await signToken(env, { sub: claims.sub, scope: "admin_flow", stage: "email", challenge: claims.challenge, exp: Math.floor(Date.now() / 1000) + 300 });
        return json(env, { ok: true, nextStep: "email", token: next });
      }
      if (!row.sms_ok) return json(env, { error: "Önce SMS doğrulamasını tamamla." }, 403);
      if (provided !== row.email_hash) {
        await env.DB.prepare("UPDATE otp_challenges SET attempts = attempts + 1 WHERE challenge_hash = ?").bind(ch).run();
        return json(env, { error: "E-posta kodu hatalı." }, 401);
      }
      await env.DB.prepare("DELETE FROM otp_challenges WHERE challenge_hash = ?").bind(ch).run();
      await audit(env, String(claims.sub), "admin_login_success");
      const adminToken = await signToken(env, { sub: claims.sub, scope: "admin", exp: Math.floor(Date.now() / 1000) + 60 * 60 * 2 });
      return json(env, { ok: true, role: "admin", token: adminToken });
    }

    if (url.pathname === "/api/me" && request.method === "GET") {
      const claims = await verifyToken(env, bearer(request));
      if (!claims || !["user", "admin"].includes(String(claims.scope))) return json(env, { authenticated: false }, 401);
      return json(env, { authenticated: true, id: claims.sub, role: claims.scope });
    }

    if (url.pathname === "/api/admin/events" && request.method === "GET") {
      const claims = await verifyToken(env, bearer(request));
      if (!claims || claims.scope !== "admin" || claims.sub !== env.ADMIN_DISCORD_ID) return json(env, { error: "Yetkisiz." }, 403);
      const rows = await env.DB.prepare("SELECT discord_id, event_type, detail, created_at FROM user_events ORDER BY created_at DESC LIMIT 200").all();
      return json(env, { events: rows.results });
    }

    if (url.pathname === "/auth/logout" && request.method === "POST") return json(env, { ok: true });
    return json(env, { error: "Not found" }, 404);
  },
};
