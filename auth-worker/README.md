# WARTEX Auth API (Cloudflare Worker)

This is a backend scaffold for the WARTEX Discord sign-in and admin step-up flow. It is deliberately on the `feature/admin-auth` branch; the live GitHub Pages `index.html` has not been changed.

## Required setup
1. Create a Cloudflare D1 database named `wartex-auth-db`, run `schema.sql`, then put its ID into `wrangler.toml`.
2. Create a Discord OAuth2 application. Set its redirect URL to:
   `https://wartex-auth-apiyaz.mustimoruk11.workers.dev/auth/callback`
3. Set Worker variables/secrets (never commit values):
   - `SITE_URL` (the current WARTEX website origin, e.g. `https://trwartexhub.github.io` only if that is the exact live origin)
   - `DISCORD_CLIENT_ID`, secret `DISCORD_CLIENT_SECRET`
   - `ADMIN_DISCORD_ID` = the administrator's Discord user ID
   - `ADMIN_PASSWORD_HASH` = PBKDF2 format `pbkdf2$iterations$base64url_salt$base64url_hash` (iterations >= 310000; generate locally, do not send password to chat)
   - `SESSION_SECRET` (random 32+ bytes), `KEY_PEPPER` (different random secret)
   - `ADMIN_PHONE`, `ADMIN_EMAIL`
   - `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM`
   - `RESEND_API_KEY`, `EMAIL_FROM` (verified sender domain required)
4. Configure D1 and deploy only after secrets are set. Do not enable Cloudflare Access for the whole Worker; app routes need to be publicly reachable.
5. Generate an admin key locally and insert only its hash into D1. Hash is SHA-256 base64url of `KEY_PEPPER + trimmed_key`; store `expires_at` as Unix milliseconds, `created_at` as Unix milliseconds, `used_at` as NULL. Never store the raw key in D1 or source control.
6. Frontend integration is a separate next step. The current API returns short-lived tokens intended to be held in memory/session storage; do not store admin tokens in localStorage. For production, use a custom domain/same-site cookie architecture if possible. Current GitHub Pages origin + workers.dev is cross-site and browser third-party cookie behavior varies.

## Endpoints
- `GET /health`
- `GET /auth/discord`
- `GET /auth/callback`
- `POST /auth/exchange` with JSON `{"code":"..."}`
- `POST /admin/verify-credentials` with bearer admin-flow token and JSON `{"password":"...","key":"..."}`
- `POST /admin/verify-sms` and `POST /admin/verify-email` with bearer step token and JSON `{"code":"123456"}`
- `GET /api/me`
- `GET /api/admin/events` (admin token only)

## Notes
- User activity tracking currently logs Discord sign-ins only. Add explicit opt-in analytics and data minimization before tracking browsing behavior.
- This scaffold must be security-reviewed and tested before production use. Add rate limiting, alerting, cleanup for expired rows, and stronger transactional protections before issuing real admin keys.
- SMS and email require active Twilio/Resend accounts and verified sender configuration; this code does not send messages until those secrets are configured.
