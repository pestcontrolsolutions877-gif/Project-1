// Skytech CRM backend for Cloudflare Workers + D1.
// Replaces the Netlify Identity login and the Netlify functions (/api/*).

const STATUSES = ['Scheduled', 'Attended', 'Completed', 'Cancelled', 'No-show', 'Client Declined', 'Reschedule', 'Unreachable', 'Follow up', 'Not Interested', 'Phone call Quote'];
const ACCESS_TTL = 3600; // access token lifetime, seconds
const IDENTITY = '/.netlify/identity';
const enc = new TextEncoder();

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT, is_admin INTEGER NOT NULL DEFAULT 0,
    confirmed_at TEXT, invited_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS auth_tokens (
    token TEXT PRIMARY KEY, user_id TEXT NOT NULL, type TEXT NOT NULL, expires_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '', service TEXT NOT NULL, date TEXT NOT NULL, time TEXT NOT NULL DEFAULT '09:00',
    status TEXT NOT NULL DEFAULT 'Scheduled', remarks TEXT NOT NULL DEFAULT '', feedback TEXT NOT NULL DEFAULT '',
    rating INTEGER, feedback_key TEXT NOT NULL UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    client_remarks TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', customer_name TEXT NOT NULL DEFAULT '')`,
  `CREATE INDEX IF NOT EXISTS appointments_owner ON appointments(owner)`,
  `CREATE TABLE IF NOT EXISTS client_access (
    key TEXT PRIMARY KEY, owner TEXT NOT NULL, email TEXT NOT NULL, invitation_sent_at TEXT,
    UNIQUE(owner, email))`,
  `CREATE TABLE IF NOT EXISTS removed_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, client_key TEXT NOT NULL, UNIQUE(owner, client_key))`,
];

let schemaReady = null;
let secretCache = null;

// ---------- small helpers ----------
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff', ...headers } });
const fail = (error, status = 400) => json({ error, msg: error }, status);
class HttpError extends Error { constructor(message, status = 400) { super(message); this.status = status; } }

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uToBytes = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0));
const randomToken = (bytes = 24) => b64u(crypto.getRandomValues(new Uint8Array(bytes)));
const now = () => new Date().toISOString();
const lower = (s) => String(s ?? '').trim().toLowerCase();
const text = (v, max = 500) => String(v ?? '').trim().slice(0, max);

async function ensureReady(env) {
  schemaReady ||= (async () => {
    await env.DB.batch(SCHEMA.map((sql) => env.DB.prepare(sql)));
    let row = await env.DB.prepare(`SELECT v FROM settings WHERE k='jwt_secret'`).first();
    if (!row) {
      await env.DB.prepare(`INSERT OR IGNORE INTO settings (k, v) VALUES ('jwt_secret', ?)`).bind(randomToken(48)).run();
      row = await env.DB.prepare(`SELECT v FROM settings WHERE k='jwt_secret'`).first();
    }
    secretCache = env.JWT_SECRET || row.v;
  })().catch((e) => { schemaReady = null; throw e; });
  return schemaReady;
}

// ---------- passwords + JWT ----------
async function hashPassword(password, saltB64) {
  const salt = saltB64 ? b64uToBytes(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, key, 256);
  return `${b64u(salt)}.${b64u(bits)}`;
}
async function verifyPassword(password, stored) {
  if (!stored) return false;
  const [salt, hash] = stored.split('.');
  const check = await hashPassword(password, salt);
  const a = enc.encode(check), b = enc.encode(`${salt}.${hash}`);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
async function hmacKey() {
  return crypto.subtle.importKey('raw', enc.encode(secretCache), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function signJwt(user) {
  const header = b64u(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const iat = Math.floor(Date.now() / 1000);
  const payload = b64u(enc.encode(JSON.stringify({
    sub: user.id, email: user.email, iat, exp: iat + ACCESS_TTL,
    app_metadata: { provider: 'email', roles: user.is_admin ? ['admin'] : [] }, user_metadata: {},
  })));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(), enc.encode(`${header}.${payload}`));
  return `${header}.${payload}.${b64u(sig)}`;
}
async function verifyJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(), b64uToBytes(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`));
    if (!ok) return null;
    const claims = JSON.parse(new TextDecoder().decode(b64uToBytes(parts[1])));
    return claims.exp > Math.floor(Date.now() / 1000) ? claims : null;
  } catch { return null; }
}

// ---------- users / sessions ----------
const userJson = (u) => ({
  id: u.id, aud: '', role: '', email: u.email, confirmed_at: u.confirmed_at || undefined, invited_at: u.invited_at || undefined,
  app_metadata: { provider: 'email', roles: u.is_admin ? ['admin'] : [] }, user_metadata: {},
  created_at: u.created_at, updated_at: u.updated_at,
});
const getUserByEmail = (env, email) => env.DB.prepare(`SELECT * FROM users WHERE email=?`).bind(lower(email)).first();
const getUserById = (env, id) => env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(id).first();

async function tokenResponse(env, user, request) {
  const refresh = randomToken(32);
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM auth_tokens WHERE type='refresh' AND expires_at < ?`).bind(Math.floor(Date.now() / 1000)),
    env.DB.prepare(`INSERT INTO auth_tokens (token, user_id, type, expires_at) VALUES (?,?,'refresh',?)`)
      .bind(refresh, user.id, Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 60),
  ]);
  const access = await signJwt(user);
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  const headers = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'private, no-store' });
  headers.append('Set-Cookie', `nf_jwt=${access}; Path=/; SameSite=Lax${secure}`);
  headers.append('Set-Cookie', `nf_refresh=${refresh}; Path=/; SameSite=Lax${secure}`);
  return new Response(JSON.stringify({ access_token: access, token_type: 'bearer', expires_in: ACCESS_TTL, refresh_token: refresh, ...userJson(user) }), { status: 200, headers });
}

function getCookie(request, name) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  if (!m) return null;
  try { return decodeURIComponent(m[1]); } catch { return m[1]; }
}
async function currentUser(env, request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : getCookie(request, 'nf_jwt');
  const claims = await verifyJwt(token);
  if (!claims) return null;
  return getUserById(env, claims.sub);
}
async function requireUser(env, request) {
  const user = await currentUser(env, request);
  if (!user) throw new HttpError('Please sign in to continue.', 401);
  return user;
}
async function requireStaff(env, request) {
  const user = await requireUser(env, request);
  if (!user.is_admin) throw new HttpError('This account does not have workspace access.', 403);
  return user;
}

// ---------- email (optional, via Resend) ----------
async function sendMail(env, to, subject, html) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM) return false;
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST', headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, html }),
  });
  return r.ok;
}
async function makeToken(env, userId, type, hours) {
  const token = randomToken(32);
  await env.DB.prepare(`INSERT INTO auth_tokens (token, user_id, type, expires_at) VALUES (?,?,?,?)`)
    .bind(token, userId, type, Math.floor(Date.now() / 1000) + hours * 3600).run();
  return token;
}

// ---------- GoTrue-compatible login endpoints ----------
async function identity(request, env, path) {
  const method = request.method;
  if (path === '/settings' && method === 'GET') {
    return json({ external: { email: true }, disable_signup: false, autoconfirm: true, mailer_autoconfirm: true });
  }

  if (path === '/signup' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const email = lower(body.email), password = String(body.password || '');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return fail('Enter a valid email address.', 422);
    if (password.length < 8) return fail('Password must be at least 8 characters.', 422);
    const count = (await env.DB.prepare(`SELECT COUNT(*) AS n FROM users WHERE is_admin=1`).first()).n;
    if (count > 0 && String(env.ALLOW_SIGNUP).toLowerCase() !== 'true') {
      return fail('Sign-ups are closed. Ask the workspace owner for access.', 403);
    }
    if (await getUserByEmail(env, email)) return fail('A user with this email address has already been registered.', 422);
    const ts = now();
    const user = { id: crypto.randomUUID(), email, is_admin: 1, confirmed_at: ts, invited_at: null, created_at: ts, updated_at: ts };
    await env.DB.prepare(`INSERT INTO users (id,email,password_hash,is_admin,confirmed_at,created_at,updated_at) VALUES (?,?,?,1,?,?,?)`)
      .bind(user.id, email, await hashPassword(password), ts, ts, ts).run();
    return tokenResponse(env, user, request);
  }

  if (path === '/token' && method === 'POST') {
    const form = new URLSearchParams(await request.text());
    if (form.get('grant_type') === 'refresh_token') {
      const row = await env.DB.prepare(`SELECT * FROM auth_tokens WHERE token=? AND type='refresh'`).bind(form.get('refresh_token') || '').first();
      if (!row || row.expires_at < Math.floor(Date.now() / 1000)) return json({ error: 'invalid_grant', error_description: 'Invalid refresh token', msg: 'Invalid refresh token' }, 400);
      const user = await getUserById(env, row.user_id);
      if (!user) return json({ error: 'invalid_grant', error_description: 'Invalid refresh token', msg: 'Invalid refresh token' }, 400);
      await env.DB.prepare(`DELETE FROM auth_tokens WHERE token=?`).bind(row.token).run();
      return tokenResponse(env, user, request);
    }
    const email = lower(form.get('username')), password = form.get('password') || '';
    const user = await getUserByEmail(env, email);
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return json({ error: 'invalid_grant', error_description: 'No user found with that email, or password invalid.', msg: 'No user found with that email, or password invalid.' }, 400);
    }
    return tokenResponse(env, user, request);
  }

  if (path === '/user' && method === 'GET') {
    const user = await requireUser(env, request);
    return json(userJson(user));
  }

  if (path === '/user' && method === 'PUT') {
    const user = await requireUser(env, request);
    const body = await request.json().catch(() => ({}));
    if (body.password !== undefined) {
      if (String(body.password).length < 8) return fail('Password must be at least 8 characters.', 422);
      await env.DB.prepare(`UPDATE users SET password_hash=?, updated_at=? WHERE id=?`).bind(await hashPassword(String(body.password)), now(), user.id).run();
    }
    return json(userJson(await getUserById(env, user.id)));
  }

  if (path === '/logout' && method === 'POST') {
    const refresh = getCookie(request, 'nf_refresh');
    if (refresh) await env.DB.prepare(`DELETE FROM auth_tokens WHERE token=?`).bind(refresh).run();
    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', 'nf_jwt=; Path=/; Max-Age=0');
    headers.append('Set-Cookie', 'nf_refresh=; Path=/; Max-Age=0');
    return new Response('{}', { status: 200, headers });
  }

  if (path === '/recover' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const user = await getUserByEmail(env, body.email);
    if (user) {
      const token = await makeToken(env, user.id, 'recovery', 1);
      const link = `${new URL(request.url).origin}/calendar/mine#recovery_token=${token}`;
      await sendMail(env, user.email, 'Reset your Skytech password', `<p>Use this link to set a new password (valid for 1 hour):</p><p><a href="${link}">${link}</a></p>`);
    }
    return json({}); // same answer whether or not the account exists
  }

  if (path === '/verify' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const row = await env.DB.prepare(`SELECT * FROM auth_tokens WHERE token=? AND type IN ('invite','recovery')`).bind(String(body.token || '')).first();
    if (!row || row.expires_at < Math.floor(Date.now() / 1000)) return fail('This link is invalid or has expired.', 400);
    const user = await getUserById(env, row.user_id);
    if (!user) return fail('This link is invalid or has expired.', 400);
    if (row.type === 'invite') {
      const password = String(body.password || '');
      if (password.length < 8) return fail('Password must be at least 8 characters.', 422);
      await env.DB.prepare(`UPDATE users SET password_hash=?, confirmed_at=COALESCE(confirmed_at, ?), updated_at=? WHERE id=?`)
        .bind(await hashPassword(password), now(), now(), user.id).run();
    }
    await env.DB.prepare(`DELETE FROM auth_tokens WHERE token=?`).bind(row.token).run();
    return tokenResponse(env, await getUserById(env, user.id), request);
  }

  return fail('Not found', 404);
}

// ---------- appointments ----------
const rowToAppointment = (r, withKey = true) => {
  const a = {
    id: r.id, name: r.name, customerName: r.customer_name, email: r.email, phone: r.phone, address: r.address,
    service: r.service, date: r.date, time: r.time, status: r.status, remarks: r.remarks,
    clientRemarks: r.client_remarks, feedback: r.feedback, rating: r.rating,
  };
  if (withKey) a.feedbackKey = r.feedback_key;
  return a;
};
function cleanAppointment(input, partial = false) {
  const o = {};
  const fields = { name: 200, customerName: 200, email: 200, phone: 60, address: 500, service: 200, date: 10, time: 5, status: 40, remarks: 5000 };
  for (const [k, max] of Object.entries(fields)) {
    if (input[k] !== undefined) o[k] = text(input[k], max);
  }
  if (!partial) { o.time ||= '09:00'; o.status ||= 'Scheduled'; o.email ||= ''; }
  if (!partial || o.name !== undefined) if (!o.name) throw new HttpError('Client name is required.');
  if (!partial || o.service !== undefined) if (!o.service) throw new HttpError('Service is required.');
  if (!partial || o.date !== undefined) if (!/^\d{4}-\d{2}-\d{2}$/.test(o.date || '')) throw new HttpError('Date must be in YYYY-MM-DD format.');
  if (o.time !== undefined && o.time !== '' && !/^\d{2}:\d{2}$/.test(o.time)) throw new HttpError('Time must be in HH:MM format.');
  if (o.status !== undefined && !STATUSES.includes(o.status)) throw new HttpError('Unknown appointment status.');
  if (o.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(o.email)) throw new HttpError('Enter a valid client email address.');
  return o;
}
const COLS = { name: 'name', customerName: 'customer_name', email: 'email', phone: 'phone', address: 'address', service: 'service', date: 'date', time: 'time', status: 'status', remarks: 'remarks' };

// Public feedback link (no login needed; the long random key is the credential)
async function feedbackApi(request, env, url) {
  const q = url.searchParams, m = request.method;
  const a = await env.DB.prepare(`SELECT * FROM appointments WHERE feedback_key=?`).bind(q.get('feedback')).first();
  if (!a) throw new HttpError('This feedback link is not valid.', 404);
  if (m === 'GET') return json({ service: a.service, date: a.date, submitted: a.rating !== null });
  if (m === 'POST') {
    if (a.rating !== null) throw new HttpError('Feedback has already been submitted for this appointment.', 409);
    const b = await request.json().catch(() => ({}));
    const rating = Number(b.rating), feedback = text(b.feedback, 5000);
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) throw new HttpError('Please choose a rating from 1 to 5.');
    if (!feedback) throw new HttpError('Please add your feedback.');
    await env.DB.prepare(`UPDATE appointments SET rating=?, feedback=? WHERE id=? AND rating IS NULL`).bind(rating, feedback, a.id).run();
    return json({ submitted: true });
  }
  throw new HttpError('Method not allowed.', 405);
}

async function appointmentsApi(request, env, url) {
  if (url.searchParams.has('feedback')) return feedbackApi(request, env, url);
  const user = await requireStaff(env, request);
  const owner = user.email;
  const id = Number(url.searchParams.get('id'));
  const m = request.method;

  if (m === 'GET') {
    const { results } = await env.DB.prepare(`SELECT * FROM appointments WHERE owner=? ORDER BY date DESC, time DESC, id DESC`).bind(owner).all();
    return json(results.map((r) => rowToAppointment(r)));
  }
  if (m === 'POST') {
    const body = await request.json().catch(() => null);
    if (!Array.isArray(body) || !body.length) throw new HttpError('Send at least one appointment.');
    if (body.length > 1000) throw new HttpError('Upload up to 1,000 appointments at a time.');
    const rows = body.map((b) => cleanAppointment(b || {}));
    const keys = rows.map(() => randomToken(18));
    const stmts = rows.map((o, i) => env.DB.prepare(
      `INSERT INTO appointments (owner,name,customer_name,email,phone,address,service,date,time,status,remarks,feedback_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(owner, o.name, o.customerName || '', o.email || '', o.phone || '', o.address || '', o.service, o.date, o.time, o.status, o.remarks || '', keys[i]));
    await env.DB.batch(stmts);
    const { results } = await env.DB.prepare(`SELECT * FROM appointments WHERE owner=? AND feedback_key IN (${keys.map(() => '?').join(',')}) ORDER BY id DESC`).bind(owner, ...keys).all();
    return json(results.map((r) => rowToAppointment(r)), 201);
  }
  if (!id) throw new HttpError('Missing appointment id.');
  const existing = await env.DB.prepare(`SELECT * FROM appointments WHERE id=? AND owner=?`).bind(id, owner).first();
  if (!existing) throw new HttpError('Appointment not found.', 404);
  if (m === 'PATCH') {
    const o = cleanAppointment(await request.json().catch(() => ({})), true);
    const sets = Object.keys(o).filter((k) => COLS[k]);
    if (sets.length) {
      await env.DB.prepare(`UPDATE appointments SET ${sets.map((k) => `${COLS[k]}=?`).join(', ')} WHERE id=? AND owner=?`).bind(...sets.map((k) => o[k]), id, owner).run();
    }
    return json(rowToAppointment(await env.DB.prepare(`SELECT * FROM appointments WHERE id=?`).bind(id).first()));
  }
  if (m === 'DELETE') {
    await env.DB.prepare(`DELETE FROM appointments WHERE id=? AND owner=?`).bind(id, owner).run();
    return json({ ok: true });
  }
  throw new HttpError('Method not allowed.', 405);
}

// ---------- clients (profile removal / restore) ----------
const clientKey = (r) => (r.email.trim() ? 'email:' + r.email.trim().toLowerCase() : 'name:' + r.name);

async function clientsApi(request, env, url) {
  const user = await requireStaff(env, request);
  const owner = user.email;
  if (request.method === 'GET') {
    const { results } = await env.DB.prepare(`SELECT client_key FROM removed_clients WHERE owner=?`).bind(owner).all();
    return json(results.map((r) => r.client_key));
  }
  const id = Number(url.searchParams.get('id'));
  const a = id && await env.DB.prepare(`SELECT * FROM appointments WHERE id=? AND owner=?`).bind(id, owner).first();
  if (!a) throw new HttpError('Client not found.', 404);
  const key = clientKey(a);
  if (request.method === 'DELETE') {
    const stmts = [env.DB.prepare(`INSERT OR IGNORE INTO removed_clients (owner, client_key) VALUES (?,?)`).bind(owner, key)];
    if (a.email.trim()) stmts.push(env.DB.prepare(`DELETE FROM client_access WHERE owner=? AND email=?`).bind(owner, lower(a.email)));
    await env.DB.batch(stmts);
    return json({ key });
  }
  if (request.method === 'POST') {
    await env.DB.prepare(`DELETE FROM removed_clients WHERE owner=? AND client_key=?`).bind(owner, key).run();
    return json({ key });
  }
  throw new HttpError('Method not allowed.', 405);
}

// ---------- workspace access ----------
async function workspaceAccess(request, env) {
  const user = await currentUser(env, request);
  return json({ client: !!user && !user.is_admin });
}

// ---------- client calendar + feedback ----------
async function clientCalendarApi(request, env, url) {
  const q = url.searchParams;
  const m = request.method;

  if (q.has('feedback')) return feedbackApi(request, env, url);

  // Staff: manage a client's calendar access
  if (q.has('email')) {
    const staff = await requireStaff(env, request);
    const owner = staff.email, email = lower(q.get('email'));
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new HttpError('Enter a valid client email address.');
    let grant = await env.DB.prepare(`SELECT * FROM client_access WHERE owner=? AND email=?`).bind(owner, email).first();

    if (m === 'GET') return json({ key: grant ? grant.key : null });
    if (m === 'DELETE') {
      await env.DB.prepare(`DELETE FROM client_access WHERE owner=? AND email=?`).bind(owner, email).run();
      return json({ key: null });
    }
    if (m === 'POST') {
      const invite = q.get('invite') === '1';
      if (!grant) {
        const key = randomToken(24);
        await env.DB.prepare(`INSERT INTO client_access (key, owner, email) VALUES (?,?,?)`).bind(key, owner, email).run();
        grant = { key };
      }
      await env.DB.prepare(`DELETE FROM removed_clients WHERE owner=? AND client_key=?`).bind(owner, 'email:' + email).run();

      // Make sure the client has a way to sign in
      let client = await getUserByEmail(env, email);
      let setupLink = null;
      if (client && client.is_admin) {
        return json({ key: grant.key, warning: 'This email belongs to a workspace owner account. Use a different email for the client.' });
      }
      if (!client || !client.password_hash) {
        const ts = now();
        if (!client) {
          const id = crypto.randomUUID();
          await env.DB.prepare(`INSERT INTO users (id,email,password_hash,is_admin,confirmed_at,invited_at,created_at,updated_at) VALUES (?,?,NULL,0,NULL,?,?,?)`).bind(id, email, ts, ts, ts).run();
          client = { id };
        }
        const token = await makeToken(env, client.id, 'invite', 24 * 7);
        setupLink = `${new URL(request.url).origin}/calendar/mine#invite_token=${token}`;
      }
      let invited = false;
      if (invite) {
        const link = setupLink || `${new URL(request.url).origin}/calendar/${grant.key}`;
        invited = await sendMail(env, email, 'Your Skytech service calendar',
          `<p>Your Skytech appointments are ready to view.</p><p><a href="${link}">${setupLink ? 'Create your password and open your calendar' : 'Open your calendar'}</a></p>`);
        if (invited) await env.DB.prepare(`UPDATE client_access SET invitation_sent_at=? WHERE key=?`).bind(now(), grant.key).run();
      }
      if (setupLink && !invited) {
        return json({ key: grant.key, warning: `Email sending is not set up, so no email was sent. Send this client the setup link so they can create a password (valid 7 days): ${setupLink} — after that they can open their calendar link.` });
      }
      if (invite && !invited) {
        return json({ key: grant.key, warning: 'Email sending is not set up, so no email was sent. Share the calendar link with the client; they sign in with their email and password.' });
      }
      return json({ key: grant.key, invited });
    }
    throw new HttpError('Method not allowed.', 405);
  }

  // Client (signed in): view and update their own appointments
  if (q.has('key')) {
    const user = await requireUser(env, request);
    const email = lower(user.email);
    const key = q.get('key');
    let grants;
    if (key === 'mine') {
      grants = (await env.DB.prepare(`SELECT * FROM client_access WHERE email=?`).bind(email).all()).results;
    } else {
      const g = await env.DB.prepare(`SELECT * FROM client_access WHERE key=?`).bind(key).first();
      if (g && g.email !== email) throw new HttpError('This calendar was shared with a different email address. Sign in with that email.', 403);
      grants = g ? [g] : [];
    }
    if (!grants.length) throw new HttpError('No calendar access has been granted for this email. Ask Skytech to grant access.', 403);
    const owners = grants.map((g) => g.owner);
    const ph = owners.map(() => '?').join(',');

    if (m === 'GET') {
      const { results } = await env.DB.prepare(`SELECT * FROM appointments WHERE owner IN (${ph}) AND lower(email)=? ORDER BY date DESC, time DESC, id DESC`).bind(...owners, email).all();
      return json(results.map((r) => rowToAppointment(r, false)));
    }
    if (m === 'POST') {
      const b = await request.json().catch(() => ({}));
      const a = await env.DB.prepare(`SELECT * FROM appointments WHERE id=? AND owner IN (${ph}) AND lower(email)=?`).bind(Number(b.id), ...owners, email).first();
      if (!a) throw new HttpError('Appointment not found.', 404);
      if (b.status !== undefined) {
        if (!STATUSES.includes(b.status)) throw new HttpError('Unknown appointment status.');
        await env.DB.prepare(`UPDATE appointments SET status=? WHERE id=?`).bind(b.status, a.id).run();
      }
      if (b.clientRemarks !== undefined) {
        await env.DB.prepare(`UPDATE appointments SET client_remarks=? WHERE id=?`).bind(text(b.clientRemarks, 5000), a.id).run();
      }
      return json(rowToAppointment(await env.DB.prepare(`SELECT * FROM appointments WHERE id=?`).bind(a.id).first(), false));
    }
    throw new HttpError('Method not allowed.', 405);
  }
  throw new HttpError('Bad request.');
}

// ---------- entry point ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    const isApi = p.startsWith('/api/');
    const isIdentity = p.startsWith(IDENTITY + '/');
    if (!isApi && !isIdentity) return env.ASSETS.fetch(request);
    try {
      if (!env.DB) throw new HttpError('The database is not connected. Add a D1 binding named DB.', 500);
      await ensureReady(env);
      if (isIdentity) return await identity(request, env, p.slice(IDENTITY.length));
      if (p === '/api/appointments') return await appointmentsApi(request, env, url);
      if (p === '/api/clients') return await clientsApi(request, env, url);
      if (p === '/api/workspace-access') return await workspaceAccess(request, env);
      if (p === '/api/client-calendar') return await clientCalendarApi(request, env, url);
      return fail('Not found', 404);
    } catch (e) {
      if (e instanceof HttpError) return fail(e.message, e.status);
      console.error(e);
      return fail('Something went wrong. Please try again.', 500);
    }
  },
};
