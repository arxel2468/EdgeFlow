import { Hono } from 'hono'

type Env = {
  DB: D1Database
  APP_URL: string
  COOKIE_NAME: string
  ENV?: string                    // 'dev' for local
  EMAIL_PROVIDER?: 'console' | 'resend'
  RESEND_API_KEY?: string
  EMAIL_FROM?: string
}

const app = new Hono<{ Bindings: Env}>({strict: false})

// --- utils ---
const now = () => Math.floor(Date.now() / 1000)
const expIn = (minutes: number) => now() + minutes * 60

const b64url = (buf: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

function randomToken(len = 32) {
  const bytes = new Uint8Array(len)
  crypto.getRandomValues(bytes)
  return b64url(bytes.buffer)
}

async function sha256(text: string) {
  const enc = new TextEncoder()
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(text))
  return b64url(digest)
}

function makeSessionCookie(name: string, value: string, maxAgeSec: number, env: Env) {
  const parts = [
    `${name}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSec}`,
  ]
  if (env.ENV !== 'dev') parts.push('Secure') // not Secure on http:// local
  return parts.join('; ')
}

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

async function sendEmail(env: Env, to: string, subject: string, html: string) {
  if (env.EMAIL_PROVIDER === 'resend' && env.RESEND_API_KEY) {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: env.EMAIL_FROM || 'EdgeFlow <onboarding@resend.dev>',
        to, subject, html,
      }),
    })
    if (!res.ok) {
      const txt = await res.text()
      console.error('Resend error', res.status, txt)
      throw new Error('Failed to send email')
    }
  } else {
    // dev -> just log
    console.log('DEV email to:', to, subject, html)
  }
}

async function getUserByEmail(DB: D1Database, email: string) {
  return DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first()
}

async function createUser(DB: D1Database, email: string) {
  const id = crypto.randomUUID()
  await DB.prepare('INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)')
    .bind(id, email, now()).run()
  return { id, email }
}

async function createSession(DB: D1Database, userId: string, ttlSec: number) {
  const id = randomToken(32)
  await DB.prepare('INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(id, userId, now(), now() + ttlSec).run()
  return id
}

async function getSession(DB: D1Database, id: string) {
  return DB.prepare(
    'SELECT s.*, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > ?'
  ).bind(id, now()).first()
}

async function getAuthed(c: any) {
	const cookie = c.req.header('Cookie') || ''
	const name = c.env.COOKIE_NAME
	const match = cookie.match(new RegExp(`${name}=([^;]+)`))
	const sid = match?.[1]
	if (!sid) return null
	const sess: any = await getSession(c.env.DB, sid)
	if (!sess) return null
	return { userId: sess.user_id as string, email: sess.email as string }
  }

// --- routes ---
app.get('/', (c) => c.text('EdgeFlow API'))
app.get('/health', (c) => c.json({ ok: true, ts: Date.now() }))

// 1) request magic link
app.post('/auth/magic/request', async (c) => {
  const body = await c.req.json().catch(() => ({} as any))
  const email = (body.email || '').toString().trim().toLowerCase()
  const redirect_to = (body.redirect_to || '/').toString()

  if (!emailRegex.test(email)) {
    return c.json({ ok: false, error: 'Invalid email' }, 400)
  }

  const token = randomToken(32)
  const tokenHash = await sha256(token)
  const id = crypto.randomUUID()
  const expires = expIn(15)

  await c.env.DB.prepare(
    'INSERT INTO magic_links (id, email, token_hash, created_at, expires_at, used, redirect_to) VALUES (?, ?, ?, ?, ?, 0, ?)'
  ).bind(id, email, tokenHash, now(), expires, redirect_to).run()

  const link = new URL('/auth/magic/verify', c.env.APP_URL)
  link.searchParams.set('id', id)
  link.searchParams.set('token', token)

  await sendEmail(
    c.env,
    email,
    'Your EdgeFlow sign-in link',
    `Click <a href="${link.toString()}">Sign in</a>. Link expires in 15 minutes.`
  )

  // console mode: return the link to make dev easy
  const devLink = c.env.EMAIL_PROVIDER === 'console' ? link.toString() : undefined
  return c.json({ ok: true, devLink })
})

// 2) verify magic link
app.get('/auth/magic/verify', async (c) => {
  const id = c.req.query('id') || ''
  const token = c.req.query('token') || ''
  if (!id || !token) return c.text('Invalid link', 400)

  const row: any = await c.env.DB.prepare('SELECT * FROM magic_links WHERE id = ?').bind(id).first()
  if (!row) return c.text('Link not found', 404)
  if (row.used) return c.text('Link already used', 400)
  if (row.expires_at <= now()) return c.text('Link expired', 400)

  const tokenHash = await sha256(token)
  if (tokenHash !== row.token_hash) return c.text('Invalid token', 400)

  let user: any = await getUserByEmail(c.env.DB, row.email)
  if (!user) user = await createUser(c.env.DB, row.email)

  // 7 days session
  const sessionId = await createSession(c.env.DB, user.id, 7 * 24 * 3600)
  const cookie = makeSessionCookie(c.env.COOKIE_NAME, sessionId, 7 * 24 * 3600, c.env)

  await c.env.DB.prepare('UPDATE magic_links SET used = 1 WHERE id = ?').bind(id).run()

  const redirectTo = row.redirect_to || '/'
  return new Response(null, { status: 302, headers: { 'Set-Cookie': cookie, 'Location': redirectTo } })
})

// 3) whoami
app.get('/me', async (c) => {
  const cookie = c.req.header('Cookie') || ''
  const name = c.env.COOKIE_NAME
  const match = cookie.match(new RegExp(`${name}=([^;]+)`))
  const sid = match?.[1]
  if (!sid) return c.json({ authenticated: false })

  const sess: any = await getSession(c.env.DB, sid)
  if (!sess) return c.json({ authenticated: false })

  return c.json({ authenticated: true, email: sess.email })
})


app.post('/flows', async (c) => {
	const auth = await getAuthed(c)
	if (!auth) return c.json({ ok: false, error: 'Unauthorized' }, 401)
	
	const body = await c.req.json().catch(() => ({} as any))
	const name = (body.name || '').toString().trim()
	const trigger_type = (body.trigger_type || 'webhook').toString()
	
	if (!name) return c.json({ ok: false, error: 'Name is required' }, 400)
	if (!['webhook', 'cron'].includes(trigger_type)) {
	return c.json({ ok: false, error: 'Invalid trigger_type' }, 400)
	}
	
	const id = crypto.randomUUID()
	const secret = trigger_type === 'webhook' ? randomToken(24) : null
	const cron = trigger_type === 'cron' ? (body.cron || '').toString() : null
	const ts = Math.floor(Date.now() / 1000)
	
	await c.env.DB.prepare(
	'INSERT INTO flows (id, user_id, name, trigger_type, trigger_secret, cron, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
	).bind(id, auth.userId, name, trigger_type, secret, cron, ts, ts).run()
	
	const webhook_url =
	trigger_type === 'webhook'
	? new URL(`/t/${id}/${secret}`, c.env.APP_URL).toString()
	: null
	
	return c.json({ ok: true, flow: { id, name, trigger_type, webhook_url } })
})

app.get('/flows', async (c) => {
	const auth = await getAuthed(c)
	if (!auth) return c.json({ ok: false, error: 'Unauthorized' }, 401)
	
	const res = await c.env.DB.prepare(
	'SELECT id, name, trigger_type, trigger_secret, created_at, updated_at FROM flows WHERE user_id = ? ORDER BY created_at DESC'
	).bind(auth.userId).all()
	
	const flows = (res.results || []).map((r: any) => ({
	id: r.id,
	name: r.name,
	trigger_type: r.trigger_type,
	created_at: r.created_at,
	updated_at: r.updated_at,
	webhook_url:
	r.trigger_type === 'webhook'
	? new URL(`/t/${r.id}/${r.trigger_secret}`, c.env.APP_URL).toString()
	: null,
	}))
	return c.json({ ok: true, flows })
})

export default app