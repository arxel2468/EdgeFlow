import { Hono } from 'hono'

type Env = {
	DB: D1Database
	RUNS_QUEUE: any
	APP_URL: string
	COOKIE_NAME: string
	ENV?: string // 'dev' for local
	EMAIL_PROVIDER?: 'console' | 'resend'
	RESEND_API_KEY?: string
	EMAIL_FROM?: string
}

const app = new Hono<{ Bindings: Env }>({ strict: false })

// --- utils ---
const now = () => Math.floor(Date.now() / 1000)
const expIn = (minutes: number) => now() + minutes * 60

const b64url = (buf: ArrayBuffer) =>
	btoa(String.fromCharCode(...new Uint8Array(buf)))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '')

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
	if (env.ENV !== 'dev') parts.push('Secure')
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
				to,
				subject,
				html,
			}),
		})
		if (!res.ok) throw new Error(`Failed to send email: ${await res.text()}`)
	} else {
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

// Auth: request magic link
app.post('/auth/magic/request', async (c) => {
	const body = await c.req.json().catch(() => ({} as any))
	const email = (body.email || '').toString().trim().toLowerCase()
	const redirect_to = (body.redirect_to || '/').toString()
	if (!emailRegex.test(email)) return c.json({ ok: false, error: 'Invalid email' }, 400)

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

	const devLink = c.env.EMAIL_PROVIDER === 'console' ? link.toString() : undefined
	return c.json({ ok: true, devLink })
})

// Auth: verify magic link
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

	const sessionId = await createSession(c.env.DB, user.id, 7 * 24 * 3600)
	const cookie = makeSessionCookie(c.env.COOKIE_NAME, sessionId, 7 * 24 * 3600, c.env)
	await c.env.DB.prepare('UPDATE magic_links SET used = 1 WHERE id = ?').bind(id).run()

	const redirectTo = row.redirect_to || '/'
	return new Response(null, { status: 302, headers: { 'Set-Cookie': cookie, 'Location': redirectTo } })
})

// Whoami
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

// Flows: create
app.post('/flows', async (c) => {
	const auth = await getAuthed(c)
	if (!auth) return c.json({ ok: false, error: 'Unauthorized' }, 401)

	const body = await c.req.json().catch(() => ({} as any))
	const name = (body.name || '').toString().trim()
	const trigger_type = (body.trigger_type || 'webhook').toString()
	if (!name) return c.json({ ok: false, error: 'Name is required' }, 400)
	if (!['webhook', 'cron'].includes(trigger_type)) return c.json({ ok: false, error: 'Invalid trigger_type' }, 400)

	const id = crypto.randomUUID()
	const secret = trigger_type === 'webhook' ? randomToken(24) : null
	const cron = trigger_type === 'cron' ? (body.cron || '').toString() : null
	const ts = now()

	await c.env.DB.prepare(
		'INSERT INTO flows (id, user_id, name, trigger_type, trigger_secret, cron, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
	).bind(id, auth.userId, name, trigger_type, secret, cron, ts, ts).run()

	const webhook_url =
		trigger_type === 'webhook'
			? new URL(`/t/${id}/${secret}`, c.env.APP_URL).toString()
			: null

	return c.json({ ok: true, flow: { id, name, trigger_type, webhook_url } })
})

// Flows: list
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

// Steps: set (replace all steps for a flow)
app.post('/flows/:id/steps', async (c) => {
	const auth = await getAuthed(c)
	if (!auth) return c.json({ ok: false, error: 'Unauthorized' }, 401)
	const flowId = c.req.param('id')

	const flow: any = await c.env.DB.prepare(
		'SELECT user_id FROM flows WHERE id = ?'
	).bind(flowId).first()
	if (!flow) return c.json({ ok: false, error: 'Flow not found' }, 404)
	if (flow.user_id !== auth.userId) return c.json({ ok: false, error: 'Forbidden' }, 403)

	const body = await c.req.json().catch(() => ({} as any))
	const steps = Array.isArray(body.steps) ? body.steps : []
	if (!steps.length) return c.json({ ok: false, error: 'steps[] required' }, 400)

	// naive validate and replace
	await c.env.DB.prepare('DELETE FROM steps WHERE flow_id = ?').bind(flowId).run()
	let idx = 0
	for (const s of steps) {
		const type = (s.type || '').toString()
		if (!['http', 'slack'].includes(type)) {
			return c.json({ ok: false, error: `Unsupported step type: ${type}` }, 400)
		}
		const id = crypto.randomUUID()
		const cfg = JSON.stringify(s.config ?? {})
		await c.env.DB.prepare(
			'INSERT INTO steps (id, flow_id, step_index, type, config, created_at) VALUES (?, ?, ?, ?, ?, ?)'
		).bind(id, flowId, idx, type, cfg, now()).run()
		idx++
	}

	return c.json({ ok: true, count: idx })
})

// Steps: list
app.get('/flows/:id/steps', async (c) => {
	const auth = await getAuthed(c)
	if (!auth) return c.json({ ok: false, error: 'Unauthorized' }, 401)
	const flowId = c.req.param('id')

	const flow: any = await c.env.DB.prepare(
		'SELECT user_id FROM flows WHERE id = ?'
	).bind(flowId).first()
	if (!flow) return c.json({ ok: false, error: 'Flow not found' }, 404)
	if (flow.user_id !== auth.userId) return c.json({ ok: false, error: 'Forbidden' }, 403)

	const res = await c.env.DB.prepare(
		'SELECT id, step_index, type, config, created_at FROM steps WHERE flow_id = ? ORDER BY step_index ASC'
	).bind(flowId).all()

	const steps = (res.results || []).map((r: any) => ({
		id: r.id,
		step_index: r.step_index,
		type: r.type,
		config: (() => { try { return JSON.parse(r.config) } catch { return r.config } })(),
		created_at: r.created_at
	}))
	return c.json({ ok: true, steps })
})

// Webhook trigger: enqueue a run
app.post('/t/:flowId/:secret', async (c) => {
	const { flowId, secret } = c.req.param()
	const flow: any = await c.env.DB.prepare(
		'SELECT id, user_id, trigger_secret, trigger_type FROM flows WHERE id = ?'
	).bind(flowId).first()

	if (!flow || flow.trigger_type !== 'webhook' || flow.trigger_secret !== secret) {
		return c.json({ ok: false, error: 'Not found' }, 404)
	}

	const payload = await c.req.json().catch(() => ({}))
	const runId = crypto.randomUUID()

	await c.env.DB.prepare(
		'INSERT INTO runs (id, flow_id, status, started_at, finished_at, error, input) VALUES (?, ?, ?, ?, ?, ?, ?)'
	).bind(runId, flowId, 'queued', null, null, null, JSON.stringify(payload)).run()

	await c.env.RUNS_QUEUE.send({ runId, flowId, input: payload })
	return c.json({ ok: true, runId }, 202)
})

// Run status
app.get('/runs/:id', async (c) => {
	const auth = await getAuthed(c)
	if (!auth) return c.json({ ok: false, error: 'Unauthorized' }, 401)

	const id = c.req.param('id')
	const row: any = await c.env.DB.prepare(
		'SELECT r.*, f.user_id FROM runs r JOIN flows f ON f.id = r.flow_id WHERE r.id = ?'
	).bind(id).first()

	if (!row || row.user_id !== auth.userId) {
		return c.json({ ok: false, error: 'Not found' }, 404)
	}

	return c.json({
		ok: true,
		run: {
			id: row.id,
			flow_id: row.flow_id,
			status: row.status,
			started_at: row.started_at,
			finished_at: row.finished_at,
			error: row.error,
		}
	})
})

// Run logs
app.get('/runs/:id/logs', async (c) => {
	const auth = await getAuthed(c)
	if (!auth) return c.json({ ok: false, error: 'Unauthorized' }, 401)

	const id = c.req.param('id')
	const owner: any = await c.env.DB.prepare(
		'SELECT f.user_id FROM runs r JOIN flows f ON f.id = r.flow_id WHERE r.id = ?'
	).bind(id).first()
	if (!owner || owner.user_id !== auth.userId) return c.json({ ok: false, error: 'Not found' }, 404)

	const res = await c.env.DB.prepare(
		'SELECT ts, level, message, data FROM run_logs WHERE run_id = ? ORDER BY ts ASC'
	).bind(id).all()

	const logs = (res.results || []).map((r: any) => ({
		ts: r.ts,
		level: r.level,
		message: r.message,
		data: r.data
	}))
	return c.json({ ok: true, logs })
})

app.get('/flows/:id', async (c) => {
	const auth = await getAuthed(c)
	if (!auth) return c.json({ ok: false, error: 'Unauthorized' }, 401)

	const flowId = c.req.param('id')
	const f: any = await c.env.DB.prepare(
		'SELECT id, user_id, name, trigger_type, trigger_secret, created_at, updated_at FROM flows WHERE id = ?'
	).bind(flowId).first()

	if (!f) return c.json({ ok: false, error: 'Flow not found' }, 404)
	if (f.user_id !== auth.userId) return c.json({ ok: false, error: 'Forbidden' }, 403)

	const webhook_url = f.trigger_type === 'webhook'
		? new URL(`/t/${f.id}/${f.trigger_secret}`, c.env.APP_URL).toString()
		: null

	return c.json({
		ok: true,
		flow: {
			id: f.id,
			name: f.name,
			trigger_type: f.trigger_type,
			created_at: f.created_at,
			updated_at: f.updated_at,
			webhook_url
		}
	})
})

app.post('/flows/:id/rotate-secret', async (c) => {
	const auth = await getAuthed(c)
	if (!auth) return c.json({ ok: false, error: 'Unauthorized' }, 401)

	const flowId = c.req.param('id')
	const f: any = await c.env.DB.prepare(
		'SELECT id, user_id, trigger_type FROM flows WHERE id = ?'
	).bind(flowId).first()

	if (!f) return c.json({ ok: false, error: 'Flow not found' }, 404)
	if (f.user_id !== auth.userId) return c.json({ ok: false, error: 'Forbidden' }, 403)
	if (f.trigger_type !== 'webhook') return c.json({ ok: false, error: 'Only webhook flows have secrets' }, 400)

	const newSecret = randomToken(24)
	const ts = now()
	await c.env.DB.prepare(
		'UPDATE flows SET trigger_secret = ?, updated_at = ? WHERE id = ?'
	).bind(newSecret, ts, flowId).run()

	const webhook_url = new URL(`/t/${flowId}/${newSecret}`, c.env.APP_URL).toString()
	return c.json({ ok: true, webhook_url })
})

app.post('/runs/:id/replay', async (c) => {
	const auth = await getAuthed(c)
	if (!auth) return c.json({ ok: false, error: 'Unauthorized' }, 401)

	const id = c.req.param('id')
	const row: any = await c.env.DB.prepare(
		'SELECT r.input, r.flow_id, f.user_id FROM runs r JOIN flows f ON f.id = r.flow_id WHERE r.id = ?'
	).bind(id).first()

	if (!row) return c.json({ ok: false, error: 'Run not found' }, 404)
	if (row.user_id !== auth.userId) return c.json({ ok: false, error: 'Forbidden' }, 403)

	let input: any = null
	try { input = row.input ? JSON.parse(row.input) : null } catch { input = null }

	const newRunId = crypto.randomUUID()
	await c.env.DB.prepare(
		'INSERT INTO runs (id, flow_id, status, started_at, finished_at, error, input) VALUES (?, ?, ?, ?, ?, ?, ?)'
	).bind(newRunId, row.flow_id, 'queued', null, null, null, JSON.stringify(input)).run()

	// optional: log replay intent
	await c.env.DB.prepare(
		'INSERT INTO run_logs (id, run_id, ts, level, message, data) VALUES (?, ?, ?, ?, ?, ?)'
	).bind(crypto.randomUUID(), newRunId, now(), 'info', 'Replay requested', id).run()

	await c.env.RUNS_QUEUE.send({ runId: newRunId, flowId: row.flow_id, input })
	return c.json({ ok: true, runId: newRunId }, 202)
})

// --- queue step executors ---
async function execHttpStep(cfg: any, input: any) {
	const url = String(cfg.url || '')
	if (!url) throw new Error('http step missing url')
	const method = (cfg.method || 'POST').toString().toUpperCase()
	const headers: Record<string, string> = { ...(cfg.headers || {}) }
	let body: any = cfg.body

	if (cfg.forwardInput && body === undefined && method !== 'GET') {
		body = input
	}

	const init: RequestInit = { method, headers }
	if (body !== undefined && method !== 'GET') {
		if (typeof body === 'string') {
			init.body = body
		} else {
			headers['Content-Type'] = headers['Content-Type'] || 'application/json'
			init.body = JSON.stringify(body)
		}
	}

	const res = await fetch(url, init)
	const text = await res.text()
	return { ok: res.ok, status: res.status, body: text.slice(0, 512) }
}

async function execSlackStep(cfg: any, input: any) {
	const url = String(cfg.webhook_url || '')
	if (!url) throw new Error('slack step missing webhook_url')
	const text = cfg.text
		? String(cfg.text)
		: 'EdgeFlow: event received'
	const payload = {
		text: cfg.forwardInput ? `${text}\n\n${JSON.stringify(input).slice(0, 2000)}` : text
	}
	const res = await fetch(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(payload)
	})
	const t = await res.text()
	return { ok: res.ok, status: res.status, body: t.slice(0, 512) }
}

// Queue consumer handler
const queueHandler = async (batch: any, env: Env) => {
	const ts = () => Math.floor(Date.now() / 1000)
	for (const msg of batch.messages) {
		const body = msg.body || {}
		const runId = body.runId
		const flowId = body.flowId
		try {
			// running
			await env.DB.prepare('UPDATE runs SET status = ?, started_at = ? WHERE id = ?')
				.bind('running', ts(), runId).run()

			// log receipt
			await env.DB.prepare(
				'INSERT INTO run_logs (id, run_id, ts, level, message, data) VALUES (?, ?, ?, ?, ?, ?)'
			).bind(
				crypto.randomUUID(),
				runId,
				ts(),
				'info',
				'Received webhook payload',
				JSON.stringify(body.input ?? null)
			).run()

			// load steps
			const stepsRes = await env.DB.prepare(
				'SELECT step_index, type, config FROM steps WHERE flow_id = ? ORDER BY step_index ASC'
			).bind(flowId).all()
			const steps = (stepsRes.results || []) as Array<{ step_index: number; type: string; config: string }>

			for (const s of steps) {
				let cfg: any = {}
				try { cfg = JSON.parse(s.config) } catch { cfg = {} }
				await env.DB.prepare(
					'INSERT INTO run_logs (id, run_id, ts, level, message, data) VALUES (?, ?, ?, ?, ?, ?)'
				).bind(crypto.randomUUID(), runId, ts(), 'info', `Executing step ${s.step_index} (${s.type})`, null).run()

				let result: any
				if (s.type === 'http') {
					result = await execHttpStep(cfg, body.input)
				} else if (s.type === 'slack') {
					result = await execSlackStep(cfg, body.input)
				} else {
					throw new Error(`Unknown step type: ${s.type}`)
				}

				await env.DB.prepare(
					'INSERT INTO run_logs (id, run_id, ts, level, message, data) VALUES (?, ?, ?, ?, ?, ?)'
				).bind(
					crypto.randomUUID(),
					runId,
					ts(),
					result.ok ? 'info' : 'error',
					`Step ${s.step_index} ${result.ok ? 'succeeded' : 'failed'} (status ${result.status})`,
					result.body
				).run()

				if (!result.ok) throw new Error(`Step ${s.step_index} failed with status ${result.status}`)
			}

			// succeeded
			await env.DB.prepare('UPDATE runs SET status = ?, finished_at = ? WHERE id = ?')
				.bind('succeeded', ts(), runId).run()
		} catch (err: any) {
			await env.DB.prepare('UPDATE runs SET status = ?, finished_at = ?, error = ? WHERE id = ?')
				.bind('failed', ts(), String(err?.message || err), runId).run()
		}
	}
}

// Export both fetch and queue
export default {
	fetch: app.fetch,
	queue: queueHandler,
}