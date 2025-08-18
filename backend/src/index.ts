import 'dotenv/config'
import './types'
import express from 'express'
import cors from 'cors'
import { z } from 'zod'
import { Kysely, PostgresDialect, sql } from 'kysely'
import pg from 'pg'
import Redis from 'ioredis'
import * as Y from 'yjs'
import { Readable } from 'node:stream'
import { createHash } from 'node:crypto'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import session from 'express-session'
import { v4 as uuidv4 } from 'uuid'

async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs = 4000,
): Promise<Response> {
  const controller = new AbortController()
  const id = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(id)
  }
}

const app = express()
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
  }),
)
app.use(express.json({ limit: '5mb' }))
app.use(express.text({ limit: '5mb' }))

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'default-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000,
    },
  }),
)

const JWT_SECRET = process.env.JWT_SECRET || 'default-jwt-secret-change-in-production'

const { Pool } = pg
const pool = new Pool({ connectionString: process.env.DATABASE_URL })
const db = new Kysely<any>({ dialect: new PostgresDialect({ pool }) })
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379')

async function ensureSchema() {
  await sql`create table if not exists users (
    id uuid primary key default gen_random_uuid(),
    email text unique not null,
    password_hash text not null,
    display_name text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
  )`.execute(db)

  await sql`create table if not exists user_sessions (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    token text unique not null,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
  )`.execute(db)

  await sql`create table if not exists documents (
    id uuid primary key default gen_random_uuid(),
    user_id uuid unique not null references users(id) on delete cascade,
    ydoc bytea not null,
    title text default 'Untitled Document',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
  )`.execute(db)

  await sql`create table if not exists blobs (
    key text primary key,
    content bytea not null,
    content_type text not null,
    updated_at timestamptz not null default now()
  )`.execute(db)

  await sql`create index if not exists idx_user_sessions_token on user_sessions(token)`.execute(db)
  await sql`create index if not exists idx_documents_user_id on documents(user_id)`.execute(db)
  await sql`create index if not exists idx_user_sessions_expires_at on user_sessions(expires_at)`.execute(
    db,
  )

  try {
    await sql`alter table documents add constraint documents_user_id_unique unique (user_id)`.execute(
      db,
    )
  } catch (e) {}
}

async function waitForDbReady(maxWaitMs = 30000) {
  const started = Date.now()
  let attempt = 0
  while (true) {
    try {
      await sql`select 1`.execute(db)
      return
    } catch (e) {
      attempt++
      const elapsed = Date.now() - started
      if (elapsed > maxWaitMs) {
        throw e
      }
      await new Promise((r) => setTimeout(r, 1000))
    }
  }
}

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12)
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash)
}

function generateToken(): string {
  return jwt.sign({ tokenId: uuidv4() }, JWT_SECRET, { expiresIn: '7d' })
}

async function authenticateUser(req: express.Request): Promise<{ userId: string } | null> {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null
  }

  const token = authHeader.substring(7)
  try {
    const session = await db
      .selectFrom('user_sessions')
      .select(['user_id'])
      .where('token', '=', token)
      .where('expires_at', '>', new Date())
      .executeTakeFirst()

    if (!session) {
      return null
    }

    return { userId: session.user_id as string }
  } catch (e) {
    return null
  }
}

async function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const auth = await authenticateUser(req)
  if (!auth) {
    return res.status(401).json({ error: 'Authentication required' })
  }
  req.user = auth
  next()
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const body = z
      .object({
        email: z.string().email(),
        password: z.string().min(6),
        displayName: z.string().optional(),
      })
      .parse(req.body)

    const existingUser = await db
      .selectFrom('users')
      .select(['id'])
      .where('email', '=', body.email.toLowerCase())
      .executeTakeFirst()

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' })
    }

    const passwordHash = await hashPassword(body.password)
    const user = await db
      .insertInto('users')
      .values({
        email: body.email.toLowerCase(),
        password_hash: passwordHash,
        display_name: body.displayName || null,
      })
      .returning(['id', 'email', 'display_name'])
      .executeTakeFirstOrThrow()

    const token = generateToken()
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 дней

    await db
      .insertInto('user_sessions')
      .values({
        user_id: user.id as string,
        token,
        expires_at: expiresAt,
      })
      .execute()

    res.json({
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
      },
      token,
    })
  } catch (e: any) {
    if (e.name === 'ZodError') {
      return res.status(400).json({ error: 'Invalid request data' })
    }
    res.status(500).json({ error: 'Registration failed' })
  }
})

app.post('/api/auth/login', async (req, res) => {
  try {
    const body = z
      .object({
        email: z.string().email(),
        password: z.string(),
      })
      .parse(req.body)

    const user = await db
      .selectFrom('users')
      .select(['id', 'email', 'password_hash', 'display_name'])
      .where('email', '=', body.email.toLowerCase())
      .executeTakeFirst()

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const isValidPassword = await verifyPassword(body.password, user.password_hash as string)
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const token = generateToken()
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 дней

    await db
      .insertInto('user_sessions')
      .values({
        user_id: user.id as string,
        token,
        expires_at: expiresAt,
      })
      .execute()

    res.json({
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
      },
      token,
    })
  } catch (e: any) {
    if (e.name === 'ZodError') {
      return res.status(400).json({ error: 'Invalid request data' })
    }
    res.status(500).json({ error: 'Login failed' })
  }
})

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    const authHeader = req.headers.authorization
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7)
      await db.deleteFrom('user_sessions').where('token', '=', token).execute()
    }
    res.json({ ok: true })
  } catch (e) {
    res.status(500).json({ error: 'Logout failed' })
  }
})

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await db
      .selectFrom('users')
      .select(['id', 'email', 'display_name'])
      .where('id', '=', req.user!.userId)
      .executeTakeFirst()

    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    res.json({
      id: user.id,
      email: user.email,
      displayName: user.display_name,
    })
  } catch (e) {
    res.status(500).json({ error: 'Failed to get user info' })
  }
})

app.post('/api/sync', requireAuth, async (req, res) => {
  const raw = typeof req.body === 'string' ? safeJson(req.body) : req.body
  if (!raw || typeof raw !== 'object')
    return res.status(400).json({ error: 'Invalid request body' })
  const body = z.object({ update: z.array(z.number()) }).parse(raw)
  const key = `ydoc:${req.user!.userId}`
  const base64 = Buffer.from(Uint8Array.from(body.update)).toString('base64')
  await redis.rpush(key, base64)
  await redis.expire(key, 60 * 10)
  res.json({ ok: true })
})

app.post('/api/flush', requireAuth, async (req, res) => {
  let raw: any
  if (typeof req.body === 'string') {
    raw = safeJson(req.body)
  } else if (req.body && typeof req.body === 'object') {
    raw = req.body
  } else {
    return res.status(400).json({ error: 'Invalid request body format' })
  }
  if (!raw || typeof raw !== 'object')
    return res.status(400).json({ error: 'Invalid request body' })

  const body = z
    .object({
      snapshot: z.array(z.number()).optional(),
      bundle: z.any().optional(),
    })
    .parse(raw)
  const key = `ydoc:${req.user!.userId}`
  let encoded: Buffer

  if (body.snapshot && body.snapshot.length > 0) {
    encoded = Buffer.from(Uint8Array.from(body.snapshot))
  } else if (body.bundle) {
    encoded = Buffer.from(JSON.stringify(body.bundle), 'utf8')
  } else {
    const chunks = await redis.lrange(key, 0, -1)
    const doc = new Y.Doc()
    for (const chunk of chunks) {
      const buf = Buffer.from(chunk, 'base64')
      Y.applyUpdate(doc, new Uint8Array(buf))
    }
    encoded = Buffer.from(Y.encodeStateAsUpdate(doc))
  }

  const existingDoc = await db
    .selectFrom('documents')
    .select(['id'])
    .where('user_id', '=', req.user!.userId)
    .executeTakeFirst()

  if (existingDoc) {
    await db
      .updateTable('documents')
      .set({ ydoc: encoded, updated_at: sql`now()` })
      .where('id', '=', existingDoc.id as string)
      .execute()
  } else {
    await db.insertInto('documents').values({ user_id: req.user!.userId, ydoc: encoded }).execute()
  }
  await redis.del(key)
  res.json({ ok: true })
})

app.get('/api/load', requireAuth, async (req, res) => {
  const row = await db
    .selectFrom('documents')
    .selectAll()
    .where('user_id', '=', req.user!.userId)
    .executeTakeFirst()
  if (!row) return res.json({ update: [] })
  const buf: Buffer = (row as any).ydoc
  res.setHeader('Cache-Control', 'no-store')

  if (buf.length > 0 && buf[0] === 0x7b) {
    try {
      const bundle = JSON.parse(buf.toString('utf8'))
      return res.json({ bundle })
    } catch {}
  }

  const bytes = new Uint8Array(buf)
  res.json({ update: Array.from(bytes) })
})

app.post('/api/gen-image', async (req, res) => {
  try {
    const parsed = z.object({ prompt: z.string().optional() }).safeParse(req.body)
    const prompt = parsed.success ? parsed.data.prompt : undefined
    await new Promise((r) => setTimeout(r, 400))
    const q = encodeURIComponent((prompt || 'nature').trim())
    const url = `https://loremflickr.com/1200/800/${q}`
    res.json({ url })
  } catch (e) {
    res.status(200).json({ url: `https://source.unsplash.com/1200x800/?nature` })
  }
})

app.get('/api/proxy-image', async (req, res) => {
  try {
    const raw = req.query.url
    const url = Array.isArray(raw) ? raw[0] : (raw ?? '')
    if (typeof url !== 'string' || url.length === 0) return res.status(400).send('bad url')
    new URL(url)
    const doStream = async (target: string) => {
      const rsp = await fetchWithTimeout(
        target,
        { redirect: 'follow', headers: { Accept: 'image/*', 'User-Agent': 'palatine-test/1.0' } },
        3500,
      )
      if (!rsp.ok || !rsp.body) return false
      const ct = rsp.headers.get('content-type') || 'image/jpeg'
      if (!ct.startsWith('image/')) return false
      res.setHeader('Content-Type', ct)
      res.setHeader('Cache-Control', 'no-store')
      Readable.fromWeb(rsp.body as any).pipe(res)
      return true
    }
    const ok = await doStream(url as string)
    if (!ok) {
      await doStream('https://picsum.photos/1200/800')
    }
  } catch (e) {
    try {
      const rsp = await fetchWithTimeout('https://picsum.photos/1200/800', {}, 3000)
      const ct = rsp.headers.get('content-type') || 'image/jpeg'
      res.setHeader('Content-Type', ct)
      res.setHeader('Cache-Control', 'no-store')
      Readable.fromWeb(rsp.body as any).pipe(res)
    } catch {
      res.status(502).send('bad upstream')
    }
  }
})

app.post('/api/blob', express.raw({ type: '*/*', limit: '15mb' }), async (req, res) => {
  try {
    const buf: Buffer = Buffer.isBuffer(req.body)
      ? (req.body as Buffer)
      : Buffer.from(req.body || '')
    if (!buf || buf.length === 0) return res.status(400).json({ error: 'empty body' })
    const ct = (req.headers['content-type'] as string) || 'application/octet-stream'
    const key = createHash('sha256').update(buf).digest('hex')
    await db
      .insertInto('blobs')
      .values({ key, content: buf, content_type: ct })
      .onConflict((oc) =>
        oc.column('key').doUpdateSet({ content: buf, content_type: ct, updated_at: sql`now()` }),
      )
      .execute()
    res.json({ key })
  } catch (e) {
    res.status(500).json({ error: 'blob store failed' })
  }
})

app.get('/api/blob/:key', async (req, res) => {
  try {
    const key = req.params.key
    const row = await db.selectFrom('blobs').selectAll().where('key', '=', key).executeTakeFirst()
    if (!row) return res.status(404).send('not found')
    const ct = (row as any).content_type as string
    const content: Buffer = (row as any).content
    res.setHeader('Content-Type', ct || 'application/octet-stream')
    res.setHeader('Cache-Control', 'no-store')
    res.end(content)
  } catch (e) {
    res.status(500).send('error')
  }
})

const port = Number(process.env.PORT || 4000)
;(async () => {
  try {
    await waitForDbReady()
    await ensureSchema()
    app.listen(port, () => {})
  } catch (e) {
    process.exit(1)
  }
})()

function safeJson(s: string) {
  try {
    return JSON.parse(s)
  } catch {
    return {}
  }
}
