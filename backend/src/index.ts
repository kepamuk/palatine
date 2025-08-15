import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { z } from 'zod'
import { Kysely, PostgresDialect, sql } from 'kysely'
import pg from 'pg'
import Redis from 'ioredis'
import * as Y from 'yjs'
import { Readable } from 'node:stream'
import { createHash } from 'node:crypto'

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
app.use(cors())
app.use(express.json({ limit: '5mb' }))
app.use(express.text({ limit: '5mb' })) // Добавляем обработку text/plain

const { Pool } = pg
const pool = new Pool({ connectionString: process.env.DATABASE_URL })
const db = new Kysely<any>({ dialect: new PostgresDialect({ pool }) })
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379')

async function ensureSchema() {
  await sql`create table if not exists documents (
    user_id text primary key,
    ydoc bytea not null,
    updated_at timestamptz not null default now()
  )`.execute(db)
  await sql`create table if not exists blobs (
    key text primary key,
    content bytea not null,
    content_type text not null,
    updated_at timestamptz not null default now()
  )`.execute(db)
}

async function waitForDbReady(maxWaitMs = 30000) {
  const started = Date.now()
  let attempt = 0
  while (true) {
    try {
      await sql`select 1`.execute(db)
      console.log('[startup] БД готова')
      return
    } catch (e) {
      attempt++
      const elapsed = Date.now() - started
      if (elapsed > maxWaitMs) {
        console.error('[startup] таймаут ожидания БД, прекращаем')
        throw e
      }
      // DB not ready yet, retry
      await new Promise((r) => setTimeout(r, 1000))
    }
  }
}

app.post('/api/sync', async (req, res) => {
  const raw = typeof req.body === 'string' ? safeJson(req.body) : req.body
  if (!raw || typeof raw !== 'object')
    return res.status(400).json({ error: 'Invalid request body' })
  const body = z.object({ userId: z.string(), update: z.array(z.number()) }).parse(raw)
  const key = `ydoc:${body.userId}`
  const base64 = Buffer.from(Uint8Array.from(body.update)).toString('base64')
  await redis.rpush(key, base64)
  await redis.expire(key, 60 * 10)
  res.json({ ok: true })
})

app.post('/api/flush', async (req, res) => {
  let raw: any
  if (typeof req.body === 'string') {
    // Если приходит как строка (content-type: text/plain)
    raw = safeJson(req.body)
  } else if (req.body && typeof req.body === 'object') {
    // Если уже объект (content-type: application/json)
    raw = req.body
  } else {
    return res.status(400).json({ error: 'Invalid request body format' })
  }
  if (!raw || typeof raw !== 'object')
    return res.status(400).json({ error: 'Invalid request body' })

  const body = z
    .object({
      userId: z.string(),
      snapshot: z.array(z.number()).optional(),
      bundle: z.any().optional(),
    })
    .parse(raw)
  const key = `ydoc:${body.userId}`
  let encoded: Buffer

  // Приоритет snapshot (бинарные данные Y.js). Bundle — доп. мета
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
  await db
    .insertInto('documents')
    .values({ user_id: body.userId, ydoc: encoded })
    .onConflict((oc) => oc.column('user_id').doUpdateSet({ ydoc: encoded, updated_at: sql`now()` }))
    .execute()
  await redis.del(key)
  res.json({ ok: true })
})

app.get('/api/load', async (req, res) => {
  const userId = z.string().parse(req.query.userId)
  const row = await db
    .selectFrom('documents')
    .selectAll()
    .where('user_id', '=', userId)
    .executeTakeFirst()
  if (!row) return res.json({ update: [] })
  const buf: Buffer = (row as any).ydoc
  res.setHeader('Cache-Control', 'no-store')

  // Проверяем, это JSON bundle или бинарные данные
  if (buf.length > 0 && buf[0] === 0x7b) {
    try {
      const bundle = JSON.parse(buf.toString('utf8'))
      return res.json({ bundle })
    } catch {}
  }

  // Возвращаем бинарные данные как update
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

// Приём и выдача постоянных blobs (для стабильного отображения изображений)
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
