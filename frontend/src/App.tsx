import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import styles from './App.module.scss'
import '@blocksuite/editor/themes/affine.css'
import { EditorContainer } from '@blocksuite/editor'
import { Schema, Workspace, type Page } from '@blocksuite/store'
import * as Y from 'yjs'
import { AffineSchemas, __unstableSchemas } from '@blocksuite/blocks/models'

type PersistedDoc = {
  workspaceId: string
  pageId: string
  update: Uint8Array
}

type PersistedBundle = {
  ws?: number[]
  pages: Array<{ id: string; update?: number[]; rootExists?: boolean }>
}

function App() {
  const editorRef = useRef<EditorContainer | null>(null)
  const [imagePrompt, setImagePrompt] = useState('')
  const [saving, setSaving] = useState<'idle' | 'saving' | 'ok' | 'err'>('idle')
  const [generating, setGenerating] = useState<'idle' | 'pending' | 'ok' | 'err'>('idle')

  const schema = useMemo(() => {
    const s = new Schema()
    s.register(AffineSchemas).register(__unstableSchemas)
    return s
  }, [])

  const workspace = useMemo(() => new Workspace({ id: 'local', schema }), [schema])
  const [page, setPage] = useState<Page | null>(null)
  const saveTimer = useRef<number | null>(null)
  const bootedRef = useRef(false)

  useEffect(() => {
    if (bootedRef.current) return
    bootedRef.current = true
    const boot = async () => {
      let hasRemoteUpdate = false
      try {
        const userId = getUserId()
        const loadUrl = `${getApiBase()}/api/load?userId=${encodeURIComponent(userId)}`
        const rsp = await fetch(loadUrl, { cache: 'no-store' })
        const data = await rsp.json()
        if (data && data.bundle) {
          await restoreFromBundle(workspace, data.bundle as PersistedBundle)
          hasRemoteUpdate = true
        } else if (data && Array.isArray(data.update) && data.update.length > 0) {
          Y.applyUpdate(workspace.doc as unknown as Y.Doc, new Uint8Array(data.update))
          hasRemoteUpdate = true
        } else {
          const b64 = localStorage.getItem('palatine:doc_b64')
          if (b64) {
            const u8 = base64ToUint8(b64)
            if (u8 && u8.length > 0) {
              hasRemoteUpdate = true
              Y.applyUpdate(workspace.doc as unknown as Y.Doc, u8)
            }
          } else {
            const saved = localStorage.getItem('palatine:doc')
            if (saved) {
              try {
                const data: PersistedDoc = JSON.parse(saved)
                if (data && data.update) {
                  hasRemoteUpdate = true
                  Y.applyUpdate(
                    workspace.doc as unknown as Y.Doc,
                    new Uint8Array(Object.values(data.update)),
                  )
                }
              } catch {}
            }
          }
        }
      } catch (e) {}

      let p: Page | null = null
      const existing = Array.from(workspace.pages.values())

      if (existing.length > 0) {
        p = existing[0]
        await ensurePageReady(p)
      } else {
        const desired = workspace.getPage('page0') || workspace.createPage({ id: 'page0' })
        await desired.load()
        if (!hasRemoteUpdate && !desired.root) {
          const pageBlockId = desired.addBlock('affine:page')
          desired.addBlock('affine:surface', {}, pageBlockId)
          const noteId = desired.addBlock('affine:note', {}, pageBlockId)
          desired.addBlock('affine:paragraph', {}, noteId)
        }
        p = desired
      }

      await hydrateMissingBlobs(p)
      setPage(p)
    }
    boot()
  }, [workspace])

  useEffect(() => {
    if (!page) return
    const onUpdate = (update: Uint8Array) => {
      const payload: PersistedDoc = { workspaceId: workspace.id, pageId: page.id, update }
      localStorage.setItem('palatine:doc', JSON.stringify(payload))
      if (saveTimer.current) window.clearTimeout(saveTimer.current)
      saveTimer.current = window.setTimeout(() => {
        const snapshot = Y.encodeStateAsUpdate(workspace.doc as unknown as Y.Doc)
        const b64 = uint8ToBase64(snapshot)
        localStorage.setItem('palatine:doc_b64', b64)
      }, 500) as unknown as number
      const userId = getUserId()
      apiPost('/api/sync', { userId, update: Array.from(update) }).catch(() => {})
    }
    workspace.doc.on('update', onUpdate)
    const iv = window.setInterval(() => {
      flushNow(workspace)
    }, 8000)
    const onUnload = () => {
      const userId = getUserId()
      const bundle = buildBundle(workspace)
      fetch(`${getApiBase()}/api/flush`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId, bundle }),
        keepalive: true,
      }).catch(() => {})
    }
    window.addEventListener('beforeunload', onUnload)
    return () => {
      workspace.doc.off('update', onUpdate)
      window.clearInterval(iv)
      window.removeEventListener('beforeunload', onUnload)
    }
  }, [page, workspace])

  const mountEditor = useCallback(
    (node: HTMLDivElement | null) => {
      if (!node || editorRef.current || !page) return
      const editor = new EditorContainer()
      editor.page = page
      editor.mode = 'edgeless'
      editor.style.width = '100%'
      editor.style.height = '100%'
      node.appendChild(editor)
      editorRef.current = editor
    },
    [page],
  )

  const handleGenerateImage = async () => {
    try {
      setGenerating('pending')
      const rsp = await apiPost('/api/gen-image', { prompt: imagePrompt })
      const data = await rsp.json()
      if (!page) return
      await ensurePageReady(page)
      await insertImageBlock(page, data.url)
      setGenerating('ok')
      setTimeout(() => setGenerating('idle'), 1200)
    } catch (e) {
      setGenerating('pending')
      const url = await fakeGenerateImage(imagePrompt)
      if (!page) return
      await ensurePageReady(page)
      await insertImageBlock(page, url)
      setGenerating('ok')
      setTimeout(() => setGenerating('idle'), 1200)
    }
  }

  const flushNow = async (ws: Workspace) => {
    try {
      setSaving('saving')
      const userId = getUserId()
      const snapshot = buildFullSnapshot(ws.doc as unknown as Y.Doc)
      const bundle = buildBundle(ws)
      const rsp = await apiPost('/api/flush', { userId, snapshot: Array.from(snapshot), bundle })
      if (!rsp.ok) throw new Error('flush failed')
      setSaving('ok')
      setTimeout(() => setSaving('idle'), 1200)
    } catch (e) {
      setSaving('err')
      setTimeout(() => setSaving('idle'), 2000)
    }
  }

  return (
    <div className={styles.container}>
      <div className={styles.topbar}>
        <input
          placeholder="Опишите картинку"
          value={imagePrompt}
          onChange={(e) => setImagePrompt(e.target.value)}
        />
        <button
          className={styles.primaryBtn}
          onClick={handleGenerateImage}
          disabled={generating === 'pending'}
        >
          Сгенерировать
        </button>
        <div className={styles.statusBar}>
          <div className={styles.badge} title="Генерация" data-state={generating}>
            {generating === 'pending' ? (
              <div className={styles.spinner} />
            ) : generating === 'ok' ? (
              <div className={styles.okDot} />
            ) : generating === 'err' ? (
              <div className={styles.errDot} />
            ) : null}
          </div>
          <div className={styles.badge} title="Синхронизация" data-state={saving}>
            {saving === 'saving' ? (
              <div className={styles.spinner} />
            ) : saving === 'ok' ? (
              <div className={styles.okDot} />
            ) : saving === 'err' ? (
              <div className={styles.errDot} />
            ) : null}
          </div>
        </div>
      </div>
      <div className={styles.editor} ref={mountEditor} />
    </div>
  )
}

export default App

function getUserId(): string {
  const key = 'palatine:user_id'
  let id = localStorage.getItem(key)
  if (!id) {
    const fingerprint = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      navigator.hardwareConcurrency || 4,
      navigator.maxTouchPoints || 0,
    ].join('|')

    let hash = 0
    for (let i = 0; i < fingerprint.length; i++) {
      const char = fingerprint.charCodeAt(i)
      hash = (hash << 5) - hash + char
      hash = hash & hash
    }

    id = 'user_' + Math.abs(hash).toString(36)

    if (!localStorage.getItem(key + '_created')) {
      id += '_' + Math.random().toString(36).substr(2, 9)
      localStorage.setItem(key + '_created', new Date().toISOString())
    }

    localStorage.setItem(key, id)
  } else {
  }
  return id
}

async function fakeGenerateImage(_prompt: string): Promise<string> {
  await new Promise((r) => setTimeout(r, 800))
  return 'https://picsum.photos/seed/' + encodeURIComponent(_prompt || 'palatine') + '/800/600'
}

async function insertImageBlock(page: any, src: string) {
  const proxied = `${getApiBase()}/api/proxy-image?url=${encodeURIComponent(src)}`
  const res = await fetch(proxied, { cache: 'no-store' })
  if (!res.ok) throw new Error('image fetch failed')
  const blob = await res.blob()
  const upload = await fetch(`${getApiBase()}/api/blob`, {
    method: 'POST',
    headers: { 'Content-Type': blob.type || 'application/octet-stream' },
    body: blob,
  })
  if (!upload.ok) throw new Error('blob upload failed')
  const { key } = await upload.json()

  const stableUrl = `${getApiBase()}/api/blob/${encodeURIComponent(key)}`
  const stableBlob = await fetch(stableUrl, { cache: 'no-store' }).then((r) => r.blob())
  const blobKey = `blob:${key}`
  const blobId = await page.blob.set(stableBlob, blobKey)
  const pageBlockId = page.root ? page.root.id : page.addBlock('affine:page')
  const surface = page.getBlockByFlavour('affine:surface')[0]
  const surfaceId = surface ? surface.id : page.addBlock('affine:surface', {}, pageBlockId)
  const imageBlockId = page.addBlock(
    'affine:image',
    {
      sourceId: blobId,
      caption: stableUrl,
      width: 300,
      height: 200,
      xywh: '[0,0,300,200]',
      rotate: 0,
      index: 'a0',
    },
    surfaceId,
  )
  return imageBlockId
}

function uint8ToBase64(u8: Uint8Array): string {
  let binary = ''
  const len = u8.byteLength
  for (let i = 0; i < len; i++) binary += String.fromCharCode(u8[i])
  return btoa(binary)
}

function base64ToUint8(b64: string): Uint8Array {
  try {
    const binary = atob(b64)
    const len = binary.length
    const bytes = new Uint8Array(len)
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i)
    return bytes
  } catch {
    return new Uint8Array()
  }
}

async function hydrateMissingBlobs(page: any) {
  await ensurePageReady(page)
  const images = page.getBlockByFlavour('affine:image') || []
  for (const img of images) {
    const id = img.sourceId
    const has = await page.blob.get(id)
    if (!has) {
      const url = img.caption as string | undefined
      if (!url) continue
      try {
        const isStable = /\/api\/blob\//.test(url)
        const targetUrl = isStable
          ? url
          : `${getApiBase()}/api/proxy-image?url=${encodeURIComponent(url)}`
        const res = await fetch(targetUrl, { cache: 'no-store' })
        if (!res.ok) continue
        const blob = await res.blob()
        await page.blob.set(blob, id)
      } catch {}
    }
  }
}

function buildFullSnapshot(doc: Y.Doc): Uint8Array {
  return Y.encodeStateAsUpdate(doc)
}

function buildBundle(ws: Workspace): PersistedBundle {
  const wsUpdate = Y.encodeStateAsUpdate(ws.doc as unknown as Y.Doc)
  const pages = Array.from(ws.pages.values()).map((p) => {
    try {
      const pageDoc = (p as any).spaceDoc as Y.Doc | undefined
      const update = pageDoc ? Array.from(Y.encodeStateAsUpdate(pageDoc)) : undefined
      return { id: p.id, update }
    } catch {
      return { id: p.id }
    }
  })
  return { ws: Array.from(wsUpdate), pages }
}

async function restoreFromBundle(ws: Workspace, bundle: PersistedBundle) {
  try {
    if (bundle.ws && bundle.ws.length > 0) {
      Y.applyUpdate(ws.doc as unknown as Y.Doc, new Uint8Array(bundle.ws))
    }
    for (const p of bundle.pages) {
      const page = ws.getPage(p.id) || ws.createPage({ id: p.id })
      if (p.update && p.update.length > 0) {
        const pageDoc = page.spaceDoc as unknown as Y.Doc
        Y.applyUpdate(pageDoc, new Uint8Array(p.update))
      }
    }
  } catch (e) {}
}

async function apiPost(path: string, body: unknown): Promise<Response> {
  const url = `${getApiBase()}${path}`
  return fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-user-id': getUserId(),
    },
    body: JSON.stringify(body ?? {}),
    cache: 'no-store',
    mode: 'cors',
    keepalive: true,
  })
}

function getApiBase(): string {
  const envBase = (import.meta as any).env?.VITE_API_URL as string | undefined
  if (envBase && !/\bbackend\b/.test(envBase)) return envBase
  try {
    const url = new URL(window.location.href)
    return `${url.protocol}//${url.hostname}:4000`
  } catch {
    return 'http://localhost:4000'
  }
}

async function ensurePageReady(p: any) {
  if (p.ready) return
  if (typeof p.waitForLoaded === 'function') {
    await p.waitForLoaded()
  } else {
    await p.load()
  }
}
