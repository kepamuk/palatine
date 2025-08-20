import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import styles from '../App.module.scss'
import '@blocksuite/editor/themes/affine.css'
import { EditorContainer } from '@blocksuite/editor'
import { Schema, Workspace, type Page } from '@blocksuite/store'
import * as Y from 'yjs'
import { AffineSchemas, __unstableSchemas } from '@blocksuite/blocks/models'
import { useAuth } from '../hooks/useAuth'
import { createRoot } from 'react-dom/client'
import ImageGenerator from './ImageGenerator'
import placeholderUrl from '../assets/test.jpg'

type PersistedDoc = {
  workspaceId: string
  pageId: string
  update: Uint8Array
}

type PersistedBundle = {
  ws?: number[]
  pages: Array<{ id: string; update?: number[]; rootExists?: boolean }>
}

function EditorApp() {
  const editorRef = useRef<EditorContainer | null>(null)
  const [saving, setSaving] = useState<'idle' | 'saving' | 'ok' | 'err'>('idle')
  const { logout, user, token } = useAuth()
  const [editorLoading, setEditorLoading] = useState(true)

  const schema = useMemo(() => {
    const s = new Schema()
    s.register(AffineSchemas).register(__unstableSchemas)
    return s
  }, [])

  const workspace = useMemo(() => new Workspace({ id: 'local', schema }), [schema])
  const [page, setPage] = useState<Page | null>(null)
  const saveTimer = useRef<number | null>(null)
  const bootedRef = useRef(false)
  const hadRemoteRef = useRef(false)

  const bcRef = useRef<BroadcastChannel | null>(null)
  const suppressBroadcastRef = useRef(false)
  const tabId = useMemo(() => `${Date.now()}-${Math.random().toString(36).slice(2)}`, [])

  useEffect(() => {
    if (bootedRef.current) return
    bootedRef.current = true
    const boot = async () => {
      setEditorLoading(true)
      let hasRemoteUpdate = false
      try {
        const loadUrl = `${getApiBase()}/api/load`
        const rsp = await fetch(loadUrl, {
          cache: 'no-store',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          credentials: 'include',
        })
        const data = await rsp.json()

        if (data && data.bundle) {
          await restoreFromBundle(workspace, data.bundle as PersistedBundle)
          hasRemoteUpdate = true
        } else if (data && Array.isArray(data.update) && data.update.length > 0) {
          Y.applyUpdate(workspace.doc as unknown as Y.Doc, new Uint8Array(data.update))

          const page = workspace.getPage('page0') || workspace.createPage({ id: 'page0' })
          await page.load()
          await ensurePageReady(page)

          const pageDoc = page.spaceDoc as unknown as Y.Doc
          Y.applyUpdate(pageDoc, new Uint8Array(data.update))

          await page.load()
          await ensurePageReady(page)

          if (!page.root) {
            try {
              page.transact(() => {
                try {
                  const pageBlockId = page.addBlock('affine:page', {})
                  page.addBlock('affine:surface', {}, pageBlockId)
                } catch {}
              })
              await new Promise((r) => setTimeout(r, 40))
              await page.load()
              await ensurePageReady(page)
            } catch {}
          }

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

      hadRemoteRef.current = hasRemoteUpdate

      let p: Page | null = null
      const existing = Array.from(workspace.pages.values())

      if (existing.length > 0) {
        p = existing[0]
        await ensurePageReady(p)

        if (!p?.root) {
          p?.transact(() => {
            try {
              const pageBlockId = p!.addBlock('affine:page', {})
              p!.addBlock('affine:surface', {}, pageBlockId)
            } catch (e) {
              try {
                p!.addBlock('affine:page', {})
              } catch (fallbackError) {}
            }
          })
          await p?.load()
          await ensurePageReady(p!)
        } else {
          await new Promise((resolve) => setTimeout(resolve, 100))

          const hasSurface = p?.getBlockByFlavour('affine:surface').length > 0

          if (!hasSurface && p?.root) {
            setTimeout(() => {
              p?.transact(() => {
                try {
                  p!.addBlock('affine:surface', {}, p!.root!.id)
                } catch (e) {}
              })
            }, 50)
          }
        }

        if (!p.root) {
          const wsDoc = workspace.doc as unknown as Y.Doc

          const spacesMap = (wsDoc as any).get('spaces')
          if (spacesMap) {
            const page0Data = spacesMap.get('page0')
            if (page0Data) {
              const pageDoc = p.spaceDoc as unknown as Y.Doc
              const page0Update = Y.encodeStateAsUpdate(page0Data)
              Y.applyUpdate(pageDoc, page0Update)
            }
          }

          await p.load()
          await ensurePageReady(p)

          if (!p.root) {
            await p.load()
            await ensurePageReady(p)
          }

          if (!p.root) {
          }
        }
      } else {
        const desired = workspace.getPage('page0') || workspace.createPage({ id: 'page0' })
        await desired.load()
        await ensurePageReady(desired)

        if (!hasRemoteUpdate && !desired.root) {
          await new Promise((resolve) => setTimeout(resolve, 100))

          desired.transact(() => {
            try {
              const pageBlockId = desired.addBlock('affine:page', {})

              setTimeout(() => {
                desired.transact(() => {
                  try {
                    desired.addBlock('affine:surface', {}, pageBlockId)
                  } catch (surfaceError) {}
                })
              }, 50)
            } catch (e) {}
          })
        }
        p = desired
      }

      await hydrateMissingBlobs(p)
      setPage(p)
      setEditorLoading(false)
    }
    boot()
  }, [workspace, token])

  useEffect(() => {
    if (!page) return

    let cancelled = false
    let attempts = 0
    const maxAttempts = 100

    const mountIntoToolbar = () => {
      if (cancelled) return
      const toolbarEl = document.querySelector('edgeless-toolbar') as HTMLElement | null
      if (!toolbarEl || !(toolbarEl as any).shadowRoot) {
        scheduleNext()
        return
      }
      const shadow = (toolbarEl as any).shadowRoot as ShadowRoot
      const rightPart = shadow.querySelector('.edgeless-toolbar-right-part') as HTMLElement | null
      const container =
        rightPart || (shadow.querySelector('.edgeless-toolbar-container') as HTMLElement | null)
      if (!container) {
        scheduleNext()
        return
      }
      if (!container.querySelector('#image-generator-container')) {
        const host = document.createElement('div')
        host.id = 'image-generator-container'
        container.appendChild(host)
        const root = createRoot(host)
        root.render(<ImageGenerator page={page} apiPost={apiPost} />)
      }
    }

    const scheduleNext = () => {
      attempts += 1
      if (attempts > maxAttempts) return
      setTimeout(mountIntoToolbar, 200)
    }

    mountIntoToolbar()

    return () => {
      cancelled = true
    }
  }, [page])

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

      apiPost('/api/sync', { update: Array.from(update) }).catch(() => {})

      if (!suppressBroadcastRef.current) {
        postCrossTab({ type: 'update', update: Array.from(update), sender: tabId })
      }
    }
    workspace.doc.on('update', onUpdate)
    const iv = window.setInterval(() => {
      flushNow(workspace)
    }, 8000)
    const onUnload = () => {
      const bundle = buildBundle(workspace)
      fetch(`${getApiBase()}/api/flush`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ bundle }),
        keepalive: true,
        credentials: 'include',
      }).catch(() => {})
    }
    window.addEventListener('beforeunload', onUnload)
    return () => {
      workspace.doc.off('update', onUpdate)
      window.clearInterval(iv)
      window.removeEventListener('beforeunload', onUnload)
    }
  }, [page, workspace, token])

  useEffect(() => {
    if (!workspace) return

    const handleMessage = (msg: any) => {
      if (!msg || msg.sender === tabId) return
      if (msg.type === 'update' && Array.isArray(msg.update)) {
        try {
          suppressBroadcastRef.current = true
          Y.applyUpdate(workspace.doc as unknown as Y.Doc, new Uint8Array(msg.update))
        } finally {
          suppressBroadcastRef.current = false
        }
      } else if (msg.type === 'request_full_snapshot') {
        try {
          const snapshot = Y.encodeStateAsUpdate(workspace.doc as unknown as Y.Doc)
          postCrossTab({ type: 'full_snapshot', snapshot: Array.from(snapshot), sender: tabId })
        } catch {}
      } else if (msg.type === 'full_snapshot' && Array.isArray(msg.snapshot)) {
        try {
          suppressBroadcastRef.current = true
          Y.applyUpdate(workspace.doc as unknown as Y.Doc, new Uint8Array(msg.snapshot))
        } finally {
          suppressBroadcastRef.current = false
        }
      }
    }

    let bc: BroadcastChannel | null = null
    if (typeof window !== 'undefined' && 'BroadcastChannel' in window) {
      bc = new BroadcastChannel('palatine-doc')
      bcRef.current = bc
      bc.onmessage = (e: MessageEvent) => handleMessage(e.data)
    }

    const storageKey = 'palatine:bc'
    const onStorage = (e: StorageEvent) => {
      if (e.key !== storageKey || !e.newValue) return
      try {
        const msg = JSON.parse(e.newValue)
        handleMessage(msg)
      } catch {}
    }
    window.addEventListener('storage', onStorage)

    setTimeout(() => {
      if (!hadRemoteRef.current) {
        postCrossTab({ type: 'request_full_snapshot', sender: tabId })
      }
    }, 200)

    return () => {
      if (bc) bc.close()
      window.removeEventListener('storage', onStorage)
    }
  }, [workspace, tabId])

  const mountEditor = useCallback(
    (node: HTMLDivElement | null) => {
      if (!node || editorRef.current || !page) return

      setTimeout(() => {
        try {
          const editor = new EditorContainer()
          editor.page = page
          editor.mode = 'edgeless'
          editor.style.width = '100%'
          editor.style.height = '100%'

          editor.addEventListener('error', (e) => {
            e.preventDefault()
            e.stopPropagation()
          })

          window.addEventListener('error', (e) => {
            if (
              e.message &&
              e.message.includes('Cannot destructure property') &&
              e.message.includes('flavour')
            ) {
              e.preventDefault()
              return false
            }
            if (
              e.message &&
              e.message.includes('Cannot read properties of null') &&
              e.message.includes('deref')
            ) {
              e.preventDefault()
              return false
            }
          })

          window.addEventListener('unhandledrejection', (e) => {
            if (e.reason && typeof e.reason === 'object' && e.reason.message) {
              if (
                e.reason.message.includes('Cannot destructure property') &&
                e.reason.message.includes('flavour')
              ) {
                e.preventDefault()
                return false
              }
              if (
                e.reason.message.includes('Cannot read properties of null') &&
                e.reason.message.includes('deref')
              ) {
                e.preventDefault()
                return false
              }
            }
          })

          node.appendChild(editor)
          editorRef.current = editor
        } catch (e) {
          node.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: center; height: 100%; background: #f5f5f5; color: #666;">
              <div style="text-align: center;">
                <div style="font-size: 24px; margin-bottom: 8px;">⚠️</div>
                <div>Ошибка загрузки редактора</div>
                <div style="font-size: 12px; margin-top: 4px;">Попробуйте перезагрузить страницу</div>
              </div>
            </div>
          `
        }
      }, 200)
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
      const snapshot = buildFullSnapshot(ws.doc as unknown as Y.Doc)
      const bundle = buildBundle(ws)
      const rsp = await apiPost('/api/flush', { snapshot: Array.from(snapshot), bundle })
      if (!rsp.ok) throw new Error('flush failed')
      setSaving('ok')
      setTimeout(() => setSaving('idle'), 1200)
    } catch (e) {
      setSaving('err')
      setTimeout(() => setSaving('idle'), 2000)
    }
  }

  const handleLogout = async () => {
    try {
      await logout()
    } catch (error) {}
  }

  const apiPost = async (path: string, body: unknown): Promise<Response> => {
    const url = `${getApiBase()}${path}`
    return fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body ?? {}),
      cache: 'no-store',
      mode: 'cors',
      keepalive: true,
      credentials: 'include',
    })
  }

  function postCrossTab(msg: any) {
    const bc = bcRef.current
    if (bc) {
      try {
        bc.postMessage(msg)
        return
      } catch {}
    }
    try {
      const envelope = JSON.stringify({ ...msg, ts: Date.now() })
      localStorage.setItem('palatine:bc', envelope)
      setTimeout(() => {
        try {
          localStorage.removeItem('palatine:bc')
        } catch {}
      }, 50)
    } catch {}
  }

  return (
    <div className={styles.container}>
      <div className={styles.topbar}>
        <div className={styles.userInfo}>
          <span>Привет, {user?.displayName || user?.email}!</span>
          <button className={styles.logoutBtn} onClick={handleLogout}>
            Выйти
          </button>
        </div>

        <div className={styles.statusBar}>
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

      {editorLoading && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 50,
          }}
        >
          <div
            style={{
              background: '#fff',
              padding: '28px 32px',
              borderRadius: 16,
              boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1), 0 10px 10px -5px rgba(0,0,0,0.04)',
              textAlign: 'center',
              color: '#374151',
              minWidth: 260,
            }}
          >
            <div
              style={{
                width: 44,
                height: 44,
                border: '4px solid #e5e7eb',
                borderTop: '4px solid #667eea',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite',
                margin: '0 auto 14px',
              }}
            />
            Загрузка холста...
          </div>
        </div>
      )}
    </div>
  )
}

export default EditorApp

async function fakeGenerateImage(_prompt: string): Promise<string> {
  await new Promise((r) => setTimeout(r, 800))
  return 'https://picsum.photos/seed/' + encodeURIComponent(_prompt || 'palatine') + '/800/600'
}

let imageCounter = 0

async function fetchProxyBlobWithFallback(src: string): Promise<Blob> {
  try {
    const proxied = `${getApiBase()}/api/proxy-image?url=${encodeURIComponent(src)}`
    const res = await fetch(proxied, { cache: 'no-store' })
    if (res.ok) {
      const blob = await res.blob()
      if (blob && blob.size > 1024) return blob
    }
  } catch {}
  const phRes = await fetch(placeholderUrl)
  return await phRes.blob()
}

async function insertImageBlock(page: any, src: string) {
  const blob = await fetchProxyBlobWithFallback(src)

  const localBlobKey = `blob:${Date.now()}-${Math.random().toString(36).slice(2)}`
  const blobId = await page.blob.set(blob, localBlobKey)

  const pageBlockId = page.root ? page.root.id : page.addBlock('affine:page')
  const surface = page.getBlockByFlavour('affine:surface')[0]
  const surfaceId = surface ? surface.id : page.addBlock('affine:surface', {}, pageBlockId)

  imageCounter++
  const x = Math.random() * 800
  const y = Math.random() * 600
  const index = `a${imageCounter}`

  const imageBlockId = page.addBlock(
    'affine:image',
    {
      sourceId: blobId,
      caption: src,
      width: 300,
      height: 200,
      xywh: `[${x},${y},300,200]`,
      rotate: 0,
      index: index,
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
        const blob = await fetchProxyBlobWithFallback(url)
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
        await page.load()
        await ensurePageReady(page)

        await new Promise((resolve) => setTimeout(resolve, 100))

        const pageDoc = page.spaceDoc as unknown as Y.Doc

        if (pageDoc && typeof pageDoc.get === 'function') {
          Y.applyUpdate(pageDoc, new Uint8Array(p.update))
        }

        await page.load()
        await ensurePageReady(page)

        if (page.root) {
          try {
            const allBlocks = (page as any).getAllBlocks ? (page as any).getAllBlocks() : []

            const blockStats: Record<string, number> = {}
            for (const block of allBlocks) {
              const flavour = block?.model?.flavour || 'undefined'
              blockStats[flavour] = (blockStats[flavour] || 0) + 1
            }
          } catch (e) {}
        }
      }
    }
  } catch (e) {}
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
