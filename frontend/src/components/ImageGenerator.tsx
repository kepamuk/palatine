import { FC, useEffect, useRef, useState } from 'react'
import { type Page } from '@blocksuite/store'
import createIconUrl from '../assets/create.svg'
import placeholderUrl from '../assets/test.jpg'

interface ImageGeneratorProps {
  page: Page
  apiPost: (path: string, body: unknown) => Promise<Response>
}

const ImageGenerator: FC<ImageGeneratorProps> = ({ page, apiPost }) => {
  const [imagePrompt, setImagePrompt] = useState('')
  const [generating, setGenerating] = useState<'idle' | 'pending' | 'ok' | 'err'>('idle')
  const [open, setOpen] = useState(false)
  const [isHovered, setIsHovered] = useState(false)
  const [mounted, setMounted] = useState(false)
  const wrapperRef = useRef<HTMLDivElement | null>(null)
  const inputRef = useRef<HTMLInputElement | null>(null)

  useEffect(() => {
    setMounted(true)
  }, [])

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [open])

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      const path = (e.composedPath && e.composedPath()) || []
      if (wrapperRef.current && !path.includes(wrapperRef.current)) {
        setOpen(false)
      }
    }
    window.addEventListener('mousedown', onDown)
    return () => window.removeEventListener('mousedown', onDown)
  }, [])

  const handleGenerateImage = async () => {
    try {
      setGenerating('pending')
      const rsp = await apiPost('/api/gen-image', { prompt: imagePrompt })
      const data = await rsp.json()
      if (!page) return
      await ensurePageReady(page)
      await insertImageBlock(page, data.url)
      setGenerating('ok')
      setImagePrompt('')
      setTimeout(() => {
        setGenerating('idle')
        setOpen(false)
      }, 800)
    } catch (e) {
      setGenerating('pending')
      const url = await fakeGenerateImage(imagePrompt)
      if (!page) return
      await ensurePageReady(page)
      await insertImageBlock(page, url)
      setGenerating('ok')
      setImagePrompt('')
      setTimeout(() => {
        setGenerating('idle')
        setOpen(false)
      }, 800)
    }
  }

  const toolbarItemStyle: React.CSSProperties = {
    width: '40px',
    height: '40px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: isHovered ? 'var(--affine-hover-color)' : 'var(--affine-background-primary-color)',
    borderRadius: '8px',
    cursor: 'pointer',
    fontSize: '22px',
    color: 'var(--affine-text-primary-color)',
    marginLeft: '8px',
    transition: 'all 0.15s ease',
    border: '1px solid var(--affine-border-color)',
    transform: isHovered ? 'scale(1.05)' : 'scale(1)',
    userSelect: 'none',
  }

  const popoverStyle: React.CSSProperties = {
    position: 'absolute',
    right: 0,
    bottom: '52px',
    width: '420px',
    maxWidth: 'min(80vw, 460px)',
    background: 'var(--affine-background-overlay-panel-color)',
    border: '1px solid var(--affine-border-color)',
    borderRadius: '12px',
    boxShadow: 'var(--affine-menu-shadow)',
    padding: '14px',
    zIndex: 1000,
    opacity: open ? 1 : 0,
    transform: open ? 'translateY(0) scale(1)' : 'translateY(6px) scale(0.98)',
    transition: 'opacity 120ms ease, transform 120ms ease',
  }

  const titleStyle: React.CSSProperties = {
    margin: 0,
    marginBottom: '8px',
    fontSize: '16px',
    fontWeight: 600,
    color: 'var(--affine-text-primary-color)',
  }

  const descriptionStyle: React.CSSProperties = {
    margin: 0,
    marginBottom: '12px',
    fontSize: '13px',
    color: 'var(--affine-text-secondary-color)',
  }

  const rowStyle: React.CSSProperties = {
    display: 'flex',
    gap: '10px',
    alignItems: 'center',
  }

  const inputStyle: React.CSSProperties = {
    flex: 1,
    height: '40px',
    padding: '0 12px',
    border: '1px solid var(--affine-border-color)',
    borderRadius: '10px',
    background: 'var(--affine-background-primary-color)',
    color: 'var(--affine-text-primary-color)',
    fontSize: '14px',
    outline: 'none',
  }

  const buttonStyle: React.CSSProperties = {
    height: '40px',
    padding: '0 14px',
    borderRadius: '10px',
    border: '1px solid var(--affine-border-color)',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    color: '#fff',
    cursor: 'pointer',
    fontWeight: 600,
    fontSize: '14px',
    transition: 'filter 0.15s ease',
    filter: generating === 'pending' ? 'grayscale(0.2) opacity(0.8)' : 'none',
  }

  const arrowStyle: React.CSSProperties = {
    position: 'absolute',
    right: '12px',
    bottom: '44px',
    width: '12px',
    height: '12px',
    background: 'var(--affine-background-overlay-panel-color)',
    transform: 'rotate(45deg)',
    borderLeft: '1px solid var(--affine-border-color)',
    borderTop: '1px solid var(--affine-border-color)',
    zIndex: 999,
  }

  return (
    <div ref={wrapperRef} style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
      <div
        style={toolbarItemStyle}
        onClick={() => setOpen((v) => !v)}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        title="Сгенерировать изображение"
        aria-label="Сгенерировать изображение"
      >
        <img src={createIconUrl} alt="Создать изображение" style={{ width: 20, height: 20 }} />
      </div>

      {open && (
        <>
          <div style={popoverStyle} onClick={(e) => e.stopPropagation()}>
            <h4 style={titleStyle}>Генерация изображения</h4>
            <p style={descriptionStyle}>Введите описание и нажмите «Сгенерировать»</p>
            <div style={rowStyle}>
              <input
                ref={inputRef}
                placeholder="Введите"
                value={imagePrompt}
                onChange={(e) => setImagePrompt(e.target.value)}
                onKeyDown={(e) =>
                  e.key === 'Enter' &&
                  imagePrompt &&
                  generating !== 'pending' &&
                  handleGenerateImage()
                }
                style={inputStyle}
              />
              <button
                onClick={handleGenerateImage}
                disabled={!imagePrompt || generating === 'pending'}
                style={{
                  ...buttonStyle,
                  opacity: !imagePrompt || generating === 'pending' ? 0.7 : 1,
                }}
              >
                {generating === 'pending' ? 'Генерация…' : 'Сгенерировать'}
              </button>
            </div>
          </div>
          <div style={arrowStyle} />
        </>
      )}
    </div>
  )
}

export default ImageGenerator

async function fakeGenerateImage(_prompt: string): Promise<string> {
  await new Promise((r) => setTimeout(r, 800))
  return 'https://picsum.photos/seed/' + encodeURIComponent(_prompt || 'palatine') + '/800/600'
}

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

let imageCounter = 0

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
