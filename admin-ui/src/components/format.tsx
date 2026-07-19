export function StatusPill({ status }: { status?: string | null }) {
  const s = (status ?? 'unknown').toLowerCase()
  return <span className={`pill ${s}`}>{s}</span>
}

export function formatBytes(n?: number | null) {
  if (n == null || Number.isNaN(n)) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}

export function formatWhen(v?: string | null) {
  if (!v) return '—'
  const d = new Date(v.includes('T') ? v : v.replace(' ', 'T') + 'Z')
  if (Number.isNaN(d.getTime())) return v
  return d.toLocaleString()
}

export function shortId(v?: string | null, n = 10) {
  if (!v) return '—'
  return v.length <= n ? v : `${v.slice(0, n)}…`
}
