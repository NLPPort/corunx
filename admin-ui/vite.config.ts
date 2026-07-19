import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.dirname(fileURLToPath(import.meta.url))
const apiProxy = process.env.VITE_API_PROXY || 'http://127.0.0.1:8787'

// Served by normalcf Worker at /console (see normalcf/wrangler.jsonc + worker.py)
const consoleBase = '/console/'

export default defineConfig({
  plugins: [react()],
  base: consoleBase,
  build: {
    outDir: path.resolve(root, '../normalcf/static/console'),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/lab': { target: apiProxy, changeOrigin: true },
      '/health': { target: apiProxy, changeOrigin: true },
    },
  },
  preview: {
    port: 4173,
  },
})
