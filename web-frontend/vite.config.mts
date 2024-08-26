import path from 'path';
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import reactJsx from 'vite-react-jsx'

// https://vitejs.dev/config/

export default defineConfig({
  root: path.resolve(__dirname, "src"),
  plugins: [react()],
  build: {
    assetsInlineLimit: 0,
    outDir: "../build",
    emptyOutDir: true,
    rollupOptions: {
      input: path.resolve(__dirname, "src/index.html"),
    }
  }
})
