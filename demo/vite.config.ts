import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig({
  root: resolve(__dirname),
  resolve: {
    alias: {
      'keytr': resolve(__dirname, '../src'),
    },
  },
})
