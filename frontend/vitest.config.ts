import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: './src/setupTests.ts',
    globals: true,
    coverage: {
      enabled: true,
      all: true,
      include: ['src/components/**/*.{ts,tsx}', 'src/pages/**/*.{ts,tsx}'],
      exclude: ['**/index.ts', '**/*.test.{ts,tsx}'],
      reporter: ['text', 'json', 'html'],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80
      }
    },
  },
});