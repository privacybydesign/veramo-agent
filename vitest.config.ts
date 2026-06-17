import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

// Pin the timezone so date-formatting assertions (e.g. VCDM validFrom "+01:00")
// are deterministic across machines and CI. Set here (before workers spawn) so each
// test worker inherits it at startup. The credential test vectors assume CET/CEST.
process.env.TZ = 'Europe/Amsterdam';

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    globals: true,
    setupFiles: './vitest.setup.ts'
  },
});

