import { build, emptyDir } from 'https://deno.land/x/dnt@0.39.0/mod.ts';
import pnpmPkg from './package.json' with { type: 'json' };

const OUTPUT_DIR = './dist';

if (import.meta.main) {
  await emptyDir(OUTPUT_DIR);

  await build({
    entryPoints: [
      './src/mod.ts',
      {
        name: './src/adaptors',
        path: './src/adaptors/mod.ts',
      },
      {
        name: './src/namespace',
        path: './src/namespace/mod.ts',
      },
      {
        name: './src/nfd-mgmt',
        path: './src/nfd-mgmt/mod.ts',
      },
      {
        name: './src/security',
        path: './src/security/mod.ts',
      },
      {
        name: './src/storage',
        path: './src/storage/mod.ts',
      },
      {
        name: './src/sync-agent',
        path: './src/sync-agent/mod.ts',
      },
      {
        name: './src/utils',
        path: './src/utils/mod.ts',
      },
      {
        name: './src/workspace',
        path: './src/workspace/mod.ts',
      },
    ],
    outDir: OUTPUT_DIR,
    shims: {
      // see JS docs for overview and more options
      deno: true,
    },
    test: false, // Required due to some dependencies do not include test files.
    esModule: true,
    typeCheck: false,
    packageManager: 'pnpm',
    // package.json properties
    package: pnpmPkg,
    postBuild() {
      // steps to run after building and before running the tests
      Deno.copyFileSync('LICENSE', `${OUTPUT_DIR}/LICENSE`);
      Deno.copyFileSync('README.md', `${OUTPUT_DIR}/README.md`);
    },
  });
}
