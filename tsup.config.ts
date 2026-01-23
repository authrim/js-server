import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'providers/index': 'src/providers/index.ts',
    'adapters/express': 'src/adapters/express.ts',
    'adapters/fastify': 'src/adapters/fastify.ts',
    'adapters/hono': 'src/adapters/hono.ts',
    'adapters/koa': 'src/adapters/koa.ts',
    'adapters/nestjs': 'src/adapters/nestjs.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  minify: true,
  sourcemap: true,
  target: 'es2020',
  external: ['express', 'fastify', 'hono', 'koa', '@nestjs/common'],
  splitting: true,
  treeshake: true,
});
