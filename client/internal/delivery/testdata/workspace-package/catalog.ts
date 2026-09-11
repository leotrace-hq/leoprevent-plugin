import { Hono } from 'hono';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { languageSchema } from '@leotrace/shared';

const CATALOG_ROOT = '/srv/catalogs';
export const catalogRoute = new Hono();

catalogRoute.get('/catalog/:language', async (c) => {
  const raw = c.req.param('language');
  const parsed = languageSchema.safeParse(raw);
  if (!parsed.success) return c.json({ error: 'invalid language' }, 400);
  const filename = path.join(CATALOG_ROOT, parsed.data, 'catalog.json');
  return c.text(await readFile(filename, 'utf8'));
});
