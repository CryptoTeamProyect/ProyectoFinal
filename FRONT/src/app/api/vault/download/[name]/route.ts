import { readFile } from 'fs/promises';
import { join } from 'path';
import { outDir } from '@/lib/vault-paths';

export const runtime = 'nodejs';

export async function GET(_request: Request, context: { params: Promise<{ name: string }> }) {
  const { name } = await context.params;
  if (!/^[a-zA-Z0-9_-]+\.vault$/.test(name)) {
    return new Response('No encontrado', { status: 404 });
  }
  try {
    const full = join(outDir(), name);
    const body = await readFile(full);
    return new Response(Uint8Array.from(body), {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${name}"`,
      },
    });
  } catch {
    return new Response('No encontrado', { status: 404 });
  }
}
