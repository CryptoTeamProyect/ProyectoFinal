import { randomUUID } from 'crypto';
import { writeFile, unlink } from 'fs/promises';
import { join } from 'path';
import { runEncryptionCli } from '@/lib/run-python';
import {
  assertValidId,
  outDir,
  resolvedKeyPath,
  tmpDir,
} from '@/lib/vault-paths';

export const runtime = 'nodejs';
export const maxDuration = 120;

type Recip = { id: string; pubKey: string };

function safeOutputName(raw: string | null): string {
  const base = (raw || `doc_${Date.now()}`).replace(/\.vault$/i, '');
  if (!/^[a-zA-Z0-9_-]{1,80}$/.test(base)) {
    return `out_${Date.now()}.vault`;
  }
  return `${base}.vault`;
}

export async function POST(request: Request) {
  let tmpIn: string | null = null;
  try {
    const form = await request.formData();
    const file = form.get('file');
    const signerId = String(form.get('signerId') || '').trim();
    const signPrivKey = String(form.get('signPrivKey') || '').trim();
    const recipientsRaw = String(form.get('recipients') || '[]');
    const outputName = safeOutputName(form.get('outputName') ? String(form.get('outputName')) : null);

    if (!(file instanceof File) || file.size === 0) {
      return Response.json({ error: 'Falta archivo' }, { status: 400 });
    }
    assertValidId(signerId);
    const signPrivPath = resolvedKeyPath(signPrivKey);

    let recipients: Recip[];
    try {
      recipients = JSON.parse(recipientsRaw) as Recip[];
    } catch {
      return Response.json({ error: 'recipients JSON inválido' }, { status: 400 });
    }
    if (!Array.isArray(recipients) || recipients.length === 0) {
      return Response.json({ error: 'Añade al menos un destinatario' }, { status: 400 });
    }

    const args = ['enc'];
    const td = tmpDir();
    tmpIn = join(td, `in_${randomUUID()}`);
    const buf = Buffer.from(await file.arrayBuffer());
    await writeFile(tmpIn, buf);

    const outPath = join(outDir(), outputName);
    args.push(tmpIn, outPath, signPrivPath, signerId);

    for (const r of recipients) {
      assertValidId(r.id);
      const pubPath = resolvedKeyPath(r.pubKey);
      args.push(`${r.id}=${pubPath}`);
    }

    const result = await runEncryptionCli(args);
    if (!result.ok) {
      return Response.json(
        { error: result.stderr || result.stdout || 'encryption.py enc falló' },
        { status: 500 },
      );
    }

    return Response.json({ ok: true, file: outputName });
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Error';
    return Response.json({ error: msg }, { status: 400 });
  } finally {
    if (tmpIn) {
      try {
        await unlink(tmpIn);
      } catch {
        /* ignore */
      }
    }
  }
}
