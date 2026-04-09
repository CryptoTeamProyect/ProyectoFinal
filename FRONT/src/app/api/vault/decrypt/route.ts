import { randomUUID } from 'crypto';
import { readFile, unlink, writeFile } from 'fs/promises';
import { join } from 'path';
import { runEncryptionCli } from '@/lib/run-python';
import {
  assertValidId,
  resolvedKeyPath,
  tmpDir,
} from '@/lib/vault-paths';

export const runtime = 'nodejs';
export const maxDuration = 120;

export async function POST(request: Request) {
  let tmpVault: string | null = null;
  let tmpOut: string | null = null;
  try {
    const form = await request.formData();
    const file = form.get('file');
    const myId = String(form.get('myId') || '').trim();
    const myPrivKey = String(form.get('myPrivKey') || '').trim();
    const signerPubKey = String(form.get('signerPubKey') || '').trim();

    if (!(file instanceof File) || file.size === 0) {
      return Response.json({ error: 'Falta contenedor' }, { status: 400 });
    }
    assertValidId(myId);
    const myPrivPath = resolvedKeyPath(myPrivKey);
    const signerPubPath = resolvedKeyPath(signerPubKey);

    const td = tmpDir();
    tmpVault = join(td, `vault_${randomUUID()}.vault`);
    tmpOut = join(td, `out_${randomUUID()}.bin`);

    const vaultBuf = Buffer.from(await file.arrayBuffer());
    await writeFile(tmpVault, vaultBuf);

    const result = await runEncryptionCli([
      'dec',
      tmpVault,
      tmpOut,
      myPrivPath,
      myId,
      signerPubPath,
    ]);

    if (!result.ok) {
      return Response.json(
        { error: result.stderr || result.stdout || 'Descifrado o firma inválida' },
        { status: 400 },
      );
    }

    const plaintext = await readFile(tmpOut);
    let downloadName = 'documento';
    try {
      const j = JSON.parse(vaultBuf.toString('utf-8')) as { header?: { filename?: string } };
      if (j.header?.filename && /^[\w.\- ]{1,200}$/.test(j.header.filename)) {
        downloadName = j.header.filename;
      }
    } catch {
      /* use default */
    }

    const safeName = downloadName.replace(/[^\w.\-]/g, '_').slice(0, 200) || 'documento';
    return new Response(Uint8Array.from(plaintext), {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${safeName}"`,
      },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Error';
    return Response.json({ error: msg }, { status: 400 });
  } finally {
    for (const p of [tmpVault, tmpOut]) {
      if (p) {
        try {
          await unlink(p);
        } catch {
          /* ignore */
        }
      }
    }
  }
}
