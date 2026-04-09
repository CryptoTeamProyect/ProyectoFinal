import { runEncryptionCli } from '@/lib/run-python';
import {
  assertValidId,
  keysDir,
  listKeyFiles,
} from '@/lib/vault-paths';
import { join } from 'path';

export const runtime = 'nodejs';

export async function GET() {
  try {
    return Response.json({ keys: listKeyFiles() });
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Error';
    return Response.json({ error: msg }, { status: 500 });
  }
}

type Body = { type: 'rsa' | 'signing'; id: string };

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as Body;
    if (!body?.id || (body.type !== 'rsa' && body.type !== 'signing')) {
      return Response.json({ error: 'JSON inválido: { type: "rsa"|"signing", id }' }, { status: 400 });
    }
    assertValidId(body.id);

    const kd = keysDir();
    if (body.type === 'rsa') {
      const priv = join(kd, `${body.id}_rsa_priv.pem`);
      const pub = join(kd, `${body.id}_rsa_pub.pem`);
      const r = await runEncryptionCli(['genrsa', priv, pub]);
      if (!r.ok) {
        return Response.json({ error: r.stderr || r.stdout || 'genrsa falló' }, { status: 500 });
      }
    } else {
      const priv = join(kd, `${body.id}_sign_priv.key`);
      const pub = join(kd, `${body.id}_sign_pub.key`);
      const r = await runEncryptionCli(['genkeys', priv, pub]);
      if (!r.ok) {
        return Response.json({ error: r.stderr || r.stdout || 'genkeys falló' }, { status: 500 });
      }
    }

    return Response.json({ ok: true, keys: listKeyFiles() });
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Error';
    return Response.json({ error: msg }, { status: 400 });
  }
}
