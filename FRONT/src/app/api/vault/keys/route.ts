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

type Body = { type: 'rsa' | 'signing'; id: string; password?: string };

function assertStrongEnoughPassword(password: string): void {
  if (password.length < 8) {
    throw new Error('La contraseña de la clave debe tener al menos 8 caracteres.');
  }
}

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as Body;
    if (!body?.id || (body.type !== 'rsa' && body.type !== 'signing')) {
      return Response.json({ error: 'JSON inválido: { type: "rsa"|"signing", id, password }' }, { status: 400 });
    }
    assertValidId(body.id);

    const password = String(body.password || '');
    assertStrongEnoughPassword(password);

    const kd = keysDir();
    if (body.type === 'rsa') {
      const priv = join(kd, `${body.id}_rsa_priv.pem`);
      const pub = join(kd, `${body.id}_rsa_pub.pem`);
      const r = await runEncryptionCli(['genrsa', priv, pub, password]);
      if (!r.ok) {
        return Response.json({ error: r.stderr || r.stdout || 'genrsa falló' }, { status: 500 });
      }
    } else {
      const priv = join(kd, `${body.id}_sign_priv.key`);
      const pub = join(kd, `${body.id}_sign_pub.key`);
      const r = await runEncryptionCli(['genkeys', priv, pub, password]);
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
