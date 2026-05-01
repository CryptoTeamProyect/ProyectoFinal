import { existsSync, mkdirSync, readdirSync, statSync } from 'fs';
import { basename, join, resolve, relative, isAbsolute } from 'path';

const VAULT_SUB = 'vault_data';

export function getProjectRoot(): string {
  const env = process.env.VAULT_PROJECT_ROOT;
  if (env) return resolve(env);
  return resolve(process.cwd(), '..');
}

export function vaultBase(): string {
  const p = join(getProjectRoot(), VAULT_SUB);
  if (!existsSync(p)) mkdirSync(p, { recursive: true });
  return p;
}

export function keysDir(): string {
  const p = join(vaultBase(), 'keys');
  if (!existsSync(p)) mkdirSync(p, { recursive: true });
  return p;
}

export function outDir(): string {
  const p = join(vaultBase(), 'out');
  if (!existsSync(p)) mkdirSync(p, { recursive: true });
  return p;
}

export function tmpDir(): string {
  const p = join(vaultBase(), 'tmp');
  if (!existsSync(p)) mkdirSync(p, { recursive: true });
  return p;
}

const ID_RE = /^[a-zA-Z0-9_-]{1,48}$/;

export function assertValidId(id: string): void {
  if (!ID_RE.test(id)) {
    throw new Error('Identificador inválido (usa letras, números, - y _, 1–48 caracteres).');
  }
}

export function assertKeyBasename(name: string): void {
  if (!/^[a-zA-Z0-9_-]+\.(pem|key)$/.test(name)) {
    throw new Error('Nombre de clave no permitido.');
  }
}

export function resolvedKeyPath(name: string): string {
  assertKeyBasename(name);

  const kd = resolve(keysDir());
  const full = resolve(join(kd, basename(name)));
  const rel = relative(kd, full);

  if (rel.startsWith('..') || isAbsolute(rel) || rel === '') {
    throw new Error('Ruta de clave inválida.');
  }

  return full;
}

export type KeyKind = 'rsa_priv' | 'rsa_pub' | 'sign_priv' | 'sign_pub' | 'other';

export function classifyKey(name: string): KeyKind {
  if (name.endsWith('_rsa_priv.pem')) return 'rsa_priv';
  if (name.endsWith('_rsa_pub.pem')) return 'rsa_pub';
  if (name.endsWith('_sign_priv.key')) return 'sign_priv';
  if (name.endsWith('_sign_pub.key')) return 'sign_pub';
  return 'other';
}

export function listKeyFiles(): { name: string; kind: KeyKind }[] {
  const kd = keysDir();
  const names = readdirSync(kd).filter((f) => statSync(join(kd, f)).isFile());
  return names.map((name) => ({ name, kind: classifyKey(name) }));
}

export function listVaultOutputs(): string[] {
  const od = outDir();
  if (!existsSync(od)) return [];
  return readdirSync(od).filter((f) => f.endsWith('.vault') && statSync(join(od, f)).isFile());
}
