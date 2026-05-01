import { spawn } from 'child_process';
import { join } from 'path';
import { getProjectRoot } from '@/lib/vault-paths';

export async function runEncryptionCli(
  args: string[],
): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  const root = getProjectRoot();
  const script = join(root, 'encryption.py');
  const python = process.env.PYTHON_BIN || 'python3';

  return new Promise((resolve, reject) => {
    const child = spawn(python, [script, ...args], {
      cwd: root,
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => {
      stdout += d.toString();
    });
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString();
    });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ ok: code === 0, stdout, stderr, code: code ?? 1 });
    });
  });
}
