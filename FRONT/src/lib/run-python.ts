import { spawn } from 'child_process';
import { join } from 'path';
import { getProjectRoot } from '@/lib/vault-paths';

export async function runEncryptionCli(
  args: string[],
): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  try {
    // Llamamos a la API de Python que Vercel sí puede ejecutar
    const response = await fetch('/api/python_bridge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ args }),
    });

    const result = await response.json();

    return {
      ok: response.ok,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      code: response.ok ? 0 : 1,
    };
  } catch (error) {
    return {
      ok: false,
      stdout: '',
      stderr: error instanceof Error ? error.message : 'Unknown error',
      code: 1,
    };
  }
}
