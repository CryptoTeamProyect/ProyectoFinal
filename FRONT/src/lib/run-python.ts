export async function runEncryptionCli(
  args: string[],
): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  try {
    // URL FIJA PARA EVITAR ERRORES DE PARSEO EN VERCEL
    const fullUrl = 'https://proyecto-final-ruddy-mu.vercel.app/api/python_bridge';

    const response = await fetch(fullUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ args }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return {
        ok: false,
        stdout: '',
        stderr: `Error del servidor (${response.status}): ${errorText.substring(0, 100)}`,
        code: 1,
      };
    }

    const result = await response.json();

    return {
      ok: true,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      code: 0,
    };
  } catch (error) {
    return {
      ok: false,
      stdout: '',
      stderr: error instanceof Error ? error.message : 'Error de red o parseo',
      code: 1,
    };
  }
}