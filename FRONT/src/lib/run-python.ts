export async function runEncryptionCli(
  args: string[],
): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  try {
    // 1. Definimos la URL base. 
    // Usamos la URL de tu proyecto directamente para que no haya falla en el parseo.
    const baseUrl = 'https://proyecto-final-ruddy-mu.vercel.app';

    // 2. Construimos la URL completa manualmente
    const fullUrl = `${baseUrl}/api/python_bridge`;

    const response = await fetch(fullUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ args }),
    });

    // Si el servidor responde algo que no es 200-299
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Servidor respondió con status ${response.status}: ${errorText.substring(0, 50)}`);
    }

    const result = await response.json();

    return {
      ok: true,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      code: 0,
    };
  } catch (error) {
    console.error("Error en fetch:", error);
    return {
      ok: false,
      stdout: '',
      stderr: error instanceof Error ? error.message : 'Error de conexión',
      code: 1,
    };
  }
}