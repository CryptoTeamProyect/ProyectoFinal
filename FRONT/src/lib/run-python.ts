export async function runEncryptionCli(
  args: string[],
): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  try {
    
    const baseUrl = process.env.NEXT_PUBLIC_VERCEL_URL 
      ? `https://${process.env.NEXT_PUBLIC_VERCEL_URL}` 
      : (typeof window !== 'undefined' ? window.location.origin : '');


    const response = await fetch(`${baseUrl}/api/python_bridge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ args }),
    });

    // Verificamos si la respuesta es JSON antes de parsear
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Error en el servidor (${response.status}): ${errorText}`);
    }

    const result = await response.json();

    return {
      ok: response.ok,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      code: response.ok ? 0 : 1,
    };
  } catch (error) {
    console.error("Error en runEncryptionCli:", error);
    return {
      ok: false,
      stdout: '',
      stderr: error instanceof Error ? error.message : 'Unknown error',
      code: 1,
    };
  }
}
