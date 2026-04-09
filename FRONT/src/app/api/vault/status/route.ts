import { runEncryptionCli } from '@/lib/run-python';
import { getProjectRoot, listKeyFiles, listVaultOutputs } from '@/lib/vault-paths';
export const runtime = 'nodejs';

export async function GET() {
  const root = getProjectRoot();
  let pythonOk = false;
  let pythonMessage = '';
  try {
    const r = await runEncryptionCli([]);
    pythonOk = r.ok;
    pythonMessage = r.stderr || r.stdout || '';
  } catch (e) {
    pythonMessage = e instanceof Error ? e.message : 'Error al ejecutar Python';
  }

  return Response.json({
    projectRoot: root,
    pythonOk,
    pythonMessage: pythonMessage.trim().slice(0, 500),
    keys: listKeyFiles(),
    containers: listVaultOutputs(),
  });
}
