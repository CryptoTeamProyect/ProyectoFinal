import { NextResponse } from 'next/server';
import { readdirSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { getProjectRoot } from '@/lib/vault-paths';

export async function GET() {
  try {
    const root = getProjectRoot(); 
    const isVercel = process.env.NODE_ENV === 'production' || process.env.VERCEL;

    // Ajustamos la ruta para que coincida EXACTAMENTE con donde Python guarda los archivos
    // En Vercel, Python guarda directo en /tmp/ para evitar errores de carpetas
    const keysDir = isVercel 
      ? root  // En Vercel, root ya es '/tmp'
      : join(root, 'vault_data', 'keys'); 

    console.log("Buscando llaves en:", keysDir);

    if (!existsSync(keysDir)) {
      // Si no existe en local, la creamos. En Vercel /tmp siempre existe.
      if (!isVercel) mkdirSync(keysDir, { recursive: true });
      return NextResponse.json({ keys: [] });
    }

    const files = readdirSync(keysDir);
    
    // Filtramos para mostrar solo los archivos que Python genera (.pub, .pem, .key, .sig)
    const keys = files.filter(f => 
      f.endsWith('.pub') || 
      f.endsWith('.pem') || 
      f.endsWith('.key') || 
      f.endsWith('.sig')
    );

    return NextResponse.json({ keys });
  } catch (error) {
    console.error("Error al listar llaves:", error);
    return NextResponse.json({ 
      keys: [], 
      error: 'No se pudieron listar las llaves',
      details: error instanceof Error ? error.message : String(error)
    }, { status: 500 });
  }
}