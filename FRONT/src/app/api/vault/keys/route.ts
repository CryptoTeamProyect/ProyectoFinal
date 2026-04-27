import { NextResponse } from 'next/server';
import { readdirSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { getProjectRoot } from '@/lib/vault-paths';

// --- ESTO SIRVE PARA LISTAR LAS LLAVES ---
export async function GET() {
  try {
    const root = getProjectRoot(); 
    const isVercel = process.env.NODE_ENV === 'production' || process.env.VERCEL;
    const keysDir = isVercel ? root : join(root, 'vault_data', 'keys'); 

    if (!existsSync(keysDir)) {
      if (!isVercel) mkdirSync(keysDir, { recursive: true });
      return NextResponse.json({ keys: [] });
    }

    const files = readdirSync(keysDir);
    const keys = files.filter(f => 
      f.endsWith('.pub') || f.endsWith('.pem') || f.endsWith('.key') || f.endsWith('.sig')
    );

    return NextResponse.json({ keys });
  } catch (error) {
    return NextResponse.json({ keys: [], error: 'Error al listar' }, { status: 500 });
  }
}

// --- ESTO SIRVE PARA CREAR LAS LLAVES (EL PUENTE) ---
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { args } = body;

    // Llamamos a tu archivo de Python en Vercel
    const baseUrl = process.env.VERCEL_URL 
      ? `https://${process.env.VERCEL_URL}` 
      : 'http://localhost:3000';

    const response = await fetch(`${baseUrl}/api/python_bridge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ args }),
    });

    const result = await response.json();
    return NextResponse.json(result);

  } catch (error) {
    console.error("Error en POST keys:", error);
    return NextResponse.json({ error: 'Error al generar llave' }, { status: 500 });
  }
}