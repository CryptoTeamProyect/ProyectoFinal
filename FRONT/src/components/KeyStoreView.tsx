'use client';

import { useCallback, useEffect, useState } from 'react';
import { Key, Loader2 } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

type KeyRow = { name: string; kind: string };

export function KeyStoreView() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const muted = isDark ? 'text-slate-400' : 'text-slate-600';
  const card = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200';
  const input = isDark ? 'bg-slate-800 border-slate-700 text-slate-100' : 'bg-white border-slate-300 text-slate-900';

  const [keys, setKeys] = useState<KeyRow[]>([]);
  const [newId, setNewId] = useState('');
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const refresh = useCallback(() => {
    fetch('/api/vault/keys')
      .then((r) => r.json())
      .then((d) => setKeys(d.keys || []))
      .catch(() => setMsg('Error al listar claves'));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function generate(type: 'rsa' | 'signing') {
    setMsg(null);
    if (!newId.trim()) {
      setMsg('Escribe un identificador (ej. alice)');
      return;
    }
    setLoading(true);
    try {
      const r = await fetch('/api/vault/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, id: newId.trim() }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || 'Error');
      setKeys(d.keys || []);
      setNewId('');
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Error');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 md:p-8 space-y-6 max-w-2xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold">Claves</h1>
        <p className={`text-sm mt-1 ${muted}`}>
          Se guardan en <code className="text-xs">vault_data/keys/</code> (RSA para cifrado, Ed25519 para firmar
          contenedores).
        </p>
      </div>

      {msg && <p className="text-sm text-amber-500">{msg}</p>}

      <div className={`${card} border rounded-xl p-4 space-y-3`}>
        <label className={`text-sm font-medium ${muted}`}>Identificador nuevo</label>
        <input
          value={newId}
          onChange={(e) => setNewId(e.target.value)}
          placeholder="ej. alice"
          className={`w-full rounded-lg border px-3 py-2 text-sm ${input}`}
        />
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={loading}
            onClick={() => generate('rsa')}
            className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-sm font-medium hover:bg-cyan-700 disabled:opacity-50 flex items-center gap-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            Par RSA
          </button>
          <button
            type="button"
            disabled={loading}
            onClick={() => generate('signing')}
            className={`px-4 py-2 rounded-lg text-sm font-medium border ${
              isDark ? 'border-slate-600 hover:bg-slate-800' : 'border-slate-300 hover:bg-slate-50'
            } disabled:opacity-50 flex items-center gap-2`}
          >
            Par firma (Ed25519)
          </button>
        </div>
      </div>

      <div className={`${card} border rounded-xl overflow-hidden`}>
        <div className={`px-4 py-3 border-b ${isDark ? 'border-slate-800' : 'border-slate-200'} flex items-center gap-2`}>
          <Key className="w-4 h-4 text-cyan-500" />
          <span className="font-medium text-sm">Archivos</span>
        </div>
        <ul className="divide-y divide-slate-800/50">
          {keys.length === 0 ? (
            <li className={`px-4 py-6 text-sm text-center ${muted}`}>No hay claves. Genera al menos un RSA y un par de firma.</li>
          ) : (
            keys.map((k) => (
              <li key={k.name} className={`px-4 py-3 flex justify-between gap-2 text-sm ${isDark ? 'bg-slate-900' : ''}`}>
                <code className="truncate">{k.name}</code>
                <span className={`shrink-0 text-xs uppercase ${muted}`}>{k.kind}</span>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}
