'use client';

import { useCallback, useEffect, useState } from 'react';
import { Unlock, Loader2 } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

type KeyRow = { name: string; kind: string };

export function VerifyDecryptView() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const muted = isDark ? 'text-slate-400' : 'text-slate-600';
  const card = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200';
  const input = isDark ? 'bg-slate-800 border-slate-700 text-slate-100' : 'bg-white border-slate-300 text-slate-900';

  const [keys, setKeys] = useState<KeyRow[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [myId, setMyId] = useState('');
  const [myPrivKey, setMyPrivKey] = useState('');
  const [signerPubKey, setSignerPubKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const refreshKeys = useCallback(() => {
    fetch('/api/vault/keys')
      .then((r) => r.json())
      .then((d) => setKeys(d.keys || []));
  }, []);

  useEffect(() => {
    refreshKeys();
  }, [refreshKeys]);

  const rsaPriv = keys.filter((k) => k.kind === 'rsa_priv');
  const signPub = keys.filter((k) => k.kind === 'sign_pub');

  async function submit() {
    setMsg(null);
    if (!file) {
      setMsg('Elige el contenedor .vault');
      return;
    }
    if (!myId.trim() || !myPrivKey || !signerPubKey) {
      setMsg('Completa id, tu RSA privada y clave pública del firmante');
      return;
    }

    setLoading(true);
    try {
      const form = new FormData();
      form.set('file', file);
      form.set('myId', myId.trim());
      form.set('myPrivKey', myPrivKey);
      form.set('signerPubKey', signerPubKey);

      const r = await fetch('/api/vault/decrypt', { method: 'POST', body: form });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        throw new Error(d.error || r.statusText);
      }

      const blob = await r.blob();
      const cd = r.headers.get('Content-Disposition');
      let filename = 'descargado';
      const m = cd?.match(/filename="([^"]+)"/);
      if (m) {
        try {
          filename = decodeURIComponent(m[1]);
        } catch {
          filename = m[1];
        }
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Error');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 md:p-8 space-y-6 max-w-xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold">Verificar y descifrar</h1>
        <p className={`text-sm mt-1 ${muted}`}>
          Verifica la firma Ed25519 y descifra si tu id está entre los destinatarios.
        </p>
      </div>

      {msg && <p className="text-sm text-red-400">{msg}</p>}

      <div className={`${card} border rounded-xl p-4 space-y-2`}>
        <label className={`text-sm font-medium ${muted}`}>Contenedor (.vault JSON)</label>
        <input
          type="file"
          accept=".vault,.json,application/json"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className={`w-full text-sm ${muted} file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-cyan-600 file:text-white`}
        />
      </div>

      <div className={`${card} border rounded-xl p-4 space-y-3`}>
        <div>
          <label className={`text-sm font-medium ${muted}`}>Tu id (como en el cifrado)</label>
          <input
            value={myId}
            onChange={(e) => setMyId(e.target.value)}
            className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${input}`}
          />
        </div>
        <div>
          <label className={`text-sm font-medium ${muted}`}>Tu RSA privada</label>
          <select
            value={myPrivKey}
            onChange={(e) => setMyPrivKey(e.target.value)}
            className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${input}`}
          >
            <option value="">—</option>
            {rsaPriv.map((k) => (
              <option key={k.name} value={k.name}>
                {k.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className={`text-sm font-medium ${muted}`}>Clave pública de firma del emisor</label>
          <select
            value={signerPubKey}
            onChange={(e) => setSignerPubKey(e.target.value)}
            className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${input}`}
          >
            <option value="">—</option>
            {signPub.map((k) => (
              <option key={k.name} value={k.name}>
                {k.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      <button
        type="button"
        disabled={loading}
        onClick={submit}
        className="w-full py-3 rounded-xl bg-cyan-600 text-white font-medium hover:bg-cyan-700 disabled:opacity-50 flex items-center justify-center gap-2"
      >
        {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Unlock className="w-5 h-5" />}
        Descifrar
      </button>
    </div>
  );
}
