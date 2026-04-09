'use client';

import { useCallback, useEffect, useState } from 'react';
import { Lock, Loader2 } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

type KeyRow = { name: string; kind: string };

type RecipRow = { id: string; pubKey: string };

export function EncryptView() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const muted = isDark ? 'text-slate-400' : 'text-slate-600';
  const card = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200';
  const input = isDark ? 'bg-slate-800 border-slate-700 text-slate-100' : 'bg-white border-slate-300 text-slate-900';

  const [keys, setKeys] = useState<KeyRow[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [signerId, setSignerId] = useState('');
  const [signPrivKey, setSignPrivKey] = useState('');
  const [outputName, setOutputName] = useState('');
  const [recipients, setRecipients] = useState<RecipRow[]>([{ id: '', pubKey: '' }]);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  const refreshKeys = useCallback(() => {
    fetch('/api/vault/keys')
      .then((r) => r.json())
      .then((d) => setKeys(d.keys || []));
  }, []);

  useEffect(() => {
    refreshKeys();
  }, [refreshKeys]);

  const signPrivOptions = keys.filter((k) => k.kind === 'sign_priv');
  const rsaPubOptions = keys.filter((k) => k.kind === 'rsa_pub');

  function addRecipient() {
    setRecipients((r) => [...r, { id: '', pubKey: '' }]);
  }

  function updateRecipient(i: number, field: keyof RecipRow, value: string) {
    setRecipients((rows) => rows.map((row, j) => (j === i ? { ...row, [field]: value } : row)));
  }

  function removeRecipient(i: number) {
    setRecipients((rows) => rows.filter((_, j) => j !== i));
  }

  async function submit() {
    setMsg(null);
    setOk(null);
    if (!file) {
      setMsg('Elige un archivo');
      return;
    }
    if (!signerId.trim() || !signPrivKey) {
      setMsg('Firmante e identificador obligatorios');
      return;
    }
    const rec = recipients.filter((r) => r.id.trim() && r.pubKey);
    if (rec.length === 0) {
      setMsg('Añade al menos un destinatario con id y clave pública RSA');
      return;
    }

    setLoading(true);
    try {
      const form = new FormData();
      form.set('file', file);
      form.set('signerId', signerId.trim());
      form.set('signPrivKey', signPrivKey);
      if (outputName.trim()) form.set('outputName', outputName.trim());
      form.set('recipients', JSON.stringify(rec.map((r) => ({ id: r.id.trim(), pubKey: r.pubKey }))));

      const r = await fetch('/api/vault/encrypt', { method: 'POST', body: form });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || 'Error al cifrar');
      setOk(`Guardado como vault_data/out/${d.file}`);
      setFile(null);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Error');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 md:p-8 space-y-6 max-w-xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold">Cifrar</h1>
        <p className={`text-sm mt-1 ${muted}`}>AES-256-GCM + RSA-OAEP + firma Ed25519 (encryption.py)</p>
      </div>

      {msg && <p className="text-sm text-red-400">{msg}</p>}
      {ok && <p className="text-sm text-green-500">{ok}</p>}

      <div className={`${card} border rounded-xl p-4 space-y-2`}>
        <label className={`text-sm font-medium ${muted}`}>Archivo</label>
        <input
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className={`w-full text-sm ${muted} file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-cyan-600 file:text-white`}
        />
      </div>

      <div className={`${card} border rounded-xl p-4 space-y-3`}>
        <div>
          <label className={`text-sm font-medium ${muted}`}>Tu id de firmante</label>
          <input
            value={signerId}
            onChange={(e) => setSignerId(e.target.value)}
            placeholder="ej. alice"
            className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${input}`}
          />
        </div>
        <div>
          <label className={`text-sm font-medium ${muted}`}>Clave privada de firma</label>
          <select
            value={signPrivKey}
            onChange={(e) => setSignPrivKey(e.target.value)}
            className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${input}`}
          >
            <option value="">—</option>
            {signPrivOptions.map((k) => (
              <option key={k.name} value={k.name}>
                {k.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className={`text-sm font-medium ${muted}`}>Nombre salida (opcional)</label>
          <input
            value={outputName}
            onChange={(e) => setOutputName(e.target.value)}
            placeholder="documento.vault"
            className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${input}`}
          />
        </div>
      </div>

      <div className={`${card} border rounded-xl p-4 space-y-3`}>
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium">Destinatarios</span>
          <button type="button" onClick={addRecipient} className="text-xs text-cyan-500 hover:underline">
            + Añadir
          </button>
        </div>
        {recipients.map((row, i) => (
          <div key={i} className="flex flex-col gap-2 sm:flex-row sm:items-end">
            <div className="flex-1">
              <label className={`text-xs ${muted}`}>Id destinatario</label>
              <input
                value={row.id}
                onChange={(e) => updateRecipient(i, 'id', e.target.value)}
                placeholder="bob"
                className={`mt-0.5 w-full rounded-lg border px-2 py-1.5 text-sm ${input}`}
              />
            </div>
            <div className="flex-[2]">
              <label className={`text-xs ${muted}`}>RSA pública</label>
              <select
                value={row.pubKey}
                onChange={(e) => updateRecipient(i, 'pubKey', e.target.value)}
                className={`mt-0.5 w-full rounded-lg border px-2 py-1.5 text-sm ${input}`}
              >
                <option value="">—</option>
                {rsaPubOptions.map((k) => (
                  <option key={k.name} value={k.name}>
                    {k.name}
                  </option>
                ))}
              </select>
            </div>
            {recipients.length > 1 && (
              <button type="button" onClick={() => removeRecipient(i)} className="text-xs text-red-400 pb-1">
                Quitar
              </button>
            )}
          </div>
        ))}
      </div>

      <button
        type="button"
        disabled={loading}
        onClick={submit}
        className="w-full py-3 rounded-xl bg-cyan-600 text-white font-medium hover:bg-cyan-700 disabled:opacity-50 flex items-center justify-center gap-2"
      >
        {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Lock className="w-5 h-5" />}
        Cifrar y firmar
      </button>
    </div>
  );
}
