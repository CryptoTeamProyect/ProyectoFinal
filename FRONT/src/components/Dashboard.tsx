'use client';

import { useEffect, useState } from 'react';
import { Lock, AlertCircle, CheckCircle2, Download } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

type Status = {
  projectRoot: string;
  pythonOk: boolean;
  pythonMessage: string;
  keys: { name: string; kind: string }[];
  containers: string[];
};

export function Dashboard() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const muted = isDark ? 'text-slate-400' : 'text-slate-600';
  const card = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200';

  const [status, setStatus] = useState<Status | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/vault/status')
      .then((r) => r.json())
      .then((data) => {
        if (data.error) setErr(data.error);
        else setStatus(data as Status);
      })
      .catch(() => setErr('No se pudo conectar con la API'));
  }, []);

  return (
    <div className="p-6 md:p-8 space-y-6 max-w-3xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold">Inicio</h1>
        <p className={`text-sm mt-1 ${muted}`}>Estado del backend Python y archivos en vault_data/</p>
      </div>

      {err && (
        <div className="flex items-center gap-2 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {err}
        </div>
      )}

      {status && (
        <>
          <div className={`${card} border rounded-xl p-4 flex items-center gap-3`}>
            {status.pythonOk ? (
              <CheckCircle2 className="w-6 h-6 text-green-500 shrink-0" />
            ) : (
              <AlertCircle className="w-6 h-6 text-amber-500 shrink-0" />
            )}
            <div>
              <p className="font-medium">{status.pythonOk ? 'Python listo' : 'Revisa Python'}</p>
              <p className={`text-xs ${muted} font-mono break-all`}>{status.projectRoot}</p>
              {!status.pythonOk && status.pythonMessage && (
                <p className="text-xs text-amber-600/90 mt-1">{status.pythonMessage}</p>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className={`${card} border rounded-xl p-4 text-center`}>
              <p className={`text-3xl font-bold ${isDark ? 'text-cyan-400' : 'text-cyan-600'}`}>
                {status.keys.length}
              </p>
              <p className={`text-xs mt-1 ${muted}`}>Archivos de clave</p>
            </div>
            <div className={`${card} border rounded-xl p-4 text-center`}>
              <p className={`text-3xl font-bold ${isDark ? 'text-emerald-400' : 'text-emerald-600'}`}>
                {status.containers.length}
              </p>
              <p className={`text-xs mt-1 ${muted}`}>Contenedores .vault</p>
            </div>
          </div>

          <div className={`${card} border rounded-xl p-4`}>
            <h2 className="text-sm font-semibold text-cyan-500 mb-3">Contenedores generados</h2>
            {status.containers.length === 0 ? (
              <p className={`text-sm ${muted}`}>Ninguno aún. Cifra un archivo en Cifrar.</p>
            ) : (
              <ul className="space-y-2">
                {status.containers.map((name) => (
                  <li
                    key={name}
                    className={`flex items-center justify-between gap-2 rounded-lg p-2 ${isDark ? 'bg-slate-800/60' : 'bg-slate-100'}`}
                  >
                    <span className="text-sm font-mono truncate">{name}</span>
                    <a
                      href={`/api/vault/download/${encodeURIComponent(name)}`}
                      download
                      className="shrink-0 flex items-center gap-1 text-xs font-medium text-cyan-500 hover:text-cyan-400"
                    >
                      <Download className="w-3.5 h-3.5" />
                      Descargar
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <p className={`text-xs ${muted} flex items-start gap-2`}>
            <Lock className="w-4 h-4 shrink-0 mt-0.5" />
            Requiere <code className="px-1 rounded bg-slate-800/50">pip install -r requirements.txt</code> en la raíz del
            proyecto y <code className="px-1 rounded bg-slate-800/50">python3</code> en el PATH (o variable{' '}
            <code className="px-1 rounded bg-slate-800/50">PYTHON_BIN</code>).
          </p>
        </>
      )}
    </div>
  );
}
