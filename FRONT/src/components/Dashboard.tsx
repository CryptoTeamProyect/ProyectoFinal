'use client';

import { Lock, Unlock, FileCheck, Key, Clock } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

export function Dashboard() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const muted = isDark ? 'text-slate-400' : 'text-slate-600';
  const card = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200';
  const inner = isDark ? 'bg-slate-800/50 hover:bg-slate-800' : 'bg-slate-50 hover:bg-slate-100';

  const recentDocuments = [
    { name: 'Contrato_Confidencial.pdf.enc', date: '2026-03-18', status: 'Cifrado' },
    { name: 'Documentos_Legales.docx.enc', date: '2026-03-17', status: 'Cifrado' },
    { name: 'Informe_Financiero_Q1.xlsx.enc', date: '2026-03-15', status: 'Cifrado' },
  ];

  const publicKeys = [
    { name: 'Alice Johnson', id: 'ed25519:a7f8...9b2c' },
    { name: 'Bob Smith', id: 'ed25519:3d4e...1a6f' },
    { name: 'Carol White', id: 'ed25519:8c9d...5e4b' },
  ];

  return (
    <div className="p-6 md:p-8 space-y-8 max-w-5xl mx-auto">
      <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight">Inicio</h1>
          <p className={`text-sm mt-1 ${muted}`}>Tu bóveda criptográfica</p>
        </div>
        <div
          className={`flex items-center gap-3 rounded-xl px-4 py-3 border ${isDark ? 'border-slate-800 bg-slate-900/60' : 'border-slate-200 bg-white'}`}
        >
          <span className="relative flex h-3 w-3">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-40" />
            <span className="relative inline-flex h-3 w-3 rounded-full bg-green-500" />
          </span>
          <span className="text-sm font-medium">Lista</span>
          <button
            type="button"
            className="ml-2 flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-cyan-700 transition-colors"
          >
            <Unlock className="w-3.5 h-3.5" />
            Abrir
          </button>
        </div>
      </header>

      <div className="grid grid-cols-3 gap-3 md:gap-4">
        <div className={`${card} border rounded-xl p-4 text-center`}>
          <FileCheck className={`w-5 h-5 mx-auto mb-2 ${isDark ? 'text-blue-400' : 'text-blue-600'}`} />
          <p className={`text-2xl md:text-3xl font-bold tabular-nums ${isDark ? 'text-blue-400' : 'text-blue-600'}`}>24</p>
          <p className={`text-xs mt-1 ${muted}`}>Archivos</p>
        </div>
        <div className={`${card} border rounded-xl p-4 text-center`}>
          <Key className={`w-5 h-5 mx-auto mb-2 ${isDark ? 'text-emerald-400' : 'text-emerald-600'}`} />
          <p className={`text-2xl md:text-3xl font-bold tabular-nums ${isDark ? 'text-emerald-400' : 'text-emerald-600'}`}>
            {publicKeys.length}
          </p>
          <p className={`text-xs mt-1 ${muted}`}>Claves</p>
        </div>
        <div className={`${card} border rounded-xl p-4 text-center`}>
          <Clock className={`w-5 h-5 mx-auto mb-2 ${isDark ? 'text-violet-400' : 'text-violet-600'}`} />
          <p className={`text-lg md:text-xl font-bold ${isDark ? 'text-violet-400' : 'text-violet-600'}`}>Hoy</p>
          <p className={`text-xs mt-1 ${muted}`}>Actividad</p>
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        <div className={`${card} border rounded-xl p-5`}>
          <h3 className="text-sm font-semibold uppercase tracking-wide text-cyan-500 mb-4">Recientes</h3>
          <ul className="space-y-2">
            {recentDocuments.map((doc, index) => (
              <li
                key={index}
                className={`flex items-center gap-3 rounded-lg p-3 ${inner} transition-colors`}
              >
                <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${isDark ? 'bg-cyan-600/20' : 'bg-cyan-100'}`}>
                  <Lock className={`h-4 w-4 ${isDark ? 'text-cyan-400' : 'text-cyan-600'}`} />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium truncate font-mono">{doc.name}</p>
                  <p className={`text-xs ${muted}`}>{doc.date}</p>
                </div>
                <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${isDark ? 'bg-green-500/20 text-green-400' : 'bg-green-100 text-green-800'}`}>
                  {doc.status}
                </span>
              </li>
            ))}
          </ul>
        </div>

        <div className={`${card} border rounded-xl p-5`}>
          <h3 className="text-sm font-semibold uppercase tracking-wide text-emerald-500 mb-4">Contactos</h3>
          <ul className="space-y-2">
            {publicKeys.map((contact, index) => (
              <li
                key={index}
                className={`flex items-center gap-3 rounded-lg p-3 ${isDark ? 'bg-slate-800/50' : 'bg-slate-50'}`}
              >
                <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${isDark ? 'bg-emerald-600/20' : 'bg-emerald-100'}`}>
                  <Key className={`h-4 w-4 ${isDark ? 'text-emerald-400' : 'text-emerald-600'}`} />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium">{contact.name}</p>
                  <p className={`text-xs truncate font-mono ${muted}`}>{contact.id}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
