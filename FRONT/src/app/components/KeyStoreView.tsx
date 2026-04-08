import { useState } from 'react';
import { Key, Plus, Download, Upload, Trash2, Copy, Check } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

interface Contact {
  id: string;
  name: string;
  email: string;
  publicKey: string;
  algorithm: string;
  dateAdded: string;
}

export function KeyStoreView() {
  const { theme } = useTheme();
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  
  const contacts: Contact[] = [
    {
      id: '1',
      name: 'Alice Johnson',
      email: 'alice@securemail.com',
      publicKey: 'ed25519:a7f83b9c4d1e5f2a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9',
      algorithm: 'Ed25519',
      dateAdded: '2026-03-15',
    },
    {
      id: '2',
      name: 'Bob Smith',
      email: 'bob@cryptotech.io',
      publicKey: 'ed25519:3d4e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7',
      algorithm: 'Ed25519',
      dateAdded: '2026-03-12',
    },
    {
      id: '3',
      name: 'Carol White',
      email: 'carol@blockchain.net',
      publicKey: 'ed25519:8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9',
      algorithm: 'Ed25519',
      dateAdded: '2026-03-10',
    },
    {
      id: '4',
      name: 'David Miller',
      email: 'david@infosec.org',
      publicKey: 'rsa:2048:9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0',
      algorithm: 'RSA-2048',
      dateAdded: '2026-03-08',
    },
  ];

  const copyToClipboard = (key: string, id: string) => {
    navigator.clipboard.writeText(key);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold mb-2">Llavero Cifrado</h1>
          <p className={theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}>Gestiona claves públicas de contactos de confianza</p>
        </div>
        <div className="flex gap-3">
          <button className={`px-4 py-2 ${theme === 'dark' ? 'bg-slate-800 hover:bg-slate-700' : 'bg-slate-200 hover:bg-slate-300'} rounded-lg font-medium transition-colors flex items-center gap-2`}>
            <Upload className="w-5 h-5" />
            Importar Clave
          </button>
          <button className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded-lg font-medium transition-colors flex items-center gap-2 text-white">
            <Download className="w-5 h-5" />
            Exportar mi Clave Pública
          </button>
        </div>
      </div>

      {/* My Public Key Card */}
      <div className={`bg-gradient-to-br ${theme === 'dark' ? 'from-cyan-900/30 to-blue-900/30 border-cyan-700/50' : 'from-cyan-100 to-blue-100 border-cyan-300'} border rounded-xl p-6`}>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-12 h-12 bg-cyan-600 rounded-full flex items-center justify-center">
            <Key className="w-6 h-6 text-white" />
          </div>
          <div>
            <h3 className="text-lg font-semibold">Mi Clave Pública</h3>
            <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-700'}`}>Comparte esta clave para recibir documentos cifrados</p>
          </div>
        </div>
        <div className={`${theme === 'dark' ? 'bg-slate-900/50 border-cyan-700/30' : 'bg-white/80 border-cyan-400/50'} rounded-lg p-4 border`}>
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <p className={`text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Ed25519 Public Key</p>
              <p
                className="text-sm font-medium break-all"
                style={{ fontFamily: 'JetBrains Mono, monospace' }}
              >
                ed25519:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2
              </p>
            </div>
            <button
              onClick={() => copyToClipboard('ed25519:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2', 'my-key')}
              className="px-3 py-2 bg-cyan-600 hover:bg-cyan-700 rounded-lg transition-colors flex items-center gap-2 shrink-0 text-white"
            >
              {copiedKey === 'my-key' ? (
                <>
                  <Check className="w-4 h-4" />
                  Copiado
                </>
              ) : (
                <>
                  <Copy className="w-4 h-4" />
                  Copiar
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-4`}>
          <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Total de Contactos</p>
          <p className={`text-3xl font-bold ${theme === 'dark' ? 'text-cyan-400' : 'text-cyan-600'}`}>{contacts.length}</p>
        </div>
        <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-4`}>
          <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Claves Ed25519</p>
          <p className={`text-3xl font-bold ${theme === 'dark' ? 'text-green-400' : 'text-green-600'}`}>
            {contacts.filter((c) => c.algorithm === 'Ed25519').length}
          </p>
        </div>
        <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-4`}>
          <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Claves RSA</p>
          <p className={`text-3xl font-bold ${theme === 'dark' ? 'text-blue-400' : 'text-blue-600'}`}>
            {contacts.filter((c) => c.algorithm.startsWith('RSA')).length}
          </p>
        </div>
      </div>

      {/* Contacts Table */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl overflow-hidden`}>
        <div className={`p-6 ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'} border-b flex items-center justify-between`}>
          <h3 className="text-xl font-semibold flex items-center gap-2">
            <Key className="w-5 h-5 text-cyan-400" />
            Claves Públicas de Contactos
          </h3>
          <button className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded-lg font-medium transition-colors flex items-center gap-2 text-white">
            <Plus className="w-5 h-5" />
            Agregar Contacto
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className={theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-100'}>
              <tr>
                <th className={`px-6 py-4 text-left text-sm font-semibold ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>Contacto</th>
                <th className={`px-6 py-4 text-left text-sm font-semibold ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>Clave Pública</th>
                <th className={`px-6 py-4 text-left text-sm font-semibold ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>Algoritmo</th>
                <th className={`px-6 py-4 text-left text-sm font-semibold ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>Fecha</th>
                <th className={`px-6 py-4 text-right text-sm font-semibold ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>Acciones</th>
              </tr>
            </thead>
            <tbody className={`divide-y ${theme === 'dark' ? 'divide-slate-800' : 'divide-slate-200'}`}>
              {contacts.map((contact) => (
                <tr key={contact.id} className={theme === 'dark' ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50'}>
                  <td className="px-6 py-4">
                    <div>
                      <p className="font-medium">{contact.name}</p>
                      <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{contact.email}</p>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2 max-w-md">
                      <p
                        className="text-sm font-medium truncate"
                        style={{ fontFamily: 'JetBrains Mono, monospace' }}
                        title={contact.publicKey}
                      >
                        {contact.publicKey}
                      </p>
                      <button
                        onClick={() => copyToClipboard(contact.publicKey, contact.id)}
                        className={`p-1.5 ${theme === 'dark' ? 'hover:bg-slate-700' : 'hover:bg-slate-200'} rounded transition-colors shrink-0`}
                        title="Copiar clave"
                      >
                        {copiedKey === contact.id ? (
                          <Check className="w-4 h-4 text-green-400" />
                        ) : (
                          <Copy className={`w-4 h-4 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`} />
                        )}
                      </button>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span
                      className={`px-3 py-1 rounded-full text-sm font-medium ${
                        contact.algorithm === 'Ed25519'
                          ? theme === 'dark'
                            ? 'bg-green-600/20 text-green-400'
                            : 'bg-green-100 text-green-700'
                          : theme === 'dark'
                          ? 'bg-blue-600/20 text-blue-400'
                          : 'bg-blue-100 text-blue-700'
                      }`}
                    >
                      {contact.algorithm}
                    </span>
                  </td>
                  <td className={`px-6 py-4 text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{contact.dateAdded}</td>
                  <td className="px-6 py-4 text-right">
                    <button
                      className={`p-2 ${theme === 'dark' ? 'hover:bg-red-600/20' : 'hover:bg-red-100'} text-red-400 rounded-lg transition-colors`}
                      title="Eliminar contacto"
                    >
                      <Trash2 className="w-5 h-5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Info */}
      <div className={`bg-gradient-to-br ${theme === 'dark' ? 'from-slate-800 to-slate-900 border-slate-700' : 'from-slate-100 to-slate-200 border-slate-300'} border rounded-xl p-6`}>
        <h4 className="font-semibold mb-3 flex items-center gap-2">
          <Key className="w-5 h-5 text-cyan-400" />
          Acerca del Llavero Cifrado
        </h4>
        <div className={`space-y-2 text-sm ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>
          <p>• Las claves públicas se almacenan en formato <strong>PEM/Base64</strong> con prefijo de algoritmo</p>
          <p>• Soporta <strong>Ed25519</strong> (curvas elípticas) y <strong>RSA-2048/4096</strong></p>
          <p>• Todas las claves privadas permanecen <strong>protegidas localmente</strong> y nunca se comparten</p>
          <p>• El llavero está cifrado con tu contraseña maestra mediante <strong>AES-256-GCM</strong></p>
        </div>
      </div>
    </div>
  );
}