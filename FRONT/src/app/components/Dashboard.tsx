import { Lock, Unlock, FileCheck, Key, Clock } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export function Dashboard() {
  const { theme } = useTheme();
  
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
    <div className="p-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold mb-2">Dashboard</h1>
        <p className={theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}>Resumen de tu bóveda criptográfica</p>
      </div>

      {/* Vault Status Card */}
      <div className={`bg-gradient-to-br ${theme === 'dark' ? 'from-cyan-900/30 to-blue-900/30 border-cyan-700/50' : 'from-cyan-100 to-blue-100 border-cyan-300'} border rounded-xl p-6`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 bg-cyan-600 rounded-full flex items-center justify-center">
              <Lock className="w-8 h-8 text-white" />
            </div>
            <div>
              <h3 className="text-xl font-semibold mb-1">Estado de la Bóveda</h3>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse" />
                <span className={`font-medium ${theme === 'dark' ? 'text-green-400' : 'text-green-600'}`}>Cerrada y Segura</span>
              </div>
            </div>
          </div>
          <button className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 rounded-lg font-medium transition-colors flex items-center gap-2 text-white">
            <Unlock className="w-5 h-5" />
            Abrir Bóveda
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
          <div className="flex items-center gap-3 mb-4">
            <div className={`w-12 h-12 ${theme === 'dark' ? 'bg-blue-600/20' : 'bg-blue-100'} rounded-lg flex items-center justify-center`}>
              <FileCheck className={`w-6 h-6 ${theme === 'dark' ? 'text-blue-400' : 'text-blue-600'}`} />
            </div>
            <h3 className="text-lg font-semibold">Documentos Protegidos</h3>
          </div>
          <p className={`text-4xl font-bold ${theme === 'dark' ? 'text-blue-400' : 'text-blue-600'}`}>24</p>
          <p className={`text-sm ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'} mt-2`}>Total de archivos cifrados</p>
        </div>

        <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
          <div className="flex items-center gap-3 mb-4">
            <div className={`w-12 h-12 ${theme === 'dark' ? 'bg-green-600/20' : 'bg-green-100'} rounded-lg flex items-center justify-center`}>
              <Key className={`w-6 h-6 ${theme === 'dark' ? 'text-green-400' : 'text-green-600'}`} />
            </div>
            <h3 className="text-lg font-semibold">Claves Públicas</h3>
          </div>
          <p className={`text-4xl font-bold ${theme === 'dark' ? 'text-green-400' : 'text-green-600'}`}>{publicKeys.length}</p>
          <p className={`text-sm ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'} mt-2`}>Contactos en llavero</p>
        </div>

        <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
          <div className="flex items-center gap-3 mb-4">
            <div className={`w-12 h-12 ${theme === 'dark' ? 'bg-purple-600/20' : 'bg-purple-100'} rounded-lg flex items-center justify-center`}>
              <Clock className={`w-6 h-6 ${theme === 'dark' ? 'text-purple-400' : 'text-purple-600'}`} />
            </div>
            <h3 className="text-lg font-semibold">Última Actividad</h3>
          </div>
          <p className={`text-xl font-bold ${theme === 'dark' ? 'text-purple-400' : 'text-purple-600'}`}>Hoy</p>
          <p className={`text-sm ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'} mt-2`}>18 de marzo, 14:30</p>
        </div>
      </div>

      {/* Recent Documents */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
        <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <FileCheck className="w-5 h-5 text-cyan-400" />
          Documentos Recientes
        </h3>
        <div className="space-y-3">
          {recentDocuments.map((doc, index) => (
            <div
              key={index}
              className={`flex items-center justify-between p-4 ${theme === 'dark' ? 'bg-slate-800/50 hover:bg-slate-800' : 'bg-slate-50 hover:bg-slate-100'} rounded-lg transition-colors`}
            >
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 ${theme === 'dark' ? 'bg-cyan-600/20' : 'bg-cyan-100'} rounded-lg flex items-center justify-center`}>
                  <Lock className={`w-5 h-5 ${theme === 'dark' ? 'text-cyan-400' : 'text-cyan-600'}`} />
                </div>
                <div>
                  <p className="font-medium" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                    {doc.name}
                  </p>
                  <p className={`text-sm ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'}`}>{doc.date}</p>
                </div>
              </div>
              <span className={`px-3 py-1 ${theme === 'dark' ? 'bg-green-600/20 text-green-400' : 'bg-green-100 text-green-700'} rounded-full text-sm font-medium`}>
                {doc.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Public Keys Summary */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
        <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <Key className="w-5 h-5 text-green-400" />
          Resumen de Claves Públicas
        </h3>
        <div className="space-y-3">
          {publicKeys.map((contact, index) => (
            <div
              key={index}
              className={`flex items-center justify-between p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}
            >
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 ${theme === 'dark' ? 'bg-green-600/20' : 'bg-green-100'} rounded-lg flex items-center justify-center`}>
                  <Key className={`w-5 h-5 ${theme === 'dark' ? 'text-green-400' : 'text-green-600'}`} />
                </div>
                <div>
                  <p className="font-medium">{contact.name}</p>
                  <p
                    className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}
                    style={{ fontFamily: 'JetBrains Mono, monospace' }}
                  >
                    {contact.id}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}