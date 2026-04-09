'use client';

import { Shield, Key, Bell, Monitor, Download } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

export function SettingsView() {
  const { theme, setTheme } = useTheme();

  return (
    <div className="p-8 space-y-8 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold mb-2">Ajustes</h1>
        <p className={theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}>Configura tu bóveda y preferencias de seguridad</p>
      </div>

      {/* Security Settings */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
        <div className="flex items-center gap-2 mb-6">
          <Shield className="w-5 h-5 text-cyan-400" />
          <h3 className="text-xl font-semibold">Configuración de Seguridad</h3>
        </div>

        <div className="space-y-4">
          <div className={`flex items-center justify-between p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <div>
              <p className="font-medium">Autenticación de Dos Factores</p>
              <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Protección adicional con código TOTP</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" defaultChecked />
              <div className={`w-11 h-6 ${theme === 'dark' ? 'bg-slate-700' : 'bg-slate-300'} peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600`}></div>
            </label>
          </div>

          <div className={`flex items-center justify-between p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <div>
              <p className="font-medium">Auto-bloqueo de Bóveda</p>
              <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Cierra automáticamente después de inactividad</p>
            </div>
            <select className={`px-4 py-2 ${theme === 'dark' ? 'bg-slate-700 border-slate-600' : 'bg-white border-slate-300'} border rounded-lg focus:outline-none focus:border-cyan-600`}>
              <option>5 minutos</option>
              <option>15 minutos</option>
              <option>30 minutos</option>
              <option>1 hora</option>
              <option>Nunca</option>
            </select>
          </div>

          <div className={`flex items-center justify-between p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <div>
              <p className="font-medium">Requiere Contraseña para Descifrar</p>
              <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Solicita autenticación en cada operación</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" defaultChecked />
              <div className={`w-11 h-6 ${theme === 'dark' ? 'bg-slate-700' : 'bg-slate-300'} peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600`}></div>
            </label>
          </div>
        </div>
      </div>

      {/* Cryptography Settings */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
        <div className="flex items-center gap-2 mb-6">
          <Key className="w-5 h-5 text-green-400" />
          <h3 className="text-xl font-semibold">Parámetros Criptográficos</h3>
        </div>

        <div className="space-y-4">
          <div className={`p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <p className="font-medium mb-2">Algoritmo AEAD Predeterminado</p>
            <select className={`w-full px-4 py-2 ${theme === 'dark' ? 'bg-slate-700 border-slate-600' : 'bg-white border-slate-300'} border rounded-lg focus:outline-none focus:border-cyan-600`} style={{ fontFamily: 'JetBrains Mono, monospace' }}>
              <option>AES-256-GCM</option>
              <option>ChaCha20-Poly1305</option>
            </select>
          </div>

          <div className={`p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <p className="font-medium mb-2">Parámetros de Argon2id</p>
            <div className="grid grid-cols-3 gap-3 mt-3">
              <div>
                <label className={`block text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Memoria (MB)</label>
                <input
                  type="number"
                  defaultValue="64"
                  className={`w-full px-3 py-2 ${theme === 'dark' ? 'bg-slate-700 border-slate-600' : 'bg-white border-slate-300'} border rounded-lg focus:outline-none focus:border-cyan-600`}
                />
              </div>
              <div>
                <label className={`block text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Iteraciones</label>
                <input
                  type="number"
                  defaultValue="3"
                  className={`w-full px-3 py-2 ${theme === 'dark' ? 'bg-slate-700 border-slate-600' : 'bg-white border-slate-300'} border rounded-lg focus:outline-none focus:border-cyan-600`}
                />
              </div>
              <div>
                <label className={`block text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Paralelismo</label>
                <input
                  type="number"
                  defaultValue="4"
                  className={`w-full px-3 py-2 ${theme === 'dark' ? 'bg-slate-700 border-slate-600' : 'bg-white border-slate-300'} border rounded-lg focus:outline-none focus:border-cyan-600`}
                />
              </div>
            </div>
            <p className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'} mt-2`}>
              Mayor seguridad = más tiempo de procesamiento. Ajusta según tu dispositivo.
            </p>
          </div>

          <div className={`p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <p className="font-medium mb-2">Formato de Clave Pública</p>
            <select className={`w-full px-4 py-2 ${theme === 'dark' ? 'bg-slate-700 border-slate-600' : 'bg-white border-slate-300'} border rounded-lg focus:outline-none focus:border-cyan-600`}>
              <option>Ed25519 (Recomendado)</option>
              <option>RSA-2048</option>
              <option>RSA-4096</option>
              <option>ECDSA P-256</option>
            </select>
          </div>
        </div>
      </div>

      {/* Notifications */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
        <div className="flex items-center gap-2 mb-6">
          <Bell className="w-5 h-5 text-blue-400" />
          <h3 className="text-xl font-semibold">Notificaciones</h3>
        </div>

        <div className="space-y-4">
          <div className={`flex items-center justify-between p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <div>
              <p className="font-medium">Notificar cuando se reciba un documento</p>
              <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Alerta de nuevo contenido cifrado</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" defaultChecked />
              <div className={`w-11 h-6 ${theme === 'dark' ? 'bg-slate-700' : 'bg-slate-300'} peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600`}></div>
            </label>
          </div>

          <div className={`flex items-center justify-between p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <div>
              <p className="font-medium">Alertas de seguridad</p>
              <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Notificaciones de intentos de acceso</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" defaultChecked />
              <div className={`w-11 h-6 ${theme === 'dark' ? 'bg-slate-700' : 'bg-slate-300'} peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600`}></div>
            </label>
          </div>
        </div>
      </div>

      {/* Appearance */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
        <div className="flex items-center gap-2 mb-6">
          <Monitor className="w-5 h-5 text-purple-400" />
          <h3 className="text-xl font-semibold">Apariencia</h3>
        </div>

        <div className="space-y-4">
          <div className={`p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <p className="font-medium mb-2">Tema</p>
            <div className="grid grid-cols-3 gap-3">
              <button
                onClick={() => setTheme('dark')}
                className={`p-3 ${theme === 'dark' ? 'bg-slate-950 border-cyan-600' : 'bg-slate-100 border-transparent hover:border-slate-400'} border-2 rounded-lg transition-all`}
              >
                <div className="w-full h-12 bg-gradient-to-br from-slate-900 to-slate-950 rounded mb-2" />
                <p className="text-sm font-medium">Oscuro</p>
              </button>
              <button
                onClick={() => setTheme('light')}
                className={`p-3 ${theme === 'light' ? 'bg-slate-950 border-cyan-600' : 'bg-slate-100 border-transparent hover:border-slate-400'} border-2 rounded-lg transition-all`}
              >
                <div className="w-full h-12 bg-gradient-to-br from-slate-200 to-slate-300 rounded mb-2" />
                <p className="text-sm font-medium">Claro</p>
              </button>
              <button className={`p-3 ${theme === 'dark' ? 'bg-slate-700' : 'bg-slate-200'} border-2 border-transparent opacity-50 rounded-lg`} disabled>
                <div className="w-full h-12 bg-gradient-to-br from-slate-900 to-slate-200 rounded mb-2" />
                <p className="text-sm font-medium">Auto (Próximamente)</p>
              </button>
            </div>
          </div>

          <div className={`p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <p className="font-medium mb-2">Color de Acento</p>
            <div className="flex gap-3">
              <button className="w-10 h-10 bg-cyan-600 border-2 border-white rounded-full" />
              <button className="w-10 h-10 bg-blue-600 border-2 border-transparent hover:border-white rounded-full" />
              <button className="w-10 h-10 bg-green-600 border-2 border-transparent hover:border-white rounded-full" />
              <button className="w-10 h-10 bg-purple-600 border-2 border-transparent hover:border-white rounded-full" />
              <button className="w-10 h-10 bg-red-600 border-2 border-transparent hover:border-white rounded-full" />
            </div>
          </div>
        </div>
      </div>

      {/* Backup & Export */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
        <div className="flex items-center gap-2 mb-6">
          <Download className="w-5 h-5 text-yellow-400" />
          <h3 className="text-xl font-semibold">Respaldo y Exportación</h3>
        </div>

        <div className="space-y-3">
          <button className={`w-full p-4 ${theme === 'dark' ? 'bg-slate-800/50 hover:bg-slate-800' : 'bg-slate-50 hover:bg-slate-100'} rounded-lg text-left transition-colors flex items-center justify-between`}>
            <div>
              <p className="font-medium">Exportar Configuración</p>
              <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Descarga tus ajustes en formato JSON</p>
            </div>
            <Download className={`w-5 h-5 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`} />
          </button>

          <button className={`w-full p-4 ${theme === 'dark' ? 'bg-slate-800/50 hover:bg-slate-800' : 'bg-slate-50 hover:bg-slate-100'} rounded-lg text-left transition-colors flex items-center justify-between`}>
            <div>
              <p className="font-medium">Respaldar Llavero</p>
              <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Copia de seguridad de claves públicas</p>
            </div>
            <Download className={`w-5 h-5 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`} />
          </button>

          <button className="w-full p-4 bg-red-600/10 hover:bg-red-600/20 border border-red-600/30 rounded-lg text-left transition-colors">
            <p className="font-medium text-red-400">Restablecer Configuración</p>
            <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Volver a valores predeterminados</p>
          </button>
        </div>
      </div>

      {/* Version Info */}
      <div className={`text-center text-sm ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>
        <p>Secure Digital Vault v1.0.0</p>
        <p className="mt-1">© 2026 - Bóveda Criptográfica de Alta Seguridad</p>
      </div>
    </div>
  );
}