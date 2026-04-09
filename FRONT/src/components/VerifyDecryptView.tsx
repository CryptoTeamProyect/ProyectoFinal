'use client';

import { useState } from 'react';
import { Upload, ShieldCheck, CheckCircle2, Unlock, Eye, EyeOff, AlertCircle } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

export function VerifyDecryptView() {
  const { theme } = useTheme();
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [fileLoaded, setFileLoaded] = useState(false);
  const [verificationStatus, setVerificationStatus] = useState<'pending' | 'verified' | 'failed'>('pending');
  const [isDeriving, setIsDeriving] = useState(false);

  const handleFileLoad = () => {
    setFileLoaded(true);
    // Simulate verification
    setTimeout(() => {
      setVerificationStatus('verified');
    }, 1000);
  };

  const handleDecrypt = () => {
    setIsDeriving(true);
    // Simulate Argon2id key derivation
    setTimeout(() => {
      setIsDeriving(false);
      // Proceed with decryption
    }, 2000);
  };

  return (
    <div className="p-8 space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold mb-2">Verificar y Descifrar Documento</h1>
        <p className={theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}>Valida la firma digital y descifra archivos protegidos</p>
      </div>

      {/* File Upload Area */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
        <div className="flex items-center gap-2 mb-4">
          <Upload className="w-5 h-5 text-cyan-400" />
          <h3 className="text-lg font-semibold">Cargar Encrypted File Container</h3>
        </div>
        
        {!fileLoaded ? (
          <div className={`border-2 border-dashed ${theme === 'dark' ? 'border-slate-700 hover:border-slate-600' : 'border-slate-300 hover:border-slate-400'} rounded-lg p-12 text-center transition-all cursor-pointer`}>
            <div className={`w-16 h-16 ${theme === 'dark' ? 'bg-cyan-600/20' : 'bg-cyan-100'} rounded-full flex items-center justify-center mx-auto mb-4`}>
              <Upload className={`w-8 h-8 ${theme === 'dark' ? 'text-cyan-400' : 'text-cyan-600'}`} />
            </div>
            <h4 className="font-semibold mb-2">Selecciona el archivo cifrado</h4>
            <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-4`}>Archivos con extensión .enc</p>
            <button
              onClick={handleFileLoad}
              className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 rounded-lg font-medium transition-colors text-white"
            >
              Examinar Archivos
            </button>
          </div>
        ) : (
          <div className={`flex items-center gap-4 p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
            <div className={`w-12 h-12 ${theme === 'dark' ? 'bg-cyan-600/20' : 'bg-cyan-100'} rounded-lg flex items-center justify-center`}>
              <ShieldCheck className={`w-6 h-6 ${theme === 'dark' ? 'text-cyan-400' : 'text-cyan-600'}`} />
            </div>
            <div className="flex-1">
              <p className="font-medium" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                Documento_Confidencial.pdf.enc
              </p>
              <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>2.4 MB • Cargado</p>
            </div>
          </div>
        )}
      </div>

      {/* Verification Status */}
      {fileLoaded && (
        <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
          <div className="flex items-center gap-2 mb-4">
            <ShieldCheck className="w-5 h-5 text-green-400" />
            <h3 className="text-lg font-semibold">Estado de Verificación de Firma Digital</h3>
          </div>

          {verificationStatus === 'pending' && (
            <div className="flex items-center gap-3 p-4 bg-yellow-600/10 border border-yellow-600/30 rounded-lg">
              <AlertCircle className="w-6 h-6 text-yellow-400" />
              <div>
                <p className="font-medium text-yellow-400">Verificando firma digital...</p>
                <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Validando integridad del documento</p>
              </div>
            </div>
          )}

          {verificationStatus === 'verified' && (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-4 bg-green-600/10 border-2 border-green-600 rounded-lg">
                <CheckCircle2 className="w-6 h-6 text-green-400" />
                <div className="flex-1">
                  <p className="font-semibold text-green-400">✓ Firma Digital Verificada</p>
                  <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>
                    El documento no ha sido modificado y proviene de un remitente válido
                  </p>
                </div>
              </div>

              <div className={`grid grid-cols-2 gap-4 p-4 ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'} rounded-lg`}>
                <div>
                  <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Firmante</p>
                  <p className="font-medium">Alice Johnson</p>
                </div>
                <div>
                  <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Fecha de Firma</p>
                  <p className="font-medium">18 de marzo, 2026</p>
                </div>
                <div className="col-span-2">
                  <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Huella Digital</p>
                  <p
                    className="text-sm font-medium"
                    style={{ fontFamily: 'JetBrains Mono, monospace' }}
                  >
                    SHA-256: 8f7a3d9e2b1c4f5a6e8d7c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9
                  </p>
                </div>
                <div className="col-span-2">
                  <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-1`}>Clave Pública del Firmante</p>
                  <p
                    className="text-sm font-medium"
                    style={{ fontFamily: 'JetBrains Mono, monospace' }}
                  >
                    ed25519:a7f83b9c4d1e5f2a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Password Input for Decryption */}
      {fileLoaded && verificationStatus === 'verified' && (
        <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
          <div className="flex items-center gap-2 mb-4">
            <Unlock className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-semibold">Descifrado con Contraseña Maestra</h3>
          </div>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">
                Contraseña Maestra de Baja Entropía
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Ingresa tu contraseña maestra"
                  className={`w-full px-4 py-3 ${theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-white border-slate-300'} border rounded-lg focus:outline-none focus:border-cyan-600 transition-colors`}
                  style={{ fontFamily: 'JetBrains Mono, monospace' }}
                />
                <button
                  onClick={() => setShowPassword(!showPassword)}
                  className={`absolute right-3 top-1/2 -translate-y-1/2 ${theme === 'dark' ? 'text-slate-400 hover:text-slate-200' : 'text-slate-500 hover:text-slate-700'}`}
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              <p className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'} mt-2 flex items-center gap-2`}>
                <AlertCircle className="w-4 h-4" />
                Derivando clave con Argon2id (memoria: 64MB, iteraciones: 3, paralelismo: 4)
              </p>
            </div>

            {isDeriving && (
              <div className="p-4 bg-blue-600/10 border border-blue-600/30 rounded-lg">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-5 h-5 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
                  <p className="font-medium text-blue-400">Derivando clave con Argon2id...</p>
                </div>
                <div className={`w-full ${theme === 'dark' ? 'bg-slate-700' : 'bg-slate-300'} rounded-full h-2`}>
                  <div className="bg-blue-500 h-2 rounded-full w-2/3 transition-all duration-500" />
                </div>
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={handleDecrypt}
                disabled={!password || isDeriving}
                className="flex-1 px-6 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 rounded-lg font-semibold transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed text-white"
              >
                <Unlock className="w-5 h-5" />
                Descifrar Documento
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Info Card */}
      <div className={`bg-gradient-to-br ${theme === 'dark' ? 'from-slate-800 to-slate-900 border-slate-700' : 'from-slate-100 to-slate-200 border-slate-300'} border rounded-xl p-6`}>
        <h4 className="font-semibold mb-3 flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-cyan-400" />
          Proceso de Verificación y Descifrado
        </h4>
        <div className={`space-y-2 text-sm ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>
          <p>1. <strong>Validación estricta de firma digital</strong> antes de cualquier descifrado</p>
          <p>2. <strong>Verificación de integridad</strong> mediante HMAC y autenticación AEAD</p>
          <p>3. <strong>Derivación de clave</strong> usando Argon2id (resistente a ataques de fuerza bruta)</p>
          <p>4. <strong>Descifrado híbrido</strong> con unwrapping de clave simétrica</p>
        </div>
      </div>
    </div>
  );
}