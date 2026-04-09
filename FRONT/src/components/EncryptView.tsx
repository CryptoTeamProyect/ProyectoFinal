'use client';

import { useState } from 'react';
import { Upload, Lock, Users, Shield } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

export function EncryptView() {
  const { theme } = useTheme();
  const [selectedAlgorithm, setSelectedAlgorithm] = useState('AES-GCM');
  const [selectedRecipients, setSelectedRecipients] = useState<string[]>([]);
  const [dragActive, setDragActive] = useState(false);

  const algorithms = [
    { value: 'AES-GCM', label: 'AES-256-GCM (Recomendado)' },
    { value: 'ChaCha20-Poly1305', label: 'ChaCha20-Poly1305' },
  ];

  const recipients = [
    { id: '1', name: 'Alice Johnson', key: 'ed25519:a7f8...9b2c' },
    { id: '2', name: 'Bob Smith', key: 'ed25519:3d4e...1a6f' },
    { id: '3', name: 'Carol White', key: 'ed25519:8c9d...5e4b' },
  ];

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    // Handle file drop
  };

  const toggleRecipient = (id: string) => {
    setSelectedRecipients((prev) =>
      prev.includes(id) ? prev.filter((r) => r !== id) : [...prev, id]
    );
  };

  return (
    <div className="p-8 space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold mb-2">Cifrar y Firmar Documento</h1>
        <p className={theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}>Protege tus archivos con cifrado AEAD y firma digital</p>
      </div>

      {/* Drag & Drop Area */}
      <div
        className={`border-2 border-dashed rounded-xl p-12 transition-all ${
          dragActive
            ? 'border-cyan-500 bg-cyan-500/10'
            : theme === 'dark'
            ? 'border-slate-700 hover:border-slate-600 bg-slate-900/50'
            : 'border-slate-300 hover:border-slate-400 bg-white'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <div className="flex flex-col items-center justify-center text-center">
          <div className={`w-20 h-20 ${theme === 'dark' ? 'bg-cyan-600/20' : 'bg-cyan-100'} rounded-full flex items-center justify-center mb-4`}>
            <Upload className={`w-10 h-10 ${theme === 'dark' ? 'text-cyan-400' : 'text-cyan-600'}`} />
          </div>
          <h3 className="text-xl font-semibold mb-2">Arrastra y suelta tu archivo aquí</h3>
          <p className={`${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-4`}>o haz clic para seleccionar</p>
          <button className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 rounded-lg font-medium transition-colors text-white">
            Seleccionar Archivo
          </button>
          <p className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'} mt-4`}>Formatos soportados: PDF, DOCX, XLSX, TXT, ZIP</p>
        </div>
      </div>

      {/* Algorithm Selection */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-5 h-5 text-blue-400" />
          <h3 className="text-lg font-semibold">Algoritmo de Cifrado AEAD</h3>
        </div>
        <div className="space-y-3">
          {algorithms.map((algo) => (
            <label
              key={algo.value}
              className={`flex items-center gap-3 p-4 rounded-lg cursor-pointer transition-all ${
                selectedAlgorithm === algo.value
                  ? 'bg-cyan-600/20 border-2 border-cyan-600'
                  : theme === 'dark'
                  ? 'bg-slate-800/50 border-2 border-transparent hover:bg-slate-800'
                  : 'bg-slate-50 border-2 border-transparent hover:bg-slate-100'
              }`}
            >
              <input
                type="radio"
                name="algorithm"
                value={algo.value}
                checked={selectedAlgorithm === algo.value}
                onChange={(e) => setSelectedAlgorithm(e.target.value)}
                className="w-4 h-4 text-cyan-600"
              />
              <div className="flex-1">
                <p className="font-medium" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                  {algo.label}
                </p>
                {algo.value === 'AES-GCM' && (
                  <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mt-1`}>
                    Authenticated Encryption with Associated Data - Estándar de la industria
                  </p>
                )}
                {algo.value === 'ChaCha20-Poly1305' && (
                  <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mt-1`}>
                    Stream cipher con autenticación - Alta velocidad en dispositivos móviles
                  </p>
                )}
              </div>
            </label>
          ))}
        </div>
      </div>

      {/* Recipients Selection (Hybrid Encryption) */}
      <div className={`${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6`}>
        <div className="flex items-center gap-2 mb-4">
          <Users className="w-5 h-5 text-green-400" />
          <h3 className="text-lg font-semibold">Destinatarios (Cifrado Híbrido)</h3>
        </div>
        <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} mb-4`}>
          Selecciona los destinatarios que podrán descifrar este documento mediante Key Wrapping
        </p>
        <div className="space-y-2">
          {recipients.map((recipient) => (
            <label
              key={recipient.id}
              className={`flex items-center gap-3 p-4 rounded-lg cursor-pointer transition-all ${
                selectedRecipients.includes(recipient.id)
                  ? 'bg-green-600/20 border-2 border-green-600'
                  : theme === 'dark'
                  ? 'bg-slate-800/50 border-2 border-transparent hover:bg-slate-800'
                  : 'bg-slate-50 border-2 border-transparent hover:bg-slate-100'
              }`}
            >
              <input
                type="checkbox"
                checked={selectedRecipients.includes(recipient.id)}
                onChange={() => toggleRecipient(recipient.id)}
                className="w-4 h-4 text-green-600 rounded"
              />
              <div className="flex-1">
                <p className="font-medium">{recipient.name}</p>
                <p
                  className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}
                  style={{ fontFamily: 'JetBrains Mono, monospace' }}
                >
                  {recipient.key}
                </p>
              </div>
            </label>
          ))}
        </div>
        <p className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'} mt-4`}>
          {selectedRecipients.length} destinatario(s) seleccionado(s)
        </p>
      </div>

      {/* Action Button */}
      <div className={`flex items-center justify-between p-6 ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border rounded-xl`}>
        <div>
          <h4 className="font-semibold mb-1">¿Listo para cifrar?</h4>
          <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>
            El documento será cifrado y firmado digitalmente con tu clave privada
          </p>
        </div>
        <button className="px-8 py-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 rounded-lg font-semibold transition-all flex items-center gap-3 shadow-lg shadow-cyan-600/20 text-white">
          <Lock className="w-5 h-5" />
          Cifrar y Firmar Documento
        </button>
      </div>
    </div>
  );
}