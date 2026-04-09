'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Home, Lock, ShieldCheck, Key, Settings, User } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

const navbarColors = [
  { name: 'Acero', value: '#1e293b' },
  { name: 'Azul Ciberseguridad', value: '#0f172a' },
  { name: 'Verde Seguro', value: '#064e3b' },
  { name: 'Gris Oscuro', value: '#18181b' },
  { name: 'Azul Profundo', value: '#0c4a6e' },
];

export function VaultShell({ children }: { children: React.ReactNode }) {
  const { theme } = useTheme();
  const pathname = usePathname();
  const [navbarBgColor, setNavbarBgColor] = useState(navbarColors[0].value);
  const [showColorPicker, setShowColorPicker] = useState(false);

  const menuItems = [
    { path: '/', icon: Home, label: 'Inicio' },
    { path: '/encrypt', icon: Lock, label: 'Cifrar' },
    { path: '/verify', icon: ShieldCheck, label: 'Descifrar/Verificar' },
    { path: '/keystore', icon: Key, label: 'Llavero' },
    { path: '/settings', icon: Settings, label: 'Ajustes' },
  ];

  const linkClassName = (href: string) => {
    const isActive =
      href === '/' ? pathname === '/' : pathname === href || pathname.startsWith(`${href}/`);
    return `flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
      isActive
        ? 'bg-cyan-600 text-white'
        : theme === 'dark'
          ? 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
          : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
    }`;
  };

  return (
    <div
      className={`flex h-screen ${theme === 'dark' ? 'bg-slate-950 text-slate-100' : 'bg-slate-50 text-slate-900'}`}
      style={{ fontFamily: 'Inter, sans-serif' }}
    >
      <aside
        className={`w-64 ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'} border-r flex flex-col`}
      >
        <div className={`p-6 border-b ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-cyan-600 rounded-lg flex items-center justify-center">
              <Lock className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="font-semibold text-lg">Secure Digital</h1>
              <p className={`text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>Vault</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-2">
          {menuItems.map((item) => (
            <Link key={item.path} href={item.path} className={linkClassName(item.path)}>
              <item.icon className="w-5 h-5" />
              <span className="font-medium">{item.label}</span>
            </Link>
          ))}
        </nav>

        <div className={`p-4 border-t ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
          <div
            className={`flex items-center gap-2 p-3 ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-100'} rounded-lg`}
          >
            <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-full flex items-center justify-center">
              <span className="text-xs font-semibold">SV</span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">Secure Vault</p>
              <p className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>v1.0.0</p>
            </div>
          </div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col overflow-hidden">
        <header
          className={`h-16 border-b ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'} flex items-center justify-between px-6 transition-colors duration-300`}
          style={{ backgroundColor: theme === 'dark' ? navbarBgColor : '#f8fafc' }}
        >
          <div className="flex items-center gap-4">
            <h2 className="text-xl font-semibold">Bóveda Digital</h2>
          </div>

          <div className="flex items-center gap-4">
            {theme === 'dark' && (
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setShowColorPicker(!showColorPicker)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg flex items-center gap-2 transition-colors"
                >
                  <div className="w-4 h-4 rounded border border-slate-600" style={{ backgroundColor: navbarBgColor }} />
                  <span className="text-sm">Color de Navbar</span>
                </button>

                {showColorPicker && (
                  <div className="absolute right-0 top-full mt-2 bg-slate-800 border border-slate-700 rounded-lg shadow-2xl p-3 w-64 z-50">
                    <p className="text-xs font-medium text-slate-400 mb-3">Selecciona un color</p>
                    <div className="space-y-2">
                      {navbarColors.map((color) => (
                        <button
                          type="button"
                          key={color.value}
                          onClick={() => {
                            setNavbarBgColor(color.value);
                            setShowColorPicker(false);
                          }}
                          className="w-full flex items-center gap-3 p-2 rounded hover:bg-slate-700 transition-colors"
                        >
                          <div
                            className="w-8 h-8 rounded border border-slate-600"
                            style={{ backgroundColor: color.value }}
                          />
                          <span className="text-sm">{color.name}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            <button
              type="button"
              className={`flex items-center gap-2 px-4 py-2 ${theme === 'dark' ? 'bg-slate-800 hover:bg-slate-700' : 'bg-slate-200 hover:bg-slate-300'} rounded-lg transition-colors`}
            >
              <User className="w-5 h-5" />
              <span className="text-sm font-medium">Usuario</span>
            </button>
          </div>
        </header>

        <main className={`flex-1 overflow-auto ${theme === 'dark' ? 'bg-slate-950' : 'bg-slate-50'}`}>
          {children}
        </main>
      </div>
    </div>
  );
}
