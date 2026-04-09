'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Home, Lock, ShieldCheck, Key, User, Moon, Sun } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

export function VaultShell({ children }: { children: React.ReactNode }) {
  const { theme, setTheme } = useTheme();
  const pathname = usePathname();

  const menuItems = [
    { path: '/', icon: Home, label: 'Inicio' },
    { path: '/encrypt', icon: Lock, label: 'Cifrar' },
    { path: '/verify', icon: ShieldCheck, label: 'Verificar' },
    { path: '/keystore', icon: Key, label: 'Claves' },
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
              <p className="text-sm font-medium truncate">Vault</p>
              <p className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>Python</p>
            </div>
          </div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col overflow-hidden">
        <header
          className={`h-16 border-b flex items-center justify-between px-6 ${
            theme === 'dark' ? 'border-slate-800 bg-slate-900' : 'border-slate-200 bg-white'
          }`}
        >
          <h2 className="text-xl font-semibold">Bóveda</h2>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              className={`p-2 rounded-lg transition-colors ${
                theme === 'dark' ? 'bg-slate-800 hover:bg-slate-700' : 'bg-slate-200 hover:bg-slate-300'
              }`}
              aria-label={theme === 'dark' ? 'Modo claro' : 'Modo oscuro'}
            >
              {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
            <div
              className={`flex items-center gap-2 px-3 py-2 ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-200'} rounded-lg`}
            >
              <User className="w-5 h-5 opacity-70" />
              <span className="text-sm font-medium hidden sm:inline">Local</span>
            </div>
          </div>
        </header>

        <main className={`flex-1 overflow-auto ${theme === 'dark' ? 'bg-slate-950' : 'bg-slate-50'}`}>
          {children}
        </main>
      </div>
    </div>
  );
}
