import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const handleLogin = async (password: string) => {
    if (!password || password.length < 1) {
      return { success: false, error: 'Password is required' };
    }
    
    try {
      const result = await invoke('unlock_vault', { password });
      if (result) {
        setIsLoggedIn(true);
        return { success: true };
      }
      return { success: false, error: 'Invalid credentials' };
    } catch (e: unknown) {
      const errorMessage = typeof e === 'string' ? e : e instanceof Error ? e.message : 'Login failed';
      return { success: false, error: errorMessage };
    }
  };

  const handleLogout = async () => {
    try {
      await invoke('lock_vault');
    } catch (e) {
      console.error('Lock failed:', e);
    }
    setIsLoggedIn(false);
  };

  if (!isLoggedIn) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return <VaultScreen onLogout={handleLogout} />;
}

function LoginScreen({ onLogin }: { onLogin: (password: string) => Promise<{ success: boolean; error?: string }> }) {
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempts, setAttempts] = useState(0);
  const [isLocked, setIsLocked] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (isLocked) {
      setError('Too many failed attempts. Please wait 30 seconds.');
      return;
    }

    if (!password) {
      setError('Please enter your master password');
      return;
    }

    setIsLoading(true);
    setError(null);

    const result = await onLogin(password);
    
    setIsLoading(false);
    
    if (!result.success) {
      setAttempts(prev => prev + 1);
      setError(result.error || 'Invalid password');
      setPassword('');
      
      if (attempts >= 2) {
        setIsLocked(true);
        setTimeout(() => {
          setIsLocked(false);
          setAttempts(0);
        }, 30000);
      }
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 relative overflow-hidden">
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-1/4 -left-1/4 w-96 h-96 bg-indigo-600/20 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-1/4 -right-1/4 w-96 h-96 bg-purple-600/20 rounded-full blur-3xl animate-pulse delay-1000" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-blue-600/10 rounded-full blur-3xl" />
      </div>

      <div className="relative min-h-screen flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 mb-4 shadow-lg shadow-indigo-500/30">
              <svg className="w-10 h-10 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h1 className="text-3xl font-bold text-white tracking-tight">PQ Vault</h1>
            <p className="text-slate-400 mt-2">Post-Quantum Secure Vault</p>
          </div>

          <div className="bg-slate-900/60 backdrop-blur-2xl border border-slate-800/50 rounded-3xl p-8 shadow-2xl">
            <form onSubmit={handleSubmit}>
              <div className="mb-6">
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Master Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isLoading || isLocked}
                  className="w-full px-4 py-3 bg-slate-800/50 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all disabled:opacity-50"
                  placeholder="Enter your master password"
                  autoFocus
                />
              </div>

              {error && (
                <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading || isLocked}
                className="w-full py-3.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl hover:from-indigo-500 hover:to-purple-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-slate-900 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin h-5 w-5" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Authenticating...
                  </>
                ) : (
                  'Unlock Vault'
                )}
              </button>
            </form>

            <div className="mt-6 relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-slate-700" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-slate-900 text-slate-500">or continue with</span>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-2 gap-3">
              <button
                type="button"
                className="flex items-center justify-center gap-2 py-2.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl transition-all"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                  <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                  <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                  <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                </svg>
                <span className="text-sm font-medium text-slate-300">Google</span>
              </button>
              <button
                type="button"
                className="flex items-center justify-center gap-2 py-2.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl transition-all"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-2.48-.79-3.16-.79-1.69 0-2.77 1.02-3.52 1.02-1.53 0-2.73-.93-3.47-1.83-1.47 1.01-2.06 2.55-2.17 3.58h1.74c.12-1.03.7-1.78 1.75-1.98 1.27-.25 2.6.58 3.32 1.58.5.7.73 1.51.82 2.36h1.74c-.11-1.38-.43-2.87-1.49-4.23-.7-.9-1.72-1.62-2.87-1.82-.79-.14-1.56-.03-2.23.23-.9.36-1.57 1.07-1.95 1.94-.35.81-.45 1.71-.24 2.57h1.83c.06-.62.33-1.19.8-1.6.56-.49 1.28-.75 2.07-.75.8 0 1.53.31 2.08.86.64.64 1.05 1.56 1.05 2.7 0 .98-.37 1.82-1.03 2.46-.73.71-1.78 1.16-2.97 1.16-1.08 0-2.1-.37-2.87-.98-1.08-.85-1.76-2.2-1.76-3.67h-1.9c.05 2.12 1.26 3.88 3.02 4.8 1.37.72 2.96.94 4.45.6 1.41-.31 2.55-1.2 3.14-2.33.66-1.27.83-2.85.38-4.2-.42-1.28-1.32-2.3-2.57-2.86-.76-.34-1.59-.47-2.41-.38-.8.08-1.56.46-2.14 1.04l-1.15-.89c.86-.97 2.07-1.57 3.43-1.57 1.4 0 2.62.55 3.47 1.46.8.87 1.34 2.03 1.34 3.32 0 .62-.17 1.19-.49 1.66z"/>
                </svg>
                <span className="text-sm font-medium text-slate-300">Apple</span>
              </button>
            </div>
          </div>

          <div className="mt-8 text-center">
            <div className="flex items-center justify-center gap-2 text-slate-500 text-sm">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <span>Post-Quantum Encrypted</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

interface VaultEntry {
  id: string;
  title: string;
  url: string;
  username: string;
  favorite: boolean;
}

function VaultScreen({ onLogout }: { onLogout: () => void }) {
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadEntries();
  }, []);

  const loadEntries = async () => {
    try {
      const result = await invoke<VaultEntry[]>('get_entries');
      setEntries(result);
    } catch (e) {
      console.error('Failed to load entries:', e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      console.error('Failed to copy:', e);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 relative overflow-hidden">
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-600/10 rounded-full blur-3xl" />
      </div>

      <div className="relative">
        <header className="bg-slate-900/50 backdrop-blur-xl border-b border-slate-800/50 sticky top-0 z-10">
          <div className="max-w-4xl mx-auto px-4 py-4 flex justify-between items-center">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h1 className="text-xl font-bold text-white">PQ Vault</h1>
            </div>
            <button
              onClick={onLogout}
              className="flex items-center gap-2 px-4 py-2 bg-slate-800/50 hover:bg-slate-800 border border-slate-700 rounded-lg text-slate-300 hover:text-white transition-all"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              Lock
            </button>
          </div>
        </header>

        <main className="max-w-4xl mx-auto px-4 py-8">
          <div className="flex justify-between items-center mb-6">
            <div>
              <h2 className="text-2xl font-bold text-white">Passwords</h2>
              <p className="text-slate-400 text-sm mt-1">{entries.length} items secured</p>
            </div>
            <button className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-medium rounded-lg hover:from-indigo-500 hover:to-purple-500 transition-all">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Add Password
            </button>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : entries.length === 0 ? (
            <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-2xl p-12 text-center">
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-slate-800 flex items-center justify-center">
                <svg className="w-8 h-8 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">No passwords yet</h3>
              <p className="text-slate-400 max-w-sm mx-auto">Add your first password to get started with secure storage.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {entries.map((entry) => (
                <div
                  key={entry.id}
                  className="group bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 hover:border-indigo-500/30 rounded-xl p-4 transition-all hover:shadow-lg hover:shadow-indigo-500/10"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-slate-700 to-slate-600 flex items-center justify-center text-white font-bold text-lg">
                        {entry.title.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-semibold text-white">{entry.title}</h3>
                          {entry.favorite && (
                            <svg className="w-4 h-4 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                              <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                            </svg>
                          )}
                        </div>
                        <p className="text-sm text-slate-400">{entry.username}</p>
                      </div>
                    </div>
                    <button
                      onClick={() => handleCopy('••••••••')}
                      className="p-2 hover:bg-slate-800 rounded-lg transition-all text-slate-400 hover:text-white"
                    >
                      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;