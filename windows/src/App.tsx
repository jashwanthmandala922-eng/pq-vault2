import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const handleLogin = async () => {
    try {
      // Call Tauri command
      await invoke('unlock_vault', { password: 'test' });
      setIsLoggedIn(true);
    } catch (e) {
      console.error('Login failed:', e);
    }
  };

  if (!isLoggedIn) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return <VaultScreen onLogout={() => setIsLoggedIn(false)} />;
}

function LoginScreen({ onLogin }: { onLogin: () => void }) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary to-accent flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
        <h1 className="text-3xl font-bold text-center mb-2 text-primary">PQ Vault</h1>
        <p className="text-gray-500 text-center mb-8">Post-Quantum Password Manager</p>

        <button
          onClick={onLogin}
          className="w-full bg-primary text-white py-3 rounded-lg font-semibold mb-4 hover:bg-primary-dark transition"
        >
          Sign in with Google
        </button>

        <button
          onClick={onLogin}
          className="w-full bg-gray-900 text-white py-3 rounded-lg font-semibold mb-4 hover:bg-gray-800 transition"
        >
          Sign in with Apple
        </button>

        <div className="flex items-center my-6">
          <div className="flex-1 h-px bg-gray-300"></div>
          <span className="px-4 text-gray-500">or</span>
          <div className="flex-1 h-px bg-gray-300"></div>
        </div>

        <input
          type="password"
          placeholder="Master Password"
          className="w-full border border-gray-300 rounded-lg px-4 py-3 mb-4"
        />

        <button
          onClick={onLogin}
          className="w-full bg-secondary text-white py-3 rounded-lg font-semibold hover:bg-secondary-dark transition"
        >
          Unlock Vault
        </button>
      </div>
    </div>
  );
}

function VaultScreen({ onLogout }: { onLogout: () => void }) {
  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm">
        <div className="max-w-4xl mx-auto px-4 py-4 flex justify-between items-center">
          <h1 className="text-xl font-bold text-primary">PQ Vault</h1>
          <button
            onClick={onLogout}
            className="text-gray-600 hover:text-primary"
          >
            Lock
          </button>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 py-8">
        <div className="bg-white rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold mb-4">Passwords</h2>
          <div className="text-gray-500 text-center py-8">
            No passwords yet. Add your first password to get started.
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;