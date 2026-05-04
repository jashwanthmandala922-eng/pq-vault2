import { useState } from 'react';
import { secureVault, VaultEntry, SecureAPIError } from '../lib/secureVault';

export type { VaultEntry };

export function useVault() {
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [isLocked, setIsLocked] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function unlock(password: string) {
    setIsLoading(true);
    setError(null);
    try {
      await secureVault.unlock(password);
      const result = await secureVault.getEntries();
      setEntries(result);
      setIsLocked(false);
    } catch (e) {
      if (e instanceof SecureAPIError) {
        setError(e.message);
      } else {
        setError(String(e));
      }
    } finally {
      setIsLoading(false);
    }
  }

  async function lock() {
    await secureVault.lock();
    setIsLocked(true);
    setEntries([]);
  }

  async function addEntry(title: string, url: string | null, username: string | null, password: string) {
    setIsLoading(true);
    try {
      await secureVault.addEntry(title, password, { 
        url: url ?? undefined, 
        username: username ?? undefined 
      });
      const result = await secureVault.getEntries();
      setEntries(result);
    } catch (e) {
      if (e instanceof SecureAPIError) {
        setError(e.message);
      } else {
        setError(String(e));
      }
    } finally {
      setIsLoading(false);
    }
  }

  async function refreshEntries() {
    try {
      const result = await secureVault.getEntries();
      setEntries(result);
    } catch (e) {
      if (e instanceof SecureAPIError) {
        setError(e.message);
      } else {
        setError(String(e));
      }
    }
  }

  return {
    entries,
    isLocked,
    isLoading,
    error,
    unlock,
    lock,
    addEntry,
    refreshEntries,
  };
}