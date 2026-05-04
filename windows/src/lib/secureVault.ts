import { invoke } from '@tauri-apps/api/core';

interface VaultEntry {
  id: string;
  title: string;
  url: string | null;
  username: string | null;
  created_at: string;
  favorite: boolean;
}

interface SyncPeer {
  id: string;
  name: string;
  address: string;
}

interface CommandError {
  code: string;
  message: string;
}

interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

class SecureAPIError extends Error {
  code: string;
  
  constructor(error: CommandError) {
    super(error.message);
    this.name = 'SecureAPIError';
    this.code = error.code;
  }
}

function handleError(error: unknown): never {
  if (error && typeof error === 'object' && 'code' in error && 'message' in error) {
    throw new SecureAPIError(error as CommandError);
  }
  throw new SecureAPIError({
    code: 'UNKNOWN_ERROR',
    message: String(error)
  });
}

export const secureVault = {
  async unlock(password: string): Promise<string> {
    try {
      return await invoke<string>('unlock_vault', { password });
    } catch (error) {
      handleError(error);
    }
  },

  async create(password: string): Promise<string> {
    try {
      return await invoke<string>('create_vault', { password });
    } catch (error) {
      handleError(error);
    }
  },

  async lock(): Promise<void> {
    try {
      await invoke('lock_vault');
    } catch (error) {
      handleError(error);
    }
  },

  async getEntries(): Promise<VaultEntry[]> {
    try {
      return await invoke<VaultEntry[]>('get_entries');
    } catch (error) {
      handleError(error);
    }
  },

  async addEntry(
    title: string,
    password: string,
    options?: {
      url?: string;
      username?: string;
    }
  ): Promise<VaultEntry> {
    try {
      return await invoke<VaultEntry>('add_entry', {
        title,
        password,
        url: options?.url || null,
        username: options?.username || null,
      });
    } catch (error) {
      handleError(error);
    }
  },

  async generatePassword(options: PasswordOptions): Promise<string> {
    try {
      return await invoke<string>('generate_password', options);
    } catch (error) {
      handleError(error);
    }
  },

  async startSync(): Promise<void> {
    try {
      await invoke('start_sync');
    } catch (error) {
      handleError(error);
    }
  },

  async getPeers(): Promise<SyncPeer[]> {
    try {
      return await invoke<SyncPeer[]>('get_peers');
    } catch (error) {
      handleError(error);
    }
  },
};

export type { VaultEntry, SyncPeer, PasswordOptions };
export { SecureAPIError };