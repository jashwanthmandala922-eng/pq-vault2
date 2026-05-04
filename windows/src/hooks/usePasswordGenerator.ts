import { useState } from 'react';
import { secureVault } from '../lib/secureVault';

export interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

export interface PasswordGeneratorProps {
  onGenerate: (password: string) => void;
}

export function usePasswordGenerator() {
  const [password, setPassword] = useState('');
  const [options, setOptions] = useState<PasswordOptions>({
    length: 20,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
  });

  async function generate() {
    try {
      const result = await secureVault.generatePassword(options);
      setPassword(result);
    } catch (e) {
      console.error('Failed to generate password:', e);
    }
  }

  function updateOption<K extends keyof PasswordOptions>(key: K, value: PasswordOptions[K]) {
    setOptions(prev => ({ ...prev, [key]: value }));
    generate();
  }

  return {
    password,
    options,
    generate,
    updateOption,
  };
}