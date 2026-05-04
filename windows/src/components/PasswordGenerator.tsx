import { usePasswordGenerator } from '../hooks/usePasswordGenerator';

export function PasswordGenerator({ onGenerate }: { onGenerate?: (password: string) => void }) {
  const { password, options, updateOption, generate } = usePasswordGenerator();

  const handleCopy = async () => {
    await navigator.clipboard.writeText(password);
    onGenerate?.(password);
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-lg font-semibold mb-4">Password Generator</h2>
      
      <div className="bg-gray-100 rounded p-4 mb-4">
        <code className="text-xl font-mono break-all">{password || 'Click generate'}</code>
      </div>

      <div className="space-y-3 mb-4">
        <div>
          <label className="text-sm text-gray-600">Length: {options.length}</label>
          <input
            type="range"
            min="8"
            max="64"
            value={options.length}
            onChange={(e) => updateOption('length', parseInt(e.target.value))}
            className="w-full"
          />
        </div>

        <div className="space-y-2">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={options.uppercase}
              onChange={(e) => updateOption('uppercase', e.target.checked)}
            />
            Uppercase (A-Z)
          </label>

          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={options.lowercase}
              onChange={(e) => updateOption('lowercase', e.target.checked)}
            />
            Lowercase (a-z)
          </label>

          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={options.numbers}
              onChange={(e) => updateOption('numbers', e.target.checked)}
            />
            Numbers (0-9)
          </label>

          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={options.symbols}
              onChange={(e) => updateOption('symbols', e.target.checked)}
            />
            Symbols (!@#$%)
          </label>
        </div>
      </div>

      <div className="flex gap-2">
        <button
          onClick={generate}
          className="flex-1 bg-primary text-white py-2 rounded hover:bg-primary-dark"
        >
          Generate
        </button>
        <button
          onClick={handleCopy}
          disabled={!password}
          className="flex-1 bg-gray-200 text-gray-700 py-2 rounded hover:bg-gray-300 disabled:opacity-50"
        >
          Copy
        </button>
      </div>
    </div>
  );
}