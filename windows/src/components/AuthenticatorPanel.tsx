import { useState, useEffect } from 'react';

interface TOTPEntry {
  id: string;
  service: string;
  account: string;
  secret: string;
}

export function AuthenticatorPanel() {
  const [codes, setCodes] = useState<Map<string, string>>(new Map());
  const [timeLeft, setTimeLeft] = useState(30);

  const [entries] = useState<TOTPEntry[]>([
    { id: '1', service: 'Google', account: 'user@gmail.com', secret: 'JBSWY3DPEHPK3PXP' },
    { id: '2', service: 'GitHub', account: 'user@email.com', secret: 'GEZDGNBVGY3TQOJQ' },
  ]);

  useEffect(() => {
    // Generate codes initially and every second
    const generateCodes = () => {
      const newCodes = new Map<string, string>();
      const now = Math.floor(Date.now() / 1000);
      const remaining = 30 - (now % 30);
      setTimeLeft(remaining);

      entries.forEach(entry => {
        newCodes.set(entry.id, generateTOTP(entry.secret, now));
      });

      setCodes(newCodes);
    };

    generateCodes();
    const interval = setInterval(generateCodes, 1000);
    return () => clearInterval(interval);
  }, [entries]);

  const copyCode = (code: string) => {
    navigator.clipboard.writeText(code);
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-semibold">Authenticator</h2>
        <button className="text-primary hover:underline text-sm">+ Add</button>
      </div>

      <div className="space-y-3">
        {entries.map(entry => {
          const code = codes.get(entry.id) || '------';
          return (
            <div
              key={entry.id}
              className="flex items-center justify-between p-3 bg-gray-50 rounded-lg cursor-pointer hover:bg-gray-100"
              onClick={() => copyCode(code)}
            >
              <div>
                <div className="font-medium">{entry.service}</div>
                <div className="text-sm text-gray-500">{entry.account}</div>
              </div>
              <div className="text-right">
                <div className="text-2xl font-mono font-bold text-primary">{code.slice(0,3)} {code.slice(3)}</div>
                <div className="text-xs text-gray-400">{timeLeft}s</div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-4 h-1 bg-gray-200 rounded-full overflow-hidden">
        <div
          className="h-full bg-primary transition-all duration-1000"
          style={{ width: `${(timeLeft / 30) * 100}%` }}
        />
      </div>
    </div>
  );
}

function generateTOTP(secret: string, timeStep: number): string {
  // Simplified TOTP - production would use proper HMAC-SHA1
  const data = secret + String(timeStep);
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    hash = ((hash << 5) - hash + data.charCodeAt(i)) | 0;
  }
  const otp = Math.abs(hash % 1000000);
  return otp.toString().padStart(6, '0');
}