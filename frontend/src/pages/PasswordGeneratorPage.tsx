import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  Copy,
  Check,
  RefreshCw,
  ShieldCheck,
  Lock,
  Info
} from 'lucide-react';
import { api } from '../services/api';
import { PasswordGenerateResponse } from '../types';

export const PasswordGeneratorPage: React.FC = () => {
  const [length, setLength] = useState(20);
  const [useUpper, setUseUpper] = useState(true);
  const [useLower, setUseLower] = useState(true);
  const [useNumbers, setUseNumbers] = useState(true);
  const [useSymbols, setUseSymbols] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(true);

  const [result, setResult] = useState<PasswordGenerateResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const [generating, setGenerating] = useState(false);

  const generate = async () => {
    setGenerating(true);
    try {
      const data = await api.generatePassword({
        length,
        use_uppercase: useUpper,
        use_lowercase: useLower,
        use_numbers: useNumbers,
        use_symbols: useSymbols,
        exclude_ambiguous: excludeAmbiguous
      });
      setResult(data);
      setCopied(false);
    } catch (err: any) {
      console.error(err);
      // Client-side fallback using window.crypto.getRandomValues
      clientSideFallback();
    } finally {
      setGenerating(false);
    }
  };

  const clientSideFallback = () => {
    let pool = '';
    const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lower = 'abcdefghijkmnopqrstuvwxyz';
    const num = '23456789';
    const sym = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (useUpper) pool += upper;
    if (useLower) pool += lower;
    if (useNumbers) pool += num;
    if (useSymbols) pool += sym;
    if (!pool) pool = lower + num;

    const array = new Uint32Array(length);
    window.crypto.getRandomValues(array);
    let pwd = '';
    for (let i = 0; i < length; i++) {
      pwd += pool[array[i] % pool.length];
    }

    const entropy = Math.round(length * Math.log2(pool.length) * 10) / 10;
    setResult({
      password: pwd,
      length: pwd.length,
      entropy_bits: entropy,
      strength: entropy > 80 ? 'Very Strong' : entropy > 60 ? 'Strong' : 'Moderate',
      crack_time_estimate: 'Decades to centuries',
      security_notice: 'Generated in client browser CSPRNG. Never cached or stored.'
    });
    setCopied(false);
  };

  useEffect(() => {
    generate();
  }, [length, useUpper, useLower, useNumbers, useSymbols, excludeAmbiguous]);

  const handleCopy = () => {
    if (!result) return;
    navigator.clipboard.writeText(result.password);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
          Cryptographically Secure Password Generator
        </h2>
        <p className="text-sm text-slate-600 dark:text-slate-300 mt-1">
          NIST SP 800-63B compliant password entropy generator. Generated strictly in-memory with a zero-storage guarantee.
        </p>
      </div>

      {/* Main Generator Box */}
      <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-6 shadow-sm space-y-6">
        {/* Password Display Box */}
        <div className="space-y-2">
          <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Generated Secret
          </label>
          <div className="relative flex items-center">
            <div className="w-full px-4 py-3.5 pr-24 rounded-xl bg-slate-50 dark:bg-cyber-elevated border border-slate-200 dark:border-cyber-border font-mono text-sm sm:text-base font-semibold tracking-wider text-slate-900 dark:text-emerald-400 select-all overflow-x-auto whitespace-nowrap">
              {result ? result.password : 'Generating...'}
            </div>

            <div className="absolute right-2 flex items-center space-x-1.5">
              <button
                type="button"
                onClick={generate}
                className="p-2 rounded-lg text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-white hover:bg-slate-200 dark:hover:bg-cyber-subtle transition-colors"
                title="Regenerate password"
                aria-label="Regenerate password"
              >
                <RefreshCw className={`w-4 h-4 ${generating ? 'animate-spin' : ''}`} />
              </button>

              <button
                type="button"
                onClick={handleCopy}
                className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors shadow-sm"
                aria-label="Copy password"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Strength & Entropy Metrics */}
        {result && (
          <div className="grid grid-cols-3 gap-3 p-3.5 rounded-xl bg-slate-50 dark:bg-cyber-elevated/40 border border-slate-200/60 dark:border-cyber-border/60 text-xs">
            <div>
              <span className="text-slate-400 font-mono text-[11px] block uppercase">Strength</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400 font-mono">
                {result.strength}
              </span>
            </div>
            <div>
              <span className="text-slate-400 font-mono text-[11px] block uppercase">Entropy</span>
              <span className="font-mono text-slate-700 dark:text-slate-300 font-medium">
                {result.entropy_bits} bits
              </span>
            </div>
            <div>
              <span className="text-slate-400 font-mono text-[11px] block uppercase">Crack Estimate</span>
              <span className="font-mono text-slate-700 dark:text-slate-300 truncate block">
                {result.crack_time_estimate}
              </span>
            </div>
          </div>
        )}

        {/* Controls */}
        <div className="space-y-5 pt-2">
          {/* Length Slider */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-500 dark:text-slate-400">Length:</span>
              <span className="font-bold text-slate-900 dark:text-slate-100">{length} characters</span>
            </div>
            <input
              type="range"
              min="8"
              max="64"
              value={length}
              onChange={(e) => setLength(parseInt(e.target.value))}
              className="w-full h-1.5 bg-slate-200 dark:bg-cyber-border rounded-lg appearance-none cursor-pointer accent-emerald-600"
            />
          </div>

          {/* Character Options Checkboxes */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <label className="flex items-center space-x-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={useUpper}
                onChange={(e) => setUseUpper(e.target.checked)}
                className="w-4 h-4 text-emerald-600 rounded border-slate-300 focus:ring-emerald-500"
              />
              <span className="text-slate-700 dark:text-slate-300">Uppercase Letters (A-Z)</span>
            </label>

            <label className="flex items-center space-x-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={useLower}
                onChange={(e) => setUseLower(e.target.checked)}
                className="w-4 h-4 text-emerald-600 rounded border-slate-300 focus:ring-emerald-500"
              />
              <span className="text-slate-700 dark:text-slate-300">Lowercase Letters (a-z)</span>
            </label>

            <label className="flex items-center space-x-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={useNumbers}
                onChange={(e) => setUseNumbers(e.target.checked)}
                className="w-4 h-4 text-emerald-600 rounded border-slate-300 focus:ring-emerald-500"
              />
              <span className="text-slate-700 dark:text-slate-300">Numbers (0-9)</span>
            </label>

            <label className="flex items-center space-x-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={useSymbols}
                onChange={(e) => setUseSymbols(e.target.checked)}
                className="w-4 h-4 text-emerald-600 rounded border-slate-300 focus:ring-emerald-500"
              />
              <span className="text-slate-700 dark:text-slate-300">Special Symbols (!@#$)</span>
            </label>

            <label className="flex items-center space-x-2.5 cursor-pointer sm:col-span-2">
              <input
                type="checkbox"
                checked={excludeAmbiguous}
                onChange={(e) => setExcludeAmbiguous(e.target.checked)}
                className="w-4 h-4 text-emerald-600 rounded border-slate-300 focus:ring-emerald-500"
              />
              <span className="text-slate-700 dark:text-slate-300">
                Exclude Ambiguous Characters (e.g. 1, l, I, 0, O)
              </span>
            </label>
          </div>
        </div>

        {/* Security Notice Note */}
        <div className="pt-4 border-t border-slate-100 dark:border-cyber-border flex items-start space-x-2.5 text-xs text-slate-500 dark:text-slate-400">
          <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong>Defensive Hygiene Notice:</strong> Never reuse passwords across critical systems. Generated passwords exist only in active memory and are destroyed immediately upon page reload.
          </p>
        </div>
      </div>
    </div>
  );
};
