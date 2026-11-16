import React, { useState } from 'react';
import {
  Send,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Terminal,
  User,
  Sparkles,
  ArrowRight,
  RotateCcw,
  ListFilter
} from 'lucide-react';
import { api } from '../services/api';
import { ChatDiagnosisResponse } from '../types';
import { Badge } from '../components/common/Badge';

interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant';
  timestamp: string;
  query?: string;
  response?: ChatDiagnosisResponse;
}

export const ChatPage: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      sender: 'assistant',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [input, setInput] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);

  const samplePrompts = [
    "Someone tried logging into my account 20 times and then successfully logged in from an unknown IP.",
    "Our accounting workstation has 100% CPU usage, files are getting renamed with .locked extension, and shadow copies were deleted.",
    "Received an urgent email claiming to be our CFO asking to open an attached macro-enabled invoice spreadsheet.",
    "Internal database server is making thousands of high-entropy DNS queries to an external domain name."
  ];

  const handleSend = async (textToSend?: string) => {
    const text = (textToSend || input).trim();
    if (!text || isProcessing) return;

    const userMsg: ChatMessage = {
      id: String(Date.now()),
      sender: 'user',
      query: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsProcessing(true);

    try {
      const result = await api.chatDiagnose(text, true);
      const assistantMsg: ChatMessage = {
        id: String(Date.now() + 1),
        sender: 'assistant',
        response: result,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      console.error(err);
      alert('Diagnosis error: ' + (err.message || 'Failed to process inquiry'));
    } finally {
      setIsProcessing(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleClear = () => {
    setMessages([
      {
        id: 'welcome',
        sender: 'assistant',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }
    ]);
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Conversational Incident Diagnosis
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-300 mt-1">
            Describe observed security events in natural language. CyberMate deterministically extracts facts and runs the expert rule engine.
          </p>
        </div>
        <button
          onClick={handleClear}
          type="button"
          className="inline-flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-cyber-border text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-50 dark:hover:bg-cyber-elevated transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Clear Chat</span>
        </button>
      </div>

      {/* Chat Thread Container */}
      <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-4 sm:p-6 shadow-sm min-h-[480px] flex flex-col justify-between">
        {/* Messages Feed */}
        <div className="space-y-6 overflow-y-auto max-h-[600px] pr-2">
          {messages.map((msg) => {
            if (msg.id === 'welcome') {
              return (
                <div key={msg.id} className="p-4 rounded-xl bg-slate-50 dark:bg-cyber-elevated/60 border border-slate-200/60 dark:border-cyber-border/60 space-y-3">
                  <div className="flex items-center space-x-2 text-xs font-mono text-emerald-600 dark:text-emerald-400">
                    <Terminal className="w-4 h-4" />
                    <span>CyberMate Diagnostic Assistant Ready</span>
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                    Hello. I am the CyberMate reasoning assistant. You can describe any suspicious system anomaly, authentication pattern, or email security incident. I will map your observations to cybersecurity facts and evaluate our 49 diagnostic rules.
                  </p>
                  <div className="pt-2">
                    <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block mb-2">
                      Sample inquiries to test:
                    </span>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {samplePrompts.map((prompt, idx) => (
                        <button
                          key={idx}
                          onClick={() => handleSend(prompt)}
                          className="text-left p-2.5 rounded-lg bg-white dark:bg-cyber-surface border border-slate-200 dark:border-cyber-border hover:border-emerald-500/50 hover:bg-emerald-50/50 dark:hover:bg-emerald-950/20 text-xs text-slate-700 dark:text-slate-300 transition-all"
                        >
                          "{prompt}"
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              );
            }

            if (msg.sender === 'user') {
              return (
                <div key={msg.id} className="flex items-start space-x-3 justify-end">
                  <div className="max-w-xl p-4 rounded-2xl bg-slate-900 text-white dark:bg-cyber-elevated dark:text-slate-100 border border-slate-800 dark:border-cyber-border text-sm leading-relaxed shadow-sm">
                    <div className="text-[11px] font-mono text-slate-400 mb-1 flex items-center justify-between">
                      <span>User Observation</span>
                      <span>{msg.timestamp}</span>
                    </div>
                    {msg.query}
                  </div>
                  <div className="w-8 h-8 rounded-full bg-slate-200 dark:bg-cyber-subtle flex items-center justify-center text-slate-700 dark:text-slate-300 shrink-0">
                    <User className="w-4 h-4" />
                  </div>
                </div>
              );
            }

            // Assistant diagnostic card
            const diag = msg.response;
            if (!diag) return null;
            const report = diag.diagnosis_report;

            return (
              <div key={msg.id} className="flex items-start space-x-3">
                <div className="w-8 h-8 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-600 dark:text-emerald-400 shrink-0 mt-1">
                  <ShieldAlert className="w-4 h-4" />
                </div>

                <div className="flex-1 space-y-4 max-w-2xl">
                  {/* Phase 1: Extracted Facts */}
                  <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-cyber-elevated/40 border border-slate-200/80 dark:border-cyber-border text-xs space-y-2">
                    <div className="flex items-center space-x-1.5 font-mono text-slate-500 dark:text-slate-400">
                      <ListFilter className="w-3.5 h-3.5 text-emerald-500" />
                      <span>Extracted Security Facts ({diag.extracted_observations.length})</span>
                    </div>
                    {diag.extracted_observations.length > 0 ? (
                      <ul className="space-y-1">
                        {diag.extracted_observations.map((obs, idx) => (
                          <li key={idx} className="flex items-center space-x-2 text-slate-700 dark:text-slate-300">
                            <span className="text-emerald-500 font-bold">•</span>
                            <span>{obs}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-slate-500">No specific threat indicator signatures detected in text.</p>
                    )}
                  </div>

                  {/* Phase 2: Deterministic Rule Diagnosis */}
                  <div className="p-4 rounded-xl bg-white dark:bg-cyber-surface border border-slate-200 dark:border-cyber-border shadow-sm space-y-3">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                          Expert System Inference
                        </div>
                        <h4 className="text-base font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                          {report.primary_threat ? report.primary_threat.threat : 'No Threat Matched'}
                        </h4>
                      </div>
                      {report.primary_threat && (
                        <Badge variant="severity" severity={report.primary_threat.severity} size="sm" />
                      )}
                    </div>

                    {report.primary_threat ? (
                      <>
                        <div className="text-xs text-slate-600 dark:text-slate-400 flex items-center space-x-3 font-mono">
                          <span>Confidence: {Math.round(report.primary_threat.confidence * 100)}%</span>
                          <span>•</span>
                          <span>Risk Score: {report.risk_score.score}/100</span>
                        </div>

                        <div className="pt-2 border-t border-slate-100 dark:border-cyber-border space-y-1.5">
                          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                            Evidence Basis
                          </div>
                          {report.primary_threat.evidence.map((ev, i) => (
                            <div key={i} className="flex items-center space-x-2 text-xs text-slate-700 dark:text-slate-300">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                              <span>{ev}</span>
                            </div>
                          ))}
                        </div>

                        {/* Phase 3: Prescriptive Actions */}
                        <div className="pt-2 border-t border-slate-100 dark:border-cyber-border space-y-1.5">
                          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                            Prescribed Defensive Actions
                          </div>
                          <ol className="space-y-1 text-xs text-slate-700 dark:text-slate-300">
                            {report.overall_recommendations.slice(0, 3).map((rec, i) => (
                              <li key={i} className="flex items-start space-x-2">
                                <span className="text-emerald-500 font-mono font-bold">{i + 1}.</span>
                                <span>{rec}</span>
                              </li>
                            ))}
                          </ol>
                        </div>
                      </>
                    ) : (
                      <p className="text-xs text-slate-600 dark:text-slate-400">
                        The observations provided do not match known attack signatures. Maintain standard monitoring.
                      </p>
                    )}
                  </div>
                </div>
              </div>
            );
          })}

          {isProcessing && (
            <div className="flex items-center space-x-3 text-xs text-slate-500 dark:text-slate-400 font-mono py-2">
              <div className="w-4 h-4 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
              <span>Extracting indicators & evaluating 49 deterministic rules...</span>
            </div>
          )}
        </div>

        {/* Input Textarea Bar */}
        <div className="pt-4 border-t border-slate-100 dark:border-cyber-border">
          <div className="relative rounded-xl border border-slate-200 dark:border-cyber-border bg-slate-50 dark:bg-cyber-elevated focus-within:ring-2 focus-within:ring-emerald-500 focus-within:border-emerald-500 transition-all">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Describe what you observed (e.g., '20 failed logins from an unknown IP followed by a successful login')..."
              rows={3}
              className="w-full p-3.5 pr-14 text-sm bg-transparent border-0 text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none resize-none"
            />
            <div className="absolute right-2.5 bottom-2.5">
              <button
                type="button"
                onClick={() => handleSend()}
                disabled={!input.trim() || isProcessing}
                className="p-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white transition-colors shadow-sm"
                aria-label="Send observation"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mt-2 px-1">
            <span>Press Enter to analyze • Shift+Enter for newline</span>
            <span>Deterministic Rule Classifier</span>
          </div>
        </div>
      </div>
    </div>
  );
};
