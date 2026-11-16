import React, { useState, useEffect } from 'react';
import {
  Search,
  BookOpen,
  ShieldCheck,
  ChevronRight,
  Filter,
  ExternalLink,
  ShieldAlert,
  Layers
} from 'lucide-react';
import { api } from '../services/api';
import { ThreatProfile, RuleDefinition } from '../types';
import { Badge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';

export const ThreatLibraryPage: React.FC = () => {
  const [threats, setThreats] = useState<ThreatProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedThreat, setSelectedThreat] = useState<ThreatProfile | null>(null);

  useEffect(() => {
    async function loadThreats() {
      try {
        const data = await api.getThreats(searchQuery, selectedCategory);
        setThreats(data);
      } catch (err) {
        console.error('Failed to load threats:', err);
      } finally {
        setLoading(false);
      }
    }
    loadThreats();
  }, [searchQuery, selectedCategory]);

  const categories = ['All', 'Authentication', 'Network', 'System', 'Endpoint', 'Application', 'Email', 'Cloud', 'Insider'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
          Defensive Threat Library
        </h2>
        <p className="text-sm text-slate-600 dark:text-slate-300 mt-1">
          Explore cybersecurity threat profiles, observable indicators, MITRE ATT&CK techniques, and prescriptive hardening mitigations.
        </p>
      </div>

      {/* Search & Category Filter Controls */}
      <div className="flex flex-col sm:flex-row gap-4 justify-between items-stretch sm:items-center">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search threats, indicators, or mitigations..."
            className="w-full pl-10 pr-4 py-2 text-sm rounded-lg bg-white dark:bg-cyber-surface border border-slate-200 dark:border-cyber-border text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          />
        </div>

        <div className="flex flex-wrap gap-1.5 items-center">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-2.5 py-1 text-xs rounded-md font-medium transition-all ${
                selectedCategory === cat
                  ? 'bg-slate-900 text-white dark:bg-emerald-500/20 dark:text-emerald-400 dark:border dark:border-emerald-500/30'
                  : 'bg-white dark:bg-cyber-surface text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-cyber-border hover:bg-slate-50 dark:hover:bg-cyber-elevated'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Threats Grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {[1, 2, 3, 4, 5, 6].map((n) => (
            <div key={n} className="h-48 rounded-xl bg-slate-100 dark:bg-cyber-surface border border-slate-200 dark:border-cyber-border animate-pulse" />
          ))}
        </div>
      ) : threats.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {threats.map((threat) => (
            <div
              key={threat.id}
              onClick={() => setSelectedThreat(threat)}
              className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-5 hover:border-emerald-500/40 dark:hover:border-emerald-500/40 hover:shadow-md transition-all cursor-pointer flex flex-col justify-between"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <Badge variant="category" size="sm">
                    {threat.category}
                  </Badge>
                  <Badge variant="severity" severity={threat.severity as any} size="sm" />
                </div>

                <div>
                  <h3 className="font-semibold text-slate-900 dark:text-slate-100 text-base">
                    {threat.name}
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                    {threat.summary}
                  </p>
                </div>

                {threat.mitre_technique && (
                  <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-cyber-elevated px-2 py-1 rounded inline-block">
                    MITRE {threat.mitre_technique}
                  </div>
                )}
              </div>

              <div className="pt-4 mt-4 border-t border-slate-100 dark:border-cyber-border flex items-center justify-between text-xs text-emerald-600 dark:text-emerald-400 font-medium">
                <span>View profile & mitigations</span>
                <ChevronRight className="w-4 h-4" />
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="p-12 text-center rounded-xl border border-dashed border-slate-200 dark:border-cyber-border bg-white/50 dark:bg-cyber-surface/50">
          <BookOpen className="w-8 h-8 text-slate-400 mx-auto mb-2" />
          <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-200">
            No Threats Match Filter
          </h4>
          <p className="text-xs text-slate-500 mt-1">
            Try adjusting search terms or resetting the domain category filter.
          </p>
        </div>
      )}

      {/* Threat Detail Modal */}
      {selectedThreat && (
        <Modal
          isOpen={Boolean(selectedThreat)}
          onClose={() => setSelectedThreat(null)}
          title={selectedThreat.name}
          subtitle={`Threat Profile • ${selectedThreat.category} Layer`}
          maxWidth="2xl"
        >
          <div className="space-y-6 text-sm">
            {/* Meta Tags */}
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="severity" severity={selectedThreat.severity as any} />
              <Badge variant="category">{selectedThreat.category}</Badge>
              {selectedThreat.mitre_technique && (
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-cyber-elevated text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-cyber-border">
                  MITRE {selectedThreat.mitre_technique}
                </span>
              )}
            </div>

            {/* Description */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Detailed Threat Analysis
              </h4>
              <p className="text-slate-700 dark:text-slate-300 leading-relaxed text-xs sm:text-sm">
                {selectedThreat.detailed_description}
              </p>
            </div>

            {/* Common Indicators */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Common Observable Indicators
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300">
                {selectedThreat.common_indicators.map((ind, i) => (
                  <li key={i} className="flex items-start space-x-2">
                    <span className="text-amber-500 font-bold">•</span>
                    <span>{ind}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Defensive Remediation */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Recommended Defensive Response
              </h4>
              <ol className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
                {selectedThreat.defensive_actions.map((act, i) => (
                  <li key={i} className="flex items-start space-x-2">
                    <span className="w-4 h-4 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-mono text-[10px] flex items-center justify-center shrink-0 mt-0.5 font-bold">
                      {i + 1}
                    </span>
                    <span>{act}</span>
                  </li>
                ))}
              </ol>
            </div>

            {/* Detection Strategies */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Detection & SIEM Monitoring Strategies
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300">
                {selectedThreat.detection_strategies.map((strat, i) => (
                  <li key={i} className="flex items-start space-x-2">
                    <span className="text-emerald-500 font-bold">✓</span>
                    <span>{strat}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
