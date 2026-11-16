import React from 'react';
import {
  LayoutDashboard,
  ShieldCheck,
  MessageSquareText,
  BookOpen,
  FlaskConical,
  Gauge,
  KeyRound,
  History,
  Info,
  ShieldAlert,
  ChevronRight
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'analyze'
  | 'chat'
  | 'threats'
  | 'scenarios'
  | 'risk'
  | 'password'
  | 'history'
  | 'about';

interface SidebarProps {
  currentPage: PageId;
  onSelectPage: (page: PageId) => void;
  isOpenMobile: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onSelectPage,
  isOpenMobile,
  onCloseMobile
}) => {
  const navItems = [
    { id: 'dashboard' as PageId, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'analyze' as PageId, label: 'Analyze Incident', icon: ShieldCheck, badge: 'Core' },
    { id: 'chat' as PageId, label: 'Chat Diagnosis', icon: MessageSquareText },
    { id: 'threats' as PageId, label: 'Threat Library', icon: BookOpen },
    { id: 'scenarios' as PageId, label: 'Attack Scenarios', icon: FlaskConical },
    { id: 'risk' as PageId, label: 'Risk Score', icon: Gauge },
    { id: 'password' as PageId, label: 'Password Generator', icon: KeyRound },
    { id: 'history' as PageId, label: 'Incident History', icon: History },
    { id: 'about' as PageId, label: 'About / System', icon: Info },
  ];

  const handleNav = (id: PageId) => {
    onSelectPage(id);
    onCloseMobile();
  };

  return (
    <>
      {/* Mobile backdrop */}
      {isOpenMobile && (
        <div
          className="fixed inset-0 z-40 bg-slate-950/60 lg:hidden backdrop-blur-sm"
          onClick={onCloseMobile}
        />
      )}

      {/* Sidebar container */}
      <aside
        className={`fixed lg:static top-0 bottom-0 left-0 z-40 w-64 bg-white dark:bg-cyber-surface border-r border-slate-200 dark:border-cyber-border flex flex-col transition-transform duration-200 ease-in-out ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div className="h-16 flex items-center px-6 border-b border-slate-200 dark:border-cyber-border">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 dark:bg-emerald-400/10 border border-emerald-500/20 flex items-center justify-center text-emerald-600 dark:text-emerald-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <span className="font-bold tracking-tight text-slate-900 dark:text-white text-base">
                CyberMate
              </span>
              <span className="block text-[10px] uppercase font-mono tracking-wider text-slate-500 dark:text-slate-400 -mt-0.5">
                Expert System
              </span>
            </div>
          </div>
        </div>

        {/* Navigation list */}
        <div className="flex-1 py-4 px-3 overflow-y-auto space-y-1">
          <div className="px-3 pb-2 text-[11px] font-mono uppercase tracking-wider text-slate-400 dark:text-slate-500">
            Navigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleNav(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-cyber-elevated'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Engine Status Footer */}
        <div className="p-4 border-t border-slate-200 dark:border-cyber-border bg-slate-50/50 dark:bg-cyber-surface/50">
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-500 dark:text-slate-400 font-mono">Engine</span>
            <span className="inline-flex items-center space-x-1.5 text-emerald-600 dark:text-emerald-400 font-mono text-[11px]">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span>49 Rules Active</span>
            </span>
          </div>
          <div className="text-[11px] text-slate-400 dark:text-slate-500 font-mono mt-1">
            Deterministic v1.0
          </div>
        </div>
      </aside>
    </>
  );
};
