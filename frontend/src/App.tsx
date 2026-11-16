import React, { useState } from 'react';
import { MainLayout } from './layouts/MainLayout';
import { PageId } from './components/common/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { AnalyzePage } from './pages/AnalyzePage';
import { ChatPage } from './pages/ChatPage';
import { ThreatLibraryPage } from './pages/ThreatLibraryPage';
import { ScenariosPage } from './pages/ScenariosPage';
import { RiskScorePage } from './pages/RiskScorePage';
import { PasswordGeneratorPage } from './pages/PasswordGeneratorPage';
import { IncidentHistoryPage } from './pages/IncidentHistoryPage';
import { AboutPage } from './pages/AboutPage';

export function App() {
  const [currentPage, setCurrentPage] = useState<PageId>('dashboard');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | undefined>(undefined);

  const handleNavigate = (page: PageId, incidentId?: string) => {
    setCurrentPage(page);
    setSelectedIncidentId(incidentId);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <MainLayout currentPage={currentPage} onSelectPage={(page) => handleNavigate(page)}>
      {currentPage === 'dashboard' && <DashboardPage onNavigate={handleNavigate} />}
      {currentPage === 'analyze' && <AnalyzePage />}
      {currentPage === 'chat' && <ChatPage />}
      {currentPage === 'threats' && <ThreatLibraryPage />}
      {currentPage === 'scenarios' && <ScenariosPage />}
      {currentPage === 'risk' && <RiskScorePage />}
      {currentPage === 'password' && <PasswordGeneratorPage />}
      {currentPage === 'history' && <IncidentHistoryPage initialOpenId={selectedIncidentId} />}
      {currentPage === 'about' && <AboutPage />}
    </MainLayout>
  );
}

export default App;
