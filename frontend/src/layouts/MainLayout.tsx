import React, { useState } from 'react';
import { Sidebar, PageId } from '../components/common/Sidebar';
import { Navbar } from '../components/common/Navbar';

interface MainLayoutProps {
  currentPage: PageId;
  onSelectPage: (page: PageId) => void;
  children: React.ReactNode;
}

export const MainLayout: React.FC<MainLayoutProps> = ({
  currentPage,
  onSelectPage,
  children
}) => {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen flex bg-light-bg dark:bg-cyber-bg text-light-text dark:text-cyber-text transition-colors duration-150">
      <Sidebar
        currentPage={currentPage}
        onSelectPage={onSelectPage}
        isOpenMobile={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <Navbar
          currentPage={currentPage}
          onOpenMobile={() => setMobileOpen(true)}
          onSelectPage={onSelectPage}
        />

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto animate-in fade-in duration-150">
          {children}
        </main>
      </div>
    </div>
  );
};
