/** Sidebar navigation + main layout wrapper with per-page animated backgrounds. */

import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import ThemeToggle from '../ui/ThemeToggle';
import NetworkBg from '../ui/NetworkBg';
import MatrixRain from '../ui/MatrixRain';
import CasesBackdrop from '../ui/CasesBackdrop';

export default function Layout() {
  const { pathname } = useLocation();
  const bg =
    pathname === '/' ? <NetworkBg /> :
    pathname === '/cases' ? <CasesBackdrop /> :
    pathname === '/profile' ? <MatrixRain /> : null;
  return (
    <div className="flex h-screen overflow-hidden relative">
      {bg}
      <Sidebar />
      <main className="flex-1 overflow-y-auto relative z-10">
        <div className="sticky top-0 z-20 flex justify-end px-6 pt-4 pointer-events-none">
          <div className="pointer-events-auto"><ThemeToggle /></div>
        </div>
        <div className="p-6 pt-2 max-w-[1600px] mx-auto animate-fade-in">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
