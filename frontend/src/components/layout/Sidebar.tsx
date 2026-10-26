/** Sidebar navigation with forensic-themed styling. */

import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import {
  LayoutDashboard, FolderOpen, Shield, Cpu, User, LogOut, Zap, ScrollText
} from 'lucide-react';
import { demoApi } from '../../api/client';
import { useState } from 'react';
import Logo from '../ui/Logo';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/cases', icon: FolderOpen, label: 'Cases' },
  { to: '/models', icon: Cpu, label: 'Models' },
  { to: '/audit-logs', icon: ScrollText, label: 'Audit Logs', adminOnly: true },
  { to: '/profile', icon: User, label: 'Profile' },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [demoLoading, setDemoLoading] = useState(false);

  const handleDemo = async () => {
    setDemoLoading(true);
    try {
      const res = await demoApi.load();
      navigate(`/cases/${res.data.case_id}`);
    } catch (err) {
      console.error('Demo failed:', err);
    } finally {
      setDemoLoading(false);
    }
  };

  return (
    <aside className="w-64 bg-cyber-dark/90 backdrop-blur-md border-r border-cyber-border flex flex-col h-full relative z-10">
      {/* Logo */}
      <div className="p-5 border-b border-cyber-border">
        <div className="flex items-center gap-3">
          <Logo size={40} />
          <div>
            <h1 className="text-sm font-bold text-white tracking-wide">AI Forensics</h1>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest">Network Analysis</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-1">
        {navItems
          .filter((item) => !item.adminOnly || user?.role === 'admin')
          .map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'active' : ''}`
              }
            >
              <item.icon className="w-4 h-4" />
              <span>{item.label}</span>
              {item.adminOnly && (
                <span className="ml-auto text-[9px] uppercase px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                  Admin
                </span>
              )}
            </NavLink>
          ))}

        {/* Demo button */}
        <button
          onClick={handleDemo}
          disabled={demoLoading}
          className="nav-link w-full text-left text-amber-400 hover:text-amber-300 hover:bg-amber-500/10 mt-4 border border-amber-500/20"
        >
          <Zap className="w-4 h-4" />
          {demoLoading ? 'Loading Demo...' : 'Load Demo Case'}
        </button>
      </nav>

      {/* User */}
      <div className="p-4 border-t border-cyber-border">
        <div className="flex items-center justify-between">
          <div className="min-w-0">
            <p className="text-sm font-medium text-white truncate">{user?.full_name || user?.username}</p>
            <p className="text-xs text-gray-500 uppercase">{user?.role}</p>
          </div>
          <button onClick={logout} className="p-2 text-gray-500 hover:text-red-400 transition-colors" title="Logout">
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
