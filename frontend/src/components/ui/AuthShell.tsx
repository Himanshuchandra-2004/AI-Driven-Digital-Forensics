/** Shared glowing glass card for Login / Register (matches the design mock). */
import type { InputHTMLAttributes, ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Link } from 'react-router-dom';
import MatrixRain from './MatrixRain';
import ThemeToggle from './ThemeToggle';
import Logo from './Logo';

export function AuthField({ icon: Icon, right, ...props }: { icon: LucideIcon; right?: ReactNode } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="auth-field">
      <Icon size={20} />
      <input {...props} />
      {right}
    </label>
  );
}

export default function AuthShell({ mode, children }: { mode: 'login' | 'register'; children: ReactNode }) {
  return (
    <div className="auth-page">
      <MatrixRain />
      <div className="fixed top-4 right-5 z-20"><ThemeToggle /></div>
      <div className="auth-card">
        <div className="flex justify-center"><Logo size={118} /></div>
        <h1 className="auth-title">AI-POWERED<br />DIGITAL FORENSICS</h1>
        <div className="auth-net">NETWORK FORENSICS</div>
        <p className="auth-tag">Uncover. Analyze. Secure.</p>
        <div className="auth-seg">
          <Link to="/login" className={mode === 'login' ? 'on' : ''}>Login</Link>
          <Link to="/register" className={mode === 'register' ? 'on' : ''}>Register</Link>
        </div>
        {children}
      </div>
    </div>
  );
}
