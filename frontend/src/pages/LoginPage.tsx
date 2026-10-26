/** Login page — neon glass card over animated falling digits. */

import { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Eye, EyeOff, Lock, User, ArrowRight } from 'lucide-react';
import AuthShell, { AuthField } from '../components/ui/AuthShell';

export default function LoginPage() {
  const { user, login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (user) return <Navigate to="/" replace />;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username.trim(), password.trim());
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell mode="login">
      <form onSubmit={handleSubmit} className="flex flex-col gap-3.5">
        {error && <div className="auth-error">{error}</div>}
        <AuthField icon={User} type="text" value={username} onChange={(e) => setUsername(e.target.value)}
          placeholder="Username" required autoFocus />
        <AuthField icon={Lock} type={showPw ? 'text' : 'password'} value={password}
          onChange={(e) => setPassword(e.target.value)} placeholder="Password" required
          right={<button type="button" onClick={() => setShowPw(!showPw)} className="auth-eye">
            {showPw ? <EyeOff size={20} /> : <Eye size={20} />}</button>} />
        <div className="flex justify-between text-sm">
          <label className="flex items-center gap-2 cursor-pointer"><input type="checkbox" className="accent-cyan-400" /> Remember me</label>
          <a href="#" onClick={(e) => e.preventDefault()} className="auth-link">Forgot Password?</a>
        </div>
        <button type="submit" disabled={loading} className="auth-primary">
          {loading ? 'Signing in...' : 'Sign In'} <ArrowRight size={20} />
        </button>
        <p className="text-center text-sm">Don't have an account? <Link to="/register" className="auth-link">Register</Link></p>
      </form>
    </AuthShell>
  );
}
