/** Register page — same glass card as Login. */

import { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ArrowRight, AtSign, Lock, Mail, User } from 'lucide-react';
import AuthShell, { AuthField } from '../components/ui/AuthShell';

export default function RegisterPage() {
  const { user, register } = useAuth();
  const [form, setForm] = useState({ username: '', email: '', password: '', fullName: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (user) return <Navigate to="/" replace />;

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await register(form.username.trim(), form.email.trim(), form.password.trim(), form.fullName.trim());
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell mode="register">
      <form onSubmit={handleSubmit} className="flex flex-col gap-3.5">
        {error && <div className="auth-error">{error}</div>}
        <AuthField icon={User} value={form.fullName} onChange={set('fullName')} placeholder="Full Name" required />
        <AuthField icon={AtSign} value={form.username} onChange={set('username')} placeholder="Username" required />
        <AuthField icon={Mail} type="email" value={form.email} onChange={set('email')} placeholder="Email" required />
        <AuthField icon={Lock} type="password" value={form.password} onChange={set('password')} placeholder="Password (min 8 characters)" required minLength={8} />
        <button type="submit" disabled={loading} className="auth-primary">
          {loading ? 'Creating account...' : 'Create Account'} <ArrowRight size={20} />
        </button>
        <p className="text-center text-sm">Already have an account? <Link to="/login" className="auth-link">Sign In</Link></p>
      </form>
    </AuthShell>
  );
}
