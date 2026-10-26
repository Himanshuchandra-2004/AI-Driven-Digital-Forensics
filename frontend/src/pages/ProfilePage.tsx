/** Profile page — highlighted glowing card over falling digits. */

import { useAuth } from '../context/AuthContext';
import { Mail, Shield, Clock, Activity } from 'lucide-react';

export default function ProfilePage() {
  const { user } = useAuth();
  if (!user) return null;
  const name = user.full_name || user.username;

  const rows = [
    { icon: Mail, label: 'Email', value: user.email },
    { icon: Shield, label: 'Role', value: <span className="uppercase">{user.role}</span> },
    { icon: Activity, label: 'Status', value: <span className={user.is_active ? 'text-green-400' : 'text-red-400'}>{user.is_active ? 'Active' : 'Inactive'}</span> },
    { icon: Clock, label: 'Member Since', value: new Date(user.created_at).toLocaleDateString() },
  ];

  return (
    <div className="max-w-xl mx-auto pt-6 space-y-6">
      <div className="text-center">
        <h1 className="page-title">Profile</h1>
        <p className="text-gray-500 text-sm mt-1">Your account information</p>
      </div>
      <div className="profile-card">
        <div className="profile-avatar">{name.charAt(0).toUpperCase()}</div>
        <h2 className="text-2xl font-bold text-white text-center mt-4">{name}</h2>
        <p className="text-center text-cyber-accent mb-6">@{user.username}</p>
        <div className="space-y-1">
          {rows.map(({ icon: Icon, label, value }) => (
            <div key={label} className="flex items-center justify-between py-3 border-b border-gray-800 last:border-0">
              <span className="flex items-center gap-2 text-sm text-gray-500"><Icon className="w-4 h-4" />{label}</span>
              <span className="text-sm text-white">{value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
