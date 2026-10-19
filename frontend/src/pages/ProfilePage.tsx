/** Profile page. */

import { useAuth } from '../context/AuthContext';
import { User, Shield, Clock } from 'lucide-react';

export default function ProfilePage() {
  const { user } = useAuth();
  if (!user) return null;

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Profile</h1>
        <p className="text-gray-500 text-sm mt-1">Your account information</p>
      </div>

      <div className="card space-y-4">
        <div className="flex items-center gap-4">
          <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
            <User className="w-8 h-8 text-white" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">{user.full_name || user.username}</h2>
            <p className="text-gray-500">@{user.username}</p>
          </div>
        </div>

        <div className="grid gap-3">
          <div className="flex justify-between py-2 border-b border-gray-800">
            <span className="text-sm text-gray-500">Email</span>
            <span className="text-sm text-white">{user.email}</span>
          </div>
          <div className="flex justify-between py-2 border-b border-gray-800">
            <span className="text-sm text-gray-500">Role</span>
            <span className="text-sm text-white uppercase flex items-center gap-2">
              <Shield className="w-3 h-3" /> {user.role}
            </span>
          </div>
          <div className="flex justify-between py-2 border-b border-gray-800">
            <span className="text-sm text-gray-500">Status</span>
            <span className={`text-sm ${user.is_active ? 'text-green-400' : 'text-red-400'}`}>
              {user.is_active ? 'Active' : 'Inactive'}
            </span>
          </div>
          <div className="flex justify-between py-2">
            <span className="text-sm text-gray-500">Member Since</span>
            <span className="text-sm text-white flex items-center gap-2">
              <Clock className="w-3 h-3" /> {new Date(user.created_at).toLocaleDateString()}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
