import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import { AuthProvider } from './context/AuthContext'
import './index.css'

// Fresh browser session -> always show the login page first (clears any stale saved login)
if (!sessionStorage.getItem('session_started')) {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  sessionStorage.setItem('session_started', '1');
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
