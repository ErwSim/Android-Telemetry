import { useState, type FormEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/client.ts';
import { useAuth } from '../state/auth.tsx';

function messageFor(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 401) return 'Identifiant ou mot de passe incorrect.';
    if (e.status === 429) return 'Trop de tentatives. Patientez avant de réessayer.';
    return e.message;
  }
  return 'Connexion impossible.';
}

export default function Login() {
  const { status, login, notice } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const from = (loc.state as { from?: string } | null)?.from ?? '/';
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  if (status === 'authed') return <Navigate to={from.startsWith('/connexion') ? '/' : from} replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await login(username.trim(), password);
      nav(from.startsWith('/connexion') ? '/' : from, { replace: true });
    } catch (err) {
      setError(messageFor(err));
      setBusy(false);
    }
  };

  return (
    <div className="login-page">
      <form className="card login-card" onSubmit={(e) => void submit(e)} aria-labelledby="login-title">
        <div className="login-brand">
          <svg viewBox="0 0 32 32" width="36" height="36" aria-hidden="true" focusable="false">
            <rect width="32" height="32" rx="7" fill="var(--accent)" />
            <path d="M4 17h6l3-8 5 15 3-7h7" fill="none" stroke="#fff" strokeWidth="2.400" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div>
            <h1 id="login-title">Vigie</h1>
            <p className="muted">Console de télémétrie de sécurité</p>
          </div>
        </div>
        {(notice || error) && (
          <div className={`state ${error ? 'state-error' : 'state-warn'}`} role="alert">
            {error ?? notice}
          </div>
        )}
        <label className="field">
          Identifiant
          <input
            name="username"
            autoComplete="username"
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        <label className="field">
          Mot de passe
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <button type="submit" className="btn btn-primary" disabled={busy || !username || !password}>
          {busy ? 'Connexion…' : 'Se connecter'}
        </button>
      </form>
    </div>
  );
}
