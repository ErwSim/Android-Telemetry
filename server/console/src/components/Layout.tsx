import { useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../state/auth.tsx';
import { useDevice } from '../state/device.tsx';
import { useTheme } from '../state/theme.tsx';
import { fmtRelative } from '../lib/format.ts';
import { ErrorBox, Loading } from './ui.tsx';

const NAV = [
  { to: '/', label: "Vue d'ensemble", end: true, icon: 'M3 10.5 12 3l9 7.5V21h-6v-6H9v6H3z' },
  { to: '/detections', label: 'Détections', icon: 'M15.500 14h-.8l-.3-.3A6.500 6.500 0 1 0 14 15.500l.3.3v.8l5 5 1.500-1.500zm-6 0a4.500 4.500 0 1 1 0-9 4.500 4.500 0 0 1 0 9z' },
  { to: '/carte', label: 'Carte', icon: 'M12 2a7 7 0 0 0-7 7c0 5 7 13 7 13s7-8 7-13a7 7 0 0 0-7-7zm0 9.5A2.5 2.5 0 1 1 12 6a2.5 2.5 0 0 1 0 5.500z' },
  { to: '/evenements', label: 'Événements', icon: 'M4 5h16v2H4zm0 6h16v2H4zm0 6h10v2H4z' },
  { to: '/reseau', label: 'Réseau', icon: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zm0 2c1 1.500 1.700 3.300 1.900 5h-3.800C10.300 8.300 11 6.500 12 5zM5.300 11h3c.1 1 .3 2 .6 3H6.200a7 7 0 0 1-.9-3zm3.600 5c.4 1.200.9 2.200 1.500 3a7 7 0 0 1-3.300-3zm6.200 0h1.800a7 7 0 0 1-3.300 3c.6-.8 1.100-1.800 1.500-3z' },
  { to: '/pistage', label: 'Pistage', icon: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zm-1-6v3.100A7 7 0 0 0 5.100 11H2v2h3.100A7 7 0 0 0 11 18.900V22h2v-3.100a7 7 0 0 0 5.900-5.900H22v-2h-3.100A7 7 0 0 0 13 5.100V2z' },
  { to: '/applications', label: 'Applications', icon: 'M4 4h7v7H4zm9 0h7v7h-7zM4 13h7v7H4zm9 0h7v7h-7z' },
  { to: '/securite', label: 'Sécurité', icon: 'M12 2 4 5v6c0 5 3.400 9.300 8 11 4.600-1.700 8-6 8-11V5z' },
  { to: '/commandes', label: 'Commandes', icon: 'M7 2h10a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zm0 3v12h10V5zm5 14.500a1 1 0 1 0 0 2 1 1 0 0 0 0-2z' },
  { to: '/alertes', label: 'Alertes', icon: 'M12 22a2.500 2.500 0 0 0 2.500-2.500h-5A2.500 2.500 0 0 0 12 22zm7-6V11a7 7 0 0 0-5.500-6.800V3a1.500 1.500 0 0 0-3 0v1.200A7 7 0 0 0 5 11v5l-2 2v1h18v-1z' },
];

function Icon({ d }: { d: string }) {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d={d} fill="currentColor" />
    </svg>
  );
}

function ThemeButton() {
  const { mode, cycle } = useTheme();
  const label = mode === 'auto' ? 'Thème : automatique' : mode === 'light' ? 'Thème : clair' : 'Thème : sombre';
  return (
    <button type="button" className="btn btn-icon" onClick={cycle} title={`${label} (cliquer pour changer)`} aria-label={`${label}. Changer de thème`}>
      <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false">
        {mode === 'dark' ? (
          <path d="M20 14.500A8 8 0 0 1 9.500 4 8 8 0 1 0 20 14.500z" fill="currentColor" />
        ) : mode === 'light' ? (
          <g fill="currentColor">
            <circle cx="12" cy="12" r="4.500" />
            <path d="M11 1h2v3h-2zm0 19h2v3h-2zM1 11h3v2H1zm19 0h3v2h-3zM4.200 5.600l1.400-1.400 2.100 2.100-1.400 1.400zm12.100 12.100 1.400-1.400 2.100 2.100-1.400 1.400zM5.600 19.800l-1.400-1.400 2.100-2.100 1.400 1.400zM17.700 7.700l-1.400-1.400 2.100-2.100 1.400 1.400z" />
          </g>
        ) : (
          <g fill="currentColor">
            <path d="M12 3a9 9 0 1 0 0 18z" />
            <path d="M12 3a9 9 0 0 1 0 18z" fillOpacity=".35" />
          </g>
        )}
      </svg>
      <span className="theme-text">{mode === 'auto' ? 'Auto' : mode === 'light' ? 'Clair' : 'Sombre'}</span>
    </button>
  );
}

export default function Layout() {
  const { username, logout } = useAuth();
  const { devices, device, setDeviceId, loading, error, reload } = useDevice();
  const [open, setOpen] = useState(false);

  return (
    <div className="shell">
      <a className="skip" href="#main">
        Aller au contenu
      </a>
      <header className="topbar">
        <button
          type="button"
          className="btn btn-icon menu-btn"
          aria-expanded={open}
          aria-controls="nav"
          aria-label="Menu"
          onClick={() => setOpen((o) => !o)}
        >
          <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false">
            <path d="M3 6h18v2H3zm0 5h18v2H3zm0 5h18v2H3z" fill="currentColor" />
          </svg>
        </button>
        <div className="brand">
          <svg viewBox="0 0 32 32" width="24" height="24" aria-hidden="true" focusable="false">
            <rect width="32" height="32" rx="7" fill="var(--accent)" />
            <path d="M4 17h6l3-8 5 15 3-7h7" fill="none" stroke="#fff" strokeWidth="2.400" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          Vigie
        </div>
        <div className="topbar-spacer" />
        {devices.length > 0 && (
          <label className="device-select">
            <span className="sr-only">Appareil</span>
            <select value={device?.device_id ?? ''} onChange={(e) => setDeviceId(e.target.value)} aria-label="Appareil">
              {devices.map((d) => (
                <option key={d.device_id} value={d.device_id}>
                  {d.name || d.device_id}
                  {d.revoked ? ' (révoqué)' : ''}
                </option>
              ))}
            </select>
          </label>
        )}
        {device && (
          <span className="topbar-seen" title="Dernier contact">
            <span className={`dot ${isFresh(device.last_seen) ? 'dot-ok' : 'dot-bad'}`} aria-hidden="true" />
            {device.last_seen ? fmtRelative(device.last_seen) : 'jamais vu'}
          </span>
        )}
        <ThemeButton />
        <button type="button" className="btn btn-sm" onClick={() => void logout()} title={username ? `Connecté : ${username}` : undefined}>
          Déconnexion
        </button>
      </header>
      <nav id="nav" className={`sidenav${open ? ' is-open' : ''}`} aria-label="Navigation principale">
        <ul>
          {NAV.map((n) => (
            <li key={n.to}>
              <NavLink to={n.to} end={n.end ?? false} onClick={() => setOpen(false)} className={({ isActive }) => `nav-link${isActive ? ' is-active' : ''}`}>
                <Icon d={n.icon} />
                {n.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <main id="main" className="main" tabIndex={-1}>
        {loading && devices.length === 0 && !error ? (
          <Loading label="Chargement des appareils…" />
        ) : error && devices.length === 0 ? (
          <ErrorBox message={error.message} onRetry={reload} />
        ) : devices.length === 0 ? (
          <div className="state state-empty">
            <strong>Aucun appareil enrôlé.</strong> Créez-en un avec <code>vigie-collector enroll</code> sur le serveur.
          </div>
        ) : (
          <Outlet />
        )}
      </main>
    </div>
  );
}

function isFresh(ts: string | undefined): boolean {
  if (!ts) return false;
  const t = new Date(ts).getTime();
  return Number.isFinite(t) && Date.now() - t < 35 * 60_000;
}
