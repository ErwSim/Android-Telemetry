import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api } from '../api/endpoints.ts';
import { ApiError, onUnauthorized } from '../api/client.ts';

export type AuthStatus = 'loading' | 'authed' | 'anon';

interface AuthValue {
  status: AuthStatus;
  username?: string;
  /** Message affiché sur la page de connexion (session expirée…). */
  notice?: string;
  login: (u: string, p: string) => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ status: AuthStatus; username?: string; notice?: string }>({ status: 'loading' });

  useEffect(() => {
    const ctrl = new AbortController();
    api
      .me(ctrl.signal)
      .then((m) => setState({ status: 'authed', username: m.username }))
      .catch((e: unknown) => {
        if (ctrl.signal.aborted) return;
        // 401 attendu hors session ; toute autre erreur renvoie aussi à la connexion (qui affichera l'erreur).
        const notice = e instanceof ApiError && e.status !== 401 ? e.message : undefined;
        setState(notice ? { status: 'anon', notice } : { status: 'anon' });
      });
    return () => ctrl.abort();
  }, []);

  useEffect(
    () =>
      onUnauthorized(() =>
        setState((s) => (s.status === 'authed' ? { status: 'anon', notice: 'Votre session a expiré. Reconnectez-vous.' } : s)),
      ),
    [],
  );

  const login = useCallback(async (username: string, password: string) => {
    await api.login(username, password);
    const m = await api.me();
    setState({ status: 'authed', username: m.username });
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      /* la session locale est quand même abandonnée */
    }
    setState({ status: 'anon' });
  }, []);

  const value = useMemo<AuthValue>(() => {
    const v: AuthValue = { status: state.status, login, logout };
    if (state.username) v.username = state.username;
    if (state.notice) v.notice = state.notice;
    return v;
  }, [state, login, logout]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthValue {
  const v = useContext(Ctx);
  if (!v) throw new Error('AuthProvider manquant');
  return v;
}
