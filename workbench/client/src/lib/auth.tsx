import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, setCsrf, setUnauthorizedHandler } from './api';
import type { PublicUser } from '@shared/types';

interface Session {
  user: PublicUser;
  csrf: string;
  permissions: string[];
  mustChangePassword: boolean;
  environment: 'demonstration' | 'production';
}

interface AuthCtx {
  session: Session | null;
  loading: boolean;
  login: (u: string, p: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (perm: string) => boolean;
  users: PublicUser[];
  refreshUsers: () => Promise<void>;
  userName: (id: string | undefined) => string;
  markPasswordChanged: () => void;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [users, setUsers] = useState<PublicUser[]>([]);

  const refreshUsers = useCallback(async () => {
    setUsers(await api.get<PublicUser[]>('/users'));
  }, []);

  const accept = useCallback(async (s: Session) => {
    setCsrf(s.csrf);
    setSession(s);
    try {
      setUsers(await api.get<PublicUser[]>('/users'));
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => setSession(null));
    api.get<Session | null>('/auth/session').then((s) => (s ? accept(s) : setSession(null))).catch(() => setSession(null)).finally(() => setLoading(false));
  }, [accept]);

  const login = async (username: string, password: string) => {
    await accept(await api.post<Session>('/auth/login', { username, password }));
  };
  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      setSession(null);
    }
  };
  const can = (perm: string) => !!session?.permissions.includes(perm);
  const userName = (id: string | undefined) => users.find((u) => u.id === id)?.displayName ?? (id === 'system' ? 'System' : id ? 'Unknown user' : '—');
  const markPasswordChanged = () => setSession((s) => (s ? { ...s, mustChangePassword: false } : s));

  return <Ctx.Provider value={{ session, loading, login, logout, can, users, refreshUsers, userName, markPasswordChanged }}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const c = useContext(Ctx);
  if (!c) throw new Error('AuthProvider missing');
  return c;
}
