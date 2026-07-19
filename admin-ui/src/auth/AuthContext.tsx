import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { api } from '../api/client'
import {
  clearSession,
  getToken,
  getUsername,
  setSession,
} from './session'

type AuthState = {
  token: string | null
  username: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => getToken())
  const [username, setUsername] = useState<string | null>(() => getUsername())

  const login = useCallback(async (user: string, password: string) => {
    const res = await api.login(user, password)
    setSession(res.token, res.username)
    setToken(res.token)
    setUsername(res.username)
  }, [])

  const logout = useCallback(() => {
    clearSession()
    setToken(null)
    setUsername(null)
  }, [])

  const value = useMemo(
    () => ({ token, username, login, logout }),
    [token, username, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth requires AuthProvider')
  return ctx
}
