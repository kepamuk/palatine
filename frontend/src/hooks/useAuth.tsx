import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import type {
  AuthState,
  User,
  LoginCredentials,
  RegisterCredentials,
  AuthResponse,
} from '../types/auth'

interface AuthContextType extends AuthState {
  login: (credentials: LoginCredentials) => Promise<void>
  register: (credentials: RegisterCredentials) => Promise<void>
  logout: () => Promise<void>
  checkAuth: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [state, setState] = useState<AuthState>({
    user: null,
    token: localStorage.getItem('auth_token'),
    isLoading: true,
    isAuthenticated: false,
  })

  const apiRequest = async (url: string, options: RequestInit = {}) => {
    const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000'
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    }

    if (state.token) {
      headers.Authorization = `Bearer ${state.token}`
    }

    const response = await fetch(`${baseUrl}${url}`, {
      ...options,
      headers,
      credentials: 'include',
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Network error' }))
      throw new Error(error.error || 'Request failed')
    }

    return response.json()
  }

  const login = async (credentials: LoginCredentials) => {
    setState((prev) => ({ ...prev, isLoading: true }))
    try {
      const response: AuthResponse = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify(credentials),
      })

      localStorage.setItem('auth_token', response.token)
      setState({
        user: response.user,
        token: response.token,
        isLoading: false,
        isAuthenticated: true,
      })
    } catch (error) {
      setState((prev) => ({ ...prev, isLoading: false }))
      throw error
    }
  }

  const register = async (credentials: RegisterCredentials) => {
    setState((prev) => ({ ...prev, isLoading: true }))
    try {
      const response: AuthResponse = await apiRequest('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify(credentials),
      })

      localStorage.setItem('auth_token', response.token)
      setState({
        user: response.user,
        token: response.token,
        isLoading: false,
        isAuthenticated: true,
      })
    } catch (error) {
      setState((prev) => ({ ...prev, isLoading: false }))
      throw error
    }
  }

  const logout = async () => {
    try {
      if (state.token) {
        await apiRequest('/api/auth/logout', { method: 'POST' })
      }
    } catch (error) {
    } finally {
      localStorage.removeItem('auth_token')
      setState({
        user: null,
        token: null,
        isLoading: false,
        isAuthenticated: false,
      })
    }
  }

  const checkAuth = async () => {
    const token = localStorage.getItem('auth_token')
    if (!token) {
      setState((prev) => ({ ...prev, isLoading: false, isAuthenticated: false }))
      return
    }

    setState((prev) => ({ ...prev, token, isLoading: true }))

    try {
      const user: User = await apiRequest('/api/auth/me')
      setState({
        user,
        token,
        isLoading: false,
        isAuthenticated: true,
      })
    } catch (error) {
      localStorage.removeItem('auth_token')
      setState({
        user: null,
        token: null,
        isLoading: false,
        isAuthenticated: false,
      })
    }
  }

  useEffect(() => {
    checkAuth()
  }, [])

  const value: AuthContextType = {
    ...state,
    login,
    register,
    logout,
    checkAuth,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
