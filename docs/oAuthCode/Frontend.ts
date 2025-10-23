### 2. package.json
    ```json
{
  "name": "your-app",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "lint": "eslint . --ext ts,tsx --report-unused-disable-directives --max-warnings 0",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.43",
    "@types/react-dom": "^18.2.17",
    "@typescript-eslint/eslint-plugin": "^6.14.0",
    "@typescript-eslint/parser": "^6.14.0",
    "@vitejs/plugin-react": "^4.2.1",
    "eslint": "^8.55.0",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-react-refresh": "^0.4.5",
    "typescript": "^5.2.2",
    "vite": "^5.0.8"
  }
}
```

### 3. tsconfig.json
    ```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

### 4. vite.config.ts
    ```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false,
      }
    }
  }
})
```

### 5. src / types / auth.types.ts
    ```typescript
export interface TokenResponse {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  sessionExpiresAt: string;
  permissions: string[];
  sponsorId: string;
  subscriberId: string;
  tokenType: string;
}

export interface SessionInfoResponse {
  remainingSeconds: number;
  expiresAt: string;
  permissions: string[];
  sponsorId: string;
  subscriberId: string;
}

export interface AuthContextType {
  isAuthenticated: boolean;
  permissions: string[];
  sponsorId: string | null;
  subscriberId: string | null;
  isLoading: boolean;
  login: (token: string) => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => string | null;
  hasPermission: (permission: string) => boolean;
  getRemainingSessionTime: () => number | null;
}
```

### 6. src / services / authService.ts
    ```typescript
import { TokenResponse } from '../types/auth.types';

class AuthService {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private tokenExpiryTime: number | null = null;
  private sessionExpiryTime: number | null = null;
  private permissions: string[] = [];
  private sponsorId: string | null = null;
  private subscriberId: string | null = null;
  private refreshTimeout: NodeJS.Timeout | null = null;
  private readonly API_BASE_URL = '/api';

  async authenticateWithToken(token: string): Promise<void> {
    try {
      const response = await fetch(`${ this.API_BASE_URL } /auth/authenticate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ token }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Authentication failed');
      }

      const data: TokenResponse = await response.json();
      this.setTokens(data);
    } catch (error) {
      console.error('Authentication error:', error);
      throw error;
    }
  }

  private setTokens(data: TokenResponse): void {
    this.accessToken = data.accessToken;
    this.refreshToken = data.refreshToken || null;
    this.permissions = data.permissions || [];
    this.sponsorId = data.sponsorId;
    this.subscriberId = data.subscriberId;
    
    // Calculate access token expiry (subtract 1 minute as buffer)
    this.tokenExpiryTime = Date.now() + (data.expiresIn - 60) * 1000;
    
    // Store session expiration
    this.sessionExpiryTime = new Date(data.sessionExpiresAt).getTime();
    
    // Schedule automatic refresh
    this.scheduleTokenRefresh();
  }

  private scheduleTokenRefresh(): void {
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
    }

    if (this.tokenExpiryTime && this.sessionExpiryTime) {
      const now = Date.now();
      
      // Check if session has expired
      if (now >= this.sessionExpiryTime) {
        console.warn('Session has expired');
        this.logout();
        return;
      }
      
      const timeUntilRefresh = this.tokenExpiryTime - now;
      const timeUntilSessionExpiry = this.sessionExpiryTime - now;
      
      // Don't schedule refresh if session expires before next refresh
      if (timeUntilRefresh >= timeUntilSessionExpiry) {
        console.warn('Session will expire before next refresh');
        this.refreshTimeout = setTimeout(() => {
          this.logout();
        }, timeUntilSessionExpiry);
        return;
      }
      
      this.refreshTimeout = setTimeout(() => {
        this.refreshAccessToken();
      }, Math.max(timeUntilRefresh, 0));
    }
  }

  async refreshAccessToken(): Promise<void> {
    try {
      // Check if session has expired
      if (this.sessionExpiryTime && Date.now() >= this.sessionExpiryTime) {
        throw new Error('Session expired');
      }

      const response = await fetch(`${ this.API_BASE_URL } /auth/refresh`, {
        method: 'POST',
        credentials: 'include',
        headers: this.refreshToken ? {
          'X-Refresh-Token': this.refreshToken
        } : {}
      });

      if (!response.ok) {
        throw new Error('Token refresh failed');
      }

      const data: TokenResponse = await response.json();
      this.setTokens(data);
    } catch (error) {
      console.error('Token refresh error:', error);
      this.logout();
      throw error;
    }
  }

  getAccessToken(): string | null {
    return this.accessToken;
  }

  getPermissions(): string[] {
    return [...this.permissions];
  }

  hasPermission(permission: string): boolean {
    return this.permissions.includes(permission);
  }

  getSponsorId(): string | null {
    return this.sponsorId;
  }

  getSubscriberId(): string | null {
    return this.subscriberId;
  }

  getRemainingSessionTime(): number | null {
    if (!this.sessionExpiryTime) return null;
    const remaining = this.sessionExpiryTime - Date.now();
    return remaining > 0 ? remaining : 0;
  }

  async logout(): Promise<void> {
    try {
      if (this.accessToken) {
        await fetch(`${ this.API_BASE_URL } /auth/logout`, {
          method: 'POST',
          credentials: 'include',
          headers: {
            Authorization: `Bearer ${ this.accessToken } `
          }
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      this.accessToken = null;
      this.refreshToken = null;
      this.tokenExpiryTime = null;
      this.sessionExpiryTime = null;
      this.permissions = [];
      this.sponsorId = null;
      this.subscriberId = null;
      
      if (this.refreshTimeout) {
        clearTimeout(this.refreshTimeout);
      }
    }
  }

  isAuthenticated(): boolean {
    if (!this.accessToken) return false;
    if (this.sessionExpiryTime && Date.now() >= this.sessionExpiryTime) {
      this.logout();
      return false;
    }
    return true;
  }
}

export const authService = new AuthService();
```

### 7. src / services / apiClient.ts
    ```typescript
import { authService } from './authService';

export interface ApiClientOptions extends RequestInit {
  skipAuth?: boolean;
}

export const apiClient = async (
  url: string, 
  options: ApiClientOptions = {}
): Promise<Response> => {
  const { skipAuth = false, ...fetchOptions } = options;
  const token = authService.getAccessToken();
  
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...fetchOptions.headers,
  };

  if (!skipAuth && token) {
    headers['Authorization'] = `Bearer ${ token } `;
  }

  let response = await fetch(url, {
    ...fetchOptions,
    headers,
    credentials: 'include',
  });

  // Handle 401 - try to refresh token
  if (response.status === 401 && !skipAuth) {
    try {
      await authService.refreshAccessToken();
      
      // Retry the request with new token
      const newToken = authService.getAccessToken();
      if (newToken) {
        headers['Authorization'] = `Bearer ${ newToken } `;
        response = await fetch(url, {
          ...fetchOptions,
          headers,
          credentials: 'include',
        });
      }
    } catch (error) {
      // Refresh failed, redirect to login
      authService.logout();
      window.location.href = '/login';
      throw error;
    }
  }

  return response;
};
```

### 8. src / context / AuthContext.tsx
    ```typescript
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { authService } from '../services/authService';
import { AuthContextType } from '../types/auth.types';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [sponsorId, setSponsorId] = useState<string | null>(null);
  const [subscriberId, setSubscriberId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check if user is already authenticated on mount
    const checkAuth = () => {
      const authenticated = authService.isAuthenticated();
      setIsAuthenticated(authenticated);
      
      if (authenticated) {
        setPermissions(authService.getPermissions());
        setSponsorId(authService.getSponsorId());
        setSubscriberId(authService.getSubscriberId());
      }
      
      setIsLoading(false);
    };

    checkAuth();
  }, []);

  const login = async (token: string) => {
    try {
      setIsLoading(true);
      await authService.authenticateWithToken(token);
      setIsAuthenticated(true);
      setPermissions(authService.getPermissions());
      setSponsorId(authService.getSponsorId());
      setSubscriberId(authService.getSubscriberId());
    } catch (error) {
      setIsAuthenticated(false);
      setPermissions([]);
      setSponsorId(null);
      setSubscriberId(null);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      setIsLoading(true);
      await authService.logout();
    } finally {
      setIsAuthenticated(false);
      setPermissions([]);
      setSponsorId(null);
      setSubscriberId(null);
      setIsLoading(false);
    }
  };

  const getAccessToken = () => {
    return authService.getAccessToken();
  };

  const hasPermission = (permission: string): boolean => {
    return authService.hasPermission(permission);
  };

  const getRemainingSessionTime = (): number | null => {
    return authService.getRemainingSessionTime();
  };

  return (
    <AuthContext.Provider value={{ 
      isAuthenticated, 
      permissions,
      sponsorId,
      subscriberId,
      isLoading,
      login, 
      logout, 
      getAccessToken,
      hasPermission,
      getRemainingSessionTime
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

### 9. src / components / AuthCallback.tsx
    ```typescript
import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export const AuthCallback: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { login } = useAuth();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const authenticateUser = async () => {
      const token = searchParams.get('token');
      
      if (!token) {
        setError('No authentication token provided');
        return;
      }

      try {
        await login(token);
        navigate('/dashboard', { replace: true });
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Authentication failed');
        console.error('Authentication error:', err);
      }
    };

    authenticateUser();
  }, [searchParams, login, navigate]);

  if (error) {
    return (
      <div style={{ 
        display: 'flex', 
        flexDirection: 'column', 
        alignItems: 'center', 
        justifyContent: 'center', 
        height: '100vh',
        padding: '20px'
      }}>
        <h2 style={{ color: '#d32f2f' }}>Authentication Failed</h2>
        <p>{error}</p>
        <button 
          onClick={() => window.location.href = '/login'}
          style={{
            marginTop: '20px',
            padding: '10px 20px',
            backgroundColor: '#1976d2',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Back to Login
        </button>
      </div>
    );
  }

  return (
    <div style={{ 
      display: 'flex', 
      alignItems: 'center', 
      justifyContent: 'center', 
      height: '100vh' 
    }}>
      <div style={{ textAlign: 'center' }}>
        <h2>Authenticating...</h2>
        <p>Please wait while we log you in.</p>
      </div>
    </div>
  );
};
```

### 10. src / components / ProtectedRoute.tsx
    ```typescript
import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredPermission?: string;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  requiredPermission 
}) => {
  const { isAuthenticated, hasPermission, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center', 
        height: '100vh' 
      }}>
        <div>Loading...</div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requiredPermission && !hasPermission(requiredPermission)) {
    return <Navigate to="/unauthorized" replace />;
  }

  return <>{children}</>;
};
```

### 11. src / components / SessionTimer.tsx
    ```typescript
import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';

export const SessionTimer: React.FC = () => {
  const { getRemainingSessionTime, logout } = useAuth();
  const [remainingTime, setRemainingTime] = useState<number | null>(null);

  useEffect(() => {
    const updateTimer = () => {
      const time = getRemainingSessionTime();
      setRemainingTime(time);

      if (time !== null && time <= 0) {
        logout();
      }
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);

    return () => clearInterval(interval);
  }, [getRemainingSessionTime, logout]);

  if (remainingTime === null) return null;

  const minutes = Math.floor(remainingTime / 60000);
  const seconds = Math.floor((remainingTime % 60000) / 1000);

  const isWarning = remainingTime < 300000; // Less than 5 minutes

  return (
    <div style={{
      position: 'fixed',
      top: '10px',
      right: '10px',
      padding: '10px 15px',
      backgroundColor: isWarning ? '#fff3cd' : '#d1ecf1',
      border: `1px solid ${ isWarning ? '#ffc107' : '#bee5eb' } `,
      borderRadius: '4px',
      fontSize: '14px',
      color: isWarning ? '#856404' : '#0c5460',
      zIndex: 1000
    }}>
      {isWarning && '⚠️ '} Session expires in: {minutes}m {seconds}s
    </div>
  );
};
```

### 12. src / components / Dashboard.tsx
    ```typescript
import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { SessionTimer } from './SessionTimer';
import { apiClient } from '../services/apiClient';

export const Dashboard: React.FC = () => {
  const { logout, permissions, sponsorId, subscriberId } = useAuth();
  const [dashboardData, setDashboardData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const response = await apiClient('/api/dashboard');
        
        if (!response.ok) {
          throw new Error('Failed to fetch dashboard data');
        }

        const data = await response.json();
        setDashboardData(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An error occurred');
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, []);

  const handleLogout = async () => {
    await logout();
    window.location.href = '/login';
  };

  if (loading) {
    return <div style={{ padding: '20px' }}>Loading dashboard...</div>;
  }

  return (
    <div style={{ padding: '20px', maxWidth: '1200px', margin: '0 auto' }}>
      <SessionTimer />
      
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        marginBottom: '30px'
      }}>
        <h1>Dashboard</h1>
        <button 
          onClick={handleLogout}
          style={{
            padding: '10px 20px',
            backgroundColor: '#d32f2f',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Logout
        </button>
      </div>

      <div style={{ 
        backgroundColor: '#f5f5f5', 
        padding: '20px', 
        borderRadius: '8px',
        marginBottom: '20px'
      }}>
        <h3>Session Information</h3>
        <p><strong>Sponsor ID:</strong> {sponsorId}</p>
        <p><strong>Subscriber ID:</strong> {subscriberId}</p>
        <p><strong>Permissions:</strong> {permissions.join(', ') || 'None'}</p>
      </div>

      {error && (
        <div style={{
          padding: '15px',
          backgroundColor: '#f8d7da',
          border: '1px solid #f5c6cb',
          borderRadius: '4px',
          color: '#721c24',
          marginBottom: '20px'
        }}>
          Error: {error}
        </div>
      )}

      <div style={{ 
        backgroundColor: 'white', 
        padding: '20px', 
        borderRadius: '8px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <h2>Welcome to Your Dashboard</h2>
        <p>You have successfully authenticated and can access protected resources.</p>
        
        {dashboardData && (
          <pre style={{ 
            backgroundColor: '#f5f5f5', 
            padding: '15px', 
            borderRadius: '4px',
            overflow: 'auto'
          }}>
            {JSON.stringify(dashboardData, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
};
```

### 13. src / components / Reports.tsx
    ```typescript
import React from 'react';
import { useAuth } from '../context/AuthContext';
import { SessionTimer } from './SessionTimer';

export const Reports: React.FC = () => {
  const { logout, hasPermission } = useAuth();

  const handleLogout = async () => {
    await logout();
    window.location.href = '/login';
  };

  if (!hasPermission('CanViewReports')) {
    return (
      <div style={{ padding: '20px' }}>
        <h2>Access Denied</h2>
        <p>You don't have permission to view reports.</p>
      </div>
    );
  }

  return (
    <div style={{ padding: '20px', maxWidth: '1200px', margin: '0 auto' }}>
      <SessionTimer />
      
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        marginBottom: '30px'
      }}>
        <h1>Reports</h1>
        <button 
          onClick={handleLogout}
          style={{
            padding: '10px 20px',
            backgroundColor: '#d32f2f',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Logout
        </button>
      </div>

      <div style={{ 
        backgroundColor: 'white', 
        padding: '20px', 
        borderRadius: '8px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <h2>Reports Dashboard</h2>
        <p>This is a protected reports page that requires the 'CanViewReports' permission.</p>
      </div>
    </div>
  );
};
```

### 14. src / App.tsx
    ```typescript
import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { AuthCallback } from './components/AuthCallback';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Dashboard } from './components/Dashboard';
import { Reports } from './components/Reports';

const LoginPage: React.FC = () => {
  return (
    <div style={{ 
      display: 'flex', 
      flexDirection: 'column',
      alignItems: 'center', 
      justifyContent: 'center', 
      height: '100vh',
      backgroundColor: '#f5f5f5'
    }}>
      <div style={{
        backgroundColor: 'white',
        padding: '40px',
        borderRadius: '8px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        textAlign: 'center'
      }}>
        <h1>Welcome</h1>
        <p>Please use the authentication link provided to access the application.</p>
        <p style={{ 
          marginTop: '20px', 
          padding: '10px', 
          backgroundColor: '#e3f2fd', 
          borderRadius: '4px',
          fontSize: '14px'
        }}>
          Format: dashboardurl.com/auth?token=&lt;your-token&gt;
        </p>
      </div>
    </div>
  );
};

const UnauthorizedPage: React.FC = () => {
  return (
    <div style={{ 
      display: 'flex', 
      flexDirection: 'column',
      alignItems: 'center', 
      justifyContent: 'center', 
      height: '100vh',
      backgroundColor: '#f5f5f5'
    }}>
      <div style={{
        backgroundColor: 'white',
        padding: '40px',
        borderRadius: '8px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        textAlign: 'center'
      }}>
        <h1 style={{ color: '#d32f2f' }}>Access Denied</h1>
        <p>You don't have permission to access this resource.</p>
        <button 
          onClick={() => window.location.href = '/dashboard'}
          style={{
            marginTop: '20px',
            padding: '10px 20px',
            backgroundColor: '#1976d2',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Go to Dashboard
        </button>
      </div>
    </div>
  );
};

const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/auth" element={<AuthCallback />} />
          <Route path="/unauthorized" element={<UnauthorizedPage />} />
          
          <Route 
            path="/dashboard" 
            element={
              <ProtectedRoute requiredPermission="CanAccessDashboard">
                <Dashboard />
              </ProtectedRoute>
            } 
          />
          
          <Route 
            path="/reports" 
            element={
              <ProtectedRoute requiredPermission="CanViewReports">
                <Reports />
              </ProtectedRoute>
            } 
          />
          
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
```

### 15. src / main.tsx
    ```typescript
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

ReactDOM.create