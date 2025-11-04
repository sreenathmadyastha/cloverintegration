// types.ts
export interface TokenResponse {
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
    refresh_expires_in?: number;
}

// authService.ts
class AuthService {
    private accessToken: string | null = null;
    private refreshToken: string | null = null;
    private accessTokenExpiry: Date | null = null;
    private refreshPromise: Promise<string> | null = null;

    async initializeFromGuid(guidToken: string): Promise<void> {
        const response = await fetch('/api/auth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ guidToken })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error_description || 'Authentication failed');
        }

        const data: TokenResponse = await response.json();
        this.setTokens(data);
    }

    async getAccessToken(): Promise<string> {
        // If no token, throw error
        if (!this.accessToken || !this.refreshToken) {
            throw new Error('Not authenticated');
        }

        // If token is still valid (with 30 second buffer), return it
        if (this.accessTokenExpiry && this.accessTokenExpiry.getTime() > Date.now() + 30000) {
            return this.accessToken;
        }

        // If already refreshing, wait for that promise
        if (this.refreshPromise) {
            return this.refreshPromise;
        }

        // Start refresh
        this.refreshPromise = this.performRefresh();

        try {
            const token = await this.refreshPromise;
            return token;
        } finally {
            this.refreshPromise = null;
        }
    }

    private async performRefresh(): Promise<string> {
        const response = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken: this.refreshToken })
        });

        if (!response.ok) {
            // Refresh failed, clear tokens
            this.clearTokens();
            throw new Error('Session expired, please log in again');
        }

        const data: TokenResponse = await response.json();
        this.setTokens(data);
        return data.access_token;
    }

    private setTokens(data: TokenResponse): void {
        this.accessToken = data.access_token;
        this.refreshToken = data.refresh_token;
        this.accessTokenExpiry = new Date(Date.now() + data.expires_in * 1000);

        // Store refresh token securely
        // Use sessionStorage for session-based, or implement secure storage
        sessionStorage.setItem('refresh_token', data.refresh_token);
    }

    private clearTokens(): void {
        this.accessToken = null;
        this.refreshToken = null;
        this.accessTokenExpiry = null;
        sessionStorage.removeItem('refresh_token');
    }

    async logout(): Promise<void> {
        this.clearTokens();
        // Optional: Call revoke endpoint
    }

    isAuthenticated(): boolean {
        return this.refreshToken !== null;
    }
}

export const authService = new AuthService();

// apiClient.ts - Axios interceptor example
import axios from 'axios';
import { authService } from './authService';

const apiClient = axios.create({
    baseURL: '/api'
});

// Request interceptor to add access token
apiClient.interceptors.request.use(
    async (config) => {
        try {
            const token = await authService.getAccessToken();
            config.headers.Authorization = `Bearer ${token}`;
        } catch (error) {
            // Not authenticated, let request proceed without token
        }
        return config;
    },
    (error) => Promise.reject(error)
);

// Response interceptor to handle 401s
apiClient.interceptors.response.use(
    (response) => response,
    async (error) => {
        if (error.response?.status === 401 && !error.config._retry) {
            error.config._retry = true;

            try {
                // Try to refresh token
                const token = await authService.getAccessToken();
                error.config.headers.Authorization = `Bearer ${token}`;
                return apiClient.request(error.config);
            } catch (refreshError) {
                // Redirect to login
                window.location.href = '/login';
                return Promise.reject(refreshError);
            }
        }

        return Promise.reject(error);
    }
);

export default apiClient;