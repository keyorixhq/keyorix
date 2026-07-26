import axios, { AxiosResponse } from 'axios';
import { ApiResponse, LoginResponse } from '../types';
import { getEnvConfig } from '../utils';

const config = getEnvConfig();

// Public axios instance for the credential-delivery setup flow (ADR-028). These
// endpoints are unauthenticated — the bearer is the single-use setup token in the
// URL / request body, not a session — so no Authorization header is attached.
const client = axios.create({
    baseURL: config.API_BASE_URL,
    timeout: config.API_TIMEOUT,
});

// SetupTokenInfo is the non-sensitive description the landing page renders. It
// deliberately carries no token and no secret material.
export interface SetupTokenInfo {
    purpose: string;
    email: string;
    display_name?: string;
}

function messageFromError(error: unknown, fallback: string): string {
    if (axios.isAxiosError(error)) {
        return error.response?.data?.error || error.response?.data?.message || fallback;
    }
    return fallback;
}

export const setupService = {
    /**
     * Validate a setup token without consuming it and return its description so the
     * page can render the right form. A dead link (unknown/expired/used) returns
     * 410 Gone, surfaced here as a thrown error.
     */
    async describe(token: string): Promise<SetupTokenInfo> {
        try {
            const response: AxiosResponse<ApiResponse<SetupTokenInfo>> = await client.get(
                `/auth/setup/${encodeURIComponent(token)}`
            );
            return response.data.data;
        } catch (error) {
            throw new Error(messageFromError(error, 'This setup link is no longer valid'), { cause: error });
        }
    },

    /**
     * Consume the setup token, setting the user's password. On success the response
     * is login-shaped (token + identity), landing the user logged in.
     */
    async consume(token: string, password: string): Promise<LoginResponse> {
        try {
            const response: AxiosResponse<ApiResponse<LoginResponse>> = await client.post('/auth/setup/consume', {
                token,
                password,
            });
            if (!response.data.data?.token) {
                throw new Error(response.data.message || 'Setup failed');
            }
            return response.data.data;
        } catch (error) {
            throw new Error(messageFromError(error, 'Setup failed'), { cause: error });
        }
    },
};
