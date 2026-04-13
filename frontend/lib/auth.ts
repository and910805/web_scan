export const ACCESS_TOKEN_KEY = "weakscan_access_token";
export const REFRESH_TOKEN_KEY = "weakscan_refresh_token";
export const USER_KEY = "weakscan_user";

export type AuthUser = {
  id: number;
  username: string;
  email: string;
  credits: number;
  auth_provider: string;
};

export function storeAuth(tokens: { access: string; refresh: string }, user: AuthUser) {
  localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access);
  localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearAuth() {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function getStoredAccessToken() {
  return localStorage.getItem(ACCESS_TOKEN_KEY) ?? "";
}

export function getStoredUser(): AuthUser | null {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
}
