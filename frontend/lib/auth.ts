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
  if (typeof window === "undefined") {
    return;
  }
  localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access);
  localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearAuth() {
  if (typeof window === "undefined") {
    return;
  }
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function getStoredAccessToken() {
  if (typeof window === "undefined") {
    return "";
  }
  return localStorage.getItem(ACCESS_TOKEN_KEY) ?? "";
}

export function getStoredRefreshToken() {
  if (typeof window === "undefined") {
    return "";
  }
  return localStorage.getItem(REFRESH_TOKEN_KEY) ?? "";
}

export function updateStoredAccessToken(access: string) {
  if (typeof window === "undefined") {
    return;
  }
  localStorage.setItem(ACCESS_TOKEN_KEY, access);
}

export function getStoredUser(): AuthUser | null {
  if (typeof window === "undefined") {
    return null;
  }
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

export async function refreshAccessToken(apiBaseUrl: string) {
  const refresh = getStoredRefreshToken();
  if (!refresh) {
    clearAuth();
    return "";
  }

  const response = await fetch(`${apiBaseUrl}/auth/token/refresh/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh }),
  });

  if (!response.ok) {
    clearAuth();
    return "";
  }

  const payload = (await response.json()) as { access?: string };
  if (!payload.access) {
    clearAuth();
    return "";
  }

  updateStoredAccessToken(payload.access);
  return payload.access;
}
