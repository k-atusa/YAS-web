import { API_BASE } from "./config";
import type { AccountPayload, AccountRecord, ContactPayload, ContactRecord } from "./types";

export async function signup(username: string, password: string): Promise<{ id: string; username: string }> {
  const response = await fetch(`${API_BASE}/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to sign up");
  }

  return response.json();
}

export async function login(username: string, password: string): Promise<{ token: string; user: { id: string; username: string } }> {
  const response = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to log in");
  }

  return response.json();
}

export async function saveAccount(payload: AccountPayload, token?: string): Promise<{ id: string; createdAt: string }> {
  const response = await fetch(`${API_BASE}/accounts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to save account");
  }

  return response.json();
}

export async function getAccountByUsername(username: string): Promise<AccountRecord | null> {
  const response = await fetch(`${API_BASE}/accounts/username/${encodeURIComponent(username)}`);

  if (response.status === 404) return null;

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to fetch account");
  }

  return response.json();
}

export async function listContacts(token: string): Promise<ContactRecord[]> {
  const response = await fetch(`${API_BASE}/contacts`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (response.status === 401) {
    throw new Error("TOKEN_EXPIRED");
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to fetch contacts");
  }

  return response.json();
}

export async function createContact(payload: ContactPayload, token: string): Promise<ContactRecord> {
  const response = await fetch(`${API_BASE}/contacts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  });

  if (response.status === 401) {
    throw new Error("TOKEN_EXPIRED");
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to save contact");
  }

  return response.json();
}

export async function deleteContact(id: string, token: string): Promise<void> {
  const response = await fetch(`${API_BASE}/contacts/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });

  if (response.status === 401) {
    throw new Error("TOKEN_EXPIRED");
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to delete contact");
  }
}
