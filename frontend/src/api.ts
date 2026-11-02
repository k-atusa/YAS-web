import { API_BASE } from "./config";
import type {
  AccountPayload,
  AccountRecord,
  AccountVault,
  ContactPayload,
  ContactRecord,
  PasskeyCredentialItem,
  WrappedMasterKey,
} from "./types";

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

export async function login(
  username: string,
  password: string
): Promise<{ token: string; user: { id: string; username: string }; r0Salt: string; hasPasskey?: boolean }> {
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

export async function verifyPassword(
  token: string,
  password: string
): Promise<{ token: string; expiresAt: string; r0Salt: string; verified: boolean }> {
  const response = await fetch(`${API_BASE}/auth/verify-password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ password }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "비밀번호 인증에 실패했습니다");
  }

  return response.json();
}

export async function deleteAccount(token: string, password: string): Promise<void> {
  const response = await fetch(`${API_BASE}/auth/delete-account`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ password }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "계정 탈퇴에 실패했습니다");
  }
}

export async function getMyPrivateKeyVault(
  token: string,
  verificationToken?: string
): Promise<AccountVault> {
  const response = await fetch(`${API_BASE}/accounts/me/vault`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(verificationToken ? { "X-Verification-Token": verificationToken } : {}),
    },
    body: JSON.stringify(verificationToken ? { verificationToken } : {}),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "개인키 암호화 데이터 조회에 실패했습니다");
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

// ==================== WebAuthn API ====================

export async function listWebAuthnCredentials(token: string): Promise<PasskeyCredentialItem[]> {
  const response = await fetch(`${API_BASE}/webauthn/credentials`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "패스키 목록을 불러오지 못했습니다");
  }

  const data = await response.json();
  return data.credentials || [];
}

export async function deleteWebAuthnCredential(token: string, credentialId: string): Promise<void> {
  const response = await fetch(`${API_BASE}/webauthn/credentials/delete`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ credentialId }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "패스키 삭제에 실패했습니다");
  }
}

export async function updateWebAuthnCredentialMasterKey(
  token: string,
  credentialId: string,
  encryptedMasterKey: WrappedMasterKey
): Promise<void> {
  const response = await fetch(`${API_BASE}/webauthn/credentials/master-key`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ credentialId, encryptedMasterKey }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "패스키 마스터키 연동에 실패했습니다");
  }
}

export async function getWebAuthnRegisterOptions(token: string): Promise<any> {
  const response = await fetch(`${API_BASE}/webauthn/register-options`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to get registration options");
  }

  return response.json();
}

export async function verifyWebAuthnRegistration(
  token: string,
  credentialId: string,
  publicKey: string,
  counter: number,
  clientDataJSON?: string,
  transports?: string[],
  name?: string,
  encryptedMasterKey?: WrappedMasterKey
): Promise<{ credentialId: string; name: string }> {
  const response = await fetch(`${API_BASE}/webauthn/register-verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      credentialId,
      name,
      publicKey,
      counter,
      clientDataJSON,
      transports,
      encryptedMasterKey,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to verify credential");
  }

  return response.json();
}

export async function getWebAuthnAuthenticateOptions(token: string, credentialId?: string): Promise<any> {
  const response = await fetch(`${API_BASE}/webauthn/authenticate-options`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(credentialId ? { credentialId } : {}),
  });

  if (response.status === 400) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "WebAuthn not registered");
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to get authentication options");
  }

  return response.json();
}

export async function verifyWebAuthnAuthentication(
  token: string,
  credentialId: string,
  clientDataJSON: string,
  authenticatorData: string,
  signature: string
): Promise<{
  token: string;
  expiresAt: string;
  verified: boolean;
  credentialId: string;
  encryptedMasterKey?: WrappedMasterKey;
}> {
  const response = await fetch(`${API_BASE}/webauthn/authenticate-verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      credentialId,
      clientDataJSON,
      authenticatorData,
      signature,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "Failed to verify authentication");
  }

  return response.json();
}
