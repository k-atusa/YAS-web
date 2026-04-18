import { API_BASE } from "./config";
export async function signup(username, password) {
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
export async function login(username, password) {
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
export async function saveAccount(payload, token) {
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
export async function getAccountByUsername(username) {
    const response = await fetch(`${API_BASE}/accounts/username/${encodeURIComponent(username)}`);
    if (response.status === 404)
        return null;
    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || "Failed to fetch account");
    }
    return response.json();
}
export async function listContacts(token) {
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
export async function createContact(payload, token) {
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
export async function deleteContact(id, token) {
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
export async function getWebAuthnRegisterOptions(token) {
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
export async function verifyWebAuthnRegistration(token, credentialId, publicKey, counter, transports) {
    const response = await fetch(`${API_BASE}/webauthn/register-verify`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
            credentialId,
            publicKey,
            counter,
            transports,
        }),
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || "Failed to verify credential");
    }
}
export async function getWebAuthnAuthenticateOptions(token) {
    const response = await fetch(`${API_BASE}/webauthn/authenticate-options`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
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
export async function verifyWebAuthnAuthentication(token, credentialId, counter) {
    const response = await fetch(`${API_BASE}/webauthn/authenticate-verify`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
            credentialId,
            counter,
        }),
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || "Failed to verify authentication");
    }
    return response.json();
}
export async function listWebAuthnCredentials(token) {
    const response = await fetch(`${API_BASE}/webauthn/credentials`, {
        headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || "Failed to list credentials");
    }
    return response.json().then((data) => data.credentials);
}
export async function removeWebAuthnCredential(token, credentialId) {
    const response = await fetch(`${API_BASE}/webauthn/credentials/${encodeURIComponent(credentialId)}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || "Failed to remove credential");
    }
}
export async function decryptStoredPrivateKey(username, token) {
    const response = await fetch(`${API_BASE}/accounts/decrypt`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ username }),
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || "Failed to decrypt private key");
    }
    return response.json();
}
