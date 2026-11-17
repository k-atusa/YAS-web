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

async function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  try {
    return await fetch(input, init);
  } catch (err) {
    if (err instanceof TypeError && (err.message === "Failed to fetch" || err.message.includes("fetch"))) {
      throw new Error("서버와 통신할 수 없습니다. 서버가 실행 중인지 확인해주세요.");
    }
    throw err;
  }
}

export async function signup(username: string, password: string): Promise<{ id: string; username: string }> {
  const response = await apiFetch(`${API_BASE}/auth/signup`, {
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
  const response = await apiFetch(`${API_BASE}/auth/login`, {
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
  const response = await apiFetch(`${API_BASE}/accounts`, {
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
  const response = await apiFetch(`${API_BASE}/accounts/username/${encodeURIComponent(username)}`);

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
  const response = await apiFetch(`${API_BASE}/auth/verify-password`, {
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
  const response = await apiFetch(`${API_BASE}/auth/delete-account`, {
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
  const response = await apiFetch(`${API_BASE}/accounts/me/vault`, {
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
  const response = await apiFetch(`${API_BASE}/contacts`, {
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
  const response = await apiFetch(`${API_BASE}/contacts`, {
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
  const response = await apiFetch(`${API_BASE}/contacts/${encodeURIComponent(id)}`, {
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
  const response = await apiFetch(`${API_BASE}/webauthn/credentials`, {
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
  const response = await apiFetch(`${API_BASE}/webauthn/credentials/delete`, {
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
  const response = await apiFetch(`${API_BASE}/webauthn/credentials/master-key`, {
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
  const response = await apiFetch(`${API_BASE}/webauthn/register-options`, {
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
  const response = await apiFetch(`${API_BASE}/webauthn/register-verify`, {
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
  const response = await apiFetch(`${API_BASE}/webauthn/authenticate-options`, {
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
  const response = await apiFetch(`${API_BASE}/webauthn/authenticate-verify`, {
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

const FALLBACK_WORDS = [
  "ability", "absent", "absorb", "abstract", "academy", "accent", "account", "action",
  "active", "actor", "advance", "airport", "album", "alert", "algebra", "alien",
  "alley", "alpha", "alpine", "amber", "anchor", "angel", "anthem", "apple",
  "apron", "arcade", "arctic", "arena", "arrow", "artist", "aspect", "atom",
  "attic", "august", "autumn", "avatar", "avenue", "bacon", "badge", "baker",
  "balcony", "bamboo", "banana", "banner", "baron", "barrel", "beacon", "beauty",
  "bicycle", "binary", "bird", "biscuit", "blade", "blanket", "blast", "blossom",
  "bounce", "breeze", "bridge", "bronze", "bubble", "bullet", "cabin", "cactus",
  "camel", "camera", "canyon", "canvas", "captain", "caravan", "carbon", "carpet",
  "castle", "cater", "cedar", "celery", "cereal", "chalk", "champion", "channel",
  "chapter", "charcoal", "charm", "cherry", "chest", "cider", "cinnamon", "circle",
  "citizen", "citrus", "civic", "clay", "cliff", "climate", "clover", "cluster",
  "coastal", "cobra", "coffee", "coin", "colony", "comet", "compass", "concert",
  "copper", "coral", "corner", "cosmos", "cotton", "cradle", "crater", "creek",
  "cricket", "crown", "crystal", "cube", "current", "curtain", "cushion", "cylinder",
  "dairy", "daisy", "dancer", "dawn", "decade", "delta", "desert", "device",
  "diamond", "diner", "disco", "dolphin", "dragon", "drift", "drum", "dynasty",
  "eagle", "echo", "eclipse", "effort", "elastic", "elder", "element", "elevator",
  "embark", "emerald", "engine", "enigma", "epoch", "equator", "escape", "essence",
  "eternal", "event", "exile", "fabric", "falcon", "fame", "fantasy", "farmer",
  "feather", "field", "filter", "finch", "finger", "firm", "fiscal", "flavor",
  "flight", "flock", "floral", "flute", "foothill", "forest", "fossil", "founder",
  "fountain", "fox", "frost", "fruit", "furnace", "galaxy", "gallery", "gamma",
  "garden", "garlic", "gateway", "gemini", "genius", "gentle", "geology", "glacier",
  "glance", "glider", "glimmer", "globe", "glory", "glove", "goblet", "goddess",
  "golden", "gospel", "grain", "granite", "grapes", "grass", "gravity", "grove",
  "guitar", "habitat", "hammer", "harbor", "harvest", "haven", "hawk", "hazard",
  "hazel", "header", "heart", "helmet", "heroic", "highway", "horizon", "humble",
  "hunter", "hybrid", "hyper", "iceberg", "icon", "impact", "impulse", "indigo",
  "island", "jacket", "jaguar", "jasper", "jelly", "jewel", "jigsaw", "jockey",
  "journey", "jubilee", "jungle", "jupiter", "kayak", "kernel", "kettle", "keyboard",
  "kinetic", "kingdom", "kitchen", "knight", "koala", "ladder", "lagoon", "lantern",
  "laptop", "laser", "laurel", "lavender", "legend", "lemon", "leopard", "level",
  "liberty", "light", "lily", "limit", "linen", "lion", "liquid", "lizard",
  "llama", "lobster", "logic", "lotus", "lumber", "lunar", "luxury", "lyric"
];

function generateLocalPassphrase(wordCount = 4): string {
  const chosen: string[] = [];
  const randomIndices = new Uint32Array(wordCount);
  window.crypto.getRandomValues(randomIndices);
  for (let i = 0; i < wordCount; i++) {
    chosen.push(FALLBACK_WORDS[randomIndices[i] % FALLBACK_WORDS.length]);
  }
  return chosen.join("-");
}

/**
 * Generates a random dictionary passphrase using https://makemeapassword.ligos.net/api/v1/passphrase/json?pc=10&wc=5&sp=1&nums=0&whenNum=never
 * Randomly picks one from the results that contains no numbers.
 * Words are separated by "-" instead of spaces.
 * Falls back to local crypto random dictionary words if network/offline occurs.
 */
export async function fetchDictionaryPassphrase(): Promise<string> {
  try {
    const res = await fetch(
      "https://makemeapassword.ligos.net/api/v1/passphrase/json?pc=10&wc=5&sp=1&nums=0&whenNum=never"
    );
    if (res.ok) {
      const data = await res.json();
      if (data && Array.isArray(data.pws) && data.pws.length > 0) {
        // 결과 중 숫자가 포함되어 있지 않은 패스프레이즈 필터링 후 랜덤 선택
        const noNumberPhrases = data.pws
          .filter((p: unknown) => typeof p === "string" && !/\d/.test(p as string))
          .map((p: string) => p.trim())
          .filter((p: string) => p.length > 0);

        if (noNumberPhrases.length > 0) {
          const randomIndex = Math.floor(Math.random() * noNumberPhrases.length);
          return noNumberPhrases[randomIndex].split(/\s+/).join("-");
        }
      }
    }
  } catch (err) {
    console.warn("Ligos passphrase API unavailable, using local dictionary fallback", err);
  }
  return generateLocalPassphrase(5);
}
