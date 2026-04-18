import { useEffect, useLayoutEffect, useRef, useState } from "react";
import {
	getAccountByUsername,
	login as loginApi,
	saveAccount,
	signup,
	listContacts,
	createContact,
	deleteContact,
	getWebAuthnRegisterOptions,
	verifyWebAuthnRegistration,
	getWebAuthnAuthenticateOptions,
	verifyWebAuthnAuthentication,
	decryptStoredPrivateKey,
} from "./api";
import {
	buildAccountPayload,
	generateKeyPair,
	encryptOpsec,
	decryptOpsecPw,
	decryptOpsecPub,
	detectAuthMode,
	u8ToBase64,
	base64ToU8,
	registerWebAuthnCredential,
	authenticateWithWebAuthn,
	isWebAuthnAvailable,
	isPlatformAuthenticatorAvailable,
} from "./crypto";
import type { AsymAlgo, KdfMethod, EncAlgo, AuthMode, DecryptResult } from "./crypto";
import type { AccountRecord, ContactRecord } from "./types";

/* ─── Helpers ─── */

function formatBytes(bytes: number): string {
	if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
	const units = ["B", "KB", "MB", "GB", "TB"];
	let value = bytes;
	let idx = 0;
	while (value >= 1024 && idx < units.length - 1) {
		value /= 1024;
		idx += 1;
	}
	const digits = value < 10 && idx > 0 ? 1 : 0;
	return `${value.toFixed(digits)} ${units[idx]}`;
}

function truncateKey(key: string): string {
	if (key.length <= 15) return key;
	return `${key.slice(0, 6)}…${key.slice(-6)}`;
}

function detectPublicKeyAlgo(publicKeyB64: string): AsymAlgo {
	try {
		const u8 = base64ToU8(publicKeyB64);
		// PQC1 public key is exactly 4273 bytes
		if (u8.length === 4273) return "pqc1";
		// Curve448 public key is exactly 113 bytes
		if (u8.length === 113) return "ecc1";
		// RSA public key is typically 290+ bytes
		return "rsa1";
	} catch {
		return "ecc1"; // Default to ecc1
	}
}

function detectPrivateKeyAlgo(privateKeyB64: string): AsymAlgo {
	try {
		const u8 = base64ToU8(privateKeyB64);
		// PQC1 private key is exactly 8177 bytes
		if (u8.length === 8177) return "pqc1";
		// Curve448 private key is exactly 113 bytes
		if (u8.length === 113) return "ecc1";
		return "rsa1";
	} catch {
		return "ecc1";
	}
}

/* ─── Icons ─── */

function IconContacts({ active }: { active?: boolean }) {
	const stroke = active ? "#fff" : "#888";
	return (
		<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
			<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
			<circle cx="9" cy="7" r="4" />
			<path d="M22 21v-2a4 4 0 0 0-3-3.87" />
			<path d="M16 3.13a4 4 0 0 1 0 7.75" />
		</svg>
	);
}

function IconKey({ active }: { active?: boolean }) {
	const stroke = active ? "#fff" : "#888";
	return (
		<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
			<circle cx="8" cy="15" r="4" />
			<path d="M11.3 11.7 20 3" />
			<path d="M17 3h3v3" />
			<path d="m17 7 3-3" />
		</svg>
	);
}

function IconEncrypt({ active }: { active?: boolean }) {
	const stroke = active ? "#fff" : "#888";
	return (
		<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
			<rect x="3" y="11" width="18" height="11" rx="2" />
			<path d="M7 11V7a5 5 0 0 1 10 0v4" />
		</svg>
	);
}

function IconDecrypt({ active }: { active?: boolean }) {
	const stroke = active ? "#fff" : "#888";
	return (
		<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
			<rect x="3" y="11" width="18" height="11" rx="2" />
			<path d="M7 11V7a5 5 0 0 1 9.9-1" />
		</svg>
	);
}

/* ─── App ─── */

type Tab = "contacts" | "keys" | "encrypt" | "decrypt";

function App() {
	/* Auth */
	const [authToken, setAuthToken] = useState<string | null>(() => localStorage.getItem("authToken"));
	const [authUsername, setAuthUsername] = useState<string | null>(() => localStorage.getItem("authUsername"));
	const [view, setView] = useState<"landing" | "login" | "signup">("landing");
	const [loginUsername, setLoginUsername] = useState("");
	const [loginPass, setLoginPass] = useState("");
	const [loginPassConfirm, setLoginPassConfirm] = useState("");
	const [loginBusy, setLoginBusy] = useState(false);

	/* Key mgmt */
	const [username, setUsername] = useState("");
	const [publicKeyPem, setPublicKeyPem] = useState("");
	const [privateKeyPem, setPrivateKeyPem] = useState("");
	const [notes, setNotes] = useState("");
	const [status, setStatus] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [tab, setTab] = useState<Tab>("keys");
	const [storedAccount, setStoredAccount] = useState<AccountRecord | null>(null);
	const [showKeySection, setShowKeySection] = useState(true);
	const [copyPublicStatus, setCopyPublicStatus] = useState<"idle" | "copied" | "error">("idle");
	const [copyPrivateStatus, setCopyPrivateStatus] = useState<"idle" | "copied" | "error">("idle");
	const [toastMsg, setToastMsg] = useState<string | null>(null);

	function showToast(msg: string) {
		setToastMsg(msg);
		setTimeout(() => setToastMsg(null), 2500);
	}
	const [keyAlgo, setKeyAlgo] = useState<AsymAlgo>("ecc1");

	/* Contacts */
	const [contacts, setContacts] = useState<ContactRecord[]>([]);
	const [contactsLoading, setContactsLoading] = useState(false);
	const [contactForm, setContactForm] = useState({ contactUsername: "", notes: "" });
	const [contactError, setContactError] = useState<string | null>(null);
	const [contactBusy, setContactBusy] = useState(false);
	const [contactModalOpen, setContactModalOpen] = useState(false);
	const [contactModalClosing, setContactModalClosing] = useState(false);
	const [contactModalMode, setContactModalMode] = useState<"add" | "edit">("add");
	const [editingContactMeta, setEditingContactMeta] = useState<{ id: string; username: string } | null>(null);
	const [contactModalError, setContactModalError] = useState<string | null>(null);
	const closeModalTimer = useRef<number | null>(null);

	/* Encrypt */
	const [encryptAuthMode, setEncryptAuthMode] = useState<AuthMode>("password");
	const [encryptKdfMethod, setEncryptKdfMethod] = useState<KdfMethod>("arg1");
	const [encryptEncAlgo, setEncryptEncAlgo] = useState<EncAlgo>("gcm1");
	const [encryptAsymAlgo, setEncryptAsymAlgo] = useState<AsymAlgo | null>(null);
	const [encryptPassword, setEncryptPassword] = useState("");
	const [encryptRecipientId, setEncryptRecipientId] = useState<string>("");
	const [encryptMsg, setEncryptMsg] = useState("");
	const [encryptSmsg, setEncryptSmsg] = useState("");
	const [encryptMode, setEncryptMode] = useState<"text" | "file">("text");
	const [encryptFile, setEncryptFile] = useState<File | null>(null);
	const [isFileDragActive, setIsFileDragActive] = useState(false);
	const [encryptSignWithKey, setEncryptSignWithKey] = useState(false);
	const [encryptBusy, setEncryptBusy] = useState(false);
	const [encryptStatus, setEncryptStatus] = useState<string | null>(null);
	const [encryptError, setEncryptError] = useState<string | null>(null);
	const [encryptedBlob, setEncryptedBlob] = useState<Uint8Array | null>(null);
	const [encryptStep, setEncryptStep] = useState(1);

	/* Decrypt */
	const [decryptPayloadInput, setDecryptPayloadInput] = useState("");
	const [decryptPayloadFile, setDecryptPayloadFile] = useState<File | null>(null);
	const [isDecryptFileDragActive, setIsDecryptFileDragActive] = useState(false);
	const [decryptPassword, setDecryptPassword] = useState("");
	const [decryptPrivateKeyInput, setDecryptPrivateKeyInput] = useState("");
	const [decryptPrivateKeySource, setDecryptPrivateKeySource] = useState<"security" | "manual">("security");
	const [decryptPeerPublicKey, setDecryptPeerPublicKey] = useState("");
	const [decryptPeerKeySource, setDecryptPeerKeySource] = useState<"contact" | "manual">("contact");
	const [decryptSelectedContactId, setDecryptSelectedContactId] = useState("");
	const [decryptDetected, setDecryptDetected] = useState<{ mode: AuthMode; algo: string; msg: string } | null>(null);
	const [decryptBusy, setDecryptBusy] = useState(false);
	const [decryptStatus, setDecryptStatus] = useState<string | null>(null);
	const [decryptError, setDecryptError] = useState<string | null>(null);
	const [decryptedResult, setDecryptedResult] = useState<DecryptResult | null>(null);
	const [decryptStep, setDecryptStep] = useState(1);

	/* WebAuthn */
	const [webauthnAvailable, setWebauthnAvailable] = useState(false);
	const [webauthnAuthBusy, setWebauthnAuthBusy] = useState(false);
	const [decryptionToken, setDecryptionToken] = useState<string | null>(null);

	/* Theme */
	const [themeMode, setThemeMode] = useState<"system" | "light" | "dark">(() => {
		return (localStorage.getItem("themeMode") as "system" | "light" | "dark") || "system";
	});
	const [resolvedDark, setResolvedDark] = useState(() => {
		const saved = localStorage.getItem("themeMode") || "system";
		if (saved === "dark") return true;
		if (saved === "light") return false;
		return window.matchMedia("(prefers-color-scheme: dark)").matches;
	});

	/* Navigation refs */
	const navInnerRef = useRef<HTMLDivElement>(null);
	const navContactsRef = useRef<HTMLButtonElement>(null);
	const navKeysRef = useRef<HTMLButtonElement>(null);
	const navEncryptRef = useRef<HTMLButtonElement>(null);
	const navDecryptRef = useRef<HTMLButtonElement>(null);
	const [pressedTab, setPressedTab] = useState<Tab | null>(null);
	/* Tooltip */
	const [showUsernameTooltip, setShowUsernameTooltip] = useState(false);
	const [showSigningTooltip, setShowSigningTooltip] = useState(false);

	/* ─── Effects ──── */

	useEffect(() => {
		return () => {
			if (closeModalTimer.current) {
				window.clearTimeout(closeModalTimer.current);
				closeModalTimer.current = null;
			}
		};
	}, []);

	/* Theme sync */
	useEffect(() => {
		const mq = window.matchMedia("(prefers-color-scheme: dark)");
		const handler = (e: MediaQueryListEvent) => {
			if (themeMode === "system") setResolvedDark(e.matches);
		};
		mq.addEventListener("change", handler);
		return () => mq.removeEventListener("change", handler);
	}, [themeMode]);

	useEffect(() => {
		localStorage.setItem("themeMode", themeMode);
		if (themeMode === "system") {
			setResolvedDark(window.matchMedia("(prefers-color-scheme: dark)").matches);
		} else {
			setResolvedDark(themeMode === "dark");
		}
	}, [themeMode]);

	useEffect(() => {
		document.documentElement.setAttribute("data-theme", resolvedDark ? "dark" : "light");
	}, [resolvedDark]);

	/* Animate navigation pill position + squish */
	const updateNavHighlight = () => {
		const refMap: Record<Tab, React.RefObject<HTMLButtonElement | null>> = { contacts: navContactsRef, keys: navKeysRef, encrypt: navEncryptRef, decrypt: navDecryptRef };
		const activeEl = refMap[tab]?.current;
		const inner = navInnerRef.current;
		if (!activeEl || !inner) return;

		const size = activeEl.offsetWidth;
		const activeX = activeEl.offsetLeft;
		let x = activeX;
		let w = size;

		if (pressedTab && pressedTab !== tab) {
			const pressedEl = refMap[pressedTab]?.current;
			if (pressedEl) {
				const pressedX = pressedEl.offsetLeft;
				const distance = Math.abs(pressedX - activeX);
				const stretch = Math.min(distance * 0.25, 22);
				if (pressedX > activeX) {
					w = size + stretch;
				} else {
					x = activeX - stretch;
					w = size + stretch;
				}
			}
		}

		inner.style.setProperty('--nav-active-x', `${x}px`);
		inner.style.setProperty('--nav-active-y', `${activeEl.offsetTop}px`);
		inner.style.setProperty('--nav-active-w', `${w}px`);
	};

	useLayoutEffect(updateNavHighlight, [tab, pressedTab]);

	useEffect(() => {
		if (!encryptedBlob) return;
		const blob = new Blob(
			[encryptedBlob.buffer.slice(encryptedBlob.byteOffset, encryptedBlob.byteOffset + encryptedBlob.byteLength) as ArrayBuffer],
			{ type: "application/octet-stream" }
		);
		const url = URL.createObjectURL(blob);
		const link = document.createElement("a");
		link.href = url;
		link.download = `encrypted-${Date.now()}.bin`;
		link.click();
		URL.revokeObjectURL(url);
	}, [encryptedBlob]);

	const canLogin = Boolean(loginUsername && loginPass && (view === "login" || loginPass === loginPassConfirm));
	const canUpload = Boolean(username && publicKeyPem && privateKeyPem);
	const isAuthed = Boolean(authToken);

	useEffect(() => {
		if (authToken) {
			localStorage.setItem("authToken", authToken);
			if (authUsername) localStorage.setItem("authUsername", authUsername);
		} else {
			localStorage.removeItem("authToken");
			localStorage.removeItem("authUsername");
		}
	}, [authToken, authUsername]);

	useEffect(() => {
		let cancelled = false;
		async function loadContacts() {
			if (!authToken) {
				if (!cancelled) { setContacts([]); setContactsLoading(false); }
				return;
			}
			if (!cancelled) { setContactsLoading(true); setContactError(null); }
			try {
				const items = await listContacts(authToken);
				if (!cancelled) setContacts(items);
			} catch (err) {
				const msg = (err as Error).message || "연락처 불러오기 실패";
				if (msg === "TOKEN_EXPIRED") { handleSignOut(); return; }
				if (!cancelled) setContactError(msg);
			} finally {
				if (!cancelled) setContactsLoading(false);
			}
		}
		loadContacts();
		return () => { cancelled = true; };
	}, [authToken]);

	useEffect(() => {
		if (!authToken) { setWebauthnAvailable(false); return; }
		setWebauthnAvailable(isWebAuthnAvailable());
	}, [authToken]);

	useEffect(() => {
		if (authUsername) setUsername(authUsername);
		else setUsername("");
	}, [authUsername]);

	useEffect(() => {
		let cancelled = false;
		const snap = authUsername?.trim();
		setStoredAccount(null);
		setShowKeySection(true);
		setPublicKeyPem("");
		setPrivateKeyPem("");
		setCopyPrivateStatus("idle");
		if (!snap) return () => { cancelled = true; };

		async function loadStored() {
			try {
				const record = await getAccountByUsername(snap as string);
				if (!cancelled && authUsername === snap) {
					setStoredAccount(record);
					setShowKeySection(!record);
					if (record) { setPublicKeyPem(record.publicKey); setStatus(null); }
				}
			} catch (err) {
				console.error(err);
				if (!cancelled && authUsername === snap) { setStoredAccount(null); setShowKeySection(true); }
			}
		}
		loadStored();
		return () => { cancelled = true; };
	}, [authUsername]);

	/* ─── Handlers ─── */

	async function handleLogin(e: React.FormEvent) {
		e.preventDefault();
		if (!canLogin) return;
		setLoginBusy(true);
		setError(null);
		setStatus(null);
		try {
			const result = await loginApi(loginUsername, loginPass);
			setAuthToken(result.token);
			setAuthUsername(result.user.username);
		} catch (err) {
			setError((err as Error).message || "로그인에 실패했습니다");
		} finally {
			setLoginBusy(false);
		}
	}

	async function handleSignup(e: React.FormEvent) {
		e.preventDefault();
		if (!canLogin) return;
		setLoginBusy(true);
		setError(null);
		setStatus(null);
		try {
			await signup(loginUsername, loginPass);
			const result = await loginApi(loginUsername, loginPass);
			setAuthToken(result.token);
			setAuthUsername(result.user.username);
		} catch (err) {
			setError((err as Error).message || "회원가입에 실패했습니다");
		} finally {
			setLoginBusy(false);
		}
	}

	function handleSignOut() {
		setAuthToken(null);
		setAuthUsername(null);
		setLoginPass("");
		setUsername("");
		setStoredAccount(null);
		setShowKeySection(true);
		setCopyPrivateStatus("idle");
		setContacts([]);
		setContactForm({ contactUsername: "", notes: "" });
		setContactError(null);
		forceCloseContactModal();
		setEncryptRecipientId("");
		setEncryptMode("text");
		setEncryptSmsg("");
		setEncryptMsg("");
		setEncryptPassword("");
		setEncryptFile(null);
		setIsFileDragActive(false);
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptedBlob(null);
		setEncryptStep(1);
		setDecryptPayloadInput("");
		setDecryptPayloadFile(null);
		setIsDecryptFileDragActive(false);
		setDecryptPassword("");
		setDecryptPrivateKeyInput("");
		setDecryptPrivateKeySource("security");
		setDecryptPeerPublicKey("");
		setDecryptDetected(null);
		setDecryptBusy(false);
		setDecryptStatus(null);
		setDecryptError(null);
		setDecryptedResult(null);
		setDecryptStep(1);
		setView("landing");
	}

	async function handleCopyPublicKey(value?: string) {
		if (!value) return;
		try {
			await navigator.clipboard.writeText(value);
			setCopyPublicStatus("copied");
			setTimeout(() => setCopyPublicStatus("idle"), 2000);
		} catch {
			setCopyPublicStatus("error");
			setTimeout(() => setCopyPublicStatus("idle"), 2000);
		}
	}

	async function handleCopyPrivateKey(value?: string) {
		if (!value) return;
		try {
			await navigator.clipboard.writeText(value);
			setCopyPrivateStatus("copied");
			setTimeout(() => setCopyPrivateStatus("idle"), 2000);
		} catch {
			setCopyPrivateStatus("error");
			setTimeout(() => setCopyPrivateStatus("idle"), 2000);
		}
	}

	/* ─── Contact modal helpers ─── */

	function reopenContactModal() {
		if (closeModalTimer.current) { window.clearTimeout(closeModalTimer.current); closeModalTimer.current = null; }
		setContactModalClosing(false);
		setContactModalOpen(true);
	}

	function forceCloseContactModal() {
		if (closeModalTimer.current) { window.clearTimeout(closeModalTimer.current); closeModalTimer.current = null; }
		setContactModalClosing(false);
		setContactModalOpen(false);
		setContactModalMode("add");
		setEditingContactMeta(null);
		setContactForm({ contactUsername: "", notes: "" });
		setContactModalError(null);
	}

	function openAddContactModal() {
		reopenContactModal();
		setContactModalMode("add");
		setEditingContactMeta(null);
		setContactForm({ contactUsername: "", notes: "" });
		setContactModalError(null);
	}

	function openEditContactModal(contact: ContactRecord) {
		reopenContactModal();
		setContactModalMode("edit");
		setEditingContactMeta({ id: contact.id, username: contact.contactUsername });
		setContactForm({ contactUsername: contact.contactUsername, notes: contact.notes || "" });
		setContactModalError(null);
	}

	function closeContactModal() {
		if (contactModalClosing) return;
		if (closeModalTimer.current) window.clearTimeout(closeModalTimer.current);
		setContactModalClosing(true);
		closeModalTimer.current = window.setTimeout(() => { forceCloseContactModal(); closeModalTimer.current = null; }, 240);
	}

	async function handleContactSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!authToken) return;
		const trimmedUsername = contactForm.contactUsername.trim();
		if (!trimmedUsername) { setContactModalError("사용자 아이디는 필수입니다"); return; }
		setContactBusy(true);
		setContactModalError(null);
		try {
			const payload: { contactUsername: string; notes?: string } = { 
                contactUsername: trimmedUsername, 
                notes: contactForm.notes.trim() || undefined 
            };
			
            const saved = await createContact(payload as any, authToken);
			setContacts((prev) => {
				const withoutSaved = prev.filter((c) => c.id !== saved.id);
				const withoutOld = contactModalMode === "edit" && editingContactMeta && trimmedUsername !== editingContactMeta.username
					? withoutSaved.filter((c) => c.id !== editingContactMeta.id)
					: withoutSaved;
				return [saved, ...withoutOld];
			});
			if (contactModalMode === "edit" && editingContactMeta && trimmedUsername !== editingContactMeta.username) {
				try {
					await deleteContact(editingContactMeta.id, authToken);
				} catch (deleteErr) {
					if ((deleteErr as Error).message === "TOKEN_EXPIRED") { handleSignOut(); return; }
					console.error(deleteErr);
					setContactError((deleteErr as Error).message || "이전 연락처 삭제 실패");
				}
			}
			closeContactModal();
		} catch (err) {
			if ((err as Error).message === "TOKEN_EXPIRED") { handleSignOut(); return; }
			setContactModalError((err as Error).message || "연락처 저장에 실패했습니다");
		} finally {
			setContactBusy(false);
		}
	}

	async function handleDeleteContact(id: string) {
		if (!authToken) return;
		if (!window.confirm("이 연락처를 삭제하시겠습니까?")) return;
		try {
			await deleteContact(id, authToken);
			setContacts((prev) => prev.filter((c) => c.id !== id));
		} catch (err) {
			if ((err as Error).message === "TOKEN_EXPIRED") { handleSignOut(); return; }
			setContactError((err as Error).message || "연락처 삭제에 실패했습니다");
		}
	}

	/* ─── Key generation ─── */

	async function handleGenerateKeys() {
		setError(null);
		setStatus("키 쌍 생성 중...");
		try {
			const { publicKey, privateKey } = await generateKeyPair(keyAlgo);
			setPublicKeyPem(publicKey);
			setPrivateKeyPem(privateKey);
			setCopyPrivateStatus("idle");
			setStatus("키 쌍이 생성되었습니다. 개인키는 안전하게 보관하세요.");
		} catch (err) {
			console.error(err);
			setError("키 쌍 생성에 실패했습니다");
			setStatus(null);
		}
	}

	async function handleUpload() {
		if (!canUpload) return;
		setBusy(true);
		setError(null);
		setStatus("암호화하여 업로드 중...");
		try {
			const payload = await buildAccountPayload(username, publicKeyPem, privateKeyPem, notes || undefined);
			const result = await saveAccount(payload, authToken ?? undefined);
			const record: AccountRecord = { ...payload, id: result.id, createdAt: result.createdAt };
			setStoredAccount(record);
			setStatus("키가 안전하게 저장되었습니다");
			setShowKeySection(false);
			setPrivateKeyPem("");
			setCopyPrivateStatus("idle");
			if (authToken && (await isWebAuthnAvailable())) {
				setStatus("보안 키 설정 중...");
				setTimeout(() => startWebAuthnRegistration(), 500);
			}
		} catch (err) {
			console.error(err);
			setError((err as Error).message || "업로드에 실패했습니다");
			setStatus(null);
		} finally {
			setBusy(false);
		}
	}

	function handleRegenerate() {
		setStoredAccount(null);
		setShowKeySection(true);
		setPublicKeyPem("");
		setPrivateKeyPem("");
		setCopyPrivateStatus("idle");
		setNotes("");
		setStatus(null);
		setError(null);
	}

	/* ─── WebAuthn ─── */

	async function startWebAuthnRegistration() {
		if (!authToken) { setError("로그인이 필요합니다"); return; }
		try {
			const optionsResp = await getWebAuthnRegisterOptions(authToken);
			const options = optionsResp.options;
			setStatus("보안 키를 사용하세요...");
			const registration = await registerWebAuthnCredential({
				challenge: options.challenge, rp: options.rp, user: options.user,
				pubKeyCredParams: options.pubKeyCredParams, timeout: options.timeout,
				attestation: options.attestation, authenticatorSelection: options.authenticatorSelection,
			});
			setStatus("보안 키 확인 중...");
			await verifyWebAuthnRegistration(authToken, registration.credentialId, registration.publicKey, registration.counter, registration.transports);
			setStatus("보안 키가 등록되었습니다!");
			setError(null);
			setTimeout(() => setStatus(null), 3000);
		} catch (err) {
			const msg = (err as Error).message || "보안 키 등록 실패";
			if (msg !== "WebAuthn registration cancelled") setError(`보안 키 설정: ${msg}`);
			setStatus(null);
		}
	}

	async function handleWebAuthnAuthenticate() {
		await requestPrivateKeyAccess("decrypt");
	}

	async function requestPrivateKeyAccess(target: "decrypt" | "encrypt"): Promise<boolean> {
		const setTargetError = target === "decrypt" ? setDecryptError : setEncryptError;
		const setTargetStatus = target === "decrypt" ? setDecryptStatus : setEncryptStatus;

		if (!authToken || !isAuthed) { setTargetError("로그인이 필요합니다"); return false; }
		if (!storedAccount?.encryptedPrivateKey || !storedAccount?.kdf) { setTargetError("저장된 개인키가 없습니다."); return false; }
		setWebauthnAuthBusy(true);
		setTargetError(null);
		setTargetStatus("보안 키 요청 중...");
		try {
			const optionsResp = await getWebAuthnAuthenticateOptions(authToken);
			const options = optionsResp.options;
			setTargetStatus("보안 키로 인증하세요...");
			const assertion = await authenticateWithWebAuthn({
				challenge: options.challenge, allowCredentials: options.allowCredentials || [],
				timeout: options.timeout, userVerification: options.userVerification,
			});
			setTargetStatus("확인 중...");
			const verifyResp = await verifyWebAuthnAuthentication(authToken, assertion.credentialId, assertion.counter);
			setDecryptionToken(verifyResp.token);
			setTargetStatus(null);
			setTargetError(null);
			return true;
		} catch (err) {
			setTargetError((err as Error).message || "보안 키 인증 실패");
			setTargetStatus(null);
			return false;
		} finally {
			setWebauthnAuthBusy(false);
		}
	}

	async function handleEncryptSignWithKeyToggle(checked: boolean) {
		if (!checked) {
			setEncryptSignWithKey(false);
			return;
		}

		if (privateKeyPem || decryptionToken) {
			setEncryptSignWithKey(true);
			return;
		}

		const success = await requestPrivateKeyAccess("encrypt");
		setEncryptSignWithKey(success);
	}

	/* ─── Encrypt helpers ─── */

	function resetEncryptionForm() {
		setEncryptSmsg("");
		setEncryptMsg("");
		setEncryptPassword("");
		applySelectedEncryptFile(null);
		setIsFileDragActive(false);
		setEncryptedBlob(null);
		setEncryptStep(1);
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptKdfMethod("arg1");
		setEncryptEncAlgo("gcm1");
		setEncryptAsymAlgo(null);
		setEncryptRecipientId("");
		setEncryptSignWithKey(false);
	}

	function handleEncryptionModeChange(mode: "text" | "file") {
		if (mode === encryptMode) return;
		setEncryptMode(mode);
		if (mode === "text") { applySelectedEncryptFile(null); setIsFileDragActive(false); }
		else setEncryptSmsg("");
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptedBlob(null);
	}

	function applySelectedEncryptFile(file: File | null) {
		setEncryptFile(file);
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptedBlob(null);
	}

	function handleFileDragEnter(e: React.DragEvent<HTMLDivElement>) { e.preventDefault(); if (!encryptBusy) setIsFileDragActive(true); }
	function handleFileDragOver(e: React.DragEvent<HTMLDivElement>) { e.preventDefault(); if (!encryptBusy) { e.dataTransfer.dropEffect = "copy"; if (!isFileDragActive) setIsFileDragActive(true); } }
	function handleFileDragLeave(e: React.DragEvent<HTMLDivElement>) {
		e.preventDefault();
		const next = e.relatedTarget as Node | null;
		if (next && e.currentTarget.contains(next)) return;
		setIsFileDragActive(false);
	}
	function handleFileDrop(e: React.DragEvent<HTMLDivElement>) {
		e.preventDefault(); setIsFileDragActive(false);
		if (encryptBusy) return;
		const f = e.dataTransfer.files?.[0];
		if (f) applySelectedEncryptFile(f);
	}
	function handleEncryptFileChange(e: React.ChangeEvent<HTMLInputElement>) {
		const f = e.target.files?.[0] ?? null;
		applySelectedEncryptFile(f);
		setIsFileDragActive(false);
		e.target.value = "";
	}

	/* ─── Decrypt helpers ─── */

	function handleDecryptDragEnter(e: React.DragEvent<HTMLDivElement>) { e.preventDefault(); if (!decryptBusy) setIsDecryptFileDragActive(true); }
	function handleDecryptDragOver(e: React.DragEvent<HTMLDivElement>) { e.preventDefault(); if (!decryptBusy) { e.dataTransfer.dropEffect = "copy"; if (!isDecryptFileDragActive) setIsDecryptFileDragActive(true); } }
	function handleDecryptDragLeave(e: React.DragEvent<HTMLDivElement>) {
		e.preventDefault();
		const next = e.relatedTarget as Node | null;
		if (next && e.currentTarget.contains(next)) return;
		setIsDecryptFileDragActive(false);
	}

	async function tryAutoDetect(data: Uint8Array) {
		try {
			const info = detectAuthMode(data);
			setDecryptDetected(info);
			setDecryptError(null);
		} catch { setDecryptDetected(null); }
	}

	function handleDecryptFileDrop(e: React.DragEvent<HTMLDivElement>) {
		e.preventDefault(); setIsDecryptFileDragActive(false);
		if (decryptBusy) return;
		const f = e.dataTransfer.files?.[0];
		if (f) {
			setDecryptPayloadFile(f);
			setDecryptPayloadInput("");
			setDecryptStatus(null); setDecryptError(null); setDecryptedResult(null);
			f.arrayBuffer().then((buf) => tryAutoDetect(new Uint8Array(buf)));
		}
	}

	function handleDecryptFileChange(e: React.ChangeEvent<HTMLInputElement>) {
		const f = e.target.files?.[0] ?? null;
		setDecryptPayloadFile(f);
		setDecryptPayloadInput("");
		setDecryptStatus(null); setDecryptError(null); setDecryptedResult(null);
		setIsDecryptFileDragActive(false);
		e.target.value = "";
		if (f) f.arrayBuffer().then((buf) => tryAutoDetect(new Uint8Array(buf)));
		else setDecryptDetected(null);
	}

	function resetDecryptForm() {
		setDecryptPayloadInput("");
		setDecryptPayloadFile(null);
		setIsDecryptFileDragActive(false);
		setDecryptPassword("");
		setDecryptPrivateKeyInput("");
		setDecryptPrivateKeySource("security");
		setDecryptPeerPublicKey("");
		setDecryptPeerKeySource("contact");
		setDecryptSelectedContactId("");
		setDecryptDetected(null);
		setDecryptStatus(null);
		setDecryptError(null);
		setDecryptedResult(null);
		setDecryptStep(1);
	}

	async function resolvePrivateKeyB64(): Promise<string> {
		const manual = decryptPrivateKeyInput.trim();
		if (manual) return manual;
		if (privateKeyPem) return privateKeyPem;
		if (storedAccount?.encryptedPrivateKey && storedAccount?.kdf) {
			if (!decryptionToken) throw new Error("저장된 개인키를 잠금 해제하려면 보안 키를 사용하세요");
			const result = await decryptStoredPrivateKey(storedAccount.username, decryptionToken);
			return result.privateKey;
		}
		throw new Error("사용 가능한 개인키가 없습니다.");
	}

	async function resolveSigningPrivateKeyB64(): Promise<string> {
		if (privateKeyPem) return privateKeyPem;
		if (storedAccount?.encryptedPrivateKey && storedAccount?.kdf) {
			if (!decryptionToken) {
				throw new Error("서명하려면 먼저 복호화 탭에서 보안 키 인증을 완료하세요.");
			}
			const result = await decryptStoredPrivateKey(storedAccount.username, decryptionToken);
			return result.privateKey;
		}
		throw new Error("서명에 사용할 개인키를 찾을 수 없습니다.");
	}

	async function loadOpsecData(): Promise<Uint8Array> {
		if (decryptPayloadFile) return new Uint8Array(await decryptPayloadFile.arrayBuffer());
		const raw = decryptPayloadInput.trim();
		if (!raw) throw new Error("Base64 텍스트를 붙여넣거나 파일을 업로드하세요");
		try { return base64ToU8(raw); } catch { throw new Error("올바르지 않은 Base64 형식입니다"); }
	}

	/* ─── Encrypt submit ─── */

	async function handleEncryptSubmit() {
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptedBlob(null);

		if (encryptAuthMode === "password") {
			if (!encryptPassword) { setEncryptError("비밀번호를 입력하세요"); return; }
		} else {
			if (!contacts.find((c) => c.id === encryptRecipientId)) { setEncryptError("수신자를 선택하세요"); return; }
		}
		if (encryptMode === "text") {
			if (!encryptSmsg) { setEncryptError("암호화할 메시지를 입력하세요"); return; }
		} else {
			if (!encryptFile) { setEncryptError("암호화할 파일을 선택하세요"); return; }
		}

		try {
			setEncryptBusy(true);
			setEncryptStatus("암호화 중...");
			const files = encryptMode === "file" && encryptFile ? [encryptFile] : undefined;
			let result: Uint8Array;
			if (encryptAuthMode === "password") {
				result = await encryptOpsec({
					mode: "password", kdfMethod: encryptKdfMethod, password: encryptPassword,
					encAlgo: encryptEncAlgo, smsg: encryptSmsg || undefined, msg: encryptMsg || undefined, files,
				});
			} else {
				const recipient = contacts.find((c) => c.id === encryptRecipientId)!;
				let myPrivateKey: string | undefined;
				if (encryptSignWithKey) {
					myPrivateKey = await resolveSigningPrivateKeyB64();
					const signAlgo = detectPrivateKeyAlgo(myPrivateKey);
					if (signAlgo !== encryptAsymAlgo) {
						throw new Error(`서명 키 알고리즘(${signAlgo})과 수신자 키 알고리즘(${encryptAsymAlgo})이 달라 서명할 수 없습니다.`);
					}
				}
				result = await encryptOpsec({
					mode: "publickey", asymAlgo: encryptAsymAlgo!, peerPublicKey: recipient.publicKey,
					myPrivateKey, encAlgo: encryptEncAlgo, smsg: encryptSmsg || undefined, msg: encryptMsg || undefined, files,
				});
			}
			setEncryptedBlob(result);
			setEncryptStatus(encryptMode === "text"
				? `암호화 완료 (${result.length} bytes). 다운로드가 시작됩니다.`
				: `파일 암호화 완료 (${formatBytes(result.length)}). 다운로드가 시작됩니다.`
			);
		} catch (err) {
			console.error(err);
			setEncryptError((err as Error).message || "암호화에 실패했습니다");
			setEncryptStatus(null);
			setEncryptedBlob(null);
		} finally {
			setEncryptBusy(false);
		}
	}

	function handleDownloadEncryptedBlob() {
		if (!encryptedBlob) return;
		const blob = new Blob([encryptedBlob.buffer.slice(encryptedBlob.byteOffset, encryptedBlob.byteOffset + encryptedBlob.byteLength) as ArrayBuffer], { type: "application/octet-stream" });
		const url = URL.createObjectURL(blob);
		const link = document.createElement("a");
		link.href = url;
		link.download = `encrypted-${Date.now()}.bin`;
		link.click();
		URL.revokeObjectURL(url);
	}

	async function handleCopyEncryptedBase64() {
		if (!encryptedBlob) return;
		try { await navigator.clipboard.writeText(u8ToBase64(encryptedBlob)); } catch (err) { console.error(err); }
	}

	/* ─── Decrypt submit ─── */

	async function handleDecryptSubmit() {
		setDecryptStatus(null);
		setDecryptError(null);
		setDecryptedResult(null);
		try {
			setDecryptBusy(true);
			setDecryptStatus("데이터 불러오는 중...");
			const dataU8 = await loadOpsecData();
			const info = decryptDetected ?? detectAuthMode(dataU8);
			setDecryptDetected(info);
			setDecryptStatus("복호화 중...");
			let result: DecryptResult;
			if (info.mode === "password") {
				if (!decryptPassword) throw new Error("비밀번호를 입력하세요");
				result = await decryptOpsecPw(dataU8, decryptPassword);
			} else {
				const priB64 = await resolvePrivateKeyB64();
				
				let finalPeerPub = decryptPeerPublicKey.trim();
				if (decryptPeerKeySource === "contact" && decryptSelectedContactId) {
					const contact = contacts.find((c) => c.id === decryptSelectedContactId);
					if (contact?.publicKey) {
						finalPeerPub = contact.publicKey.trim();
					}
				}
				const peerPub = finalPeerPub || undefined;
				
				result = await decryptOpsecPub(dataU8, priB64, peerPub);
			}
			setDecryptedResult(result);
			setDecryptStatus("복호화 완료");
		} catch (err) {
			console.error(err);
			setDecryptError((err as Error).message || "복호화에 실패했습니다");
			setDecryptStatus(null);
			setDecryptedResult(null);
		} finally {
			setDecryptBusy(false);
		}
	}

	function handleDownloadDecryptedFile(name: string, data: Uint8Array) {
		const blob = new Blob([data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer], { type: "application/octet-stream" });
		const url = URL.createObjectURL(blob);
		const link = document.createElement("a");
		link.href = url;
		link.download = name;
		link.click();
		URL.revokeObjectURL(url);
	}

	async function handleDecryptAdvanceToStep2() {
		setDecryptError(null);
		try {
			const data = await loadOpsecData();
			const info = detectAuthMode(data);
			setDecryptDetected(info);
			setDecryptStep(2);
		} catch (err) {
			setDecryptError((err as Error).message || "데이터를 분석할 수 없습니다");
		}
	}

	/* ─── Render: Landing / Auth ─── */

	if (!isAuthed) {
		if (view === "login") {
			return (
				<div className="auth-page" key="login">
					<div className="auth-card view-animate">
						<h1 className="auth-title">로그인</h1>
						<form className="auth-form" onSubmit={handleLogin}>
							<div className="form-group">
								<label className="form-label">아이디</label>
								<input type="text" value={loginUsername} onChange={(e) => setLoginUsername(e.target.value)} placeholder="아이디 입력" autoComplete="username" />
							</div>
							<div className="form-group">
								<label className="form-label">비밀번호</label>
								<input type="password" value={loginPass} onChange={(e) => setLoginPass(e.target.value)} placeholder="비밀번호 입력" autoComplete="current-password" />
							</div>
							{error && <div className="status-bar error">{error}</div>}
							<button type="submit" className="btn btn-primary btn-full" disabled={!canLogin || loginBusy}>
								{loginBusy ? "로그인 중..." : "로그인"}
							</button>
						</form>
						<p className="auth-hint">
							<button onClick={() => { setView("landing"); setError(null); }}>← 돌아가기</button>
						</p>
					</div>
				</div>
			);
		}

		if (view === "signup") {
			return (
				<div className="auth-page" key="signup">
					<div className="auth-card view-animate">
						<h1 className="auth-title">회원가입</h1>
						<form className="auth-form" onSubmit={handleSignup}>
							<div className="form-group">
								<label className="form-label">아이디</label>
								<input type="text" value={loginUsername} onChange={(e) => setLoginUsername(e.target.value)} placeholder="사용할 아이디" autoComplete="username" />
							</div>
							<div className="form-group">
								<label className="form-label">비밀번호</label>
								<input type="password" value={loginPass} onChange={(e) => setLoginPass(e.target.value)} placeholder="비밀번호 입력" autoComplete="new-password" />
							</div>
							<div className="form-group">
								<label className="form-label">비밀번호 확인</label>
								<input type="password" value={loginPassConfirm} onChange={(e) => setLoginPassConfirm(e.target.value)} placeholder="비밀번호 다시 입력" autoComplete="new-password" />
							</div>
							{error && <div className="status-bar error">{error}</div>}
							<button type="submit" className="btn btn-primary btn-full" disabled={!canLogin || loginBusy}>
								{loginBusy ? "처리 중..." : "가입하기"}
							</button>
						</form>
						<p className="auth-hint">
							<button onClick={() => { setView("landing"); setError(null); }}>← 돌아가기</button>
						</p>
					</div>
				</div>
			);
		}

		/* Landing */
		return (
			<div className="landing" key="landing">
				<div className="view-animate">
					<h1 className="brand">
						Yet<br />Another<br />Security
					</h1>
				</div>
				<div className="landing-buttons view-animate">
					<button className="btn btn-primary btn-full" onClick={() => { setView("login"); setError(null); setLoginUsername(""); setLoginPass(""); }}>
						로그인
					</button>
					<button className="btn btn-secondary btn-full" onClick={() => { setView("signup"); setError(null); setLoginUsername(""); setLoginPass(""); setLoginPassConfirm(""); }}>
						회원가입
					</button>
				</div>
			</div>
		);
	}

	/* ─── Render: Main App ─── */

	function renderStepDots(total: number, current: number) {
		return (
			<div className="step-dots">
				{Array.from({ length: total }, (_, i) => (
					<div key={i} className={`step-dot ${i + 1 === current ? "active" : i + 1 < current ? "done" : ""}`} />
				))}
			</div>
		);
	}

	/* ─── Contacts tab ─── */

	function renderContactsTab() {
		return (
			<>
				<br />
				<div className="section-header">
					<h2 className="section-title">주소록</h2>
					<button className="btn btn-secondary btn-sm" onClick={openAddContactModal}>+ 추가</button>
				</div>
				<p className="section-desc">상대방의 공개키를 관리하여 안전하게 암호화된 메시지를 주고받으세요.</p>

				{contactError && <div className="status-bar error">{contactError}</div>}

				{contactsLoading ? (
					<p className="text-hint text-center mt-4">불러오는 중...</p>
				) : contacts.length === 0 ? (
					<div className="empty-state">
						<p>저장된 연락처가 없습니다</p>
						<p className="text-hint">연락처를 추가하면 공개키 암호화를 시작할 수 있어요.</p>
					</div>
				) : (
					<div className="contact-list">
						{contacts.map((c) => (
							<div key={c.id} className="contact-row">
								<div className="contact-info">
									<div className="contact-name-row">
										<span className="contact-name">{c.contactUsername}</span>
										<span className={`contact-algo-badge algo-${detectPublicKeyAlgo(c.publicKey)}`}>
											{detectPublicKeyAlgo(c.publicKey) === "pqc1" ? "PQC" : detectPublicKeyAlgo(c.publicKey) === "ecc1" ? "ECC" : "RSA"}
										</span>
									</div>
									{c.notes && (
										<div className="contact-meta-row">
											<span className="contact-note">{c.notes}</span>
										</div>
									)}
								</div>
								<div className="contact-btns">
									<span className="contact-pk-preview" style={{ marginRight: "12px", opacity: 0.6 }}>
										{c.publicKey && c.publicKey.length > 20 ? `${c.publicKey.slice(0, 6)}…${c.publicKey.slice(-5)}` : c.publicKey}
									</span>
									<button className="btn-ghost btn-sm" onClick={() => { handleCopyPublicKey(c.publicKey); showToast("복사 되었습니다"); }}>복사</button>
									<button className="btn-ghost btn-sm" onClick={() => openEditContactModal(c)}>수정</button>
									<button className="btn-ghost btn-sm btn-danger" onClick={() => handleDeleteContact(c.id)}>삭제</button>
								</div>
							</div>
						))}
					</div>
				)}
			</>
		);
	}

	/* ─── Keys tab ─── */

	function renderKeysTab() {
		const hasStoredKey = Boolean(storedAccount?.publicKey && storedAccount?.encryptedPrivateKey?.cipherText);

		if (hasStoredKey && !showKeySection) {
			return (
				<>
					<br />
					<h2 className="section-title">내 키</h2>
					<p className="section-desc">키가 서버에 안전하게 저장되어 있어요.</p>
					<div className="card">
						<div className="key-item">
							<span className="key-label">공개키</span>
							<div className="key-value-row">
								<code className="key-truncated">{truncateKey(storedAccount!.publicKey)}</code>
								<button className="btn btn-ghost btn-sm" onClick={() => handleCopyPublicKey(storedAccount?.publicKey)}>
									{copyPublicStatus === "copied" ? "복사됨 ✓" : "복사"}
								</button>
							</div>
						</div>
						<div className="key-item">
							<span className="key-label">개인키</span>
							<span className="text-hint">서버에 암호화되어 저장됨</span>
						</div>
					</div>
					{status && <div className="status-bar success">{status}</div>}
					{error && <div className="status-bar error">{error}</div>}
					<div className="btn-row">
						<button className="btn btn-secondary" onClick={handleRegenerate}>키 재생성</button>
					</div>
				</>
			);
		}

		return (
			<>
				<h2 className="section-title">키 생성</h2>
				<p className="section-desc">암호화에 사용할 키 쌍을 생성하고 서버에 안전하게 저장합니다.</p>

				<div className="card">
					<div className="form-group">
						<label className="form-label">메모 (선택)</label>
						<input type="text" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="이 키에 대한 메모..." />
					</div>
					<div className="form-group">
						<label className="form-label">키 알고리즘</label>
						<div className="option-cards">
							<button className={`option-card ${keyAlgo === "pqc1" ? "selected" : ""}`} onClick={() => setKeyAlgo("pqc1")}>
								<span className="option-title">PQC1</span>
								<span className="option-desc">양자내성 하이브리드 키</span>
							</button>
							<button className={`option-card ${keyAlgo === "ecc1" ? "selected" : ""}`} onClick={() => setKeyAlgo("ecc1")}>
								<span className="option-title">Curve448</span>
								<span className="option-desc">높은 보안 강도 (추천)</span>
							</button>
							<button className={`option-card ${keyAlgo === "rsa1" ? "selected" : ""}`} onClick={() => setKeyAlgo("rsa1")}>
								<span className="option-title">RSA-2048</span>
								<span className="option-desc">호환성 우선</span>
							</button>
						</div>
					</div>
					<div className="btn-row">
						<button className="btn btn-secondary" onClick={handleGenerateKeys}>키 쌍 생성</button>
						<button className="btn btn-primary" onClick={handleUpload} disabled={!canUpload || busy}>
							{busy ? "처리 중..." : "암호화하여 저장"}
						</button>
					</div>
					{status && <div className="status-bar success mt-3">{status}</div>}
					{error && <div className="status-bar error mt-3">{error}</div>}
				</div>

				{/* Key preview */}
				<div className="card">
					<h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>미리보기</h3>
					<div className="key-item">
						<span className="key-label">공개키</span>
						<div className="key-full">
							{publicKeyPem || "(키 쌍을 생성하세요)"}
							{publicKeyPem && (
								<button className={`key-copy-btn ${copyPublicStatus === "copied" ? "copied" : ""}`} onClick={() => handleCopyPublicKey(publicKeyPem)}>
									{copyPublicStatus === "copied" ? "복사됨" : "복사"}
								</button>
							)}
						</div>
					</div>
					<div className="key-item">
						<span className="key-label">개인키 (평문)</span>
						<div className="key-full">
							{privateKeyPem || "(키 쌍을 생성하세요)"}
							{privateKeyPem && (
								<button className={`key-copy-btn ${copyPrivateStatus === "copied" ? "copied" : ""}`} onClick={() => handleCopyPrivateKey(privateKeyPem)}>
									{copyPrivateStatus === "copied" ? "복사됨" : "복사"}
								</button>
							)}
						</div>
					</div>
					<p className="text-hint mt-2">개인키는 브라우저에서 암호화된 후 서버에 안전하게 저장됩니다.</p>
				</div>
			</>
		);
	}

	/* ─── Encrypt tab (wizard) ─── */

	function renderEncryptTab() {
		if (encryptedBlob) {
			return (
				<>
					<h2 className="section-title">암호화 완료</h2>
					<div className="card">
						<div className="result-grid">
							<div className="result-item">
								<span className="result-label">방식</span>
								<span className="result-value">{encryptAuthMode === "password" ? "비밀번호" : "공개키"}</span>
							</div>
							<div className="result-item">
								<span className="result-label">크기</span>
								<span className="result-value">{formatBytes(encryptedBlob.length)}</span>
							</div>
							<div className="result-item">
								<span className="result-label">알고리즘</span>
								<span className="result-value">{encryptEncAlgo === "gcmx1" ? "대용량" : "표준"}</span>
							</div>
						</div>
						<div className="btn-row">
							{encryptedBlob.length < 10240 && (
								<button className="btn btn-secondary btn-sm" onClick={handleCopyEncryptedBase64}>Base64 복사</button>
							)}
							<button className="btn btn-secondary btn-sm" onClick={handleDownloadEncryptedBlob}>파일 다운로드</button>
						</div>
					</div>
					{encryptStatus && <div className="status-bar success">{encryptStatus}</div>}
					<div className="btn-row mt-3">
						<button className="btn btn-primary" onClick={resetEncryptionForm}>처음으로</button>
					</div>
				</>
			);
		}

		return (
			<div className="view-animate" key={`enc-step-${encryptStep}`}>
				{renderStepDots(4, encryptStep)}

				{encryptStep === 1 && (
					<>
						<h2 className="section-title">암호화</h2>
						<p className="section-desc">어떤 방식으로 데이터를 보호할까요?</p>
						<div className="option-cards">
							<button className="option-card" onClick={() => { setEncryptAuthMode("password"); setEncryptStep(2); }}>
								<span className="option-title">🔑 비밀번호</span>
								<span className="option-desc">비밀번호를 아는 사람만 열 수 있어요.</span>
							</button>
							<button className="option-card" onClick={() => { setEncryptAuthMode("publickey"); setEncryptStep(2); }}>
								<span className="option-title">👤 공개키</span>
								<span className="option-desc">지정한 상대방만 열 수 있도록 보호해요. 먼저 주소록에 상대방의 공개키를 등록해주세요.</span>
							</button>
						</div>
					</>
				)}

				{encryptStep === 2 && encryptAuthMode === "password" && (
					<>
						<h2 className="section-title">비밀번호 설정</h2>
						<p className="section-desc">암호화에 사용할 비밀번호를 입력하세요.</p>
						<div className="form-group">
							<label className="form-label">비밀번호</label>
							<input type="password" value={encryptPassword} onChange={(e) => setEncryptPassword(e.target.value)} placeholder="비밀번호 입력" autoFocus />
						</div>
						<div className="form-group">
							<label className="form-label">키 유도 방식</label>
							<div className="option-cards row-layout">
								<button className={`option-card ${encryptKdfMethod === "arg1" ? "selected" : ""}`} onClick={() => setEncryptKdfMethod("arg1")}>
									<span className="option-title">Argon2id</span>
									<span className="option-desc">높은 보안 강도 (추천)</span>
								</button>
								<button className={`option-card ${encryptKdfMethod === "pbk1" ? "selected" : ""}`} onClick={() => setEncryptKdfMethod("pbk1")}>
									<span className="option-title">PBKDF2</span>
									<span className="option-desc">호환성 우선</span>
								</button>
							</div>
						</div>
						<div className="btn-row">
							<button className="btn btn-secondary" onClick={() => setEncryptStep(1)}>이전</button>
							<button className="btn btn-primary" disabled={!encryptPassword} onClick={() => setEncryptStep(3)}>다음</button>
						</div>
					</>
				)}

				{encryptStep === 2 && encryptAuthMode === "publickey" && (
					<>
						<h2 className="section-title">수신자 설정</h2>
						<p className="section-desc">암호화된 데이터를 받을 사람을 선택하세요.</p>
						<div className="form-group">
							<label className="form-label">수신자</label>
							<select value={encryptRecipientId} onChange={(e) => {
								const value = e.target.value;
								setEncryptRecipientId(value);
								if (value) {
									const selected = contacts.find((c) => c.id === value);
									if (selected) {
										const detectedAlgo = detectPublicKeyAlgo(selected.publicKey);
										setEncryptAsymAlgo(detectedAlgo);
									}
								} else {
									setEncryptAsymAlgo(null);
								}
							}}>
								<option value="">연락처에서 선택...</option>
								{contacts.map((c) => (
									<option key={c.id} value={c.id}>{c.contactUsername}</option>
								))}
							</select>
							{contacts.length === 0 && <span className="text-hint">주소록에 연락처를 먼저 추가하세요.</span>}
						</div>
						<div className="form-group">
							<label className="form-label">비대칭 알고리즘</label>
							<div className="option-cards">
								<button
									className={`option-card ${encryptAsymAlgo === "pqc1" ? "selected" : ""}`}
									disabled
								>
									<span className="option-title">PQC1</span>
									<span className="option-desc">양자내성 하이브리드</span>
									{encryptAsymAlgo === "pqc1" && <span className="option-badge">자동 선택</span>}
								</button>
								<button
									className={`option-card ${encryptAsymAlgo === "ecc1" ? "selected" : ""}`}
									disabled
								>
									<span className="option-title">Curve448</span>
									<span className="option-desc">높은 보안 강도 (추천)</span>
									{encryptAsymAlgo === "ecc1" && <span className="option-badge">자동 선택</span>}
								</button>
								<button
									className={`option-card ${encryptAsymAlgo === "rsa1" ? "selected" : ""}`}
									disabled
								>
									<span className="option-title">RSA-2048</span>
									<span className="option-desc">호환성 우선</span>
									{encryptAsymAlgo === "rsa1" && <span className="option-badge">자동 선택</span>}
								</button>
							</div>
							<span className="form-hint">상대방의 공개키 형식에 따라 자동으로 선택됩니다</span>
						</div>
						<label className="checkbox-row">
							<input
								type="checkbox"
								checked={encryptSignWithKey}
								onChange={(e) => { void handleEncryptSignWithKeyToggle(e.target.checked); }}
								disabled={encryptBusy || webauthnAuthBusy}
							/>
							<div className="checkbox-label-with-help">
								<span className="checkbox-text">내 개인키로 서명하기</span>
								<div className="help-icon-wrapper">
									<svg
										className="help-icon"
										width="14"
										height="14"
										viewBox="0 0 24 24"
										fill="none"
										stroke="currentColor"
										strokeWidth="2"
										strokeLinecap="round"
										strokeLinejoin="round"
										onMouseEnter={() => setShowSigningTooltip(true)}
										onMouseLeave={() => setShowSigningTooltip(false)}
										onClick={() => setShowSigningTooltip(!showSigningTooltip)}
									>
										<circle cx="12" cy="12" r="10" />
										<path d="M12 16v-4M12 8h.01" />
									</svg>
									{showSigningTooltip && (
										<div className="tooltip">
											내 개인키로 암호문에 서명하여 상대방은 이것이 진짜 나로부터 온 메시지임을 확인할 수 있어요.
										</div>
									)}
								</div>
							</div>
						</label>
						<div className="btn-row">
							<button className="btn btn-secondary" onClick={() => setEncryptStep(1)}>이전</button>
							<button className="btn btn-primary" disabled={!encryptRecipientId} onClick={() => setEncryptStep(3)}>다음</button>
						</div>
					</>
				)}

				{encryptStep === 3 && (
					<>
						<h2 className="section-title">암호화 방식</h2>
						<p className="section-desc">데이터를 암호화할 방식을 선택하세요.</p>
						<div className="option-cards">
							<button className="option-card" onClick={() => { setEncryptEncAlgo("gcm1"); setEncryptStep(4); }}>
								<span className="option-title">표준 (AES-GCM)</span>
								<span className="option-desc">일반적인 텍스트와 파일에 적합합니다</span>
							</button>
							<button className="option-card" onClick={() => { setEncryptEncAlgo("gcmx1"); setEncryptStep(4); }}>
								<span className="option-title">대용량 파일 전용 (AES-GCM 청크)</span>
								<span className="option-desc">대용량 파일을 효율적으로 처리합니다</span>
							</button>
						</div>
						<div className="btn-row">
							<button className="btn btn-secondary" onClick={() => setEncryptStep(2)}>이전</button>
						</div>
					</>
				)}

				{encryptStep === 4 && (
					<>
						<h2 className="section-title">데이터 입력</h2>
						<p className="section-desc">암호화할 내용을 입력하세요.</p>

						<div className="form-group">
							<label className="form-label">공개 메시지 (선택)</label>
							<input type="text" value={encryptMsg} onChange={(e) => setEncryptMsg(e.target.value)} placeholder="암호화 없이 표시되는 메시지" />
							<span className="form-hint">이 메시지는 복호화 없이도 볼 수 있어요</span>
						</div>

						<div className="tab-toggle">
							<button className={encryptMode === "text" ? "active" : ""} onClick={() => handleEncryptionModeChange("text")}>텍스트</button>
							<button className={encryptMode === "file" ? "active" : ""} onClick={() => handleEncryptionModeChange("file")}>파일</button>
						</div>

						{encryptMode === "text" ? (
							<div className="form-group">
								<label className="form-label">비밀 메시지</label>
								<textarea value={encryptSmsg} onChange={(e) => { setEncryptSmsg(e.target.value); setEncryptError(null); }} placeholder="암호화할 메시지 입력" />
							</div>
						) : (
							<div className="form-group">
								<div
									className={`file-drop ${isFileDragActive ? "active" : ""}`}
									onDragEnter={handleFileDragEnter}
									onDragOver={handleFileDragOver}
									onDragLeave={handleFileDragLeave}
									onDrop={handleFileDrop}
								>
									<input id="encrypt-file" type="file" onChange={handleEncryptFileChange} disabled={encryptBusy} className="sr-only" />
									<label htmlFor="encrypt-file" style={{ cursor: "pointer" }}>
										<div className="file-drop-icon">📁</div>
										<p className="file-drop-text">파일을 끌어놓거나 클릭하세요</p>
										<p className="file-drop-hint">브라우저에서 암호화됩니다</p>
									</label>
								</div>
								{encryptFile && (
									<div className="file-info-bar">
										<div>
											<span className="file-info-name">{encryptFile.name}</span>
											<span className="file-info-size"> · {formatBytes(encryptFile.size)}</span>
										</div>
										<button className="btn-ghost btn-sm" onClick={() => applySelectedEncryptFile(null)}>제거</button>
									</div>
								)}
							</div>
						)}

						{encryptError && <div className="status-bar error">{encryptError}</div>}
						{encryptBusy && <div className="progress-bar"><div className="progress-fill" /></div>}

						<div className="btn-row">
							<button className="btn btn-secondary" onClick={() => setEncryptStep(3)}>이전</button>
							<button className="btn btn-primary" disabled={encryptBusy} onClick={handleEncryptSubmit}>
								{encryptBusy ? "암호화 중..." : "암호화"}
							</button>
						</div>
					</>
				)}
			</div>
		);
	}

	/* ─── Decrypt tab (wizard) ─── */

	function renderDecryptTab() {
		if (decryptedResult) {
			const rows: { label: string; value: string }[] = [];
			if (decryptedResult.msg) rows.push({ label: "공개 메시지", value: decryptedResult.msg });
			if (decryptedResult.smsg) rows.push({ label: "비밀 메시지", value: decryptedResult.smsg });
			if (decryptedResult.files.length > 0) rows.push({ label: "파일", value: `${decryptedResult.files.length}개` });

			return (
				<>
					<h2 className="section-title">복호화 결과</h2>
					<br />
					{decryptStatus && <div className="status-bar success">{decryptStatus}</div>}
					
					{/* Signature verification result */}
					{decryptedResult.verified === true && (
						<div className="status-bar success" style={{ marginBottom: 12 }}>
							✓ 서명 검증 성공 - 발신자의 신원이 확인되었습니다
						</div>
					)}
					{decryptedResult.verified === false && decryptedResult.verifyError && (
						<div className="status-bar error" style={{ marginBottom: 12 }}>
							✗ 서명 검증 실패: {decryptedResult.verifyError}
						</div>
					)}
					{decryptedResult.verifyError && decryptedResult.verified !== false && (
						<div className="status-bar error" style={{ marginBottom: 12 }}>
							⚠ {decryptedResult.verifyError}
						</div>
					)}

					<div className="card">
						{rows.map((r) => (
							<div key={r.label} style={{ marginBottom: 14 }}>
								<span className="result-label">{r.label}</span>
								<p style={{ whiteSpace: "pre-wrap", marginTop: 4, fontSize: 15, fontWeight: 500 }}>{r.value}</p>
							</div>
						))}
						
						{/* Show signature status in result */}
						<div style={{ marginBottom: 0, paddingTop: 8, borderTop: "1px solid var(--border)" }}>
							<span className="result-label">서명 상태</span>
							<p style={{ whiteSpace: "pre-wrap", marginTop: 4, fontSize: 15, fontWeight: 500 }}>
								{decryptedResult.verified === true && "✓ 유효 (발신자 확인됨)"}
								{decryptedResult.verified === false && "✗ 유효하지 않음 (경고)"}
								{decryptedResult.verified === undefined && (decryptedResult.verifyError ? `- ${decryptedResult.verifyError}` : "- 서명 검증 생략됨 (공개키 미제공)")}
							</p>
						</div>
					</div>

					{decryptedResult.files.length > 0 && (
						<div className="card">
							<h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>추출된 파일</h3>
							{decryptedResult.files.map((f, i) => (
								<div key={i} className="file-info-bar" style={{ marginTop: i > 0 ? 8 : 0 }}>
									<div>
										<span className="file-info-name">{f.name}</span>
										<span className="file-info-size"> · {formatBytes(f.data.length)}</span>
									</div>
									<button className="btn btn-secondary btn-sm" onClick={() => handleDownloadDecryptedFile(f.name, f.data)}>다운로드</button>
								</div>
							))}
						</div>
					)}

					<div className="btn-row mt-3">
						<button className="btn btn-primary" onClick={resetDecryptForm}>처음으로</button>
					</div>
				</>
			);
		}

		return (
			<div className="view-animate" key={`dec-step-${decryptStep}`}>
				{decryptDetected?.mode === "publickey" ? renderStepDots(3, decryptStep) : renderStepDots(2, decryptStep)}

				{decryptStep === 1 && (
					<>
						<h2 className="section-title">복호화</h2>
						<p className="section-desc">암호화된 데이터를 불러오세요.</p>

						<div className="form-group">
							<div
								className={`file-drop ${isDecryptFileDragActive ? "active" : ""}`}
								onDragEnter={handleDecryptDragEnter}
								onDragOver={handleDecryptDragOver}
								onDragLeave={handleDecryptDragLeave}
								onDrop={handleDecryptFileDrop}
							>
								<input id="decrypt-file" type="file" onChange={handleDecryptFileChange} disabled={decryptBusy} className="sr-only" />
								<label htmlFor="decrypt-file" style={{ cursor: "pointer" }}>
									<div className="file-drop-icon">📂</div>
									<p className="file-drop-text">암호화된 파일을 끌어놓거나 클릭하세요</p>
									<p className="file-drop-hint">.bin 파일을 여기에 놓으세요</p>
								</label>
							</div>
							{decryptPayloadFile && (
								<div className="file-info-bar">
									<div>
										<span className="file-info-name">{decryptPayloadFile.name}</span>
										<span className="file-info-size"> · {formatBytes(decryptPayloadFile.size)}</span>
									</div>
									<button className="btn-ghost btn-sm" onClick={() => { setDecryptPayloadFile(null); setDecryptDetected(null); }}>제거</button>
								</div>
							)}
						</div>

						<div className="form-group">
							<label className="form-label">또는 Base64 텍스트 붙여넣기</label>
							<textarea
								value={decryptPayloadInput}
								onChange={(e) => {
									const val = e.target.value;
									setDecryptPayloadInput(val);
									setDecryptPayloadFile(null);
									setDecryptError(null);
									if (val.trim()) {
										try { tryAutoDetect(base64ToU8(val.trim())); } catch { setDecryptDetected(null); }
									} else { setDecryptDetected(null); }
								}}
								placeholder="Base64로 인코딩된 암호문..."
								disabled={decryptBusy}
							/>
						</div>

						{decryptError && <div className="status-bar error">{decryptError}</div>}

						<div className="btn-row btn-row-right">
							<button className="btn btn-primary" disabled={!decryptPayloadFile && !decryptPayloadInput.trim()} onClick={handleDecryptAdvanceToStep2}>
								다음
							</button>
						</div>
					</>
				)}

				{decryptStep === 2 && (
					<>
						<h2 className="section-title">복호화 설정</h2>
						<br />
						{decryptDetected && (
							<div className="card mb-3">
								<div className="result-grid">
									<div className="result-item">
										<span className="result-label">감지된 방식</span>
										<span className="result-value">{decryptDetected.mode === "password" ? "🔑 비밀번호" : "👤 공개키"}</span>
									</div>
									<div className="result-item">
										<span className="result-label">알고리즘</span>
										<span className="result-value">{decryptDetected.algo}</span>
									</div>
								</div>
								{decryptDetected.msg && (
									<div className="detected-msg">
										<p className="detected-msg-label">공개 메시지</p>
										<pre className="detected-msg-body">{decryptDetected.msg}</pre>
									</div>
								)}
							</div>
						)}

						{/* Password mode */}
						{decryptDetected?.mode === "password" && (
							<div className="form-group">
								<label className="form-label">비밀번호</label>
								<input
									type="password"
									value={decryptPassword}
									onChange={(e) => { setDecryptPassword(e.target.value); setDecryptError(null); }}
									placeholder="암호화에 사용한 비밀번호"
									disabled={decryptBusy}
									autoFocus
								/>
							</div>
						)}

						{/* Public key mode - Private key input */}
						{decryptDetected?.mode === "publickey" && (
							<>
								<div className="form-group">
									<label className="form-label">개인키</label>
									<div className="tab-toggle mb-2">
										<button 
											className={decryptPrivateKeySource === "security" ? "active" : ""} 
											onClick={() => {
												if (storedAccount?.encryptedPrivateKey && isAuthed && webauthnAvailable) {
													setDecryptPrivateKeySource("security");
												} else {
													setDecryptPrivateKeySource("manual");
												}
											}}
										>
											보안 키로 인증
										</button>
										<button className={decryptPrivateKeySource === "manual" ? "active" : ""} onClick={() => setDecryptPrivateKeySource("manual")}>직접 입력</button>
									</div>
									
									{decryptPrivateKeySource === "security" ? (
										<>
											{storedAccount?.encryptedPrivateKey && isAuthed && webauthnAvailable ? (
												<>
													<button className="btn btn-secondary btn-full" onClick={handleWebAuthnAuthenticate} disabled={decryptBusy || webauthnAuthBusy}>
														{webauthnAuthBusy ? "인증 중..." : "🔐 보안 키로 인증"}
													</button>
													{decryptionToken && <p className="text-hint mt-3" style={{ color: "var(--success)" }}>✓ 보안 키 인증 완료</p>}
												</>
											) : (
												<p className="text-hint">저장된 키가 없거나 WebAuthn이 불가능합니다. 직접 입력을 사용하세요.</p>
											)}
										</>
									) : (
										<textarea
											value={decryptPrivateKeyInput}
											onChange={(e) => { setDecryptPrivateKeyInput(e.target.value); setDecryptError(null); }}
											placeholder="Base64로 인코딩된 개인키"
											disabled={decryptBusy}
											autoFocus
										/>
									)}
								</div>
							</>
						)}

						{decryptStatus && <div className="status-bar info">{decryptStatus}</div>}
						{decryptError && <div className="status-bar error">{decryptError}</div>}
						{decryptBusy && <div className="progress-bar"><div className="progress-fill" /></div>}

						<div className="btn-row">
							<button className="btn btn-secondary" onClick={() => setDecryptStep(1)}>이전</button>
							<button className="btn btn-primary" disabled={decryptBusy || (decryptDetected?.mode === "publickey" && decryptPrivateKeySource === "manual" && !decryptPrivateKeyInput.trim()) || (decryptDetected?.mode === "publickey" && decryptPrivateKeySource === "security" && !decryptionToken) || (decryptDetected?.mode === "password" && !decryptPassword)} onClick={() => {
								if (decryptDetected?.mode === "publickey") {
									setDecryptStep(3);
								} else {
									handleDecryptSubmit();
								}
							}}>
								{decryptDetected?.mode === "publickey" ? "다음" : "복호화"}
							</button>
						</div>
					</>
				)}

				{decryptStep === 3 && decryptDetected?.mode === "publickey" && (
					<>
						<h2 className="section-title">서명 검증</h2>
						<p className="section-desc">발신자의 공개키를 입력하여 서명을 검증할 수 있습니다 (선택).</p>

						<div className="form-group">
							<label className="form-label">발신자의 공개키</label>
							<div className="tab-toggle mb-2">
								<button className={decryptPeerKeySource === "contact" ? "active" : ""} onClick={() => setDecryptPeerKeySource("contact")}>연락처에서</button>
								<button className={decryptPeerKeySource === "manual" ? "active" : ""} onClick={() => setDecryptPeerKeySource("manual")}>직접 입력</button>
							</div>
							{decryptPeerKeySource === "contact" ? (
								<select
									value={decryptSelectedContactId}
									onChange={(e) => {
										const id = e.target.value;
										setDecryptSelectedContactId(id);
										const contact = contacts.find((c) => c.id === id);
										setDecryptPeerPublicKey(contact?.publicKey ?? "");
									}}
									disabled={decryptBusy || contacts.length === 0}
								>
									<option value="">{contacts.length === 0 ? "저장된 연락처 없음" : "연락처 선택..."}</option>
									{contacts.map((c) => (
										<option key={c.id} value={c.id}>{c.contactUsername}{c.notes ? ` — ${c.notes}` : ""}</option>
									))}
								</select>
							) : (
								<textarea
									value={decryptPeerPublicKey}
									onChange={(e) => { setDecryptPeerPublicKey(e.target.value); setDecryptSelectedContactId(""); }}
									placeholder="Base64로 인코딩된 공개키 (선택)"
									disabled={decryptBusy}
								/>
							)}
							<span className="form-hint">서명 검증이 필요하지 않으면 비워도 됩니다</span>
						</div>

						{decryptStatus && <div className="status-bar info">{decryptStatus}</div>}
						{decryptError && <div className="status-bar error">{decryptError}</div>}
						{decryptBusy && <div className="progress-bar"><div className="progress-fill" /></div>}

						<div className="btn-row">
							<button className="btn btn-secondary" onClick={() => setDecryptStep(2)}>이전</button>
							<button className="btn btn-primary" disabled={decryptBusy || (decryptPrivateKeySource === "manual" && !decryptPrivateKeyInput.trim()) || (decryptPrivateKeySource === "security" && !decryptionToken)} onClick={handleDecryptSubmit}>
								{decryptBusy ? "복호화 중..." : "복호화"}
							</button>
						</div>
					</>
				)}
			</div>
		);
	}

	/* ─── Tab content router ─── */

	function renderTabContent() {
		switch (tab) {
			case "contacts": return renderContactsTab();
			case "keys": return renderKeysTab();
			case "encrypt": return renderEncryptTab();
			case "decrypt": return renderDecryptTab();
		}
	}

	/* ─── Main layout ─── */

	return (
		<div className="page">
			<div className="topbar">
				<div className="topbar-left">
					<span className="topbar-brand">YAS</span>
					<span className="topbar-user">{authUsername}</span>
				</div>
				<div className="topbar-right">
					<button
						className="theme-toggle"
						onClick={() => setThemeMode(prev => prev === "system" ? (resolvedDark ? "light" : "dark") : prev === "light" ? "dark" : "system")}
						title={themeMode === "system" ? "시스템 테마" : resolvedDark ? "다크 모드" : "라이트 모드"}
					>
						{themeMode === "system" ? (
							<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8" /><path d="M12 17v4" /></svg>
						) : resolvedDark ? (
							<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" /></svg>
						) : (
							<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5" /><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" /></svg>
						)}
					</button>
					<button className="topbar-logout" onClick={handleSignOut}>로그아웃</button>
				</div>
			</div>

			<nav className="pill-nav">
				<div className="pill-nav-inner" ref={navInnerRef}>
					{(["keys", "contacts", "encrypt", "decrypt"] as Tab[]).map((t) => {
						const ref = { contacts: navContactsRef, keys: navKeysRef, encrypt: navEncryptRef, decrypt: navDecryptRef }[t];
						const Icon = { contacts: IconContacts, keys: IconKey, encrypt: IconEncrypt, decrypt: IconDecrypt }[t];
						const title = { contacts: "주소록", keys: "내 키", encrypt: "암호화", decrypt: "복호화" }[t];
						return (
							<button
								key={t}
								ref={ref}
								className={`pill-nav-item ${tab === t ? "active" : ""}`}
								onClick={() => { setPressedTab(null); setTab(t); }}
								onPointerDown={() => { if (t !== tab) setPressedTab(t); }}
								onPointerUp={() => setPressedTab(null)}
								onPointerLeave={() => setPressedTab(null)}
								onPointerCancel={() => setPressedTab(null)}
								title={title}
							>
								<Icon active={tab === t} />
							</button>
						);
					})}
				</div>
			</nav>

			<div className="view-animate" key={tab}>
				{renderTabContent()}
			</div>

			{toastMsg && <div className="toast-message">{toastMsg}</div>}

			{/* Contact modal */}
			{(contactModalOpen || contactModalClosing) && (
				<div className={`modal-overlay ${contactModalClosing ? "closing" : ""}`} onClick={(e) => { if (e.target === e.currentTarget) closeContactModal(); }}>
					<div className={`modal-box ${contactModalClosing ? "closing" : ""}`}>
						<h3 className="modal-title">{contactModalMode === "add" ? "연락처 추가" : "연락처 수정"}</h3>
						<form onSubmit={handleContactSubmit}>
							<div className="form-group">
								<label className="form-label">
									사용자 아이디
									<div className="help-icon-wrapper">
										<svg
											className="help-icon"
											width="16"
											height="16"
											viewBox="0 0 24 24"
											fill="none"
											stroke="currentColor"
											strokeWidth="2"
											strokeLinecap="round"
											strokeLinejoin="round"
											onMouseEnter={() => setShowUsernameTooltip(true)}
											onMouseLeave={() => setShowUsernameTooltip(false)}
											onClick={() => setShowUsernameTooltip(!showUsernameTooltip)}
										>
											<circle cx="12" cy="12" r="10" />
											<path d="M12 16v-4M12 8h.01" />
										</svg>
										{showUsernameTooltip && (
											<div className="tooltip">
												상대방이 서비스에 가입할 때 사용한 실제 아이디(username)를 정확히 입력해야 합니다.
											</div>
										)}
									</div>
								</label>
								<input
									type="text"
									value={contactForm.contactUsername}
									onChange={(e) => setContactForm((prev) => ({ ...prev, contactUsername: e.target.value }))}
									placeholder="아이디"
									required
								/>
							</div>
							<div className="form-group">
								<label className="form-label">메모 (선택)</label>
								<input
									type="text"
									value={contactForm.notes}
									onChange={(e) => setContactForm((prev) => ({ ...prev, notes: e.target.value }))}
									placeholder="간단한 메모"
								/>
							</div>
							{contactModalError && <div className="status-bar error">{contactModalError}</div>}
							<div className="modal-footer">
								<button type="button" className="btn btn-ghost" onClick={closeContactModal}>취소</button>
								<button type="submit" className="btn btn-primary" disabled={contactBusy || !contactForm.contactUsername.trim()}>
									{contactBusy ? "저장 중..." : contactModalMode === "add" ? "저장" : "수정"}
								</button>
							</div>
						</form>
					</div>
				</div>
			)}
		</div>
	);
}

export default App;
