import { useEffect, useRef, useState } from "react";
import generate from "random-words";
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
	listWebAuthnCredentials,
	removeWebAuthnCredential,
	decryptStoredPrivateKey,
} from "./api";
import {
	buildAccountPayload,
	generateKeyPair,
	encryptOpsec,
	decryptOpsecPw,
	decryptOpsecPub,
	detectAuthMode,
	decryptPrivateKey,
	u8ToBase64,
	base64ToU8,
	registerWebAuthnCredential,
	authenticateWithWebAuthn,
	isWebAuthnAvailable,
	isPlatformAuthenticatorAvailable,
	arrayBufferToBase64,
	base64ToArrayBuffer,
} from "./crypto";
import type { AsymAlgo, KdfMethod, EncAlgo, AuthMode, DecryptResult } from "./crypto";
import type { AccountRecord, ContactRecord } from "./types";

type IconProps = { active?: boolean };

function formatBytes(bytes: number): string {
	if (!Number.isFinite(bytes) || bytes <= 0) {
		return "0 B";
	}
	const units = ["B", "KB", "MB", "GB", "TB"];
	let value = bytes;
	let unitIndex = 0;
	while (value >= 1024 && unitIndex < units.length - 1) {
		value /= 1024;
		unitIndex += 1;
	}
	const digits = value < 10 && unitIndex > 0 ? 1 : 0;
	return `${value.toFixed(digits)} ${units[unitIndex]}`;
}

function formatTimestamp(value?: string | number | null): string | null {
	if (!value) return null;
	const date = typeof value === "string" ? new Date(value) : new Date(value);
	if (Number.isNaN(date.getTime())) {
		return typeof value === "string" ? value : String(value);
	}
	return date.toLocaleString();
}

function IconHome({ active }: IconProps) {
	const stroke = active ? "#38bdf8" : "#94a3b8";
	return (
		<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
			<path d="M3 10.5 12 3l9 7.5" />
			<path d="M5 12v7.5a.5.5 0 0 0 .5.5H10v-5h4v5h4.5a.5.5 0 0 0 .5-.5V12" />
		</svg>
	);
}

function IconBook({ active }: IconProps) {
	const stroke = active ? "#38bdf8" : "#94a3b8";
	return (
		<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
			<path d="M5 4h11a3 3 0 0 1 3 3v12" />
			<path d="M5 20h11a3 3 0 0 0 3-3" />
			<path d="M5 20a3 3 0 0 1 0-6h14" />
			<path d="M9 8h6" />
			<path d="M9 12h3" />
		</svg>
	);
}

function IconLock({ active }: IconProps) {
	const stroke = active ? "#38bdf8" : "#94a3b8";
	return (
		<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
			<rect x="4" y="11" width="16" height="10" rx="2" />
			<path d="M8 11V7a4 4 0 0 1 8 0v4" />
			<path d="M12 15v2" />
		</svg>
	);
}

function IconUnlock({ active }: IconProps) {
	const stroke = active ? "#38bdf8" : "#94a3b8";
	return (
		<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
			<rect x="4" y="11" width="16" height="10" rx="2" />
			<path d="M16 11V7a4 4 0 0 0-8 0" />
			<path d="M12 15v2" />
		</svg>
	);
}

type Tab = "keys" | "address-book" | "encrypt" | "decrypt";

function App() {
	const [authToken, setAuthToken] = useState<string | null>(() => localStorage.getItem("authToken"));
	const [authUsername, setAuthUsername] = useState<string | null>(() => localStorage.getItem("authUsername"));
	const [authMode, setAuthMode] = useState<"login" | "signup">("login");
	const [loginUsername, setLoginUsername] = useState("");
	const [loginPass, setLoginPass] = useState("");
	const [loginPassConfirm, setLoginPassConfirm] = useState("");
	const [loginBusy, setLoginBusy] = useState(false);

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
	const [contacts, setContacts] = useState<ContactRecord[]>([]);
	const [contactsLoading, setContactsLoading] = useState(false);
	const [contactForm, setContactForm] = useState({ contactUsername: "", publicKey: "", notes: "" });
	const [contactError, setContactError] = useState<string | null>(null);
	const [contactBusy, setContactBusy] = useState(false);
	const [contactModalOpen, setContactModalOpen] = useState(false);
	const [contactModalClosing, setContactModalClosing] = useState(false);
	const [contactModalMode, setContactModalMode] = useState<"add" | "edit">("add");
	const [editingContactMeta, setEditingContactMeta] = useState<{ id: string; username: string } | null>(null);
	const [contactModalError, setContactModalError] = useState<string | null>(null);
	const closeModalTimer = useRef<number | null>(null);
	const [keyAlgo, setKeyAlgo] = useState<AsymAlgo>("ecc1");
	const [encryptAuthMode, setEncryptAuthMode] = useState<AuthMode>("password");
	const [encryptKdfMethod, setEncryptKdfMethod] = useState<KdfMethod>("pbk1");
	const [encryptEncAlgo, setEncryptEncAlgo] = useState<EncAlgo>("gcm1");
	const [encryptAsymAlgo, setEncryptAsymAlgo] = useState<AsymAlgo>("ecc1");
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
	const [decryptPayloadInput, setDecryptPayloadInput] = useState("");
	const [decryptPayloadFile, setDecryptPayloadFile] = useState<File | null>(null);
	const [isDecryptFileDragActive, setIsDecryptFileDragActive] = useState(false);
	const [decryptPassword, setDecryptPassword] = useState("");
	const [decryptPrivateKeyInput, setDecryptPrivateKeyInput] = useState("");
	const [decryptPeerPublicKey, setDecryptPeerPublicKey] = useState("");
	const [decryptDetected, setDecryptDetected] = useState<{ mode: AuthMode; algo: string; msg: string } | null>(null);
	const [decryptBusy, setDecryptBusy] = useState(false);
	const [decryptStatus, setDecryptStatus] = useState<string | null>(null);
	const [decryptError, setDecryptError] = useState<string | null>(null);
	const [decryptedResult, setDecryptedResult] = useState<DecryptResult | null>(null);
	
	// WebAuthn states
	const [webauthnAvailable, setWebauthnAvailable] = useState(false);
	const [webauthnAuthBusy, setWebauthnAuthBusy] = useState(false);
	const [decryptionToken, setDecryptionToken] = useState<string | null>(null);

	useEffect(() => {
		return () => {
			if (closeModalTimer.current) {
				window.clearTimeout(closeModalTimer.current);
				closeModalTimer.current = null;
			}
		};
	}, []);

	useEffect(() => {
		if (!encryptedBlob) return;
		const blob = new Blob([encryptedBlob.buffer.slice(encryptedBlob.byteOffset, encryptedBlob.byteOffset + encryptedBlob.byteLength) as ArrayBuffer], { type: "application/octet-stream" });
		const url = URL.createObjectURL(blob);
		const link = document.createElement("a");
		link.href = url;
		link.download = `encrypted-${Date.now()}.bin`;
		link.click();
		URL.revokeObjectURL(url);
	}, [encryptedBlob]);

	const canUpload = Boolean(username && publicKeyPem && privateKeyPem);
	const canLogin = Boolean(loginUsername && loginPass && (authMode === "login" || loginPass === loginPassConfirm));
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
				if (!cancelled) {
					setContacts([]);
					setContactsLoading(false);
				}
				return;
			}
			if (!cancelled) {
				setContactsLoading(true);
				setContactError(null);
			}
			try {
				const items = await listContacts(authToken);
				if (!cancelled) {
					setContacts(items);
				}
			} catch (err) {
				const errMsg = (err as Error).message || "Failed to load contacts";
				console.error(err);
				if (errMsg === "TOKEN_EXPIRED") {
					// Token expired, auto-logout
					handleSignOut();
					return;
				}
				if (!cancelled) {
					setContactError(errMsg);
				}
			} finally {
				if (!cancelled) {
					setContactsLoading(false);
				}
			}
		}
		loadContacts();
		return () => {
			cancelled = true;
		};
	}, [authToken]);

	// Check WebAuthn availability
	useEffect(() => {
		if (!authToken) {
			setWebauthnAvailable(false);
			return;
		}
		setWebauthnAvailable(isWebAuthnAvailable());
	}, [authToken]);

	useEffect(() => {
		if (authUsername) {
			setUsername(authUsername);
		} else {
			setUsername("");
		}
	}, [authUsername]);

	useEffect(() => {
		let cancelled = false;
		const usernameSnapshot = authUsername?.trim();

		setStoredAccount(null);
		setShowKeySection(true);
		setPublicKeyPem("");
		setPrivateKeyPem("");
		setCopyPrivateStatus("idle");

		if (!usernameSnapshot) {
			return () => {
				cancelled = true;
			};
		}

		async function loadStored() {
			try {
				const record = await getAccountByUsername(usernameSnapshot as string);
				if (!cancelled && authUsername === usernameSnapshot) {
					setStoredAccount(record);
					setShowKeySection(!record);
					if (record) {
						setPublicKeyPem(record.publicKey);
						setStatus(null);
					}
				}
			} catch (err) {
				console.error(err);
				if (!cancelled && authUsername === usernameSnapshot) {
					setStoredAccount(null);
					setShowKeySection(true);
				}
			}
		}
		loadStored();
		return () => {
			cancelled = true;
		};
	}, [authUsername]);

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
			console.error(err);
			setError((err as Error).message || "Login failed");
		} finally {
			setLoginBusy(false);
		}
	}

	async function handleCopyPublicKey(value?: string) {
		if (!value) return;
		try {
			await navigator.clipboard.writeText(value);
			setCopyPublicStatus("copied");
			setTimeout(() => setCopyPublicStatus("idle"), 2000);
		} catch (err) {
			console.error(err);
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
		} catch (err) {
			console.error(err);
			setCopyPrivateStatus("error");
			setTimeout(() => setCopyPrivateStatus("idle"), 2000);
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
			setAuthMode("login");
		} catch (err) {
			console.error(err);
			setError((err as Error).message || "Signup failed");
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
		setContactForm({ contactUsername: "", publicKey: "", notes: "" });
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
		setDecryptPayloadInput("");
		setDecryptPayloadFile(null);
		setIsDecryptFileDragActive(false);
		setDecryptPassword("");
		setDecryptPrivateKeyInput("");
		setDecryptPeerPublicKey("");
		setDecryptDetected(null);
		setDecryptBusy(false);
		setDecryptStatus(null);
		setDecryptError(null);
		setDecryptedResult(null);
	}

	function reopenContactModal() {
		if (closeModalTimer.current) {
			window.clearTimeout(closeModalTimer.current);
			closeModalTimer.current = null;
		}
		setContactModalClosing(false);
		setContactModalOpen(true);
	}

	function forceCloseContactModal() {
		if (closeModalTimer.current) {
			window.clearTimeout(closeModalTimer.current);
			closeModalTimer.current = null;
		}
		setContactModalClosing(false);
		setContactModalOpen(false);
		setContactModalMode("add");
		setEditingContactMeta(null);
		setContactForm({ contactUsername: "", publicKey: "", notes: "" });
		setContactModalError(null);
	}

	function openAddContactModal() {
		reopenContactModal();
		setContactModalMode("add");
		setEditingContactMeta(null);
		setContactForm({ contactUsername: "", publicKey: "", notes: "" });
		setContactModalError(null);
	}

	function openEditContactModal(contact: ContactRecord) {
		reopenContactModal();
		setContactModalMode("edit");
		setEditingContactMeta({ id: contact.id, username: contact.contactUsername });
		setContactForm({
			contactUsername: contact.contactUsername,
			publicKey: contact.publicKey,
			notes: contact.notes || "",
		});
		setContactModalError(null);
	}

	function closeContactModal() {
		if (contactModalClosing) return;
		if (closeModalTimer.current) {
			window.clearTimeout(closeModalTimer.current);
		}
		setContactModalClosing(true);
		closeModalTimer.current = window.setTimeout(() => {
			forceCloseContactModal();
			closeModalTimer.current = null;
		}, 240);
	}

	function resetEncryptionForm() {
		setEncryptSmsg("");
		setEncryptMsg("");
		setEncryptPassword("");
		applySelectedEncryptFile(null);
		setIsFileDragActive(false);
		setEncryptedBlob(null);
	}

	function handleEncryptionModeChange(mode: "text" | "file") {
		if (mode === encryptMode) return;
		setEncryptMode(mode);
		if (mode === "text") {
			applySelectedEncryptFile(null);
			setIsFileDragActive(false);
		} else {
			setEncryptSmsg("");
		}
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

	function handleFileDragEnter(event: React.DragEvent<HTMLDivElement>) {
		event.preventDefault();
		if (encryptBusy) return;
		setIsFileDragActive(true);
	}

	function handleFileDragOver(event: React.DragEvent<HTMLDivElement>) {
		event.preventDefault();
		if (encryptBusy) return;
		event.dataTransfer.dropEffect = "copy";
		if (!isFileDragActive) {
			setIsFileDragActive(true);
		}
	}

	function handleFileDragLeave(event: React.DragEvent<HTMLDivElement>) {
		event.preventDefault();
		const nextTarget = event.relatedTarget as Node | null;
		if (nextTarget && event.currentTarget.contains(nextTarget)) {
			return;
		}
		setIsFileDragActive(false);
	}

	function handleFileDrop(event: React.DragEvent<HTMLDivElement>) {
		event.preventDefault();
		setIsFileDragActive(false);
		if (encryptBusy) return;
		const droppedFile = event.dataTransfer.files?.[0];
		if (droppedFile) {
			applySelectedEncryptFile(droppedFile);
		}
	}

	function handleEncryptFileChange(event: React.ChangeEvent<HTMLInputElement>) {
		const file = event.target.files?.[0] ?? null;
		applySelectedEncryptFile(file);
		setIsFileDragActive(false);
		event.target.value = "";
	}

	function clearSelectedFile() {
		applySelectedEncryptFile(null);
		setIsFileDragActive(false);
	}

	function handleDecryptDragEnter(event: React.DragEvent<HTMLDivElement>) {
		event.preventDefault();
		if (decryptBusy) return;
		setIsDecryptFileDragActive(true);
	}

	function handleDecryptDragOver(event: React.DragEvent<HTMLDivElement>) {
		event.preventDefault();
		if (decryptBusy) return;
		event.dataTransfer.dropEffect = "copy";
		if (!isDecryptFileDragActive) {
			setIsDecryptFileDragActive(true);
		}
	}

	function handleDecryptDragLeave(event: React.DragEvent<HTMLDivElement>) {
		event.preventDefault();
		const nextTarget = event.relatedTarget as Node | null;
		if (nextTarget && event.currentTarget.contains(nextTarget)) {
			return;
		}
		setIsDecryptFileDragActive(false);
	}

	function handleDecryptFileDrop(event: React.DragEvent<HTMLDivElement>) {
		event.preventDefault();
		setIsDecryptFileDragActive(false);
		if (decryptBusy) return;
		const droppedFile = event.dataTransfer.files?.[0];
		if (droppedFile) {
			setDecryptPayloadFile(droppedFile);
			setDecryptPayloadInput("");
			setDecryptStatus(null);
			setDecryptError(null);
			setDecryptedResult(null);
		}
	}

	function resetDecryptForm() {
		setDecryptPayloadInput("");
		setDecryptPayloadFile(null);
		setIsDecryptFileDragActive(false);
		setDecryptPassword("");
		setDecryptPrivateKeyInput("");
		setDecryptPeerPublicKey("");
		setDecryptDetected(null);
		setDecryptStatus(null);
		setDecryptError(null);
		setDecryptedResult(null);
	}

	function handleDecryptFileChange(event: React.ChangeEvent<HTMLInputElement>) {
		const file = event.target.files?.[0] ?? null;
		setDecryptPayloadFile(file);
		setDecryptPayloadInput("");
		setDecryptStatus(null);
		setDecryptError(null);
		setDecryptedResult(null);
		setIsDecryptFileDragActive(false);
		event.target.value = "";
	}

	async function resolvePrivateKeyB64(): Promise<string> {
		const manual = decryptPrivateKeyInput.trim();
		if (manual) return manual;
		if (privateKeyPem) return privateKeyPem;
		if (storedAccount?.encryptedPrivateKey && storedAccount?.kdf) {
			// Must use WebAuthn for stored keys
			if (!decryptionToken) {
				throw new Error("Use WebAuthn to unlock your stored private key");
			}
			// Decrypt using server-side decryption with WebAuthn token
			console.log("[resolvePrivateKeyB64] Using decryption token:", decryptionToken?.substring(0, 50) + "...");
			const result = await decryptStoredPrivateKey(storedAccount.username, decryptionToken);
			return result.privateKey;
		}
		throw new Error("No private key available. Paste one or use WebAuthn.");
	}

	async function startWebAuthnRegistration() {
		if (!authToken) {
			setError("Must be logged in to register WebAuthn");
			return;
		}

		try {
			// Get registration options from server
			const optionsResp = await getWebAuthnRegisterOptions(authToken);
			const options = optionsResp.options;

			// Create credential with WebAuthn
			setStatus("Please interact with your security key...");
			const registration = await registerWebAuthnCredential({
				challenge: options.challenge,
				rp: options.rp,
				user: options.user,
				pubKeyCredParams: options.pubKeyCredParams,
				timeout: options.timeout,
				attestation: options.attestation,
				authenticatorSelection: options.authenticatorSelection,
			});

			// Verify credential on server
			setStatus("Verifying WebAuthn credential...");
			await verifyWebAuthnRegistration(
				authToken,
				registration.credentialId,
				registration.publicKey,
				registration.counter,
				registration.transports
			);

			setStatus("✅ WebAuthn credential registered successfully!");
			setError(null);
			setTimeout(() => setStatus(null), 3000);
		} catch (err) {
			const msg = (err as Error).message || "WebAuthn registration failed";
			if (msg !== "WebAuthn registration cancelled") {
				setError(`WebAuthn setup: ${msg}`);
			}
			setStatus(null);
		}
	}

	async function handleWebAuthnAuthenticate() {
		if (!authToken || !isAuthed) {
			setDecryptError("You must be logged in to use WebAuthn");
			return;
		}

		if (!storedAccount?.encryptedPrivateKey || !storedAccount?.kdf) {
			setDecryptError("No stored private key found. Please upload a key first.");
			return;
		}

		setWebauthnAuthBusy(true);
		setDecryptError(null);
		setDecryptStatus("Requesting WebAuthn...");

		try {
			// Get authentication options from server
			const optionsResp = await getWebAuthnAuthenticateOptions(authToken);
			const options = optionsResp.options;

			// Authenticate with WebAuthn
			setDecryptStatus("Please verify with your security key...");
			const assertion = await authenticateWithWebAuthn({
				challenge: options.challenge,
				allowCredentials: options.allowCredentials || [],
				timeout: options.timeout,
				userVerification: options.userVerification,
			});

			// Verify authentication on server
			setDecryptStatus("Verifying...");
			const verifyResp = await verifyWebAuthnAuthentication(authToken, assertion.credentialId, assertion.counter);

			// Store decryption token
			console.log("[WebAuthn] Decryption token received:", verifyResp.token?.substring(0, 50) + "...");
			setDecryptionToken(verifyResp.token);
			setDecryptStatus(null);
			setDecryptError(null);

			// Success message would be shown in UI
		} catch (err) {
			const msg = (err as Error).message || "WebAuthn authentication failed";
			setDecryptError(msg);
			setDecryptStatus(null);
		} finally {
			setWebauthnAuthBusy(false);
		}
	}

	async function loadOpsecData(): Promise<Uint8Array> {
		if (decryptPayloadFile) {
			return new Uint8Array(await decryptPayloadFile.arrayBuffer());
		}
		const raw = decryptPayloadInput.trim();
		if (!raw) {
			throw new Error("Paste Base64 ciphertext or upload a file");
		}
		try {
			return base64ToU8(raw);
		} catch {
			throw new Error("Invalid Base64 format");
		}
	}

	async function handleDecryptSubmit(e: React.FormEvent) {
		e.preventDefault();
		setDecryptStatus(null);
		setDecryptError(null);
		setDecryptedResult(null);
		try {
			setDecryptBusy(true);
			setDecryptStatus("Loading data...");
			const dataU8 = await loadOpsecData();

			// Detect auth mode
			const info = detectAuthMode(dataU8);
			setDecryptDetected(info);

			setDecryptStatus("Decrypting...");

			let result: DecryptResult;
			if (info.mode === "password") {
				if (!decryptPassword) throw new Error("Enter the encryption password");
				result = await decryptOpsecPw(dataU8, decryptPassword);
			} else {
				const priB64 = await resolvePrivateKeyB64();
				const peerPub = decryptPeerPublicKey.trim() || undefined;
				result = await decryptOpsecPub(dataU8, priB64, peerPub);
			}
			setDecryptedResult(result);
			setDecryptStatus("Decrypted successfully");
		} catch (err) {
			console.error(err);
			setDecryptError((err as Error).message || "Failed to decrypt");
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

	async function handleEncryptSubmit(e: React.FormEvent) {
		e.preventDefault();
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptedBlob(null);

		// Validate based on auth mode
		if (encryptAuthMode === "password") {
			if (!encryptPassword) {
				setEncryptError("Enter a password");
				return;
			}
		} else {
			const recipient = contacts.find((c) => c.id === encryptRecipientId);
			if (!recipient) {
				setEncryptError("Select a contact (recipient)");
				return;
			}
		}

		// Validate data
		if (encryptMode === "text") {
			if (!encryptSmsg) {
				setEncryptError("Enter a secure message to encrypt");
				return;
			}
		} else {
			if (!encryptFile) {
				setEncryptError("Select a file to encrypt");
				return;
			}
		}

		try {
			setEncryptBusy(true);
			setEncryptStatus("Encrypting...");

			const files = encryptMode === "file" && encryptFile ? [encryptFile] : undefined;

			let result: Uint8Array;
			if (encryptAuthMode === "password") {
				result = await encryptOpsec({
					mode: "password",
					kdfMethod: encryptKdfMethod,
					password: encryptPassword,
					encAlgo: encryptEncAlgo,
					smsg: encryptSmsg || undefined,
					msg: encryptMsg || undefined,
					files,
				});
			} else {
				const recipient = contacts.find((c) => c.id === encryptRecipientId)!;
				let myPrivateKey: string | undefined;
				if (encryptSignWithKey) {
					if (privateKeyPem) {
						myPrivateKey = privateKeyPem;
					}
					// Note: Stored keys require WebAuthn - implement server-side decryption
				}
				result = await encryptOpsec({
					mode: "publickey",
					asymAlgo: encryptAsymAlgo,
					peerPublicKey: recipient.publicKey,
					myPrivateKey,
					encAlgo: encryptEncAlgo,
					smsg: encryptSmsg || undefined,
					msg: encryptMsg || undefined,
					files,
				});
			}

			setEncryptedBlob(result);

			// For text-only mode (no files), also show base64
			if (encryptMode === "text") {
				setEncryptStatus(`Encrypted (${result.length} bytes). Download started.`);
			} else {
				setEncryptStatus(`Encrypted file (${formatBytes(result.length)}). Download started.`);
			}
		} catch (err) {
			console.error(err);
			setEncryptError((err as Error).message || "Failed to encrypt");
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
		try {
			await navigator.clipboard.writeText(u8ToBase64(encryptedBlob));
		} catch (err) {
			console.error(err);
		}
	}

	async function handleGenerateKeys() {
		setError(null);
		setStatus(`Generating ${keyAlgo.toUpperCase()} key pair...`);
		try {
			const { publicKey, privateKey } = await generateKeyPair(keyAlgo);
			setPublicKeyPem(publicKey);
			setPrivateKeyPem(privateKey);
			setCopyPrivateStatus("idle");
			setStatus("Key pair ready. Keep the private key encrypted only.");
		} catch (err) {
			console.error(err);
			setError("Failed to generate key pair");
			setStatus(null);
		}
	}

	async function handleUpload() {
		if (!canUpload) return;
		setBusy(true);
		setError(null);
		setStatus("Encrypting and uploading...");
		try {
			const payload = await buildAccountPayload(username, publicKeyPem, privateKeyPem, notes || undefined);
			const result = await saveAccount(payload, authToken ?? undefined);
			const record: AccountRecord = {
				...payload,
				id: result.id,
				createdAt: result.createdAt,
			};
			setStoredAccount(record);
			setStatus("Stored encrypted key");
			setShowKeySection(false);
			setPrivateKeyPem("");
			setCopyPrivateStatus("idle");

			// Auto-register WebAuthn if user is logged in
			if (authToken && (await isWebAuthnAvailable())) {
				setStatus("Setting up WebAuthn for secure access...");
				setTimeout(() => startWebAuthnRegistration(), 500);
			}
		} catch (err) {
			console.error(err);
			setError((err as Error).message || "Upload failed");
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

	async function handleContactSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!authToken) return;
		const trimmedUsername = contactForm.contactUsername.trim();
		const trimmedKey = contactForm.publicKey.trim();
		const selfKey = storedAccount?.publicKey || publicKeyPem;
		if (selfKey && trimmedKey && selfKey === trimmedKey) {
			setContactModalError("This public key already belongs to you");
			return;
		}
		if (!trimmedUsername || !trimmedKey) {
			setContactModalError("Username and public key are required");
			return;
		}
		setContactBusy(true);
		setContactModalError(null);
		try {
			const payload = {
				contactUsername: trimmedUsername,
				publicKey: trimmedKey,
				notes: contactForm.notes.trim() || undefined,
			};
			const saved = await createContact(payload, authToken);
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
					if ((deleteErr as Error).message === "TOKEN_EXPIRED") {
						handleSignOut();
						return;
					}
					console.error(deleteErr);
					setContactError((deleteErr as Error).message || "Failed to remove old contact");
				}
			}
			closeContactModal();
		} catch (err) {
			if ((err as Error).message === "TOKEN_EXPIRED") {
				handleSignOut();
				return;
			}
			console.error(err);
			setContactModalError((err as Error).message || "Failed to save contact");
		} finally {
			setContactBusy(false);
		}
	}

	async function handleDeleteContact(id: string) {
		if (!authToken) return;
		const confirmed = window.confirm("Delete this contact?");
		if (!confirmed) return;
		try {
			await deleteContact(id, authToken);
			setContacts((prev) => prev.filter((contact) => contact.id !== id));
		} catch (err) {
			if ((err as Error).message === "TOKEN_EXPIRED") {
				handleSignOut();
				return;
			}
			console.error(err);
			setContactError((err as Error).message || "Failed to delete contact");
		}
	}

	function renderDecryptedInfo(result: DecryptResult) {
		const rows: { label: string; value: string | undefined }[] = [];
		if (result.msg) rows.push({ label: "Public message", value: result.msg });
		if (result.smsg) rows.push({ label: "Secure message", value: result.smsg });
		if (result.files.length > 0) rows.push({ label: "Files", value: `${result.files.length} file(s)` });
		if (result.verified !== undefined) rows.push({ label: "Signature", value: result.verified ? "Valid" : "INVALID" });
		return (
			<div className="meta-grid">
				{rows.map((row) =>
					row.value ? (
						<div key={row.label}>
							<span className="summary-label">{row.label}</span>
							<p style={{ whiteSpace: "pre-wrap" }}>{row.value}</p>
						</div>
					) : null
				)}
			</div>
		);
	}

	function renderTabContent() {
		if (tab === "keys") {
			const hasStoredKey = Boolean(storedAccount?.publicKey && storedAccount?.encryptedPrivateKey?.cipherText);

			if (tab === "keys") {
				return hasStoredKey && !showKeySection ? (
					<section className="card">
						<h2>Your stored key</h2>
						<p className="hint">Private key is stored encrypted. Regenerate to replace it.</p>
						<div className="preview">
							<div>
								<h3>Public key</h3>
								<div className="copy-block">
									<button
										type="button"
										className={copyPublicStatus === "copied" ? "copy-button copied" : "copy-button"}
										onClick={() => handleCopyPublicKey(storedAccount?.publicKey)}
									>
										{copyPublicStatus === "copied" ? "Copied" : copyPublicStatus === "error" ? "Error" : "Copy"}
									</button>
									<pre>{storedAccount?.publicKey}</pre>
								</div>
							</div>
							<div>
								<h3>Private key</h3>
								<pre>Encrypted (ciphertext saved on server)</pre>
							</div>
						</div>
						<div className="actions">
							<button className="secondary" onClick={handleRegenerate}>Regenerate keys</button>
						</div>
					</section>
				) : (
					<>
						<section className="card">
							<label className="label" htmlFor="notes">Notes (optional)</label>
							<textarea id="notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Label this key..." />

							<label className="label" htmlFor="key-algo">Key algorithm</label>
							<select id="key-algo" value={keyAlgo} onChange={(e) => setKeyAlgo(e.target.value as AsymAlgo)}>
								<option value="ecc1">Curve448 (X448 + Ed448)</option>
								<option value="rsa1">RSA-2048</option>
							</select>

							<div className="actions">
								<button onClick={handleGenerateKeys} className="secondary">Generate key pair</button>
								<button onClick={handleUpload} disabled={!canUpload || busy}>
									{busy ? "Working..." : "Encrypt and upload"}
								</button>
							</div>

							{status && <div className="status success">{status}</div>}
							{error && <div className="status error">{error}</div>}
						</section>

						<section className="card">
							<h2>Local preview</h2>
							<div className="preview">
								<div>
									<h3>Public key</h3>
									<div className="copy-block">
										<button
											type="button"
											className={copyPublicStatus === "copied" ? "copy-button copied" : "copy-button"}
											onClick={() => handleCopyPublicKey(publicKeyPem || undefined)}
											disabled={!publicKeyPem}
										>
											{copyPublicStatus === "copied" ? "Copied" : copyPublicStatus === "error" ? "Error" : "Copy"}
										</button>
										<pre>{publicKeyPem || "(generate a key pair)"}</pre>
									</div>
								</div>
								<div>
									<h3>Private key (plaintext)
									</h3>
									<div className="copy-block">
										{privateKeyPem && (
											<button
												type="button"
												className={copyPrivateStatus === "copied" ? "copy-button copied" : "copy-button"}
												onClick={() => handleCopyPrivateKey(privateKeyPem)}
											>
												{copyPrivateStatus === "copied" ? "Copied" : copyPrivateStatus === "error" ? "Error" : "Copy"}
											</button>
										)}
										<pre>{privateKeyPem || "(generate a key pair)"}</pre>
									</div>
								</div>
							</div>
							<p className="hint">Private key is encrypted in-browser with AES-GCM using PBKDF2-derived key.</p>
						</section>
					</>
				);
			}
		}

		if (tab === "encrypt") {
			const hasContacts = contacts.length > 0;
			const canEncrypt = encryptAuthMode === "password"
				? (encryptPassword && !encryptBusy && (encryptMode === "text" ? !!encryptSmsg : !!encryptFile))
				: (!!encryptRecipientId && !encryptBusy && (encryptMode === "text" ? !!encryptSmsg : !!encryptFile));

			return (
				<>
					<section className="card">
						<h2>Encrypt data</h2>
						<p className="hint">YAS2 Opsec encryption — supports password-based or public-key modes with AES-GCM.</p>

						<form className="form-vertical" onSubmit={handleEncryptSubmit}>
							{/* Auth mode selector */}
							<label className="label">Authentication mode</label>
							<div className="segment-control" role="tablist" aria-label="Auth mode">
								<button
									type="button"
									className={encryptAuthMode === "password" ? "segment-option active" : "segment-option"}
									onClick={() => { setEncryptAuthMode("password"); setEncryptError(null); setEncryptStatus(null); setEncryptedBlob(null); }}
								>
									Password
								</button>
								<button
									type="button"
									className={encryptAuthMode === "publickey" ? "segment-option active" : "segment-option"}
									onClick={() => { setEncryptAuthMode("publickey"); setEncryptError(null); setEncryptStatus(null); setEncryptedBlob(null); }}
								>
									Public key
								</button>
							</div>

							{/* Password-mode fields */}
							{encryptAuthMode === "password" && (
								<>
									<label className="label" htmlFor="encrypt-password">Password</label>
									<input
										id="encrypt-password"
										type="password"
										value={encryptPassword}
										onChange={(e) => { setEncryptPassword(e.target.value); setEncryptError(null); }}
										placeholder="Encryption password"
									/>
									<label className="label" htmlFor="encrypt-kdf">Key derivation</label>
									<select id="encrypt-kdf" value={encryptKdfMethod} onChange={(e) => setEncryptKdfMethod(e.target.value as KdfMethod)}>
										<option value="arg1">Argon2id (recommended)</option>
										<option value="pbk1">PBKDF2-SHA512</option>
									</select>
								</>
							)}

							{/* Public-key-mode fields */}
							{encryptAuthMode === "publickey" && (
								<>
									{!hasContacts && !contactsLoading && <div className="status info">Add a contact first to enable public key encryption.</div>}
									<label className="label" htmlFor="encrypt-contact">Recipient</label>
									<select
										id="encrypt-contact"
										value={encryptRecipientId}
										onChange={(e) => { setEncryptRecipientId(e.target.value); setEncryptError(null); setEncryptStatus(null); setEncryptedBlob(null); }}
										disabled={!hasContacts || encryptBusy}
									>
										<option value="">Select a contact</option>
										{contacts.map((c) => (
											<option key={c.id} value={c.id}>{c.contactUsername}</option>
										))}
									</select>
									<label className="label" htmlFor="encrypt-asym">Asymmetric algorithm</label>
									<select id="encrypt-asym" value={encryptAsymAlgo} onChange={(e) => setEncryptAsymAlgo(e.target.value as AsymAlgo)}>
										<option value="ecc1">Curve448 (X448 + Ed448)</option>
										<option value="rsa1">RSA-2048 (OAEP + PKCS1v1.5)</option>
									</select>
									<label className="label">
										<input
											type="checkbox"
											checked={encryptSignWithKey}
											onChange={(e) => setEncryptSignWithKey(e.target.checked)}
										/>{" "}
										Sign with my private key
									</label>
								</>
							)}

							{/* Encryption algorithm */}
							<label className="label" htmlFor="encrypt-enc-algo">Encryption algorithm</label>
							<select id="encrypt-enc-algo" value={encryptEncAlgo} onChange={(e) => setEncryptEncAlgo(e.target.value as EncAlgo)}>
								<option value="gcm1">AES-GCM (single block)</option>
								<option value="gcmx1">AES-GCM chunked (large files)</option>
							</select>

							{/* Public message */}
							<label className="label" htmlFor="encrypt-msg">Public message (optional, visible without decrypt)</label>
							<input
								id="encrypt-msg"
								type="text"
								value={encryptMsg}
								onChange={(e) => setEncryptMsg(e.target.value)}
								placeholder="Short public note"
							/>

							{/* Payload mode selector */}
							<div className="segment-control" role="tablist" aria-label="Payload type">
								<button
									type="button"
									className={encryptMode === "text" ? "segment-option active" : "segment-option"}
									onClick={() => handleEncryptionModeChange("text")}
								>
									Text
								</button>
								<button
									type="button"
									className={encryptMode === "file" ? "segment-option active" : "segment-option"}
									onClick={() => handleEncryptionModeChange("file")}
								>
									File
								</button>
							</div>

							{encryptMode === "text" ? (
								<>
									<label className="label" htmlFor="encrypt-smsg">Secure message (encrypted)</label>
									<textarea
										id="encrypt-smsg"
										value={encryptSmsg}
										onChange={(e) => { setEncryptSmsg(e.target.value); setEncryptError(null); setEncryptStatus(null); setEncryptedBlob(null); }}
										placeholder="Write the secret message to encrypt"
									/>
								</>
							) : (
								<div className="file-picker">
									<div
										className={isFileDragActive ? "file-dropzone drag-active" : "file-dropzone"}
										onDragEnter={handleFileDragEnter}
										onDragOver={handleFileDragOver}
										onDragLeave={handleFileDragLeave}
										onDrop={handleFileDrop}
										aria-disabled={encryptBusy}
									>
										<input
											id="encrypt-file"
											type="file"
											onChange={handleEncryptFileChange}
											disabled={encryptBusy}
											className="visually-hidden"
										/>
										<label htmlFor="encrypt-file">
											<div className="drop-graphic" aria-hidden="true">
												<svg width="40" height="40" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
													<rect x="7" y="23" width="26" height="10" rx="3" stroke="#38bdf8" strokeWidth="1.6" opacity="0.7" />
													<path d="M20 7v18" stroke="#38bdf8" strokeWidth="1.6" strokeLinecap="round" />
													<path d="M15 18l5 5 5-5" stroke="#38bdf8" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
												</svg>
											</div>
											<strong>Drag & drop a file to encrypt</strong>
											<span className="drop-highlight">Drop it anywhere inside this panel or click to browse.</span>
											<span className="muted">Files stay local. We encrypt in your browser before anything leaves.</span>
										</label>
									</div>

									{encryptFile && (
										<div className="file-info">
											<div>
												<strong>{encryptFile.name || "Selected file"}</strong>
												<p className="muted">{formatBytes(encryptFile.size)} · {encryptFile.type || "application/octet-stream"}</p>
											</div>
											<button type="button" className="secondary button-inline" onClick={clearSelectedFile} disabled={encryptBusy}>
												Remove
											</button>
										</div>
									)}
								</div>
							)}

							<div className="actions">
								<button type="submit" disabled={!canEncrypt}>{encryptBusy ? "Encrypting..." : "Encrypt"}</button>
								<button type="button" className="secondary" onClick={resetEncryptionForm} disabled={encryptBusy}>
									Reset
								</button>
							</div>

							{encryptBusy && (
								<div className="progress-row" role="status" aria-live="polite">
									<div className="progress-bar">
										<div className="progress-fill" />
									</div>
									<span className="muted">Encrypting payload...</span>
								</div>
							)}
						</form>
						{encryptStatus && <div className="status success">{encryptStatus}</div>}
						{encryptError && <div className="status error">{encryptError}</div>}
					</section>

					{encryptedBlob && (
						<section className="card">
							<div className="encrypt-summary">
								<div>
									<span className="summary-label">Mode</span>
									<p>{encryptAuthMode === "password" ? "Password" : "Public key"}</p>
								</div>
								<div>
									<span className="summary-label">Size</span>
									<p>{formatBytes(encryptedBlob.length)}</p>
								</div>
								<div>
									<span className="summary-label">Algorithm</span>
									<p>{encryptEncAlgo === "gcmx1" ? "AES-GCM chunked" : "AES-GCM"}</p>
								</div>
							</div>
							<p className="hint">Download the encrypted binary or copy as Base64.</p>
							<div className="result-actions">
								<button type="button" className="secondary button-inline" onClick={handleCopyEncryptedBase64}>
									Copy Base64
								</button>
								<button type="button" className="ghost button-inline" onClick={handleDownloadEncryptedBlob}>
									Download .bin
								</button>
							</div>
						</section>
					)}
				</>
			);
		}

		if (tab === "address-book") {
			const isContactFormValid = Boolean(contactForm.contactUsername.trim() && contactForm.publicKey.trim());

			return (
				<>
					<section className="card">
						<div className="contact-header">
							<div>
								<h2>Contacts</h2>
								<p className="hint">Manage trusted recipients and their public keys so you can encrypt messages to them.</p>
							</div>
							<button type="button" className="secondary button-inline" onClick={openAddContactModal}>Add contact</button>
						</div>
						{contactError && <div className="status error">{contactError}</div>}
						<div className="contact-list">
							<div className="contact-list-header">
								<h3>Saved contacts</h3>
								{contactsLoading && <span className="muted">Loading...</span>}
							</div>
							{contacts.length === 0 && !contactsLoading ? (
								<p className="hint">No contacts yet. Add someone to start encrypting messages for them.</p>
							) : (
								<ul className="contact-items">
									{contacts.map((contact) => (
										<li key={contact.id} className="contact-item">
											<div className="contact-meta">
												<strong>{contact.contactUsername}</strong>
												{contact.notes && <p className="hint">{contact.notes}</p>}
											</div>
											<div className="contact-actions">
												<button
													type="button"
													className={`secondary button-inline copy-state ${
														copyPublicStatus === "copied" ? "copied" : copyPublicStatus === "error" ? "error" : ""
													}`}
													onClick={() => handleCopyPublicKey(contact.publicKey)}
												>
													{copyPublicStatus === "copied" ? "Copied" : copyPublicStatus === "error" ? "Error" : "Copy key"}
												</button>
												<button type="button" className="secondary button-inline" onClick={() => openEditContactModal(contact)}>
													Edit
												</button>
												<button type="button" className="ghost button-inline danger" onClick={() => handleDeleteContact(contact.id)}>
													Delete
												</button>
											</div>
										</li>
									))}
								</ul>
							)}
						</div>
					</section>

					{(contactModalOpen || contactModalClosing) && (
						<div className={contactModalClosing ? "modal-backdrop closing" : "modal-backdrop"} role="dialog" aria-modal="true">
							<div className={contactModalClosing ? "modal-card closing" : "modal-card"}>
								<div className="modal-header">
									<h3>{contactModalMode === "add" ? "Add contact" : "Edit contact"}</h3>
									<button type="button" className="ghost button-inline" onClick={closeContactModal}>Close</button>
								</div>
								<form className="form-vertical" onSubmit={handleContactSubmit}>
									<label className="label" htmlFor="contact-username">Contact username</label>
									<input
										id="contact-username"
										type="text"
										value={contactForm.contactUsername}
										onChange={(e) => setContactForm((prev) => ({ ...prev, contactUsername: e.target.value }))}
										placeholder="recipient_id"
										required
									/>
									<label className="label" htmlFor="contact-notes">Notes (optional)</label>
									<textarea
										id="contact-notes"
										value={contactForm.notes}
										onChange={(e) => setContactForm((prev) => ({ ...prev, notes: e.target.value }))}
										placeholder="PGP fingerprint, onboarding status, etc."
									/>
									<label className="label" htmlFor="contact-public-key">Public key</label>
									<textarea
										id="contact-public-key"
										value={contactForm.publicKey}
										onChange={(e) => setContactForm((prev) => ({ ...prev, publicKey: e.target.value }))}
										placeholder="Base64-encoded public key"
										required
									/>
									<div className="modal-actions">
										<button type="button" className="ghost button-inline" onClick={closeContactModal}>Cancel</button>
										<button type="submit" disabled={contactBusy || !isContactFormValid}>
											{contactBusy ? "Saving..." : contactModalMode === "add" ? "Save contact" : "Update contact"}
										</button>
									</div>
									{contactModalError && <div className="status error">{contactModalError}</div>}
								</form>
							</div>
						</div>
					)}
				</>
			);
		}

		return (
			<>
				<section className="card">
					<h2>Decrypt</h2>
					<p className="hint">Paste Base64 ciphertext or upload an encrypted binary, then decrypt locally.</p>
					<form className="form-vertical" onSubmit={handleDecryptSubmit}>
						<label className="label" htmlFor="decrypt-base64">Ciphertext (Base64)</label>
						<textarea
							id="decrypt-base64"
							placeholder="Paste Base64-encoded ciphertext..."
							value={decryptPayloadInput}
							onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => {
								setDecryptPayloadInput(e.target.value);
								setDecryptPayloadFile(null);
								setDecryptStatus(null);
								setDecryptError(null);
								setDecryptedResult(null);
								setDecryptDetected(null);
							}}
							disabled={decryptBusy}
						/>

						<div className="file-picker">
							<div
								className={isDecryptFileDragActive ? "file-dropzone drag-active" : "file-dropzone"}
								onDragEnter={handleDecryptDragEnter}
								onDragOver={handleDecryptDragOver}
								onDragLeave={handleDecryptDragLeave}
								onDrop={handleDecryptFileDrop}
								aria-disabled={decryptBusy}
							>
								<input
									id="decrypt-file"
									type="file"
									onChange={handleDecryptFileChange}
									disabled={decryptBusy}
									className="visually-hidden"
								/>
								<label htmlFor="decrypt-file">
									<div className="drop-graphic" aria-hidden="true">
										<svg width="40" height="40" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
											<rect x="7" y="23" width="26" height="10" rx="3" stroke="#38bdf8" strokeWidth="1.6" opacity="0.7" />
											<path d="M20 7v18" stroke="#38bdf8" strokeWidth="1.6" strokeLinecap="round" />
											<path d="M15 18l5 5 5-5" stroke="#38bdf8" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
										</svg>
									</div>
									<strong>Drag & drop encrypted .bin file</strong>
									<span className="drop-highlight">Drop your encrypted binary here or click to browse.</span>
									<span className="muted">We parse and decrypt entirely in your browser.</span>
								</label>
							</div>

							{decryptPayloadFile && (
								<div className="file-info">
									<div>
										<strong>{decryptPayloadFile.name}</strong>
										<p className="muted">{formatBytes(decryptPayloadFile.size)} · {decryptPayloadFile.type || "application/octet-stream"}</p>
									</div>
									<button
										type="button"
										className="secondary button-inline"
										onClick={() => {
											setDecryptPayloadFile(null);
											setIsDecryptFileDragActive(false);
										}}
										disabled={decryptBusy}
									>
										Remove
									</button>
								</div>
							)}
						</div>

						{/* Detected mode info */}
						{decryptDetected && (
							<div className="status info">
								Detected mode: <strong>{decryptDetected.mode}</strong>
								{decryptDetected.msg && <> — Public message: {decryptDetected.msg}</>}
							</div>
						)}

						{/* Password field (for password-mode decryption) */}
						<label className="label" htmlFor="decrypt-password">Password (for password-mode)</label>
						<input
							id="decrypt-password"
							type="password"
							value={decryptPassword}
							onChange={(e) => { setDecryptPassword(e.target.value); setDecryptError(null); }}
							placeholder="Enter the encryption password"
							disabled={decryptBusy}
						/>

						<div>
							{storedAccount?.encryptedPrivateKey && isAuthed && webauthnAvailable && (
								<div>
									<label className="label">Unlock stored key with security key</label>
									<button
										type="button"
										className="secondary full-width"
										onClick={handleWebAuthnAuthenticate}
										disabled={decryptBusy || webauthnAuthBusy}
									>
										{webauthnAuthBusy ? "Verifying..." : "🔐 Authenticate with Security Key"}
									</button>
									{decryptionToken && (
										<p className="hint success-text">✓ Security key verified</p>
									)}
								</div>
							)}
						</div>

						<div className="grid">
							<div>
								<label className="label" htmlFor="decrypt-private-key">Or paste a private key (Base64)</label>
								<textarea
									id="decrypt-private-key"
									value={decryptPrivateKeyInput}
									onChange={(e) => {
										setDecryptPrivateKeyInput(e.target.value);
										setDecryptStatus(null);
										setDecryptError(null);
									}}
									placeholder="Base64-encoded private key"
									disabled={decryptBusy}
								/>
								<p className="hint">If provided, this overrides stored keys and passphrase unlocking.</p>
							</div>
						</div>

						<label className="label" htmlFor="decrypt-peer-pubkey">Peer public key (optional, for signature verification)</label>
						<textarea
							id="decrypt-peer-pubkey"
							value={decryptPeerPublicKey}
							onChange={(e) => setDecryptPeerPublicKey(e.target.value)}
							placeholder="Base64-encoded sender's public key (for verifying signatures)"
							disabled={decryptBusy}
						/>

						<div className="actions">
							<button type="submit" disabled={decryptBusy}>{decryptBusy ? "Decrypting..." : "Decrypt"}</button>
							<button type="button" className="secondary" onClick={resetDecryptForm} disabled={decryptBusy}>
								Reset
							</button>
						</div>

						{decryptBusy && (
							<div className="progress-row" role="status" aria-live="polite">
								<div className="progress-bar">
									<div className="progress-fill" />
								</div>
								<span className="muted">Decrypting payload...</span>
							</div>
						)}
					</form>
					{decryptStatus && <div className="status success">{decryptStatus}</div>}
					{decryptError && <div className="status error">{decryptError}</div>}
				</section>

				{decryptedResult && (
					<section className="card">
						<h3>Decryption result</h3>
						{renderDecryptedInfo(decryptedResult)}

						{decryptedResult.files.length > 0 && (
							<div className="file-list">
								<h4>Extracted files</h4>
								{decryptedResult.files.map((f, i) => (
									<div key={i} className="file-info">
										<div>
											<strong>{f.name}</strong>
											<p className="muted">{formatBytes(f.data.length)}</p>
										</div>
										<button type="button" className="secondary button-inline" onClick={() => handleDownloadDecryptedFile(f.name, f.data)}>
											Download
										</button>
									</div>
								))}
							</div>
						)}
					</section>
				)}
			</>
		);
	}

	if (!isAuthed) {
		const onSubmit = authMode === "login" ? handleLogin : handleSignup;
		return (
			<div className="page">
				<header className="hero">
					<div>
						<p className="eyebrow">Yet Another Security - Web</p>
						<h1>{authMode === "login" ? "Sign in to manage encrypted keys" : "Create an account to get started"}</h1>
						<p className="lede">Access your encrypted key vault and tools after authentication.</p>
					</div>
				</header>

				<section className="card">
					<form className="form-vertical" onSubmit={onSubmit}>
						<div>
							<label className="label" htmlFor="login-username">Username</label>
							<input
								id="login-username"
								type="text"
								value={loginUsername}
								onChange={(e) => setLoginUsername(e.target.value)}
								placeholder="your_id"
								autoComplete="username"
							/>
						</div>
						<div>
							<label className="label" htmlFor="login-pass">Password</label>
							<input
								id="login-pass"
								type="password"
								value={loginPass}
								onChange={(e) => setLoginPass(e.target.value)}
								placeholder="••••••••"
								autoComplete={authMode === "login" ? "current-password" : "new-password"}
							/>
						</div>
						{authMode === "signup" && (
							<div>
								<label className="label" htmlFor="login-pass-confirm">Confirm password</label>
								<input
									id="login-pass-confirm"
									type="password"
									value={loginPassConfirm}
									onChange={(e) => setLoginPassConfirm(e.target.value)}
									placeholder="repeat password"
									autoComplete="new-password"
								/>
							</div>
						)}
						<div className="actions vertical-actions">
							<button type="submit" disabled={!canLogin || loginBusy}>
								{loginBusy ? "Working..." : authMode === "login" ? "Sign in" : "Create account"}
							</button>
							<button
								type="button"
								className="secondary"
								onClick={() => setAuthMode(authMode === "login" ? "signup" : "login")}
							>
								{authMode === "login" ? "Need an account? Sign up" : "Have an account? Sign in"}
							</button>
						</div>
					</form>
					{error && <div className="status error">{error}</div>}
					<p className="hint">Passwords are stored hashed (bcrypt) in MongoDB. Tokens are JWT (1d).</p>
				</section>
			</div>
		);
	}

	const heroTitle =
		tab === "keys"
			? "Protect private keys with a passphrase-derived key"
			: tab === "address-book"
			? "Manage trusted contacts and their public keys"
			: tab === "encrypt"
			? "Encrypt data with recipients' public keys"
			: "Decrypt securely in your browser";

	const heroLede =
		tab === "keys"
			? "Encrypt in the browser, store only ciphertext, and keep your passphrase local. Public keys are shareable; private keys stay yours."
			: tab === "address-book"
			? "Keep recipients' public keys organized so you can encrypt to the right person every time."
			: tab === "encrypt"
			? "YAS2 Opsec encryption: password-based (Argon2id/PBKDF2) or public-key (Curve448/RSA-2048) with AES-GCM."
			: "Decrypt YAS2 Opsec ciphertext locally — paste Base64 or upload a .bin file.";

	return (
		<div className="page">
			<nav className="nav-bar">
				<button className={tab === "keys" ? "nav-item active" : "nav-item"} onClick={() => setTab("keys")}>
					<IconHome active={tab === "keys"} />
					<span>Keys</span>
				</button>
				<button className={tab === "address-book" ? "nav-item active" : "nav-item"} onClick={() => setTab("address-book")}>
					<IconBook active={tab === "address-book"} />
					<span>Contacts</span>
				</button>
				<button className={tab === "encrypt" ? "nav-item active" : "nav-item"} onClick={() => setTab("encrypt")}>
					<IconLock active={tab === "encrypt"} />
					<span>Encrypt</span>
				</button>
				<button className={tab === "decrypt" ? "nav-item active" : "nav-item"} onClick={() => setTab("decrypt")}>
					<IconUnlock active={tab === "decrypt"} />
					<span>Decrypt</span>
				</button>
			</nav>

			<header className="hero">
				<div>
					<p className="eyebrow">Yet Another Security - Web</p>
					<h1>{heroTitle}</h1>
					<p className="lede">{heroLede}</p>
				</div>
			</header>

			<div className="top-actions">
				<span className="muted">Signed in as {authUsername}</span>
				<button className="ghost" onClick={handleSignOut}>Sign out</button>
			</div>

			{renderTabContent()}
		</div>
	);
}

export default App;
