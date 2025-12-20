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
} from "./api";
import { buildAccountPayload, generateRsaKeyPair, encryptForPublicKey, encodeUtf8, decryptForPrivateKey, decryptPrivateKey, decodeUtf8 } from "./crypto";
import type { AccountRecord, ContactRecord } from "./types";

type IconProps = { active?: boolean };

function extractPublicKeyBody(pem: string | undefined | null): string | null {
	if (!pem) return null;
	const normalized = pem.replace(/\r/g, "");
	const headerRegex = /-*\s*BEGIN\s+PUBLIC\s+KEY\s*-*/i;
	const footerRegex = /-*\s*END\s+PUBLIC\s+KEY\s*-*/i;
	const headerMatch = headerRegex.exec(normalized);
	const startIndex = headerMatch ? headerMatch.index + headerMatch[0].length : 0;
	const afterHeader = normalized.slice(startIndex);
	const footerMatch = footerRegex.exec(afterHeader);
	const bodySection = footerMatch ? afterHeader.slice(0, footerMatch.index) : afterHeader;
	const stripped = bodySection.replace(/[^A-Za-z0-9+/=]/g, "");
	return stripped.trim() || null;
}

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

type EncryptedEnvelope = {
	schema: string;
	payload: {
		type: "text" | "file";
		meta?: {
			algorithm: string;
			iv: string;
			cipherText: string;
		};
	};
	encryption: {
		algorithm: string;
		iv: string;
		cipherText: string;
	};
	wrappedKey: {
		algorithm: string;
		cipherText: string;
	};
};

type EncryptedPayloadMetadata =
	| {
		type: "text";
		encoding: string;
		length: number;
		createdAt: string;
	}
	| {
		type: "file";
		fileName: string;
		mimeType: string;
		size: number;
		modifiedAt?: string;
	};

type DecryptedTextResult = {
	type: "text";
	text: string;
	metadata?: EncryptedPayloadMetadata;
};

type DecryptedFileResult = {
	type: "file";
	blob: Blob;
	fileName: string;
	mimeType: string;
	metadata?: EncryptedPayloadMetadata;
};

function downloadEncryptedEnvelope(payload: EncryptedEnvelope) {
	const json = JSON.stringify(payload, null, 2);
	const blob = new Blob([json], { type: "application/json" });
	const url = URL.createObjectURL(blob);
	const link = document.createElement("a");
	link.href = url;
	link.download = `yas-ciphertext-${Date.now()}.json`;
	link.click();
	URL.revokeObjectURL(url);
}

function App() {
	const [authToken, setAuthToken] = useState<string | null>(() => localStorage.getItem("authToken"));
	const [authUsername, setAuthUsername] = useState<string | null>(() => localStorage.getItem("authUsername"));
	const [authMode, setAuthMode] = useState<"login" | "signup">("login");
	const [loginUsername, setLoginUsername] = useState("");
	const [loginPass, setLoginPass] = useState("");
	const [loginPassConfirm, setLoginPassConfirm] = useState("");
	const [loginBusy, setLoginBusy] = useState(false);

	const [username, setUsername] = useState("");
	const [passphrase, setPassphrase] = useState("");
	const [showPassphrase, setShowPassphrase] = useState(false);
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
	const [encryptRecipientId, setEncryptRecipientId] = useState<string>("");
	const [encryptMode, setEncryptMode] = useState<"text" | "file">("text");
	const [encryptPlaintext, setEncryptPlaintext] = useState("");
	const [encryptFile, setEncryptFile] = useState<File | null>(null);
	const [isFileDragActive, setIsFileDragActive] = useState(false);
	const [encryptBusy, setEncryptBusy] = useState(false);
	const [encryptStatus, setEncryptStatus] = useState<string | null>(null);
	const [encryptError, setEncryptError] = useState<string | null>(null);
	const [encryptedPayload, setEncryptedPayload] = useState<EncryptedEnvelope | null>(null);
	const [copyPayloadStatus, setCopyPayloadStatus] = useState<"idle" | "copied" | "error">("idle");
	const [lastEncryptionSummary, setLastEncryptionSummary] = useState<{ recipient: string; payloadDescription: string } | null>(null);
	const [decryptPayloadInput, setDecryptPayloadInput] = useState("");
	const [decryptPayloadFile, setDecryptPayloadFile] = useState<File | null>(null);
	const [decryptPassphrase, setDecryptPassphrase] = useState("");
	const [decryptPrivateKeyInput, setDecryptPrivateKeyInput] = useState("");
	const [decryptBusy, setDecryptBusy] = useState(false);
	const [decryptStatus, setDecryptStatus] = useState<string | null>(null);
	const [decryptError, setDecryptError] = useState<string | null>(null);
	const [decryptedResult, setDecryptedResult] = useState<DecryptedTextResult | DecryptedFileResult | null>(null);

	useEffect(() => {
		return () => {
			if (closeModalTimer.current) {
				window.clearTimeout(closeModalTimer.current);
				closeModalTimer.current = null;
			}
		};
	}, []);

	useEffect(() => {
		if (!encryptedPayload) return;
		downloadEncryptedEnvelope(encryptedPayload);
	}, [encryptedPayload]);

	const canUpload = Boolean(username && passphrase && publicKeyPem && privateKeyPem);
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
				console.error(err);
				if (!cancelled) {
					setContactError((err as Error).message || "Failed to load contacts");
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
		setContacts([]);
		setContactForm({ contactUsername: "", publicKey: "", notes: "" });
		setContactError(null);
		forceCloseContactModal();
		setEncryptRecipientId("");
		setEncryptMode("text");
		setEncryptPlaintext("");
		setEncryptFile(null);
		setIsFileDragActive(false);
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptedPayload(null);
		setCopyPayloadStatus("idle");
		setLastEncryptionSummary(null);
		setDecryptPayloadInput("");
		setDecryptPayloadFile(null);
		setDecryptPassphrase("");
		setDecryptPrivateKeyInput("");
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
		setEncryptPlaintext("");
		applySelectedEncryptFile(null);
		setIsFileDragActive(false);
	}

	function handleEncryptionModeChange(mode: "text" | "file") {
		if (mode === encryptMode) return;
		setEncryptMode(mode);
		if (mode === "text") {
			applySelectedEncryptFile(null);
			setIsFileDragActive(false);
		} else {
			setEncryptPlaintext("");
		}
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptedPayload(null);
		setCopyPayloadStatus("idle");
		setLastEncryptionSummary(null);
	}

	function applySelectedEncryptFile(file: File | null) {
		setEncryptFile(file);
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptedPayload(null);
		setCopyPayloadStatus("idle");
		setLastEncryptionSummary(null);
	}

	function handleFileDragEnter(event: React.DragEvent<HTMLDivElement>) {
		event.preventDefault();
		if (encryptBusy || contacts.length === 0) return;
		setIsFileDragActive(true);
	}

	function handleFileDragOver(event: React.DragEvent<HTMLDivElement>) {
		event.preventDefault();
		if (encryptBusy || contacts.length === 0) return;
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
		if (encryptBusy || contacts.length === 0) return;
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

	function resetDecryptForm() {
		setDecryptPayloadInput("");
		setDecryptPayloadFile(null);
		setDecryptPassphrase("");
		setDecryptPrivateKeyInput("");
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
		event.target.value = "";
	}

	async function resolvePrivateKeyPem(): Promise<string> {
		const manual = decryptPrivateKeyInput.trim();
		if (manual) return manual;
		if (privateKeyPem) return privateKeyPem;
		if (storedAccount?.encryptedPrivateKey && storedAccount?.kdf) {
			if (!decryptPassphrase) {
				throw new Error("Enter your passphrase to unlock your stored private key");
			}
			return decryptPrivateKey(storedAccount.encryptedPrivateKey, storedAccount.kdf, decryptPassphrase);
		}
		throw new Error("No private key available. Paste one or unlock your stored key.");
	}

	async function loadEnvelopeFromInput(): Promise<EncryptedEnvelope> {
		let raw = decryptPayloadInput.trim();
		if (decryptPayloadFile) {
			raw = await decryptPayloadFile.text();
		}
		if (!raw) {
			throw new Error("Paste ciphertext JSON or upload a file");
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(raw);
		} catch (err) {
			throw new Error("Invalid JSON format");
		}
		const candidate = parsed as Partial<EncryptedEnvelope>;
		if (!candidate?.encryption?.cipherText || !candidate?.encryption?.iv || !candidate?.wrappedKey?.cipherText) {
			throw new Error("Missing required encryption fields");
		}
		const payloadType = candidate.payload?.type === "file" ? "file" : "text";
		const payloadMeta = candidate.payload?.meta && candidate.payload.meta.cipherText && candidate.payload.meta.iv
			? {
				algorithm: candidate.payload.meta.algorithm || "AES-GCM",
				iv: candidate.payload.meta.iv,
				cipherText: candidate.payload.meta.cipherText,
			}
			: undefined;
		return {
			schema: candidate.schema || "yas.hybrid.v1",
			payload: { type: payloadType, meta: payloadMeta },
			encryption: {
				algorithm: candidate.encryption.algorithm || "AES-GCM",
				iv: candidate.encryption.iv,
				cipherText: candidate.encryption.cipherText,
			},
			wrappedKey: {
				algorithm: candidate.wrappedKey.algorithm || "RSA-OAEP",
				cipherText: candidate.wrappedKey.cipherText,
			},
		};
	}

	async function handleDecryptSubmit(e: React.FormEvent) {
		e.preventDefault();
		setDecryptStatus(null);
		setDecryptError(null);
		setDecryptedResult(null);
		try {
			setDecryptBusy(true);
			setDecryptStatus("Decrypting...");
			const envelope = await loadEnvelopeFromInput();
			const privatePem = await resolvePrivateKeyPem();
			const { data: plainBuffer, metadata: metaBuffer } = await decryptForPrivateKey(envelope, privatePem);
			const metadata = metaBuffer ? (JSON.parse(decodeUtf8(metaBuffer)) as EncryptedPayloadMetadata) : null;
			if (envelope.payload.type === "text") {
				const textMetadata = metadata?.type === "text" ? metadata : undefined;
				setDecryptedResult({ type: "text", text: decodeUtf8(plainBuffer), metadata: textMetadata });
			} else {
				const fileMetadata = metadata?.type === "file" ? metadata : undefined;
				const mimeType = fileMetadata?.mimeType || "application/octet-stream";
				const fileName = fileMetadata?.fileName || "yas-decrypted.bin";
				const blob = new Blob([plainBuffer], { type: mimeType });
				setDecryptedResult({ type: "file", blob, fileName, mimeType, metadata: fileMetadata });
			}
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

	function handleDownloadDecryptedFile() {
		if (!decryptedResult || decryptedResult.type !== "file") return;
		const url = URL.createObjectURL(decryptedResult.blob);
		const link = document.createElement("a");
		link.href = url;
		link.download = decryptedResult.fileName || `yas-decrypted-${Date.now()}.bin`;
		link.click();
		URL.revokeObjectURL(url);
	}

	async function handleEncryptSubmit(e: React.FormEvent) {
		e.preventDefault();
		const recipient = contacts.find((contact) => contact.id === encryptRecipientId);
		if (!recipient) {
			setEncryptError("Select a contact to encrypt for");
			return;
		}

		let payloadBuffer: ArrayBuffer | null = null;
		const payloadMeta: EncryptedEnvelope["payload"] = { type: encryptMode };
		let metadataObj: EncryptedPayloadMetadata | null = null;
		try {
			if (encryptMode === "text") {
				if (!encryptPlaintext) {
					setEncryptError("Enter text to encrypt");
					return;
				}
				payloadBuffer = encodeUtf8(encryptPlaintext);
				metadataObj = {
					type: "text",
					encoding: "utf-8",
					length: encryptPlaintext.length,
					createdAt: new Date().toISOString(),
				};
			} else {
				if (!encryptFile) {
					setEncryptError("Select a file to encrypt");
					return;
				}
				payloadBuffer = await encryptFile.arrayBuffer();
				metadataObj = {
					type: "file",
					fileName: encryptFile.name || "payload.bin",
					mimeType: encryptFile.type || "application/octet-stream",
					size: encryptFile.size,
					modifiedAt: new Date(encryptFile.lastModified || Date.now()).toISOString(),
				};
			}
		} catch (fileError) {
			console.error(fileError);
			setEncryptError("Failed to read input data");
			return;
		}

		if (!payloadBuffer) {
			setEncryptError("Nothing to encrypt");
			return;
		}

		try {
			setEncryptBusy(true);
			setEncryptStatus("Encrypting...");
			setEncryptError(null);
			setCopyPayloadStatus("idle");
			const metadataBuffer = metadataObj ? encodeUtf8(JSON.stringify(metadataObj)) : undefined;
			const hybrid = await encryptForPublicKey(payloadBuffer, recipient.publicKey, metadataBuffer);
			if (hybrid.metadata) {
				payloadMeta.meta = {
					algorithm: "AES-GCM",
					iv: hybrid.metadata.iv,
					cipherText: hybrid.metadata.cipherText,
				};
			}
			const envelope: EncryptedEnvelope = {
				schema: "yas.hybrid.v1",
				payload: payloadMeta,
				encryption: {
					algorithm: "AES-GCM",
					iv: hybrid.iv,
					cipherText: hybrid.cipherText,
				},
				wrappedKey: {
					algorithm: "RSA-OAEP",
					cipherText: hybrid.encryptedKey,
				},
			};
			setEncryptedPayload(envelope);
			let payloadDescription: string;
			if (metadataObj?.type === "file") {
				payloadDescription = `${metadataObj.fileName} (${formatBytes(metadataObj.size)})`;
			} else {
				const length = metadataObj?.length ?? encryptPlaintext.length;
				payloadDescription = `${length} chars`;
			}
			setLastEncryptionSummary({ recipient: recipient.contactUsername, payloadDescription });
			const label = encryptMode === "file" ? "file" : "text";
			setEncryptStatus(`Encrypted ${label} for ${recipient.contactUsername}`);
		} catch (err) {
			console.error(err);
			setEncryptError((err as Error).message || "Failed to encrypt data");
			setEncryptStatus(null);
			setEncryptedPayload(null);
			setLastEncryptionSummary(null);
		} finally {
			setEncryptBusy(false);
		}
	}

	async function handleCopyEncryptedPayload() {
		if (!encryptedPayload) return;
		try {
			await navigator.clipboard.writeText(JSON.stringify(encryptedPayload, null, 2));
			setCopyPayloadStatus("copied");
			setTimeout(() => setCopyPayloadStatus("idle"), 2000);
		} catch (err) {
			console.error(err);
			setCopyPayloadStatus("error");
			setTimeout(() => setCopyPayloadStatus("idle"), 2000);
		}
	}

	function handleDownloadEncryptedPayload() {
		if (!encryptedPayload) return;
		downloadEncryptedEnvelope(encryptedPayload);
	}

	function generatePassphrase() {
		const phrase = generate({ exactly: 8, join: "-" }) as string;
		setPassphrase(phrase);
	}

	async function handleGenerateKeys() {
		setError(null);
		setStatus("Generating RSA-4096 key pair...");
		try {
			const { publicKeyPem, privateKeyPem } = await generateRsaKeyPair();
			setPublicKeyPem(publicKeyPem);
			setPrivateKeyPem(privateKeyPem);
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
			const payload = await buildAccountPayload(username, passphrase, publicKeyPem, privateKeyPem, notes || undefined);
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
			setPassphrase("");
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
		setPassphrase("");
		setNotes("");
		setStatus(null);
		setError(null);
	}

	async function handleContactSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!authToken) return;
		const trimmedUsername = contactForm.contactUsername.trim();
		const trimmedKey = contactForm.publicKey.trim();
		const selfPublicKeyBody = extractPublicKeyBody(storedAccount?.publicKey || publicKeyPem);
		const targetKeyBody = extractPublicKeyBody(trimmedKey);
		if (selfPublicKeyBody && targetKeyBody && selfPublicKeyBody === targetKeyBody) {
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
					console.error(deleteErr);
					setContactError((deleteErr as Error).message || "Failed to remove old contact");
				}
			}
			closeContactModal();
		} catch (err) {
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
			console.error(err);
			setContactError((err as Error).message || "Failed to delete contact");
		}
	}

	function renderDecryptedMetadata(meta: EncryptedPayloadMetadata) {
		const rows = meta.type === "text"
			? [
					{ label: "Encoding", value: meta.encoding },
					{ label: "Length", value: `${meta.length} chars` },
					{ label: "Captured", value: formatTimestamp(meta.createdAt) },
				]
			: [
					{ label: "File name", value: meta.fileName },
					{ label: "Type", value: meta.mimeType },
					{ label: "Size", value: formatBytes(meta.size) },
					{ label: "Modified", value: formatTimestamp(meta.modifiedAt ?? null) },
				];
		return (
			<div className="meta-grid">
				{rows.map((row) =>
					row.value ? (
						<div key={row.label}>
							<span className="summary-label">{row.label}</span>
							<p>{row.value}</p>
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
							<div className="grid single-col">
								<div>
									<label className="label" htmlFor="passphrase">Passphrase</label>
									<div className="input-row">
										<input
											id="passphrase"
											type={showPassphrase ? "text" : "password"}
											value={passphrase}
											onChange={(e) => setPassphrase(e.target.value)}
											placeholder="Enter a strong passphrase"
										/>
										<button type="button" className="secondary" onClick={generatePassphrase}>Generate</button>
										<button type="button" className="secondary" onClick={() => setShowPassphrase((v) => !v)}>
											{showPassphrase ? "Hide" : "Show"}
										</button>
									</div>
								</div>
							</div>

							<label className="label" htmlFor="notes">Notes (optional)</label>
							<textarea id="notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Label this key..." />

							<div className="actions">
								<button onClick={handleGenerateKeys} className="secondary">Generate RSA key pair</button>
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
									<pre>{privateKeyPem || "(generate a key pair)"}</pre>
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
			const disableEncrypt = !encryptRecipientId || encryptBusy || (encryptMode === "text" ? !encryptPlaintext : !encryptFile);

			return (
				<>
					<section className="card">
						<h2>Encrypt data</h2>
						<p className="hint">Use hybrid RSA-OAEP + AES-GCM so only the selected contact can recover the payload.</p>
						{!hasContacts && !contactsLoading && <div className="status info">Add a contact first to enable encryption.</div>}
						<form className="form-vertical" onSubmit={handleEncryptSubmit}>
							<label className="label" htmlFor="encrypt-contact">Recipient</label>
							<select
								id="encrypt-contact"
								value={encryptRecipientId}
								onChange={(e) => {
									setEncryptRecipientId(e.target.value);
									setEncryptStatus(null);
									setEncryptError(null);
									setEncryptedPayload(null);
									setCopyPayloadStatus("idle");
									setLastEncryptionSummary(null);
								}}
								disabled={!hasContacts || encryptBusy}
							>
								<option value="">Select a contact</option>
								{contacts.map((contact) => (
									<option key={contact.id} value={contact.id}>
										{contact.contactUsername}
									</option>
								))}
							</select>

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
								<textarea
									id="plaintext"
									value={encryptPlaintext}
									onChange={(e) => {
										setEncryptPlaintext(e.target.value);
										setEncryptStatus(null);
										setEncryptError(null);
										setEncryptedPayload(null);
										setCopyPayloadStatus("idle");
										setLastEncryptionSummary(null);
									}}
									placeholder="Write the message to encrypt"
									disabled={!hasContacts}
								/>
							) : (
								<div className="file-picker">
									<div
										className={isFileDragActive ? "file-dropzone drag-active" : "file-dropzone"}
										onDragEnter={handleFileDragEnter}
										onDragOver={handleFileDragOver}
										onDragLeave={handleFileDragLeave}
										onDrop={handleFileDrop}
										aria-disabled={!hasContacts || encryptBusy}
									>
										<input
											id="encrypt-file"
											type="file"
											onChange={handleEncryptFileChange}
											disabled={!hasContacts || encryptBusy}
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
								<button type="submit" disabled={!hasContacts || disableEncrypt}>{encryptBusy ? "Encrypting..." : "Encrypt"}</button>
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

						{encryptedPayload && (
							<section className="card">
								<div className="encrypt-summary">
									{lastEncryptionSummary?.recipient && (
										<div>
											<span className="summary-label">Recipient</span>
											<p>{lastEncryptionSummary.recipient}</p>
										</div>
									)}
									<div>
										<span className="summary-label">Payload</span>
										<p>{lastEncryptionSummary?.payloadDescription || (encryptedPayload.payload.type === "text" ? "Text" : "Binary data")}</p>
									</div>
									<div>
										<span className="summary-label">Algorithm</span>
										<p>AES-GCM + RSA-OAEP</p>
									</div>
								</div>
								<p className="hint">Ciphertext downloaded automatically with only the metadata needed for decryption.</p>
								<div className="result-actions">
									<button
										type="button"
										className={`secondary button-inline copy-state ${copyPayloadStatus === "copied" ? "copied" : copyPayloadStatus === "error" ? "error" : ""}`}
										onClick={handleCopyEncryptedPayload}
									>
										{copyPayloadStatus === "copied" ? "Copied" : copyPayloadStatus === "error" ? "Error" : "Copy JSON"}
									</button>
									<button type="button" className="ghost button-inline" onClick={handleDownloadEncryptedPayload}>
										Download ciphertext
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
										placeholder="-----BEGIN PUBLIC KEY-----"
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
			<section className="card">
				<h2>Decrypt</h2>
				<p className="hint">Paste or upload ciphertext JSON, unlock your private key (passphrase or PEM), and decrypt locally.</p>
				<form className="form-vertical" onSubmit={handleDecryptSubmit}>
					<label className="label" htmlFor="decrypt-json">Ciphertext JSON</label>
					<textarea
						id="decrypt-json"
						placeholder='{"schema":"yas.hybrid.v1",...}'
						value={decryptPayloadInput}
						onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => {
							setDecryptPayloadInput(e.target.value);
							setDecryptPayloadFile(null);
							setDecryptStatus(null);
							setDecryptError(null);
							setDecryptedResult(null);
						}}
						disabled={decryptBusy}
					/>

					<div className="file-picker">
						<label className="label" htmlFor="decrypt-file">Or upload ciphertext (.json)</label>
						<input id="decrypt-file" type="file" accept="application/json" onChange={handleDecryptFileChange} disabled={decryptBusy} />
						{decryptPayloadFile && (
							<div className="file-info">
								<div>
									<strong>{decryptPayloadFile.name}</strong>
									<p className="muted">{formatBytes(decryptPayloadFile.size)} · {decryptPayloadFile.type || "application/json"}</p>
								</div>
								<button type="button" className="secondary button-inline" onClick={() => setDecryptPayloadFile(null)} disabled={decryptBusy}>
									Remove
								</button>
							</div>
						)}
					</div>

					<div className="grid">
						<div>
							<label className="label" htmlFor="decrypt-passphrase">Passphrase (to unlock stored key)</label>
							<input
								id="decrypt-passphrase"
								type="password"
								value={decryptPassphrase}
								onChange={(e) => {
									setDecryptPassphrase(e.target.value);
									setDecryptStatus(null);
									setDecryptError(null);
								}}
								placeholder="Enter passphrase to unlock stored key"
								disabled={decryptBusy}
							/>
						</div>
						<div>
							<label className="label" htmlFor="decrypt-private-key">Or paste a private key (PEM)</label>
							<textarea
								id="decrypt-private-key"
								value={decryptPrivateKeyInput}
								onChange={(e) => {
									setDecryptPrivateKeyInput(e.target.value);
									setDecryptStatus(null);
									setDecryptError(null);
								}}
								placeholder="-----BEGIN PRIVATE KEY-----"
								disabled={decryptBusy}
							/>
							<p className="hint">If provided, this overrides stored keys and passphrase unlocking.</p>
						</div>
					</div>

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

				{decryptedResult && (
					<section className="card">
						<h3>Decryption result</h3>
						{decryptedResult.metadata && renderDecryptedMetadata(decryptedResult.metadata)}
						{decryptedResult.type === "text" ? (
							<pre>{decryptedResult.text}</pre>
						) : (
							<>
								<p className="hint">Ready to restore {decryptedResult.fileName} ({decryptedResult.mimeType}).</p>
								<div className="result-actions">
									<button type="button" onClick={handleDownloadDecryptedFile}>Download original file</button>
								</div>
							</>
						)}
					</section>
				)}
			</section>
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
			? "Use hybrid RSA-OAEP + AES-GCM: choose a contact, encrypt locally, and share only ciphertext."
			: "Paste ciphertext and KDF metadata, derive your AES key from your passphrase, and decrypt without leaving the browser.";

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
