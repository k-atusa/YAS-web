import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect, useRef, useState } from "react";
import { getAccountByUsername, login as loginApi, saveAccount, signup, listContacts, createContact, deleteContact, getWebAuthnAuthenticateOptions, verifyWebAuthnAuthentication, } from "./api";
import { buildAccountPayload, generateKeyPair, encryptOpsec, decryptOpsecPw, decryptOpsecPub, detectAuthMode, u8ToBase64, base64ToU8, authenticateWithWebAuthn, isWebAuthnAvailable, } from "./crypto";
function formatBytes(bytes) {
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
function formatTimestamp(value) {
	if (!value)
		return null;
	const date = typeof value === "string" ? new Date(value) : new Date(value);
	if (Number.isNaN(date.getTime())) {
		return typeof value === "string" ? value : String(value);
	}
	return date.toLocaleString();
}
function IconHome({ active }) {
	const stroke = active ? "#38bdf8" : "#94a3b8";
	return (_jsxs("svg", { width: "20", height: "20", viewBox: "0 0 24 24", fill: "none", stroke: stroke, strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("path", { d: "M3 10.5 12 3l9 7.5" }), _jsx("path", { d: "M5 12v7.5a.5.5 0 0 0 .5.5H10v-5h4v5h4.5a.5.5 0 0 0 .5-.5V12" })] }));
}
function IconBook({ active }) {
	const stroke = active ? "#38bdf8" : "#94a3b8";
	return (_jsxs("svg", { width: "20", height: "20", viewBox: "0 0 24 24", fill: "none", stroke: stroke, strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("path", { d: "M5 4h11a3 3 0 0 1 3 3v12" }), _jsx("path", { d: "M5 20h11a3 3 0 0 0 3-3" }), _jsx("path", { d: "M5 20a3 3 0 0 1 0-6h14" }), _jsx("path", { d: "M9 8h6" }), _jsx("path", { d: "M9 12h3" })] }));
}
function IconLock({ active }) {
	const stroke = active ? "#38bdf8" : "#94a3b8";
	return (_jsxs("svg", { width: "20", height: "20", viewBox: "0 0 24 24", fill: "none", stroke: stroke, strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("rect", { x: "4", y: "11", width: "16", height: "10", rx: "2" }), _jsx("path", { d: "M8 11V7a4 4 0 0 1 8 0v4" }), _jsx("path", { d: "M12 15v2" })] }));
}
function IconUnlock({ active }) {
	const stroke = active ? "#38bdf8" : "#94a3b8";
	return (_jsxs("svg", { width: "20", height: "20", viewBox: "0 0 24 24", fill: "none", stroke: stroke, strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("rect", { x: "4", y: "11", width: "16", height: "10", rx: "2" }), _jsx("path", { d: "M16 11V7a4 4 0 0 0-8 0" }), _jsx("path", { d: "M12 15v2" })] }));
}
function App() {
	const [authToken, setAuthToken] = useState(() => localStorage.getItem("authToken"));
	const [authUsername, setAuthUsername] = useState(() => localStorage.getItem("authUsername"));
	const [authMode, setAuthMode] = useState("login");
	const [loginUsername, setLoginUsername] = useState("");
	const [loginPass, setLoginPass] = useState("");
	const [loginPassConfirm, setLoginPassConfirm] = useState("");
	const [loginBusy, setLoginBusy] = useState(false);
	const [username, setUsername] = useState("");
	const [publicKeyPem, setPublicKeyPem] = useState("");
	const [privateKeyPem, setPrivateKeyPem] = useState("");
	const [notes, setNotes] = useState("");
	const [status, setStatus] = useState(null);
	const [error, setError] = useState(null);
	const [busy, setBusy] = useState(false);
	const [tab, setTab] = useState("keys");
	const [storedAccount, setStoredAccount] = useState(null);
	const [showKeySection, setShowKeySection] = useState(true);
	const [copyPublicStatus, setCopyPublicStatus] = useState("idle");
	const [copyPrivateStatus, setCopyPrivateStatus] = useState("idle");
	const [contacts, setContacts] = useState([]);
	const [contactsLoading, setContactsLoading] = useState(false);
	const [contactForm, setContactForm] = useState({ contactUsername: "", publicKey: "", notes: "" });
	const [contactError, setContactError] = useState(null);
	const [contactBusy, setContactBusy] = useState(false);
	const [contactModalOpen, setContactModalOpen] = useState(false);
	const [contactModalClosing, setContactModalClosing] = useState(false);
	const [contactModalMode, setContactModalMode] = useState("add");
	const [editingContactMeta, setEditingContactMeta] = useState(null);
	const [contactModalError, setContactModalError] = useState(null);
	const closeModalTimer = useRef(null);
	const [keyAlgo, setKeyAlgo] = useState("ecc1");
	const [encryptAuthMode, setEncryptAuthMode] = useState("password");
	const [encryptKdfMethod, setEncryptKdfMethod] = useState("pbk1");
	const [encryptEncAlgo, setEncryptEncAlgo] = useState("gcm1");
	const [encryptAsymAlgo, setEncryptAsymAlgo] = useState("ecc1");
	const [encryptPassword, setEncryptPassword] = useState("");
	const [encryptRecipientId, setEncryptRecipientId] = useState("");
	const [encryptMsg, setEncryptMsg] = useState("");
	const [encryptSmsg, setEncryptSmsg] = useState("");
	const [encryptMode, setEncryptMode] = useState("text");
	const [encryptFile, setEncryptFile] = useState(null);
	const [isFileDragActive, setIsFileDragActive] = useState(false);
	const [encryptSignWithKey, setEncryptSignWithKey] = useState(false);
	const [encryptBusy, setEncryptBusy] = useState(false);
	const [encryptStatus, setEncryptStatus] = useState(null);
	const [encryptError, setEncryptError] = useState(null);
	const [encryptedBlob, setEncryptedBlob] = useState(null);
	const [decryptPayloadInput, setDecryptPayloadInput] = useState("");
	const [decryptPayloadFile, setDecryptPayloadFile] = useState(null);
	const [isDecryptFileDragActive, setIsDecryptFileDragActive] = useState(false);
	const [decryptPassword, setDecryptPassword] = useState("");
	const [decryptPrivateKeyInput, setDecryptPrivateKeyInput] = useState("");
	const [decryptPeerPublicKey, setDecryptPeerPublicKey] = useState("");
	const [decryptDetected, setDecryptDetected] = useState(null);
	const [decryptBusy, setDecryptBusy] = useState(false);
	const [decryptStatus, setDecryptStatus] = useState(null);
	const [decryptError, setDecryptError] = useState(null);
	const [decryptedResult, setDecryptedResult] = useState(null);
	// WebAuthn states
	const [webauthnAvailable, setWebauthnAvailable] = useState(false);
	const [webauthnAuthBusy, setWebauthnAuthBusy] = useState(false);
	const [decryptionToken, setDecryptionToken] = useState(null);
	useEffect(() => {
		return () => {
			if (closeModalTimer.current) {
				window.clearTimeout(closeModalTimer.current);
				closeModalTimer.current = null;
			}
		};
	}, []);
	useEffect(() => {
		if (!encryptedBlob)
			return;
		const blob = new Blob([encryptedBlob.buffer.slice(encryptedBlob.byteOffset, encryptedBlob.byteOffset + encryptedBlob.byteLength)], { type: "application/octet-stream" });
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
			if (authUsername)
				localStorage.setItem("authUsername", authUsername);
		}
		else {
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
			}
			catch (err) {
				const errMsg = err.message || "Failed to load contacts";
				console.error(err);
				if (errMsg === "TOKEN_EXPIRED") {
					// Token expired, auto-logout
					handleSignOut();
					return;
				}
				if (!cancelled) {
					setContactError(errMsg);
				}
			}
			finally {
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
		}
		else {
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
				const record = await getAccountByUsername(usernameSnapshot);
				if (!cancelled && authUsername === usernameSnapshot) {
					setStoredAccount(record);
					setShowKeySection(!record);
					if (record) {
						setPublicKeyPem(record.publicKey);
						setStatus(null);
					}
				}
			}
			catch (err) {
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
	async function handleLogin(e) {
		e.preventDefault();
		if (!canLogin)
			return;
		setLoginBusy(true);
		setError(null);
		setStatus(null);
		try {
			const result = await loginApi(loginUsername, loginPass);
			setAuthToken(result.token);
			setAuthUsername(result.user.username);
		}
		catch (err) {
			console.error(err);
			setError(err.message || "Login failed");
		}
		finally {
			setLoginBusy(false);
		}
	}
	async function handleCopyPublicKey(value) {
		if (!value)
			return;
		try {
			await navigator.clipboard.writeText(value);
			setCopyPublicStatus("copied");
			setTimeout(() => setCopyPublicStatus("idle"), 2000);
		}
		catch (err) {
			console.error(err);
			setCopyPublicStatus("error");
			setTimeout(() => setCopyPublicStatus("idle"), 2000);
		}
	}
	async function handleCopyPrivateKey(value) {
		if (!value)
			return;
		try {
			await navigator.clipboard.writeText(value);
			setCopyPrivateStatus("copied");
			setTimeout(() => setCopyPrivateStatus("idle"), 2000);
		}
		catch (err) {
			console.error(err);
			setCopyPrivateStatus("error");
			setTimeout(() => setCopyPrivateStatus("idle"), 2000);
		}
	}
	async function handleSignup(e) {
		e.preventDefault();
		if (!canLogin)
			return;
		setLoginBusy(true);
		setError(null);
		setStatus(null);
		try {
			await signup(loginUsername, loginPass);
			const result = await loginApi(loginUsername, loginPass);
			setAuthToken(result.token);
			setAuthUsername(result.user.username);
			setAuthMode("login");
		}
		catch (err) {
			console.error(err);
			setError(err.message || "Signup failed");
		}
		finally {
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
	function openEditContactModal(contact) {
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
		if (contactModalClosing)
			return;
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
	function handleEncryptionModeChange(mode) {
		if (mode === encryptMode)
			return;
		setEncryptMode(mode);
		if (mode === "text") {
			applySelectedEncryptFile(null);
			setIsFileDragActive(false);
		}
		else {
			setEncryptSmsg("");
		}
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptedBlob(null);
	}
	function applySelectedEncryptFile(file) {
		setEncryptFile(file);
		setEncryptStatus(null);
		setEncryptError(null);
		setEncryptedBlob(null);
	}
	function handleFileDragEnter(event) {
		event.preventDefault();
		if (encryptBusy)
			return;
		setIsFileDragActive(true);
	}
	function handleFileDragOver(event) {
		event.preventDefault();
		if (encryptBusy)
			return;
		event.dataTransfer.dropEffect = "copy";
		if (!isFileDragActive) {
			setIsFileDragActive(true);
		}
	}
	function handleFileDragLeave(event) {
		event.preventDefault();
		const nextTarget = event.relatedTarget;
		if (nextTarget && event.currentTarget.contains(nextTarget)) {
			return;
		}
		setIsFileDragActive(false);
	}
	function handleFileDrop(event) {
		event.preventDefault();
		setIsFileDragActive(false);
		if (encryptBusy)
			return;
		const droppedFile = event.dataTransfer.files?.[0];
		if (droppedFile) {
			applySelectedEncryptFile(droppedFile);
		}
	}
	function handleEncryptFileChange(event) {
		const file = event.target.files?.[0] ?? null;
		applySelectedEncryptFile(file);
		setIsFileDragActive(false);
		event.target.value = "";
	}
	function clearSelectedFile() {
		applySelectedEncryptFile(null);
		setIsFileDragActive(false);
	}
	function handleDecryptDragEnter(event) {
		event.preventDefault();
		if (decryptBusy)
			return;
		setIsDecryptFileDragActive(true);
	}
	function handleDecryptDragOver(event) {
		event.preventDefault();
		if (decryptBusy)
			return;
		event.dataTransfer.dropEffect = "copy";
		if (!isDecryptFileDragActive) {
			setIsDecryptFileDragActive(true);
		}
	}
	function handleDecryptDragLeave(event) {
		event.preventDefault();
		const nextTarget = event.relatedTarget;
		if (nextTarget && event.currentTarget.contains(nextTarget)) {
			return;
		}
		setIsDecryptFileDragActive(false);
	}
	function handleDecryptFileDrop(event) {
		event.preventDefault();
		setIsDecryptFileDragActive(false);
		if (decryptBusy)
			return;
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
	function handleDecryptFileChange(event) {
		const file = event.target.files?.[0] ?? null;
		setDecryptPayloadFile(file);
		setDecryptPayloadInput("");
		setDecryptStatus(null);
		setDecryptError(null);
		setDecryptedResult(null);
		setIsDecryptFileDragActive(false);
		event.target.value = "";
	}
	async function resolvePrivateKeyB64() {
		const manual = decryptPrivateKeyInput.trim();
		if (manual)
			return manual;
		if (privateKeyPem)
			return privateKeyPem;
		if (storedAccount?.encryptedPrivateKey && storedAccount?.kdf) {
			// Must use WebAuthn for stored keys
			if (!decryptionToken) {
				throw new Error("Use WebAuthn to unlock your stored private key");
			}
			// TODO: Implement server-side decryption with WebAuthn token
			throw new Error("Server-side key decryption not yet implemented");
		}
		throw new Error("No private key available. Paste one or use WebAuthn.");
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
			setDecryptionToken(verifyResp.token);
			setDecryptStatus(null);
			setDecryptError(null);
			// Success message would be shown in UI
		}
		catch (err) {
			const msg = err.message || "WebAuthn authentication failed";
			setDecryptError(msg);
			setDecryptStatus(null);
		}
		finally {
			setWebauthnAuthBusy(false);
		}
	}
	async function loadOpsecData() {
		if (decryptPayloadFile) {
			return new Uint8Array(await decryptPayloadFile.arrayBuffer());
		}
		const raw = decryptPayloadInput.trim();
		if (!raw) {
			throw new Error("Paste Base64 ciphertext or upload a file");
		}
		try {
			return base64ToU8(raw);
		}
		catch {
			throw new Error("Invalid Base64 format");
		}
	}
	async function handleDecryptSubmit(e) {
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
			let result;
			if (info.mode === "password") {
				if (!decryptPassword)
					throw new Error("Enter the encryption password");
				result = await decryptOpsecPw(dataU8, decryptPassword);
			}
			else {
				const priB64 = await resolvePrivateKeyB64();
				const peerPub = decryptPeerPublicKey.trim() || undefined;
				result = await decryptOpsecPub(dataU8, priB64, peerPub);
			}
			setDecryptedResult(result);
			setDecryptStatus("Decrypted successfully");
		}
		catch (err) {
			console.error(err);
			setDecryptError(err.message || "Failed to decrypt");
			setDecryptStatus(null);
			setDecryptedResult(null);
		}
		finally {
			setDecryptBusy(false);
		}
	}
	function handleDownloadDecryptedFile(name, data) {
		const blob = new Blob([data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)], { type: "application/octet-stream" });
		const url = URL.createObjectURL(blob);
		const link = document.createElement("a");
		link.href = url;
		link.download = name;
		link.click();
		URL.revokeObjectURL(url);
	}
	async function handleEncryptSubmit(e) {
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
		}
		else {
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
		}
		else {
			if (!encryptFile) {
				setEncryptError("Select a file to encrypt");
				return;
			}
		}
		try {
			setEncryptBusy(true);
			setEncryptStatus("Encrypting...");
			const files = encryptMode === "file" && encryptFile ? [encryptFile] : undefined;
			let result;
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
			}
			else {
				const recipient = contacts.find((c) => c.id === encryptRecipientId);
				let myPrivateKey;
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
			}
			else {
				setEncryptStatus(`Encrypted file (${formatBytes(result.length)}). Download started.`);
			}
		}
		catch (err) {
			console.error(err);
			setEncryptError(err.message || "Failed to encrypt");
			setEncryptStatus(null);
			setEncryptedBlob(null);
		}
		finally {
			setEncryptBusy(false);
		}
	}
	function handleDownloadEncryptedBlob() {
		if (!encryptedBlob)
			return;
		const blob = new Blob([encryptedBlob.buffer.slice(encryptedBlob.byteOffset, encryptedBlob.byteOffset + encryptedBlob.byteLength)], { type: "application/octet-stream" });
		const url = URL.createObjectURL(blob);
		const link = document.createElement("a");
		link.href = url;
		link.download = `encrypted-${Date.now()}.bin`;
		link.click();
		URL.revokeObjectURL(url);
	}
	async function handleCopyEncryptedBase64() {
		if (!encryptedBlob)
			return;
		try {
			await navigator.clipboard.writeText(u8ToBase64(encryptedBlob));
		}
		catch (err) {
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
		}
		catch (err) {
			console.error(err);
			setError("Failed to generate key pair");
			setStatus(null);
		}
	}
	async function handleUpload() {
		if (!canUpload)
			return;
		setBusy(true);
		setError(null);
		setStatus("Encrypting and uploading...");
		try {
			const payload = await buildAccountPayload(username, publicKeyPem, privateKeyPem, notes || undefined);
			const result = await saveAccount(payload, authToken ?? undefined);
			const record = {
				...payload,
				id: result.id,
				createdAt: result.createdAt,
			};
			setStoredAccount(record);
			setStatus("Stored encrypted key");
			setShowKeySection(false);
			setPrivateKeyPem("");
			setCopyPrivateStatus("idle");
		}
		catch (err) {
			console.error(err);
			setError(err.message || "Upload failed");
			setStatus(null);
		}
		finally {
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
	async function handleContactSubmit(e) {
		e.preventDefault();
		if (!authToken)
			return;
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
				}
				catch (deleteErr) {
					if (deleteErr.message === "TOKEN_EXPIRED") {
						handleSignOut();
						return;
					}
					console.error(deleteErr);
					setContactError(deleteErr.message || "Failed to remove old contact");
				}
			}
			closeContactModal();
		}
		catch (err) {
			if (err.message === "TOKEN_EXPIRED") {
				handleSignOut();
				return;
			}
			console.error(err);
			setContactModalError(err.message || "Failed to save contact");
		}
		finally {
			setContactBusy(false);
		}
	}
	async function handleDeleteContact(id) {
		if (!authToken)
			return;
		const confirmed = window.confirm("Delete this contact?");
		if (!confirmed)
			return;
		try {
			await deleteContact(id, authToken);
			setContacts((prev) => prev.filter((contact) => contact.id !== id));
		}
		catch (err) {
			if (err.message === "TOKEN_EXPIRED") {
				handleSignOut();
				return;
			}
			console.error(err);
			setContactError(err.message || "Failed to delete contact");
		}
	}
	function renderDecryptedInfo(result) {
		const rows = [];
		if (result.msg)
			rows.push({ label: "Public message", value: result.msg });
		if (result.smsg)
			rows.push({ label: "Secure message", value: result.smsg });
		if (result.files.length > 0)
			rows.push({ label: "Files", value: `${result.files.length} file(s)` });
		if (result.verified !== undefined)
			rows.push({ label: "Signature", value: result.verified ? "Valid" : "INVALID" });
		return (_jsx("div", { className: "meta-grid", children: rows.map((row) => row.value ? (_jsxs("div", { children: [_jsx("span", { className: "summary-label", children: row.label }), _jsx("p", { style: { whiteSpace: "pre-wrap" }, children: row.value })] }, row.label)) : null) }));
	}
	function renderTabContent() {
		if (tab === "keys") {
			const hasStoredKey = Boolean(storedAccount?.publicKey && storedAccount?.encryptedPrivateKey?.cipherText);
			if (tab === "keys") {
				return hasStoredKey && !showKeySection ? (_jsxs("section", { className: "card", children: [_jsx("h2", { children: "Your stored key" }), _jsx("p", { className: "hint", children: "Private key is stored encrypted. Regenerate to replace it." }), _jsxs("div", { className: "preview", children: [_jsxs("div", { children: [_jsx("h3", { children: "Public key" }), _jsxs("div", { className: "copy-block", children: [_jsx("button", { type: "button", className: copyPublicStatus === "copied" ? "copy-button copied" : "copy-button", onClick: () => handleCopyPublicKey(storedAccount?.publicKey), children: copyPublicStatus === "copied" ? "Copied" : copyPublicStatus === "error" ? "Error" : "Copy" }), _jsx("pre", { children: storedAccount?.publicKey })] })] }), _jsxs("div", { children: [_jsx("h3", { children: "Private key" }), _jsx("pre", { children: "Encrypted (ciphertext saved on server)" })] })] }), _jsx("div", { className: "actions", children: _jsx("button", { className: "secondary", onClick: handleRegenerate, children: "Regenerate keys" }) })] })) : (_jsxs(_Fragment, { children: [_jsxs("section", { className: "card", children: [_jsx("label", { className: "label", htmlFor: "notes", children: "Notes (optional)" }), _jsx("textarea", { id: "notes", value: notes, onChange: (e) => setNotes(e.target.value), placeholder: "Label this key..." }), _jsx("label", { className: "label", htmlFor: "key-algo", children: "Key algorithm" }), _jsxs("select", { id: "key-algo", value: keyAlgo, onChange: (e) => setKeyAlgo(e.target.value), children: [_jsx("option", { value: "ecc1", children: "Curve448 (X448 + Ed448)" }), _jsx("option", { value: "rsa1", children: "RSA-2048" })] }), _jsxs("div", { className: "actions", children: [_jsx("button", { onClick: handleGenerateKeys, className: "secondary", children: "Generate key pair" }), _jsx("button", { onClick: handleUpload, disabled: !canUpload || busy, children: busy ? "Working..." : "Encrypt and upload" })] }), status && _jsx("div", { className: "status success", children: status }), error && _jsx("div", { className: "status error", children: error })] }), _jsxs("section", { className: "card", children: [_jsx("h2", { children: "Local preview" }), _jsxs("div", { className: "preview", children: [_jsxs("div", { children: [_jsx("h3", { children: "Public key" }), _jsxs("div", { className: "copy-block", children: [_jsx("button", { type: "button", className: copyPublicStatus === "copied" ? "copy-button copied" : "copy-button", onClick: () => handleCopyPublicKey(publicKeyPem || undefined), disabled: !publicKeyPem, children: copyPublicStatus === "copied" ? "Copied" : copyPublicStatus === "error" ? "Error" : "Copy" }), _jsx("pre", { children: publicKeyPem || "(generate a key pair)" })] })] }), _jsxs("div", { children: [_jsx("h3", { children: "Private key (plaintext)" }), _jsxs("div", { className: "copy-block", children: [privateKeyPem && (_jsx("button", { type: "button", className: copyPrivateStatus === "copied" ? "copy-button copied" : "copy-button", onClick: () => handleCopyPrivateKey(privateKeyPem), children: copyPrivateStatus === "copied" ? "Copied" : copyPrivateStatus === "error" ? "Error" : "Copy" })), _jsx("pre", { children: privateKeyPem || "(generate a key pair)" })] })] })] }), _jsx("p", { className: "hint", children: "Private key is encrypted in-browser with AES-GCM using PBKDF2-derived key." })] })] }));
			}
		}
		if (tab === "encrypt") {
			const hasContacts = contacts.length > 0;
			const canEncrypt = encryptAuthMode === "password"
				? (encryptPassword && !encryptBusy && (encryptMode === "text" ? !!encryptSmsg : !!encryptFile))
				: (!!encryptRecipientId && !encryptBusy && (encryptMode === "text" ? !!encryptSmsg : !!encryptFile));
			return (_jsxs(_Fragment, { children: [_jsxs("section", { className: "card", children: [_jsx("h2", { children: "Encrypt data" }), _jsx("p", { className: "hint", children: "YAS2 Opsec encryption \u2014 supports password-based or public-key modes with AES-GCM." }), _jsxs("form", { className: "form-vertical", onSubmit: handleEncryptSubmit, children: [_jsx("label", { className: "label", children: "Authentication mode" }), _jsxs("div", { className: "segment-control", role: "tablist", "aria-label": "Auth mode", children: [_jsx("button", { type: "button", className: encryptAuthMode === "password" ? "segment-option active" : "segment-option", onClick: () => { setEncryptAuthMode("password"); setEncryptError(null); setEncryptStatus(null); setEncryptedBlob(null); }, children: "Password" }), _jsx("button", { type: "button", className: encryptAuthMode === "publickey" ? "segment-option active" : "segment-option", onClick: () => { setEncryptAuthMode("publickey"); setEncryptError(null); setEncryptStatus(null); setEncryptedBlob(null); }, children: "Public key" })] }), encryptAuthMode === "password" && (_jsxs(_Fragment, { children: [_jsx("label", { className: "label", htmlFor: "encrypt-password", children: "Password" }), _jsx("input", { id: "encrypt-password", type: "password", value: encryptPassword, onChange: (e) => { setEncryptPassword(e.target.value); setEncryptError(null); }, placeholder: "Encryption password" }), _jsx("label", { className: "label", htmlFor: "encrypt-kdf", children: "Key derivation" }), _jsxs("select", { id: "encrypt-kdf", value: encryptKdfMethod, onChange: (e) => setEncryptKdfMethod(e.target.value), children: [_jsx("option", { value: "arg1", children: "Argon2id (recommended)" }), _jsx("option", { value: "pbk1", children: "PBKDF2-SHA512" })] })] })), encryptAuthMode === "publickey" && (_jsxs(_Fragment, { children: [!hasContacts && !contactsLoading && _jsx("div", { className: "status info", children: "Add a contact first to enable public key encryption." }), _jsx("label", { className: "label", htmlFor: "encrypt-contact", children: "Recipient" }), _jsxs("select", { id: "encrypt-contact", value: encryptRecipientId, onChange: (e) => { setEncryptRecipientId(e.target.value); setEncryptError(null); setEncryptStatus(null); setEncryptedBlob(null); }, disabled: !hasContacts || encryptBusy, children: [_jsx("option", { value: "", children: "Select a contact" }), contacts.map((c) => (_jsx("option", { value: c.id, children: c.contactUsername }, c.id)))] }), _jsx("label", { className: "label", htmlFor: "encrypt-asym", children: "Asymmetric algorithm" }), _jsxs("select", { id: "encrypt-asym", value: encryptAsymAlgo, onChange: (e) => setEncryptAsymAlgo(e.target.value), children: [_jsx("option", { value: "ecc1", children: "Curve448 (X448 + Ed448)" }), _jsx("option", { value: "rsa1", children: "RSA-2048 (OAEP + PKCS1v1.5)" })] }), _jsxs("label", { className: "label", children: [_jsx("input", { type: "checkbox", checked: encryptSignWithKey, onChange: (e) => setEncryptSignWithKey(e.target.checked) }), " ", "Sign with my private key"] })] })), _jsx("label", { className: "label", htmlFor: "encrypt-enc-algo", children: "Encryption algorithm" }), _jsxs("select", { id: "encrypt-enc-algo", value: encryptEncAlgo, onChange: (e) => setEncryptEncAlgo(e.target.value), children: [_jsx("option", { value: "gcm1", children: "AES-GCM (single block)" }), _jsx("option", { value: "gcmx1", children: "AES-GCM chunked (large files)" })] }), _jsx("label", { className: "label", htmlFor: "encrypt-msg", children: "Public message (optional, visible without decrypt)" }), _jsx("input", { id: "encrypt-msg", type: "text", value: encryptMsg, onChange: (e) => setEncryptMsg(e.target.value), placeholder: "Short public note" }), _jsxs("div", { className: "segment-control", role: "tablist", "aria-label": "Payload type", children: [_jsx("button", { type: "button", className: encryptMode === "text" ? "segment-option active" : "segment-option", onClick: () => handleEncryptionModeChange("text"), children: "Text" }), _jsx("button", { type: "button", className: encryptMode === "file" ? "segment-option active" : "segment-option", onClick: () => handleEncryptionModeChange("file"), children: "File" })] }), encryptMode === "text" ? (_jsxs(_Fragment, { children: [_jsx("label", { className: "label", htmlFor: "encrypt-smsg", children: "Secure message (encrypted)" }), _jsx("textarea", { id: "encrypt-smsg", value: encryptSmsg, onChange: (e) => { setEncryptSmsg(e.target.value); setEncryptError(null); setEncryptStatus(null); setEncryptedBlob(null); }, placeholder: "Write the secret message to encrypt" })] })) : (_jsxs("div", { className: "file-picker", children: [_jsxs("div", { className: isFileDragActive ? "file-dropzone drag-active" : "file-dropzone", onDragEnter: handleFileDragEnter, onDragOver: handleFileDragOver, onDragLeave: handleFileDragLeave, onDrop: handleFileDrop, "aria-disabled": encryptBusy, children: [_jsx("input", { id: "encrypt-file", type: "file", onChange: handleEncryptFileChange, disabled: encryptBusy, className: "visually-hidden" }), _jsxs("label", { htmlFor: "encrypt-file", children: [_jsx("div", { className: "drop-graphic", "aria-hidden": "true", children: _jsxs("svg", { width: "40", height: "40", viewBox: "0 0 40 40", fill: "none", xmlns: "http://www.w3.org/2000/svg", children: [_jsx("rect", { x: "7", y: "23", width: "26", height: "10", rx: "3", stroke: "#38bdf8", strokeWidth: "1.6", opacity: "0.7" }), _jsx("path", { d: "M20 7v18", stroke: "#38bdf8", strokeWidth: "1.6", strokeLinecap: "round" }), _jsx("path", { d: "M15 18l5 5 5-5", stroke: "#38bdf8", strokeWidth: "1.6", strokeLinecap: "round", strokeLinejoin: "round" })] }) }), _jsx("strong", { children: "Drag & drop a file to encrypt" }), _jsx("span", { className: "drop-highlight", children: "Drop it anywhere inside this panel or click to browse." }), _jsx("span", { className: "muted", children: "Files stay local. We encrypt in your browser before anything leaves." })] })] }), encryptFile && (_jsxs("div", { className: "file-info", children: [_jsxs("div", { children: [_jsx("strong", { children: encryptFile.name || "Selected file" }), _jsxs("p", { className: "muted", children: [formatBytes(encryptFile.size), " \u00B7 ", encryptFile.type || "application/octet-stream"] })] }), _jsx("button", { type: "button", className: "secondary button-inline", onClick: clearSelectedFile, disabled: encryptBusy, children: "Remove" })] }))] })), _jsxs("div", { className: "actions", children: [_jsx("button", { type: "submit", disabled: !canEncrypt, children: encryptBusy ? "Encrypting..." : "Encrypt" }), _jsx("button", { type: "button", className: "secondary", onClick: resetEncryptionForm, disabled: encryptBusy, children: "Reset" })] }), encryptBusy && (_jsxs("div", { className: "progress-row", role: "status", "aria-live": "polite", children: [_jsx("div", { className: "progress-bar", children: _jsx("div", { className: "progress-fill" }) }), _jsx("span", { className: "muted", children: "Encrypting payload..." })] }))] }), encryptStatus && _jsx("div", { className: "status success", children: encryptStatus }), encryptError && _jsx("div", { className: "status error", children: encryptError })] }), encryptedBlob && (_jsxs("section", { className: "card", children: [_jsxs("div", { className: "encrypt-summary", children: [_jsxs("div", { children: [_jsx("span", { className: "summary-label", children: "Mode" }), _jsx("p", { children: encryptAuthMode === "password" ? "Password" : "Public key" })] }), _jsxs("div", { children: [_jsx("span", { className: "summary-label", children: "Size" }), _jsx("p", { children: formatBytes(encryptedBlob.length) })] }), _jsxs("div", { children: [_jsx("span", { className: "summary-label", children: "Algorithm" }), _jsx("p", { children: encryptEncAlgo === "gcmx1" ? "AES-GCM chunked" : "AES-GCM" })] })] }), _jsx("p", { className: "hint", children: "Download the encrypted binary or copy as Base64." }), _jsxs("div", { className: "result-actions", children: [_jsx("button", { type: "button", className: "secondary button-inline", onClick: handleCopyEncryptedBase64, children: "Copy Base64" }), _jsx("button", { type: "button", className: "ghost button-inline", onClick: handleDownloadEncryptedBlob, children: "Download .bin" })] })] }))] }));
		}
		if (tab === "address-book") {
			const isContactFormValid = Boolean(contactForm.contactUsername.trim() && contactForm.publicKey.trim());
			return (_jsxs(_Fragment, { children: [_jsxs("section", { className: "card", children: [_jsxs("div", { className: "contact-header", children: [_jsxs("div", { children: [_jsx("h2", { children: "Contacts" }), _jsx("p", { className: "hint", children: "Manage trusted recipients and their public keys so you can encrypt messages to them." })] }), _jsx("button", { type: "button", className: "secondary button-inline", onClick: openAddContactModal, children: "Add contact" })] }), contactError && _jsx("div", { className: "status error", children: contactError }), _jsxs("div", { className: "contact-list", children: [_jsxs("div", { className: "contact-list-header", children: [_jsx("h3", { children: "Saved contacts" }), contactsLoading && _jsx("span", { className: "muted", children: "Loading..." })] }), contacts.length === 0 && !contactsLoading ? (_jsx("p", { className: "hint", children: "No contacts yet. Add someone to start encrypting messages for them." })) : (_jsx("ul", { className: "contact-items", children: contacts.map((contact) => (_jsxs("li", { className: "contact-item", children: [_jsxs("div", { className: "contact-meta", children: [_jsx("strong", { children: contact.contactUsername }), contact.notes && _jsx("p", { className: "hint", children: contact.notes })] }), _jsxs("div", { className: "contact-actions", children: [_jsx("button", { type: "button", className: `secondary button-inline copy-state ${copyPublicStatus === "copied" ? "copied" : copyPublicStatus === "error" ? "error" : ""}`, onClick: () => handleCopyPublicKey(contact.publicKey), children: copyPublicStatus === "copied" ? "Copied" : copyPublicStatus === "error" ? "Error" : "Copy key" }), _jsx("button", { type: "button", className: "secondary button-inline", onClick: () => openEditContactModal(contact), children: "Edit" }), _jsx("button", { type: "button", className: "ghost button-inline danger", onClick: () => handleDeleteContact(contact.id), children: "Delete" })] })] }, contact.id))) }))] })] }), (contactModalOpen || contactModalClosing) && (_jsx("div", { className: contactModalClosing ? "modal-backdrop closing" : "modal-backdrop", role: "dialog", "aria-modal": "true", children: _jsxs("div", { className: contactModalClosing ? "modal-card closing" : "modal-card", children: [_jsxs("div", { className: "modal-header", children: [_jsx("h3", { children: contactModalMode === "add" ? "Add contact" : "Edit contact" }), _jsx("button", { type: "button", className: "ghost button-inline", onClick: closeContactModal, children: "Close" })] }), _jsxs("form", { className: "form-vertical", onSubmit: handleContactSubmit, children: [_jsx("label", { className: "label", htmlFor: "contact-username", children: "Contact username" }), _jsx("input", { id: "contact-username", type: "text", value: contactForm.contactUsername, onChange: (e) => setContactForm((prev) => ({ ...prev, contactUsername: e.target.value })), placeholder: "recipient_id", required: true }), _jsx("label", { className: "label", htmlFor: "contact-notes", children: "Notes (optional)" }), _jsx("textarea", { id: "contact-notes", value: contactForm.notes, onChange: (e) => setContactForm((prev) => ({ ...prev, notes: e.target.value })), placeholder: "PGP fingerprint, onboarding status, etc." }), _jsx("label", { className: "label", htmlFor: "contact-public-key", children: "Public key" }), _jsx("textarea", { id: "contact-public-key", value: contactForm.publicKey, onChange: (e) => setContactForm((prev) => ({ ...prev, publicKey: e.target.value })), placeholder: "Base64-encoded public key", required: true }), _jsxs("div", { className: "modal-actions", children: [_jsx("button", { type: "button", className: "ghost button-inline", onClick: closeContactModal, children: "Cancel" }), _jsx("button", { type: "submit", disabled: contactBusy || !isContactFormValid, children: contactBusy ? "Saving..." : contactModalMode === "add" ? "Save contact" : "Update contact" })] }), contactModalError && _jsx("div", { className: "status error", children: contactModalError })] })] }) }))] }));
		}
		return (_jsxs(_Fragment, {
			children: [_jsxs("section", {
				className: "card", children: [_jsx("h2", { children: "Decrypt" }), _jsx("p", { className: "hint", children: "Paste Base64 ciphertext or upload an encrypted binary, then decrypt locally." }), _jsxs("form", {
					className: "form-vertical", onSubmit: handleDecryptSubmit, children: [_jsx("label", { className: "label", htmlFor: "decrypt-base64", children: "Ciphertext (Base64)" }), _jsx("textarea", {
						id: "decrypt-base64", placeholder: "Paste Base64-encoded ciphertext...", value: decryptPayloadInput, onChange: (e) => {
							setDecryptPayloadInput(e.target.value);
							setDecryptPayloadFile(null);
							setDecryptStatus(null);
							setDecryptError(null);
							setDecryptedResult(null);
							setDecryptDetected(null);
						}, disabled: decryptBusy
					}), _jsxs("div", {
						className: "file-picker", children: [_jsxs("div", { className: isDecryptFileDragActive ? "file-dropzone drag-active" : "file-dropzone", onDragEnter: handleDecryptDragEnter, onDragOver: handleDecryptDragOver, onDragLeave: handleDecryptDragLeave, onDrop: handleDecryptFileDrop, "aria-disabled": decryptBusy, children: [_jsx("input", { id: "decrypt-file", type: "file", onChange: handleDecryptFileChange, disabled: decryptBusy, className: "visually-hidden" }), _jsxs("label", { htmlFor: "decrypt-file", children: [_jsx("div", { className: "drop-graphic", "aria-hidden": "true", children: _jsxs("svg", { width: "40", height: "40", viewBox: "0 0 40 40", fill: "none", xmlns: "http://www.w3.org/2000/svg", children: [_jsx("rect", { x: "7", y: "23", width: "26", height: "10", rx: "3", stroke: "#38bdf8", strokeWidth: "1.6", opacity: "0.7" }), _jsx("path", { d: "M20 7v18", stroke: "#38bdf8", strokeWidth: "1.6", strokeLinecap: "round" }), _jsx("path", { d: "M15 18l5 5 5-5", stroke: "#38bdf8", strokeWidth: "1.6", strokeLinecap: "round", strokeLinejoin: "round" })] }) }), _jsx("strong", { children: "Drag & drop encrypted .bin file" }), _jsx("span", { className: "drop-highlight", children: "Drop your encrypted binary here or click to browse." }), _jsx("span", { className: "muted", children: "We parse and decrypt entirely in your browser." })] })] }), decryptPayloadFile && (_jsxs("div", {
							className: "file-info", children: [_jsxs("div", { children: [_jsx("strong", { children: decryptPayloadFile.name }), _jsxs("p", { className: "muted", children: [formatBytes(decryptPayloadFile.size), " \u00B7 ", decryptPayloadFile.type || "application/octet-stream"] })] }), _jsx("button", {
								type: "button", className: "secondary button-inline", onClick: () => {
									setDecryptPayloadFile(null);
									setIsDecryptFileDragActive(false);
								}, disabled: decryptBusy, children: "Remove"
							})]
						}))]
					}), decryptDetected && (_jsxs("div", { className: "status info", children: ["Detected mode: ", _jsx("strong", { children: decryptDetected.mode }), decryptDetected.msg && _jsxs(_Fragment, { children: [" \u2014 Public message: ", decryptDetected.msg] })] })), _jsx("label", { className: "label", htmlFor: "decrypt-password", children: "Password (for password-mode)" }), _jsx("input", { id: "decrypt-password", type: "password", value: decryptPassword, onChange: (e) => { setDecryptPassword(e.target.value); setDecryptError(null); }, placeholder: "Enter the encryption password", disabled: decryptBusy }), _jsx("div", { children: storedAccount?.encryptedPrivateKey && isAuthed && webauthnAvailable && (_jsxs("div", { children: [_jsx("label", { className: "label", children: "Unlock stored key with security key" }), _jsx("button", { type: "button", className: "secondary full-width", onClick: handleWebAuthnAuthenticate, disabled: decryptBusy || webauthnAuthBusy, children: webauthnAuthBusy ? "Verifying..." : "🔐 Authenticate with Security Key" }), decryptionToken && (_jsx("p", { className: "hint success-text", children: "\u2713 Security key verified" }))] })) }), _jsx("div", {
						className: "grid", children: _jsxs("div", {
							children: [_jsx("label", { className: "label", htmlFor: "decrypt-private-key", children: "Or paste a private key (Base64)" }), _jsx("textarea", {
								id: "decrypt-private-key", value: decryptPrivateKeyInput, onChange: (e) => {
									setDecryptPrivateKeyInput(e.target.value);
									setDecryptStatus(null);
									setDecryptError(null);
								}, placeholder: "Base64-encoded private key", disabled: decryptBusy
							}), _jsx("p", { className: "hint", children: "If provided, this overrides stored keys and passphrase unlocking." })]
						})
					}), _jsx("label", { className: "label", htmlFor: "decrypt-peer-pubkey", children: "Peer public key (optional, for signature verification)" }), _jsx("textarea", { id: "decrypt-peer-pubkey", value: decryptPeerPublicKey, onChange: (e) => setDecryptPeerPublicKey(e.target.value), placeholder: "Base64-encoded sender's public key (for verifying signatures)", disabled: decryptBusy }), _jsxs("div", { className: "actions", children: [_jsx("button", { type: "submit", disabled: decryptBusy, children: decryptBusy ? "Decrypting..." : "Decrypt" }), _jsx("button", { type: "button", className: "secondary", onClick: resetDecryptForm, disabled: decryptBusy, children: "Reset" })] }), decryptBusy && (_jsxs("div", { className: "progress-row", role: "status", "aria-live": "polite", children: [_jsx("div", { className: "progress-bar", children: _jsx("div", { className: "progress-fill" }) }), _jsx("span", { className: "muted", children: "Decrypting payload..." })] }))]
				}), decryptStatus && _jsx("div", { className: "status success", children: decryptStatus }), decryptError && _jsx("div", { className: "status error", children: decryptError })]
			}), decryptedResult && (_jsxs("section", { className: "card", children: [_jsx("h3", { children: "Decryption result" }), renderDecryptedInfo(decryptedResult), decryptedResult.files.length > 0 && (_jsxs("div", { className: "file-list", children: [_jsx("h4", { children: "Extracted files" }), decryptedResult.files.map((f, i) => (_jsxs("div", { className: "file-info", children: [_jsxs("div", { children: [_jsx("strong", { children: f.name }), _jsx("p", { className: "muted", children: formatBytes(f.data.length) })] }), _jsx("button", { type: "button", className: "secondary button-inline", onClick: () => handleDownloadDecryptedFile(f.name, f.data), children: "Download" })] }, i)))] }))] }))]
		}));
	}
	if (!isAuthed) {
		const onSubmit = authMode === "login" ? handleLogin : handleSignup;
		return (_jsxs("div", { className: "page", children: [_jsx("header", { className: "hero", children: _jsxs("div", { children: [_jsx("p", { className: "eyebrow", children: "Yet Another Security - Web" }), _jsx("h1", { children: authMode === "login" ? "Sign in to manage encrypted keys" : "Create an account to get started" }), _jsx("p", { className: "lede", children: "Access your encrypted key vault and tools after authentication." })] }) }), _jsxs("section", { className: "card", children: [_jsxs("form", { className: "form-vertical", onSubmit: onSubmit, children: [_jsxs("div", { children: [_jsx("label", { className: "label", htmlFor: "login-username", children: "Username" }), _jsx("input", { id: "login-username", type: "text", value: loginUsername, onChange: (e) => setLoginUsername(e.target.value), placeholder: "your_id", autoComplete: "username" })] }), _jsxs("div", { children: [_jsx("label", { className: "label", htmlFor: "login-pass", children: "Password" }), _jsx("input", { id: "login-pass", type: "password", value: loginPass, onChange: (e) => setLoginPass(e.target.value), placeholder: "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022", autoComplete: authMode === "login" ? "current-password" : "new-password" })] }), authMode === "signup" && (_jsxs("div", { children: [_jsx("label", { className: "label", htmlFor: "login-pass-confirm", children: "Confirm password" }), _jsx("input", { id: "login-pass-confirm", type: "password", value: loginPassConfirm, onChange: (e) => setLoginPassConfirm(e.target.value), placeholder: "repeat password", autoComplete: "new-password" })] })), _jsxs("div", { className: "actions vertical-actions", children: [_jsx("button", { type: "submit", disabled: !canLogin || loginBusy, children: loginBusy ? "Working..." : authMode === "login" ? "Sign in" : "Create account" }), _jsx("button", { type: "button", className: "secondary", onClick: () => setAuthMode(authMode === "login" ? "signup" : "login"), children: authMode === "login" ? "Need an account? Sign up" : "Have an account? Sign in" })] })] }), error && _jsx("div", { className: "status error", children: error }), _jsx("p", { className: "hint", children: "Passwords are stored hashed (bcrypt) in MongoDB. Tokens are JWT (1d)." })] })] }));
	}
	const heroTitle = tab === "keys"
		? "Protect private keys with a passphrase-derived key"
		: tab === "address-book"
			? "Manage trusted contacts and their public keys"
			: tab === "encrypt"
				? "Encrypt data with recipients' public keys"
				: "Decrypt securely in your browser";
	const heroLede = tab === "keys"
		? "Encrypt in the browser, store only ciphertext, and keep your passphrase local. Public keys are shareable; private keys stay yours."
		: tab === "address-book"
			? "Keep recipients' public keys organized so you can encrypt to the right person every time."
			: tab === "encrypt"
				? "YAS2 Opsec encryption: password-based (Argon2id/PBKDF2) or public-key (Curve448/RSA-2048) with AES-GCM."
				: "Decrypt YAS2 Opsec ciphertext locally — paste Base64 or upload a .bin file.";
	return (_jsxs("div", { className: "page", children: [_jsxs("nav", { className: "nav-bar", children: [_jsxs("button", { className: tab === "keys" ? "nav-item active" : "nav-item", onClick: () => setTab("keys"), children: [_jsx(IconHome, { active: tab === "keys" }), _jsx("span", { children: "Keys" })] }), _jsxs("button", { className: tab === "address-book" ? "nav-item active" : "nav-item", onClick: () => setTab("address-book"), children: [_jsx(IconBook, { active: tab === "address-book" }), _jsx("span", { children: "Contacts" })] }), _jsxs("button", { className: tab === "encrypt" ? "nav-item active" : "nav-item", onClick: () => setTab("encrypt"), children: [_jsx(IconLock, { active: tab === "encrypt" }), _jsx("span", { children: "Encrypt" })] }), _jsxs("button", { className: tab === "decrypt" ? "nav-item active" : "nav-item", onClick: () => setTab("decrypt"), children: [_jsx(IconUnlock, { active: tab === "decrypt" }), _jsx("span", { children: "Decrypt" })] })] }), _jsx("header", { className: "hero", children: _jsxs("div", { children: [_jsx("p", { className: "eyebrow", children: "Yet Another Security - Web" }), _jsx("h1", { children: heroTitle }), _jsx("p", { className: "lede", children: heroLede })] }) }), _jsxs("div", { className: "top-actions", children: [_jsxs("span", { className: "muted", children: ["Signed in as ", authUsername] }), _jsx("button", { className: "ghost", onClick: handleSignOut, children: "Sign out" })] }), renderTabContent()] }));
}
export default App;
