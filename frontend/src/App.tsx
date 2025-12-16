import { useEffect, useState } from "react";
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
import { buildAccountPayload, generateRsaKeyPair } from "./crypto";
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
	const [contactModalMode, setContactModalMode] = useState<"add" | "edit">("add");
	const [editingContactMeta, setEditingContactMeta] = useState<{ id: string; username: string } | null>(null);
	const [contactModalError, setContactModalError] = useState<string | null>(null);

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
		setContactModalOpen(false);
		setContactModalMode("add");
		setEditingContactMeta(null);
		setContactModalError(null);
	}

	function openAddContactModal() {
		setContactModalMode("add");
		setEditingContactMeta(null);
		setContactForm({ contactUsername: "", publicKey: "", notes: "" });
		setContactModalError(null);
		setContactModalOpen(true);
	}

	function openEditContactModal(contact: ContactRecord) {
		setContactModalMode("edit");
		setEditingContactMeta({ id: contact.id, username: contact.contactUsername });
		setContactForm({
			contactUsername: contact.contactUsername,
			publicKey: contact.publicKey,
			notes: contact.notes || "",
		});
		setContactModalError(null);
		setContactModalOpen(true);
	}

	function closeContactModal() {
		setContactModalOpen(false);
		setContactModalMode("add");
		setEditingContactMeta(null);
		setContactForm({ contactUsername: "", publicKey: "", notes: "" });
		setContactModalError(null);
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
			return (
				<section className="card">
					<h2>Encrypt data</h2>
					<p className="hint">Use recipients' public keys to encrypt text or files. Payloads are protected with hybrid RSA-OAEP + AES-GCM.</p>
					<p className="hint">Coming soon: paste plaintext or upload a file, choose a contact, and download ciphertext locally.</p>
				</section>
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

					{contactModalOpen && (
						<div className="modal-backdrop" role="dialog" aria-modal="true">
							<div className="modal-card">
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
				<p className="hint">Restore plaintext locally using your encrypted private key and passphrase-derived AES-GCM key.</p>
				<p className="hint">Coming soon: paste ciphertext and KDF metadata, enter your passphrase, and decrypt entirely in-browser.</p>
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
