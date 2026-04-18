import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { getAccountByUsername, login as loginApi, saveAccount, signup, listContacts, createContact, deleteContact, getWebAuthnRegisterOptions, verifyWebAuthnRegistration, getWebAuthnAuthenticateOptions, verifyWebAuthnAuthentication, decryptStoredPrivateKey, } from "./api";
import { buildAccountPayload, generateKeyPair, encryptOpsec, decryptOpsecPw, decryptOpsecPub, detectAuthMode, u8ToBase64, base64ToU8, registerWebAuthnCredential, authenticateWithWebAuthn, isWebAuthnAvailable, } from "./crypto";
/* ─── Helpers ─── */
function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0)
        return "0 B";
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
function truncateKey(key) {
    if (key.length <= 15)
        return key;
    return `${key.slice(0, 6)}…${key.slice(-6)}`;
}
function detectPublicKeyAlgo(publicKeyB64) {
    try {
        const u8 = base64ToU8(publicKeyB64);
        // PQC1 public key is exactly 4273 bytes
        if (u8.length === 4273)
            return "pqc1";
        // Curve448 public key is exactly 113 bytes
        if (u8.length === 113)
            return "ecc1";
        // RSA public key is typically 290+ bytes
        return "rsa1";
    }
    catch {
        return "ecc1"; // Default to ecc1
    }
}
function detectPrivateKeyAlgo(privateKeyB64) {
    try {
        const u8 = base64ToU8(privateKeyB64);
        // PQC1 private key is exactly 8177 bytes
        if (u8.length === 8177)
            return "pqc1";
        // Curve448 private key is exactly 113 bytes
        if (u8.length === 113)
            return "ecc1";
        return "rsa1";
    }
    catch {
        return "ecc1";
    }
}
/* ─── Icons ─── */
function IconContacts({ active }) {
    const stroke = active ? "#fff" : "#888";
    return (_jsxs("svg", { width: "22", height: "22", viewBox: "0 0 24 24", fill: "none", stroke: stroke, strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("path", { d: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" }), _jsx("circle", { cx: "9", cy: "7", r: "4" }), _jsx("path", { d: "M22 21v-2a4 4 0 0 0-3-3.87" }), _jsx("path", { d: "M16 3.13a4 4 0 0 1 0 7.75" })] }));
}
function IconKey({ active }) {
    const stroke = active ? "#fff" : "#888";
    return (_jsxs("svg", { width: "22", height: "22", viewBox: "0 0 24 24", fill: "none", stroke: stroke, strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("circle", { cx: "8", cy: "15", r: "4" }), _jsx("path", { d: "M11.3 11.7 20 3" }), _jsx("path", { d: "M17 3h3v3" }), _jsx("path", { d: "m17 7 3-3" })] }));
}
function IconEncrypt({ active }) {
    const stroke = active ? "#fff" : "#888";
    return (_jsxs("svg", { width: "22", height: "22", viewBox: "0 0 24 24", fill: "none", stroke: stroke, strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("rect", { x: "3", y: "11", width: "18", height: "11", rx: "2" }), _jsx("path", { d: "M7 11V7a5 5 0 0 1 10 0v4" })] }));
}
function IconDecrypt({ active }) {
    const stroke = active ? "#fff" : "#888";
    return (_jsxs("svg", { width: "22", height: "22", viewBox: "0 0 24 24", fill: "none", stroke: stroke, strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("rect", { x: "3", y: "11", width: "18", height: "11", rx: "2" }), _jsx("path", { d: "M7 11V7a5 5 0 0 1 9.9-1" })] }));
}
function App() {
    /* Auth */
    const [authToken, setAuthToken] = useState(() => localStorage.getItem("authToken"));
    const [authUsername, setAuthUsername] = useState(() => localStorage.getItem("authUsername"));
    const [view, setView] = useState("landing");
    const [loginUsername, setLoginUsername] = useState("");
    const [loginPass, setLoginPass] = useState("");
    const [loginPassConfirm, setLoginPassConfirm] = useState("");
    const [loginBusy, setLoginBusy] = useState(false);
    /* Key mgmt */
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
    const [toastMsg, setToastMsg] = useState(null);
    function showToast(msg) {
        setToastMsg(msg);
        setTimeout(() => setToastMsg(null), 2500);
    }
    const [keyAlgo, setKeyAlgo] = useState("ecc1");
    /* Contacts */
    const [contacts, setContacts] = useState([]);
    const [contactsLoading, setContactsLoading] = useState(false);
    const [contactForm, setContactForm] = useState({ contactUsername: "", notes: "" });
    const [contactError, setContactError] = useState(null);
    const [contactBusy, setContactBusy] = useState(false);
    const [contactModalOpen, setContactModalOpen] = useState(false);
    const [contactModalClosing, setContactModalClosing] = useState(false);
    const [contactModalMode, setContactModalMode] = useState("add");
    const [editingContactMeta, setEditingContactMeta] = useState(null);
    const [contactModalError, setContactModalError] = useState(null);
    const closeModalTimer = useRef(null);
    /* Encrypt */
    const [encryptAuthMode, setEncryptAuthMode] = useState("password");
    const [encryptKdfMethod, setEncryptKdfMethod] = useState("arg1");
    const [encryptEncAlgo, setEncryptEncAlgo] = useState("gcm1");
    const [encryptAsymAlgo, setEncryptAsymAlgo] = useState(null);
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
    const [encryptStep, setEncryptStep] = useState(1);
    /* Decrypt */
    const [decryptPayloadInput, setDecryptPayloadInput] = useState("");
    const [decryptPayloadFile, setDecryptPayloadFile] = useState(null);
    const [isDecryptFileDragActive, setIsDecryptFileDragActive] = useState(false);
    const [decryptPassword, setDecryptPassword] = useState("");
    const [decryptPrivateKeyInput, setDecryptPrivateKeyInput] = useState("");
    const [decryptPrivateKeySource, setDecryptPrivateKeySource] = useState("security");
    const [decryptPeerPublicKey, setDecryptPeerPublicKey] = useState("");
    const [decryptPeerKeySource, setDecryptPeerKeySource] = useState("contact");
    const [decryptSelectedContactId, setDecryptSelectedContactId] = useState("");
    const [decryptDetected, setDecryptDetected] = useState(null);
    const [decryptBusy, setDecryptBusy] = useState(false);
    const [decryptStatus, setDecryptStatus] = useState(null);
    const [decryptError, setDecryptError] = useState(null);
    const [decryptedResult, setDecryptedResult] = useState(null);
    const [decryptStep, setDecryptStep] = useState(1);
    /* WebAuthn */
    const [webauthnAvailable, setWebauthnAvailable] = useState(false);
    const [webauthnAuthBusy, setWebauthnAuthBusy] = useState(false);
    const [decryptionToken, setDecryptionToken] = useState(null);
    /* Theme */
    const [themeMode, setThemeMode] = useState(() => {
        return localStorage.getItem("themeMode") || "system";
    });
    const [resolvedDark, setResolvedDark] = useState(() => {
        const saved = localStorage.getItem("themeMode") || "system";
        if (saved === "dark")
            return true;
        if (saved === "light")
            return false;
        return window.matchMedia("(prefers-color-scheme: dark)").matches;
    });
    /* Navigation refs */
    const navInnerRef = useRef(null);
    const navContactsRef = useRef(null);
    const navKeysRef = useRef(null);
    const navEncryptRef = useRef(null);
    const navDecryptRef = useRef(null);
    const [pressedTab, setPressedTab] = useState(null);
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
        const handler = (e) => {
            if (themeMode === "system")
                setResolvedDark(e.matches);
        };
        mq.addEventListener("change", handler);
        return () => mq.removeEventListener("change", handler);
    }, [themeMode]);
    useEffect(() => {
        localStorage.setItem("themeMode", themeMode);
        if (themeMode === "system") {
            setResolvedDark(window.matchMedia("(prefers-color-scheme: dark)").matches);
        }
        else {
            setResolvedDark(themeMode === "dark");
        }
    }, [themeMode]);
    useEffect(() => {
        document.documentElement.setAttribute("data-theme", resolvedDark ? "dark" : "light");
    }, [resolvedDark]);
    /* Animate navigation pill position + squish */
    const updateNavHighlight = () => {
        const refMap = { contacts: navContactsRef, keys: navKeysRef, encrypt: navEncryptRef, decrypt: navDecryptRef };
        const activeEl = refMap[tab]?.current;
        const inner = navInnerRef.current;
        if (!activeEl || !inner)
            return;
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
                }
                else {
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
    const canLogin = Boolean(loginUsername && loginPass && (view === "login" || loginPass === loginPassConfirm));
    const canUpload = Boolean(username && publicKeyPem && privateKeyPem);
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
                if (!cancelled)
                    setContacts(items);
            }
            catch (err) {
                const msg = err.message || "연락처 불러오기 실패";
                if (msg === "TOKEN_EXPIRED") {
                    handleSignOut();
                    return;
                }
                if (!cancelled)
                    setContactError(msg);
            }
            finally {
                if (!cancelled)
                    setContactsLoading(false);
            }
        }
        loadContacts();
        return () => { cancelled = true; };
    }, [authToken]);
    useEffect(() => {
        if (!authToken) {
            setWebauthnAvailable(false);
            return;
        }
        setWebauthnAvailable(isWebAuthnAvailable());
    }, [authToken]);
    useEffect(() => {
        if (authUsername)
            setUsername(authUsername);
        else
            setUsername("");
    }, [authUsername]);
    useEffect(() => {
        let cancelled = false;
        const snap = authUsername?.trim();
        setStoredAccount(null);
        setShowKeySection(true);
        setPublicKeyPem("");
        setPrivateKeyPem("");
        setCopyPrivateStatus("idle");
        if (!snap)
            return () => { cancelled = true; };
        async function loadStored() {
            try {
                const record = await getAccountByUsername(snap);
                if (!cancelled && authUsername === snap) {
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
                if (!cancelled && authUsername === snap) {
                    setStoredAccount(null);
                    setShowKeySection(true);
                }
            }
        }
        loadStored();
        return () => { cancelled = true; };
    }, [authUsername]);
    /* ─── Handlers ─── */
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
            setError(err.message || "로그인에 실패했습니다");
        }
        finally {
            setLoginBusy(false);
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
        }
        catch (err) {
            setError(err.message || "회원가입에 실패했습니다");
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
    async function handleCopyPublicKey(value) {
        if (!value)
            return;
        try {
            await navigator.clipboard.writeText(value);
            setCopyPublicStatus("copied");
            setTimeout(() => setCopyPublicStatus("idle"), 2000);
        }
        catch {
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
        catch {
            setCopyPrivateStatus("error");
            setTimeout(() => setCopyPrivateStatus("idle"), 2000);
        }
    }
    /* ─── Contact modal helpers ─── */
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
    function openEditContactModal(contact) {
        reopenContactModal();
        setContactModalMode("edit");
        setEditingContactMeta({ id: contact.id, username: contact.contactUsername });
        setContactForm({ contactUsername: contact.contactUsername, notes: contact.notes || "" });
        setContactModalError(null);
    }
    function closeContactModal() {
        if (contactModalClosing)
            return;
        if (closeModalTimer.current)
            window.clearTimeout(closeModalTimer.current);
        setContactModalClosing(true);
        closeModalTimer.current = window.setTimeout(() => { forceCloseContactModal(); closeModalTimer.current = null; }, 240);
    }
    async function handleContactSubmit(e) {
        e.preventDefault();
        if (!authToken)
            return;
        const trimmedUsername = contactForm.contactUsername.trim();
        if (!trimmedUsername) {
            setContactModalError("사용자 아이디는 필수입니다");
            return;
        }
        setContactBusy(true);
        setContactModalError(null);
        try {
            const payload = {
                contactUsername: trimmedUsername,
                notes: contactForm.notes.trim() || undefined
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
                    setContactError(deleteErr.message || "이전 연락처 삭제 실패");
                }
            }
            closeContactModal();
        }
        catch (err) {
            if (err.message === "TOKEN_EXPIRED") {
                handleSignOut();
                return;
            }
            setContactModalError(err.message || "연락처 저장에 실패했습니다");
        }
        finally {
            setContactBusy(false);
        }
    }
    async function handleDeleteContact(id) {
        if (!authToken)
            return;
        if (!window.confirm("이 연락처를 삭제하시겠습니까?"))
            return;
        try {
            await deleteContact(id, authToken);
            setContacts((prev) => prev.filter((c) => c.id !== id));
        }
        catch (err) {
            if (err.message === "TOKEN_EXPIRED") {
                handleSignOut();
                return;
            }
            setContactError(err.message || "연락처 삭제에 실패했습니다");
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
        }
        catch (err) {
            console.error(err);
            setError("키 쌍 생성에 실패했습니다");
            setStatus(null);
        }
    }
    async function handleUpload() {
        if (!canUpload)
            return;
        setBusy(true);
        setError(null);
        setStatus("암호화하여 업로드 중...");
        try {
            const payload = await buildAccountPayload(username, publicKeyPem, privateKeyPem, notes || undefined);
            const result = await saveAccount(payload, authToken ?? undefined);
            const record = { ...payload, id: result.id, createdAt: result.createdAt };
            setStoredAccount(record);
            setStatus("키가 안전하게 저장되었습니다");
            setShowKeySection(false);
            setPrivateKeyPem("");
            setCopyPrivateStatus("idle");
            if (authToken && (await isWebAuthnAvailable())) {
                setStatus("보안 키 설정 중...");
                setTimeout(() => startWebAuthnRegistration(), 500);
            }
        }
        catch (err) {
            console.error(err);
            setError(err.message || "업로드에 실패했습니다");
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
    /* ─── WebAuthn ─── */
    async function startWebAuthnRegistration() {
        if (!authToken) {
            setError("로그인이 필요합니다");
            return;
        }
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
        }
        catch (err) {
            const msg = err.message || "보안 키 등록 실패";
            if (msg !== "WebAuthn registration cancelled")
                setError(`보안 키 설정: ${msg}`);
            setStatus(null);
        }
    }
    async function handleWebAuthnAuthenticate() {
        await requestPrivateKeyAccess("decrypt");
    }
    async function requestPrivateKeyAccess(target) {
        const setTargetError = target === "decrypt" ? setDecryptError : setEncryptError;
        const setTargetStatus = target === "decrypt" ? setDecryptStatus : setEncryptStatus;
        if (!authToken || !isAuthed) {
            setTargetError("로그인이 필요합니다");
            return false;
        }
        if (!storedAccount?.encryptedPrivateKey || !storedAccount?.kdf) {
            setTargetError("저장된 개인키가 없습니다.");
            return false;
        }
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
        }
        catch (err) {
            setTargetError(err.message || "보안 키 인증 실패");
            setTargetStatus(null);
            return false;
        }
        finally {
            setWebauthnAuthBusy(false);
        }
    }
    async function handleEncryptSignWithKeyToggle(checked) {
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
    function handleEncryptionModeChange(mode) {
        if (mode === encryptMode)
            return;
        setEncryptMode(mode);
        if (mode === "text") {
            applySelectedEncryptFile(null);
            setIsFileDragActive(false);
        }
        else
            setEncryptSmsg("");
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
    function handleFileDragEnter(e) { e.preventDefault(); if (!encryptBusy)
        setIsFileDragActive(true); }
    function handleFileDragOver(e) { e.preventDefault(); if (!encryptBusy) {
        e.dataTransfer.dropEffect = "copy";
        if (!isFileDragActive)
            setIsFileDragActive(true);
    } }
    function handleFileDragLeave(e) {
        e.preventDefault();
        const next = e.relatedTarget;
        if (next && e.currentTarget.contains(next))
            return;
        setIsFileDragActive(false);
    }
    function handleFileDrop(e) {
        e.preventDefault();
        setIsFileDragActive(false);
        if (encryptBusy)
            return;
        const f = e.dataTransfer.files?.[0];
        if (f)
            applySelectedEncryptFile(f);
    }
    function handleEncryptFileChange(e) {
        const f = e.target.files?.[0] ?? null;
        applySelectedEncryptFile(f);
        setIsFileDragActive(false);
        e.target.value = "";
    }
    /* ─── Decrypt helpers ─── */
    function handleDecryptDragEnter(e) { e.preventDefault(); if (!decryptBusy)
        setIsDecryptFileDragActive(true); }
    function handleDecryptDragOver(e) { e.preventDefault(); if (!decryptBusy) {
        e.dataTransfer.dropEffect = "copy";
        if (!isDecryptFileDragActive)
            setIsDecryptFileDragActive(true);
    } }
    function handleDecryptDragLeave(e) {
        e.preventDefault();
        const next = e.relatedTarget;
        if (next && e.currentTarget.contains(next))
            return;
        setIsDecryptFileDragActive(false);
    }
    async function tryAutoDetect(data) {
        try {
            const info = detectAuthMode(data);
            setDecryptDetected(info);
            setDecryptError(null);
        }
        catch {
            setDecryptDetected(null);
        }
    }
    function handleDecryptFileDrop(e) {
        e.preventDefault();
        setIsDecryptFileDragActive(false);
        if (decryptBusy)
            return;
        const f = e.dataTransfer.files?.[0];
        if (f) {
            setDecryptPayloadFile(f);
            setDecryptPayloadInput("");
            setDecryptStatus(null);
            setDecryptError(null);
            setDecryptedResult(null);
            f.arrayBuffer().then((buf) => tryAutoDetect(new Uint8Array(buf)));
        }
    }
    function handleDecryptFileChange(e) {
        const f = e.target.files?.[0] ?? null;
        setDecryptPayloadFile(f);
        setDecryptPayloadInput("");
        setDecryptStatus(null);
        setDecryptError(null);
        setDecryptedResult(null);
        setIsDecryptFileDragActive(false);
        e.target.value = "";
        if (f)
            f.arrayBuffer().then((buf) => tryAutoDetect(new Uint8Array(buf)));
        else
            setDecryptDetected(null);
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
    async function resolvePrivateKeyB64() {
        const manual = decryptPrivateKeyInput.trim();
        if (manual)
            return manual;
        if (privateKeyPem)
            return privateKeyPem;
        if (storedAccount?.encryptedPrivateKey && storedAccount?.kdf) {
            if (!decryptionToken)
                throw new Error("저장된 개인키를 잠금 해제하려면 보안 키를 사용하세요");
            const result = await decryptStoredPrivateKey(storedAccount.username, decryptionToken);
            return result.privateKey;
        }
        throw new Error("사용 가능한 개인키가 없습니다.");
    }
    async function resolveSigningPrivateKeyB64() {
        if (privateKeyPem)
            return privateKeyPem;
        if (storedAccount?.encryptedPrivateKey && storedAccount?.kdf) {
            if (!decryptionToken) {
                throw new Error("서명하려면 먼저 복호화 탭에서 보안 키 인증을 완료하세요.");
            }
            const result = await decryptStoredPrivateKey(storedAccount.username, decryptionToken);
            return result.privateKey;
        }
        throw new Error("서명에 사용할 개인키를 찾을 수 없습니다.");
    }
    async function loadOpsecData() {
        if (decryptPayloadFile)
            return new Uint8Array(await decryptPayloadFile.arrayBuffer());
        const raw = decryptPayloadInput.trim();
        if (!raw)
            throw new Error("Base64 텍스트를 붙여넣거나 파일을 업로드하세요");
        try {
            return base64ToU8(raw);
        }
        catch {
            throw new Error("올바르지 않은 Base64 형식입니다");
        }
    }
    /* ─── Encrypt submit ─── */
    async function handleEncryptSubmit() {
        setEncryptStatus(null);
        setEncryptError(null);
        setEncryptedBlob(null);
        if (encryptAuthMode === "password") {
            if (!encryptPassword) {
                setEncryptError("비밀번호를 입력하세요");
                return;
            }
        }
        else {
            if (!contacts.find((c) => c.id === encryptRecipientId)) {
                setEncryptError("수신자를 선택하세요");
                return;
            }
        }
        if (encryptMode === "text") {
            if (!encryptSmsg) {
                setEncryptError("암호화할 메시지를 입력하세요");
                return;
            }
        }
        else {
            if (!encryptFile) {
                setEncryptError("암호화할 파일을 선택하세요");
                return;
            }
        }
        try {
            setEncryptBusy(true);
            setEncryptStatus("암호화 중...");
            const files = encryptMode === "file" && encryptFile ? [encryptFile] : undefined;
            let result;
            if (encryptAuthMode === "password") {
                result = await encryptOpsec({
                    mode: "password", kdfMethod: encryptKdfMethod, password: encryptPassword,
                    encAlgo: encryptEncAlgo, smsg: encryptSmsg || undefined, msg: encryptMsg || undefined, files,
                });
            }
            else {
                const recipient = contacts.find((c) => c.id === encryptRecipientId);
                let myPrivateKey;
                if (encryptSignWithKey) {
                    myPrivateKey = await resolveSigningPrivateKeyB64();
                    const signAlgo = detectPrivateKeyAlgo(myPrivateKey);
                    if (signAlgo !== encryptAsymAlgo) {
                        throw new Error(`서명 키 알고리즘(${signAlgo})과 수신자 키 알고리즘(${encryptAsymAlgo})이 달라 서명할 수 없습니다.`);
                    }
                }
                result = await encryptOpsec({
                    mode: "publickey", asymAlgo: encryptAsymAlgo, peerPublicKey: recipient.publicKey,
                    myPrivateKey, encAlgo: encryptEncAlgo, smsg: encryptSmsg || undefined, msg: encryptMsg || undefined, files,
                });
            }
            setEncryptedBlob(result);
            setEncryptStatus(encryptMode === "text"
                ? `암호화 완료 (${result.length} bytes). 다운로드가 시작됩니다.`
                : `파일 암호화 완료 (${formatBytes(result.length)}). 다운로드가 시작됩니다.`);
        }
        catch (err) {
            console.error(err);
            setEncryptError(err.message || "암호화에 실패했습니다");
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
            let result;
            if (info.mode === "password") {
                if (!decryptPassword)
                    throw new Error("비밀번호를 입력하세요");
                result = await decryptOpsecPw(dataU8, decryptPassword);
            }
            else {
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
        }
        catch (err) {
            console.error(err);
            setDecryptError(err.message || "복호화에 실패했습니다");
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
    async function handleDecryptAdvanceToStep2() {
        setDecryptError(null);
        try {
            const data = await loadOpsecData();
            const info = detectAuthMode(data);
            setDecryptDetected(info);
            setDecryptStep(2);
        }
        catch (err) {
            setDecryptError(err.message || "데이터를 분석할 수 없습니다");
        }
    }
    /* ─── Render: Landing / Auth ─── */
    if (!isAuthed) {
        if (view === "login") {
            return (_jsx("div", { className: "auth-page", children: _jsxs("div", { className: "auth-card view-animate", children: [_jsx("h1", { className: "auth-title", children: "\uB85C\uADF8\uC778" }), _jsxs("form", { className: "auth-form", onSubmit: handleLogin, children: [_jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uC544\uC774\uB514" }), _jsx("input", { type: "text", value: loginUsername, onChange: (e) => setLoginUsername(e.target.value), placeholder: "\uC544\uC774\uB514 \uC785\uB825", autoComplete: "username" })] }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uBE44\uBC00\uBC88\uD638" }), _jsx("input", { type: "password", value: loginPass, onChange: (e) => setLoginPass(e.target.value), placeholder: "\uBE44\uBC00\uBC88\uD638 \uC785\uB825", autoComplete: "current-password" })] }), error && _jsx("div", { className: "status-bar error", children: error }), _jsx("button", { type: "submit", className: "btn btn-primary btn-full", disabled: !canLogin || loginBusy, children: loginBusy ? "로그인 중..." : "로그인" })] }), _jsx("p", { className: "auth-hint", children: _jsx("button", { onClick: () => { setView("landing"); setError(null); }, children: "\u2190 \uB3CC\uC544\uAC00\uAE30" }) })] }) }, "login"));
        }
        if (view === "signup") {
            return (_jsx("div", { className: "auth-page", children: _jsxs("div", { className: "auth-card view-animate", children: [_jsx("h1", { className: "auth-title", children: "\uD68C\uC6D0\uAC00\uC785" }), _jsxs("form", { className: "auth-form", onSubmit: handleSignup, children: [_jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uC544\uC774\uB514" }), _jsx("input", { type: "text", value: loginUsername, onChange: (e) => setLoginUsername(e.target.value), placeholder: "\uC0AC\uC6A9\uD560 \uC544\uC774\uB514", autoComplete: "username" })] }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uBE44\uBC00\uBC88\uD638" }), _jsx("input", { type: "password", value: loginPass, onChange: (e) => setLoginPass(e.target.value), placeholder: "\uBE44\uBC00\uBC88\uD638 \uC785\uB825", autoComplete: "new-password" })] }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uBE44\uBC00\uBC88\uD638 \uD655\uC778" }), _jsx("input", { type: "password", value: loginPassConfirm, onChange: (e) => setLoginPassConfirm(e.target.value), placeholder: "\uBE44\uBC00\uBC88\uD638 \uB2E4\uC2DC \uC785\uB825", autoComplete: "new-password" })] }), error && _jsx("div", { className: "status-bar error", children: error }), _jsx("button", { type: "submit", className: "btn btn-primary btn-full", disabled: !canLogin || loginBusy, children: loginBusy ? "처리 중..." : "가입하기" })] }), _jsx("p", { className: "auth-hint", children: _jsx("button", { onClick: () => { setView("landing"); setError(null); }, children: "\u2190 \uB3CC\uC544\uAC00\uAE30" }) })] }) }, "signup"));
        }
        /* Landing */
        return (_jsxs("div", { className: "landing", children: [_jsx("div", { className: "view-animate", children: _jsxs("h1", { className: "brand", children: ["Yet", _jsx("br", {}), "Another", _jsx("br", {}), "Security"] }) }), _jsxs("div", { className: "landing-buttons view-animate", children: [_jsx("button", { className: "btn btn-primary btn-full", onClick: () => { setView("login"); setError(null); setLoginUsername(""); setLoginPass(""); }, children: "\uB85C\uADF8\uC778" }), _jsx("button", { className: "btn btn-secondary btn-full", onClick: () => { setView("signup"); setError(null); setLoginUsername(""); setLoginPass(""); setLoginPassConfirm(""); }, children: "\uD68C\uC6D0\uAC00\uC785" })] })] }, "landing"));
    }
    /* ─── Render: Main App ─── */
    function renderStepDots(total, current) {
        return (_jsx("div", { className: "step-dots", children: Array.from({ length: total }, (_, i) => (_jsx("div", { className: `step-dot ${i + 1 === current ? "active" : i + 1 < current ? "done" : ""}` }, i))) }));
    }
    /* ─── Contacts tab ─── */
    function renderContactsTab() {
        return (_jsxs(_Fragment, { children: [_jsx("br", {}), _jsxs("div", { className: "section-header", children: [_jsx("h2", { className: "section-title", children: "\uC8FC\uC18C\uB85D" }), _jsx("button", { className: "btn btn-secondary btn-sm", onClick: openAddContactModal, children: "+ \uCD94\uAC00" })] }), _jsx("p", { className: "section-desc", children: "\uC0C1\uB300\uBC29\uC758 \uACF5\uAC1C\uD0A4\uB97C \uAD00\uB9AC\uD558\uC5EC \uC548\uC804\uD558\uAC8C \uC554\uD638\uD654\uB41C \uBA54\uC2DC\uC9C0\uB97C \uC8FC\uACE0\uBC1B\uC73C\uC138\uC694." }), contactError && _jsx("div", { className: "status-bar error", children: contactError }), contactsLoading ? (_jsx("p", { className: "text-hint text-center mt-4", children: "\uBD88\uB7EC\uC624\uB294 \uC911..." })) : contacts.length === 0 ? (_jsxs("div", { className: "empty-state", children: [_jsx("p", { children: "\uC800\uC7A5\uB41C \uC5F0\uB77D\uCC98\uAC00 \uC5C6\uC2B5\uB2C8\uB2E4" }), _jsx("p", { className: "text-hint", children: "\uC5F0\uB77D\uCC98\uB97C \uCD94\uAC00\uD558\uBA74 \uACF5\uAC1C\uD0A4 \uC554\uD638\uD654\uB97C \uC2DC\uC791\uD560 \uC218 \uC788\uC5B4\uC694." })] })) : (_jsx("div", { className: "contact-list", children: contacts.map((c) => (_jsxs("div", { className: "contact-row", children: [_jsxs("div", { className: "contact-info", children: [_jsxs("div", { className: "contact-name-row", children: [_jsx("span", { className: "contact-name", children: c.contactUsername }), _jsx("span", { className: `contact-algo-badge algo-${detectPublicKeyAlgo(c.publicKey)}`, children: detectPublicKeyAlgo(c.publicKey) === "pqc1" ? "PQC" : detectPublicKeyAlgo(c.publicKey) === "ecc1" ? "ECC" : "RSA" })] }), c.notes && (_jsx("div", { className: "contact-meta-row", children: _jsx("span", { className: "contact-note", children: c.notes }) }))] }), _jsxs("div", { className: "contact-btns", children: [_jsx("span", { className: "contact-pk-preview", style: { marginRight: "12px", opacity: 0.6 }, children: c.publicKey && c.publicKey.length > 20 ? `${c.publicKey.slice(0, 6)}…${c.publicKey.slice(-5)}` : c.publicKey }), _jsx("button", { className: "btn-ghost btn-sm", onClick: () => { handleCopyPublicKey(c.publicKey); showToast("복사 되었습니다"); }, children: "\uBCF5\uC0AC" }), _jsx("button", { className: "btn-ghost btn-sm", onClick: () => openEditContactModal(c), children: "\uC218\uC815" }), _jsx("button", { className: "btn-ghost btn-sm btn-danger", onClick: () => handleDeleteContact(c.id), children: "\uC0AD\uC81C" })] })] }, c.id))) }))] }));
    }
    /* ─── Keys tab ─── */
    function renderKeysTab() {
        const hasStoredKey = Boolean(storedAccount?.publicKey && storedAccount?.encryptedPrivateKey?.cipherText);
        if (hasStoredKey && !showKeySection) {
            return (_jsxs(_Fragment, { children: [_jsx("br", {}), _jsx("h2", { className: "section-title", children: "\uB0B4 \uD0A4" }), _jsx("p", { className: "section-desc", children: "\uD0A4\uAC00 \uC11C\uBC84\uC5D0 \uC548\uC804\uD558\uAC8C \uC800\uC7A5\uB418\uC5B4 \uC788\uC5B4\uC694." }), _jsxs("div", { className: "card", children: [_jsxs("div", { className: "key-item", children: [_jsx("span", { className: "key-label", children: "\uACF5\uAC1C\uD0A4" }), _jsxs("div", { className: "key-value-row", children: [_jsx("code", { className: "key-truncated", children: truncateKey(storedAccount.publicKey) }), _jsx("button", { className: "btn btn-ghost btn-sm", onClick: () => handleCopyPublicKey(storedAccount?.publicKey), children: copyPublicStatus === "copied" ? "복사됨 ✓" : "복사" })] })] }), _jsxs("div", { className: "key-item", children: [_jsx("span", { className: "key-label", children: "\uAC1C\uC778\uD0A4" }), _jsx("span", { className: "text-hint", children: "\uC11C\uBC84\uC5D0 \uC554\uD638\uD654\uB418\uC5B4 \uC800\uC7A5\uB428" })] })] }), status && _jsx("div", { className: "status-bar success", children: status }), error && _jsx("div", { className: "status-bar error", children: error }), _jsx("div", { className: "btn-row", children: _jsx("button", { className: "btn btn-secondary", onClick: handleRegenerate, children: "\uD0A4 \uC7AC\uC0DD\uC131" }) })] }));
        }
        return (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uD0A4 \uC0DD\uC131" }), _jsx("p", { className: "section-desc", children: "\uC554\uD638\uD654\uC5D0 \uC0AC\uC6A9\uD560 \uD0A4 \uC30D\uC744 \uC0DD\uC131\uD558\uACE0 \uC11C\uBC84\uC5D0 \uC548\uC804\uD558\uAC8C \uC800\uC7A5\uD569\uB2C8\uB2E4." }), _jsxs("div", { className: "card", children: [_jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uBA54\uBAA8 (\uC120\uD0DD)" }), _jsx("input", { type: "text", value: notes, onChange: (e) => setNotes(e.target.value), placeholder: "\uC774 \uD0A4\uC5D0 \uB300\uD55C \uBA54\uBAA8..." })] }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uD0A4 \uC54C\uACE0\uB9AC\uC998" }), _jsxs("div", { className: "option-cards", children: [_jsxs("button", { className: `option-card ${keyAlgo === "pqc1" ? "selected" : ""}`, onClick: () => setKeyAlgo("pqc1"), children: [_jsx("span", { className: "option-title", children: "PQC1" }), _jsx("span", { className: "option-desc", children: "\uC591\uC790\uB0B4\uC131 \uD558\uC774\uBE0C\uB9AC\uB4DC \uD0A4" })] }), _jsxs("button", { className: `option-card ${keyAlgo === "ecc1" ? "selected" : ""}`, onClick: () => setKeyAlgo("ecc1"), children: [_jsx("span", { className: "option-title", children: "Curve448" }), _jsx("span", { className: "option-desc", children: "\uB192\uC740 \uBCF4\uC548 \uAC15\uB3C4 (\uCD94\uCC9C)" })] }), _jsxs("button", { className: `option-card ${keyAlgo === "rsa1" ? "selected" : ""}`, onClick: () => setKeyAlgo("rsa1"), children: [_jsx("span", { className: "option-title", children: "RSA-2048" }), _jsx("span", { className: "option-desc", children: "\uD638\uD658\uC131 \uC6B0\uC120" })] })] })] }), _jsxs("div", { className: "btn-row", children: [_jsx("button", { className: "btn btn-secondary", onClick: handleGenerateKeys, children: "\uD0A4 \uC30D \uC0DD\uC131" }), _jsx("button", { className: "btn btn-primary", onClick: handleUpload, disabled: !canUpload || busy, children: busy ? "처리 중..." : "암호화하여 저장" })] }), status && _jsx("div", { className: "status-bar success mt-3", children: status }), error && _jsx("div", { className: "status-bar error mt-3", children: error })] }), _jsxs("div", { className: "card", children: [_jsx("h3", { style: { fontSize: 16, fontWeight: 600, marginBottom: 16 }, children: "\uBBF8\uB9AC\uBCF4\uAE30" }), _jsxs("div", { className: "key-item", children: [_jsx("span", { className: "key-label", children: "\uACF5\uAC1C\uD0A4" }), _jsxs("div", { className: "key-full", children: [publicKeyPem || "(키 쌍을 생성하세요)", publicKeyPem && (_jsx("button", { className: `key-copy-btn ${copyPublicStatus === "copied" ? "copied" : ""}`, onClick: () => handleCopyPublicKey(publicKeyPem), children: copyPublicStatus === "copied" ? "복사됨" : "복사" }))] })] }), _jsxs("div", { className: "key-item", children: [_jsx("span", { className: "key-label", children: "\uAC1C\uC778\uD0A4 (\uD3C9\uBB38)" }), _jsxs("div", { className: "key-full", children: [privateKeyPem || "(키 쌍을 생성하세요)", privateKeyPem && (_jsx("button", { className: `key-copy-btn ${copyPrivateStatus === "copied" ? "copied" : ""}`, onClick: () => handleCopyPrivateKey(privateKeyPem), children: copyPrivateStatus === "copied" ? "복사됨" : "복사" }))] })] }), _jsx("p", { className: "text-hint mt-2", children: "\uAC1C\uC778\uD0A4\uB294 \uBE0C\uB77C\uC6B0\uC800\uC5D0\uC11C \uC554\uD638\uD654\uB41C \uD6C4 \uC11C\uBC84\uC5D0 \uC548\uC804\uD558\uAC8C \uC800\uC7A5\uB429\uB2C8\uB2E4." })] })] }));
    }
    /* ─── Encrypt tab (wizard) ─── */
    function renderEncryptTab() {
        if (encryptedBlob) {
            return (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uC554\uD638\uD654 \uC644\uB8CC" }), _jsxs("div", { className: "card", children: [_jsxs("div", { className: "result-grid", children: [_jsxs("div", { className: "result-item", children: [_jsx("span", { className: "result-label", children: "\uBC29\uC2DD" }), _jsx("span", { className: "result-value", children: encryptAuthMode === "password" ? "비밀번호" : "공개키" })] }), _jsxs("div", { className: "result-item", children: [_jsx("span", { className: "result-label", children: "\uD06C\uAE30" }), _jsx("span", { className: "result-value", children: formatBytes(encryptedBlob.length) })] }), _jsxs("div", { className: "result-item", children: [_jsx("span", { className: "result-label", children: "\uC54C\uACE0\uB9AC\uC998" }), _jsx("span", { className: "result-value", children: encryptEncAlgo === "gcmx1" ? "대용량" : "표준" })] })] }), _jsxs("div", { className: "btn-row", children: [encryptedBlob.length < 10240 && (_jsx("button", { className: "btn btn-secondary btn-sm", onClick: handleCopyEncryptedBase64, children: "Base64 \uBCF5\uC0AC" })), _jsx("button", { className: "btn btn-secondary btn-sm", onClick: handleDownloadEncryptedBlob, children: "\uD30C\uC77C \uB2E4\uC6B4\uB85C\uB4DC" })] })] }), encryptStatus && _jsx("div", { className: "status-bar success", children: encryptStatus }), _jsx("div", { className: "btn-row mt-3", children: _jsx("button", { className: "btn btn-primary", onClick: resetEncryptionForm, children: "\uCC98\uC74C\uC73C\uB85C" }) })] }));
        }
        return (_jsxs("div", { className: "view-animate", children: [renderStepDots(4, encryptStep), encryptStep === 1 && (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uC554\uD638\uD654" }), _jsx("p", { className: "section-desc", children: "\uC5B4\uB5A4 \uBC29\uC2DD\uC73C\uB85C \uB370\uC774\uD130\uB97C \uBCF4\uD638\uD560\uAE4C\uC694?" }), _jsxs("div", { className: "option-cards", children: [_jsxs("button", { className: "option-card", onClick: () => { setEncryptAuthMode("password"); setEncryptStep(2); }, children: [_jsx("span", { className: "option-title", children: "\uD83D\uDD11 \uBE44\uBC00\uBC88\uD638" }), _jsx("span", { className: "option-desc", children: "\uBE44\uBC00\uBC88\uD638\uB97C \uC544\uB294 \uC0AC\uB78C\uB9CC \uC5F4 \uC218 \uC788\uC5B4\uC694." })] }), _jsxs("button", { className: "option-card", onClick: () => { setEncryptAuthMode("publickey"); setEncryptStep(2); }, children: [_jsx("span", { className: "option-title", children: "\uD83D\uDC64 \uACF5\uAC1C\uD0A4" }), _jsx("span", { className: "option-desc", children: "\uC9C0\uC815\uD55C \uC0C1\uB300\uBC29\uB9CC \uC5F4 \uC218 \uC788\uB3C4\uB85D \uBCF4\uD638\uD574\uC694. \uBA3C\uC800 \uC8FC\uC18C\uB85D\uC5D0 \uC0C1\uB300\uBC29\uC758 \uACF5\uAC1C\uD0A4\uB97C \uB4F1\uB85D\uD574\uC8FC\uC138\uC694." })] })] })] })), encryptStep === 2 && encryptAuthMode === "password" && (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uBE44\uBC00\uBC88\uD638 \uC124\uC815" }), _jsx("p", { className: "section-desc", children: "\uC554\uD638\uD654\uC5D0 \uC0AC\uC6A9\uD560 \uBE44\uBC00\uBC88\uD638\uB97C \uC785\uB825\uD558\uC138\uC694." }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uBE44\uBC00\uBC88\uD638" }), _jsx("input", { type: "password", value: encryptPassword, onChange: (e) => setEncryptPassword(e.target.value), placeholder: "\uBE44\uBC00\uBC88\uD638 \uC785\uB825", autoFocus: true })] }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uD0A4 \uC720\uB3C4 \uBC29\uC2DD" }), _jsxs("div", { className: "option-cards row-layout", children: [_jsxs("button", { className: `option-card ${encryptKdfMethod === "arg1" ? "selected" : ""}`, onClick: () => setEncryptKdfMethod("arg1"), children: [_jsx("span", { className: "option-title", children: "Argon2id" }), _jsx("span", { className: "option-desc", children: "\uB192\uC740 \uBCF4\uC548 \uAC15\uB3C4 (\uCD94\uCC9C)" })] }), _jsxs("button", { className: `option-card ${encryptKdfMethod === "pbk1" ? "selected" : ""}`, onClick: () => setEncryptKdfMethod("pbk1"), children: [_jsx("span", { className: "option-title", children: "PBKDF2" }), _jsx("span", { className: "option-desc", children: "\uD638\uD658\uC131 \uC6B0\uC120" })] })] })] }), _jsxs("div", { className: "btn-row", children: [_jsx("button", { className: "btn btn-ghost", onClick: () => setEncryptStep(1), children: "\uC774\uC804" }), _jsx("button", { className: "btn btn-primary", disabled: !encryptPassword, onClick: () => setEncryptStep(3), children: "\uB2E4\uC74C" })] })] })), encryptStep === 2 && encryptAuthMode === "publickey" && (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uC218\uC2E0\uC790 \uC124\uC815" }), _jsx("p", { className: "section-desc", children: "\uC554\uD638\uD654\uB41C \uB370\uC774\uD130\uB97C \uBC1B\uC744 \uC0AC\uB78C\uC744 \uC120\uD0DD\uD558\uC138\uC694." }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uC218\uC2E0\uC790" }), _jsxs("select", { value: encryptRecipientId, onChange: (e) => {
                                        const value = e.target.value;
                                        setEncryptRecipientId(value);
                                        if (value) {
                                            const selected = contacts.find((c) => c.id === value);
                                            if (selected) {
                                                const detectedAlgo = detectPublicKeyAlgo(selected.publicKey);
                                                setEncryptAsymAlgo(detectedAlgo);
                                            }
                                        }
                                        else {
                                            setEncryptAsymAlgo(null);
                                        }
                                    }, children: [_jsx("option", { value: "", children: "\uC5F0\uB77D\uCC98\uC5D0\uC11C \uC120\uD0DD..." }), contacts.map((c) => (_jsx("option", { value: c.id, children: c.contactUsername }, c.id)))] }), contacts.length === 0 && _jsx("span", { className: "text-hint", children: "\uC8FC\uC18C\uB85D\uC5D0 \uC5F0\uB77D\uCC98\uB97C \uBA3C\uC800 \uCD94\uAC00\uD558\uC138\uC694." })] }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uBE44\uB300\uCE6D \uC54C\uACE0\uB9AC\uC998" }), _jsxs("div", { className: "option-cards row-layout", children: [_jsxs("button", { className: `option-card ${encryptAsymAlgo === "pqc1" ? "selected" : ""}`, disabled: true, children: [_jsx("span", { className: "option-title", children: "PQC1" }), _jsx("span", { className: "option-desc", children: "\uC591\uC790\uB0B4\uC131 \uD558\uC774\uBE0C\uB9AC\uB4DC" }), encryptAsymAlgo === "pqc1" && _jsx("span", { className: "option-badge", children: "\uC790\uB3D9 \uC120\uD0DD" })] }), _jsxs("button", { className: `option-card ${encryptAsymAlgo === "ecc1" ? "selected" : ""}`, disabled: true, children: [_jsx("span", { className: "option-title", children: "Curve448" }), _jsx("span", { className: "option-desc", children: "\uB192\uC740 \uBCF4\uC548 \uAC15\uB3C4 (\uCD94\uCC9C)" }), encryptAsymAlgo === "ecc1" && _jsx("span", { className: "option-badge", children: "\uC790\uB3D9 \uC120\uD0DD" })] }), _jsxs("button", { className: `option-card ${encryptAsymAlgo === "rsa1" ? "selected" : ""}`, disabled: true, children: [_jsx("span", { className: "option-title", children: "RSA-2048" }), _jsx("span", { className: "option-desc", children: "\uD638\uD658\uC131 \uC6B0\uC120" }), encryptAsymAlgo === "rsa1" && _jsx("span", { className: "option-badge", children: "\uC790\uB3D9 \uC120\uD0DD" })] })] }), _jsx("span", { className: "form-hint", children: "\uC0C1\uB300\uBC29\uC758 \uACF5\uAC1C\uD0A4 \uD615\uC2DD\uC5D0 \uB530\uB77C \uC790\uB3D9\uC73C\uB85C \uC120\uD0DD\uB429\uB2C8\uB2E4" })] }), _jsxs("label", { className: "checkbox-row", children: [_jsx("input", { type: "checkbox", checked: encryptSignWithKey, onChange: (e) => { void handleEncryptSignWithKeyToggle(e.target.checked); }, disabled: encryptBusy || webauthnAuthBusy }), _jsxs("div", { className: "checkbox-label-with-help", children: [_jsx("span", { className: "checkbox-text", children: "\uB0B4 \uAC1C\uC778\uD0A4\uB85C \uC11C\uBA85\uD558\uAE30" }), _jsxs("div", { className: "help-icon-wrapper", children: [_jsxs("svg", { className: "help-icon", width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", onMouseEnter: () => setShowSigningTooltip(true), onMouseLeave: () => setShowSigningTooltip(false), onClick: () => setShowSigningTooltip(!showSigningTooltip), children: [_jsx("circle", { cx: "12", cy: "12", r: "10" }), _jsx("path", { d: "M12 16v-4M12 8h.01" })] }), showSigningTooltip && (_jsx("div", { className: "tooltip", children: "\uB0B4 \uAC1C\uC778\uD0A4\uB85C \uC554\uD638\uBB38\uC5D0 \uC11C\uBA85\uD558\uC5EC \uC0C1\uB300\uBC29\uC740 \uC774\uAC83\uC774 \uC9C4\uC9DC \uB098\uB85C\uBD80\uD130 \uC628 \uBA54\uC2DC\uC9C0\uC784\uC744 \uD655\uC778\uD560 \uC218 \uC788\uC5B4\uC694." }))] })] })] }), _jsxs("div", { className: "btn-row", children: [_jsx("button", { className: "btn btn-ghost", onClick: () => setEncryptStep(1), children: "\uC774\uC804" }), _jsx("button", { className: "btn btn-primary", disabled: !encryptRecipientId, onClick: () => setEncryptStep(3), children: "\uB2E4\uC74C" })] })] })), encryptStep === 3 && (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uC554\uD638\uD654 \uBC29\uC2DD" }), _jsx("p", { className: "section-desc", children: "\uB370\uC774\uD130\uB97C \uC554\uD638\uD654\uD560 \uBC29\uC2DD\uC744 \uC120\uD0DD\uD558\uC138\uC694." }), _jsxs("div", { className: "option-cards", children: [_jsxs("button", { className: "option-card", onClick: () => { setEncryptEncAlgo("gcm1"); setEncryptStep(4); }, children: [_jsx("span", { className: "option-title", children: "\uD45C\uC900 (AES-GCM)" }), _jsx("span", { className: "option-desc", children: "\uC77C\uBC18\uC801\uC778 \uD14D\uC2A4\uD2B8\uC640 \uD30C\uC77C\uC5D0 \uC801\uD569\uD569\uB2C8\uB2E4" })] }), _jsxs("button", { className: "option-card", onClick: () => { setEncryptEncAlgo("gcmx1"); setEncryptStep(4); }, children: [_jsx("span", { className: "option-title", children: "\uB300\uC6A9\uB7C9 \uD30C\uC77C \uC804\uC6A9 (AES-GCM \uCCAD\uD06C)" }), _jsx("span", { className: "option-desc", children: "\uB300\uC6A9\uB7C9 \uD30C\uC77C\uC744 \uD6A8\uC728\uC801\uC73C\uB85C \uCC98\uB9AC\uD569\uB2C8\uB2E4" })] })] }), _jsx("div", { className: "btn-row", children: _jsx("button", { className: "btn btn-ghost", onClick: () => setEncryptStep(2), children: "\uC774\uC804" }) })] })), encryptStep === 4 && (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uB370\uC774\uD130 \uC785\uB825" }), _jsx("p", { className: "section-desc", children: "\uC554\uD638\uD654\uD560 \uB0B4\uC6A9\uC744 \uC785\uB825\uD558\uC138\uC694." }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uACF5\uAC1C \uBA54\uC2DC\uC9C0 (\uC120\uD0DD)" }), _jsx("input", { type: "text", value: encryptMsg, onChange: (e) => setEncryptMsg(e.target.value), placeholder: "\uC554\uD638\uD654 \uC5C6\uC774 \uD45C\uC2DC\uB418\uB294 \uBA54\uC2DC\uC9C0" }), _jsx("span", { className: "form-hint", children: "\uC774 \uBA54\uC2DC\uC9C0\uB294 \uBCF5\uD638\uD654 \uC5C6\uC774\uB3C4 \uBCFC \uC218 \uC788\uC5B4\uC694" })] }), _jsxs("div", { className: "tab-toggle", children: [_jsx("button", { className: encryptMode === "text" ? "active" : "", onClick: () => handleEncryptionModeChange("text"), children: "\uD14D\uC2A4\uD2B8" }), _jsx("button", { className: encryptMode === "file" ? "active" : "", onClick: () => handleEncryptionModeChange("file"), children: "\uD30C\uC77C" })] }), encryptMode === "text" ? (_jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uBE44\uBC00 \uBA54\uC2DC\uC9C0" }), _jsx("textarea", { value: encryptSmsg, onChange: (e) => { setEncryptSmsg(e.target.value); setEncryptError(null); }, placeholder: "\uC554\uD638\uD654\uD560 \uBA54\uC2DC\uC9C0 \uC785\uB825" })] })) : (_jsxs("div", { className: "form-group", children: [_jsxs("div", { className: `file-drop ${isFileDragActive ? "active" : ""}`, onDragEnter: handleFileDragEnter, onDragOver: handleFileDragOver, onDragLeave: handleFileDragLeave, onDrop: handleFileDrop, children: [_jsx("input", { id: "encrypt-file", type: "file", onChange: handleEncryptFileChange, disabled: encryptBusy, className: "sr-only" }), _jsxs("label", { htmlFor: "encrypt-file", style: { cursor: "pointer" }, children: [_jsx("div", { className: "file-drop-icon", children: "\uD83D\uDCC1" }), _jsx("p", { className: "file-drop-text", children: "\uD30C\uC77C\uC744 \uB04C\uC5B4\uB193\uAC70\uB098 \uD074\uB9AD\uD558\uC138\uC694" }), _jsx("p", { className: "file-drop-hint", children: "\uBE0C\uB77C\uC6B0\uC800\uC5D0\uC11C \uC554\uD638\uD654\uB429\uB2C8\uB2E4" })] })] }), encryptFile && (_jsxs("div", { className: "file-info-bar", children: [_jsxs("div", { children: [_jsx("span", { className: "file-info-name", children: encryptFile.name }), _jsxs("span", { className: "file-info-size", children: [" \u00B7 ", formatBytes(encryptFile.size)] })] }), _jsx("button", { className: "btn-ghost btn-sm", onClick: () => applySelectedEncryptFile(null), children: "\uC81C\uAC70" })] }))] })), encryptError && _jsx("div", { className: "status-bar error", children: encryptError }), encryptBusy && _jsx("div", { className: "progress-bar", children: _jsx("div", { className: "progress-fill" }) }), _jsxs("div", { className: "btn-row", children: [_jsx("button", { className: "btn btn-ghost", onClick: () => setEncryptStep(3), children: "\uC774\uC804" }), _jsx("button", { className: "btn btn-primary", disabled: encryptBusy, onClick: handleEncryptSubmit, children: encryptBusy ? "암호화 중..." : "암호화" })] })] }))] }, `enc-step-${encryptStep}`));
    }
    /* ─── Decrypt tab (wizard) ─── */
    function renderDecryptTab() {
        if (decryptedResult) {
            const rows = [];
            if (decryptedResult.msg)
                rows.push({ label: "공개 메시지", value: decryptedResult.msg });
            if (decryptedResult.smsg)
                rows.push({ label: "비밀 메시지", value: decryptedResult.smsg });
            if (decryptedResult.files.length > 0)
                rows.push({ label: "파일", value: `${decryptedResult.files.length}개` });
            return (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uBCF5\uD638\uD654 \uACB0\uACFC" }), _jsx("br", {}), decryptStatus && _jsx("div", { className: "status-bar success", children: decryptStatus }), decryptedResult.verified === true && (_jsx("div", { className: "status-bar success", style: { marginBottom: 12 }, children: "\u2713 \uC11C\uBA85 \uAC80\uC99D \uC131\uACF5 - \uBC1C\uC2E0\uC790\uC758 \uC2E0\uC6D0\uC774 \uD655\uC778\uB418\uC5C8\uC2B5\uB2C8\uB2E4" })), decryptedResult.verified === false && decryptedResult.verifyError && (_jsxs("div", { className: "status-bar error", style: { marginBottom: 12 }, children: ["\u2717 \uC11C\uBA85 \uAC80\uC99D \uC2E4\uD328: ", decryptedResult.verifyError] })), decryptedResult.verifyError && decryptedResult.verified !== false && (_jsxs("div", { className: "status-bar error", style: { marginBottom: 12 }, children: ["\u26A0 ", decryptedResult.verifyError] })), _jsxs("div", { className: "card", children: [rows.map((r) => (_jsxs("div", { style: { marginBottom: 14 }, children: [_jsx("span", { className: "result-label", children: r.label }), _jsx("p", { style: { whiteSpace: "pre-wrap", marginTop: 4, fontSize: 15, fontWeight: 500 }, children: r.value })] }, r.label))), _jsxs("div", { style: { marginBottom: 0, paddingTop: 8, borderTop: "1px solid var(--border)" }, children: [_jsx("span", { className: "result-label", children: "\uC11C\uBA85 \uC0C1\uD0DC" }), _jsxs("p", { style: { whiteSpace: "pre-wrap", marginTop: 4, fontSize: 15, fontWeight: 500 }, children: [decryptedResult.verified === true && "✓ 유효 (발신자 확인됨)", decryptedResult.verified === false && "✗ 유효하지 않음 (경고)", decryptedResult.verified === undefined && (decryptedResult.verifyError ? `- ${decryptedResult.verifyError}` : "- 서명 검증 생략됨 (공개키 미제공)")] })] })] }), decryptedResult.files.length > 0 && (_jsxs("div", { className: "card", children: [_jsx("h3", { style: { fontSize: 15, fontWeight: 600, marginBottom: 12 }, children: "\uCD94\uCD9C\uB41C \uD30C\uC77C" }), decryptedResult.files.map((f, i) => (_jsxs("div", { className: "file-info-bar", style: { marginTop: i > 0 ? 8 : 0 }, children: [_jsxs("div", { children: [_jsx("span", { className: "file-info-name", children: f.name }), _jsxs("span", { className: "file-info-size", children: [" \u00B7 ", formatBytes(f.data.length)] })] }), _jsx("button", { className: "btn btn-secondary btn-sm", onClick: () => handleDownloadDecryptedFile(f.name, f.data), children: "\uB2E4\uC6B4\uB85C\uB4DC" })] }, i)))] })), _jsx("div", { className: "btn-row mt-3", children: _jsx("button", { className: "btn btn-primary", onClick: resetDecryptForm, children: "\uCC98\uC74C\uC73C\uB85C" }) })] }));
        }
        return (_jsxs("div", { className: "view-animate", children: [decryptDetected?.mode === "publickey" ? renderStepDots(3, decryptStep) : renderStepDots(2, decryptStep), decryptStep === 1 && (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uBCF5\uD638\uD654" }), _jsx("p", { className: "section-desc", children: "\uC554\uD638\uD654\uB41C \uB370\uC774\uD130\uB97C \uBD88\uB7EC\uC624\uC138\uC694." }), _jsxs("div", { className: "form-group", children: [_jsxs("div", { className: `file-drop ${isDecryptFileDragActive ? "active" : ""}`, onDragEnter: handleDecryptDragEnter, onDragOver: handleDecryptDragOver, onDragLeave: handleDecryptDragLeave, onDrop: handleDecryptFileDrop, children: [_jsx("input", { id: "decrypt-file", type: "file", onChange: handleDecryptFileChange, disabled: decryptBusy, className: "sr-only" }), _jsxs("label", { htmlFor: "decrypt-file", style: { cursor: "pointer" }, children: [_jsx("div", { className: "file-drop-icon", children: "\uD83D\uDCC2" }), _jsx("p", { className: "file-drop-text", children: "\uC554\uD638\uD654\uB41C \uD30C\uC77C\uC744 \uB04C\uC5B4\uB193\uAC70\uB098 \uD074\uB9AD\uD558\uC138\uC694" }), _jsx("p", { className: "file-drop-hint", children: ".bin \uD30C\uC77C\uC744 \uC5EC\uAE30\uC5D0 \uB193\uC73C\uC138\uC694" })] })] }), decryptPayloadFile && (_jsxs("div", { className: "file-info-bar", children: [_jsxs("div", { children: [_jsx("span", { className: "file-info-name", children: decryptPayloadFile.name }), _jsxs("span", { className: "file-info-size", children: [" \u00B7 ", formatBytes(decryptPayloadFile.size)] })] }), _jsx("button", { className: "btn-ghost btn-sm", onClick: () => { setDecryptPayloadFile(null); setDecryptDetected(null); }, children: "\uC81C\uAC70" })] }))] }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uB610\uB294 Base64 \uD14D\uC2A4\uD2B8 \uBD99\uC5EC\uB123\uAE30" }), _jsx("textarea", { value: decryptPayloadInput, onChange: (e) => {
                                        const val = e.target.value;
                                        setDecryptPayloadInput(val);
                                        setDecryptPayloadFile(null);
                                        setDecryptError(null);
                                        if (val.trim()) {
                                            try {
                                                tryAutoDetect(base64ToU8(val.trim()));
                                            }
                                            catch {
                                                setDecryptDetected(null);
                                            }
                                        }
                                        else {
                                            setDecryptDetected(null);
                                        }
                                    }, placeholder: "Base64\uB85C \uC778\uCF54\uB529\uB41C \uC554\uD638\uBB38...", disabled: decryptBusy })] }), decryptError && _jsx("div", { className: "status-bar error", children: decryptError }), _jsx("div", { className: "btn-row btn-row-right", children: _jsx("button", { className: "btn btn-primary", disabled: !decryptPayloadFile && !decryptPayloadInput.trim(), onClick: handleDecryptAdvanceToStep2, children: "\uB2E4\uC74C" }) })] })), decryptStep === 2 && (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uBCF5\uD638\uD654 \uC124\uC815" }), _jsx("br", {}), decryptDetected && (_jsxs("div", { className: "card mb-3", children: [_jsxs("div", { className: "result-grid", children: [_jsxs("div", { className: "result-item", children: [_jsx("span", { className: "result-label", children: "\uAC10\uC9C0\uB41C \uBC29\uC2DD" }), _jsx("span", { className: "result-value", children: decryptDetected.mode === "password" ? "🔑 비밀번호" : "👤 공개키" })] }), _jsxs("div", { className: "result-item", children: [_jsx("span", { className: "result-label", children: "\uC54C\uACE0\uB9AC\uC998" }), _jsx("span", { className: "result-value", children: decryptDetected.algo })] })] }), decryptDetected.msg && (_jsxs("div", { className: "detected-msg", children: [_jsx("p", { className: "detected-msg-label", children: "\uACF5\uAC1C \uBA54\uC2DC\uC9C0" }), _jsx("pre", { className: "detected-msg-body", children: decryptDetected.msg })] }))] })), decryptDetected?.mode === "password" && (_jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uBE44\uBC00\uBC88\uD638" }), _jsx("input", { type: "password", value: decryptPassword, onChange: (e) => { setDecryptPassword(e.target.value); setDecryptError(null); }, placeholder: "\uC554\uD638\uD654\uC5D0 \uC0AC\uC6A9\uD55C \uBE44\uBC00\uBC88\uD638", disabled: decryptBusy, autoFocus: true })] })), decryptDetected?.mode === "publickey" && (_jsx(_Fragment, { children: _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uAC1C\uC778\uD0A4" }), _jsxs("div", { className: "tab-toggle mb-2", children: [_jsx("button", { className: decryptPrivateKeySource === "security" ? "active" : "", onClick: () => {
                                                    if (storedAccount?.encryptedPrivateKey && isAuthed && webauthnAvailable) {
                                                        setDecryptPrivateKeySource("security");
                                                    }
                                                    else {
                                                        setDecryptPrivateKeySource("manual");
                                                    }
                                                }, children: "\uBCF4\uC548 \uD0A4\uB85C \uC778\uC99D" }), _jsx("button", { className: decryptPrivateKeySource === "manual" ? "active" : "", onClick: () => setDecryptPrivateKeySource("manual"), children: "\uC9C1\uC811 \uC785\uB825" })] }), decryptPrivateKeySource === "security" ? (_jsx(_Fragment, { children: storedAccount?.encryptedPrivateKey && isAuthed && webauthnAvailable ? (_jsxs(_Fragment, { children: [_jsx("button", { className: "btn btn-secondary btn-full", onClick: handleWebAuthnAuthenticate, disabled: decryptBusy || webauthnAuthBusy, children: webauthnAuthBusy ? "인증 중..." : "🔐 보안 키로 인증" }), decryptionToken && _jsx("p", { className: "text-hint mt-3", style: { color: "var(--success)" }, children: "\u2713 \uBCF4\uC548 \uD0A4 \uC778\uC99D \uC644\uB8CC" })] })) : (_jsx("p", { className: "text-hint", children: "\uC800\uC7A5\uB41C \uD0A4\uAC00 \uC5C6\uAC70\uB098 WebAuthn\uC774 \uBD88\uAC00\uB2A5\uD569\uB2C8\uB2E4. \uC9C1\uC811 \uC785\uB825\uC744 \uC0AC\uC6A9\uD558\uC138\uC694." })) })) : (_jsx("textarea", { value: decryptPrivateKeyInput, onChange: (e) => { setDecryptPrivateKeyInput(e.target.value); setDecryptError(null); }, placeholder: "Base64\uB85C \uC778\uCF54\uB529\uB41C \uAC1C\uC778\uD0A4", disabled: decryptBusy, autoFocus: true }))] }) })), decryptStatus && _jsx("div", { className: "status-bar info", children: decryptStatus }), decryptError && _jsx("div", { className: "status-bar error", children: decryptError }), decryptBusy && _jsx("div", { className: "progress-bar", children: _jsx("div", { className: "progress-fill" }) }), _jsxs("div", { className: "btn-row", children: [_jsx("button", { className: "btn btn-ghost", onClick: () => setDecryptStep(1), children: "\uC774\uC804" }), _jsx("button", { className: "btn btn-primary", disabled: decryptBusy || (decryptDetected?.mode === "publickey" && decryptPrivateKeySource === "manual" && !decryptPrivateKeyInput.trim()) || (decryptDetected?.mode === "publickey" && decryptPrivateKeySource === "security" && !decryptionToken) || (decryptDetected?.mode === "password" && !decryptPassword), onClick: () => {
                                        if (decryptDetected?.mode === "publickey") {
                                            setDecryptStep(3);
                                        }
                                        else {
                                            handleDecryptSubmit();
                                        }
                                    }, children: decryptDetected?.mode === "publickey" ? "다음" : "복호화" })] })] })), decryptStep === 3 && decryptDetected?.mode === "publickey" && (_jsxs(_Fragment, { children: [_jsx("h2", { className: "section-title", children: "\uC11C\uBA85 \uAC80\uC99D" }), _jsx("p", { className: "section-desc", children: "\uBC1C\uC2E0\uC790\uC758 \uACF5\uAC1C\uD0A4\uB97C \uC785\uB825\uD558\uC5EC \uC11C\uBA85\uC744 \uAC80\uC99D\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4 (\uC120\uD0DD)." }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uBC1C\uC2E0\uC790\uC758 \uACF5\uAC1C\uD0A4" }), _jsxs("div", { className: "tab-toggle mb-2", children: [_jsx("button", { className: decryptPeerKeySource === "contact" ? "active" : "", onClick: () => setDecryptPeerKeySource("contact"), children: "\uC5F0\uB77D\uCC98\uC5D0\uC11C" }), _jsx("button", { className: decryptPeerKeySource === "manual" ? "active" : "", onClick: () => setDecryptPeerKeySource("manual"), children: "\uC9C1\uC811 \uC785\uB825" })] }), decryptPeerKeySource === "contact" ? (_jsxs("select", { value: decryptSelectedContactId, onChange: (e) => {
                                        const id = e.target.value;
                                        setDecryptSelectedContactId(id);
                                        const contact = contacts.find((c) => c.id === id);
                                        setDecryptPeerPublicKey(contact?.publicKey ?? "");
                                    }, disabled: decryptBusy || contacts.length === 0, children: [_jsx("option", { value: "", children: contacts.length === 0 ? "저장된 연락처 없음" : "연락처 선택..." }), contacts.map((c) => (_jsxs("option", { value: c.id, children: [c.contactUsername, c.notes ? ` — ${c.notes}` : ""] }, c.id)))] })) : (_jsx("textarea", { value: decryptPeerPublicKey, onChange: (e) => { setDecryptPeerPublicKey(e.target.value); setDecryptSelectedContactId(""); }, placeholder: "Base64\uB85C \uC778\uCF54\uB529\uB41C \uACF5\uAC1C\uD0A4 (\uC120\uD0DD)", disabled: decryptBusy })), _jsx("span", { className: "form-hint", children: "\uC11C\uBA85 \uAC80\uC99D\uC774 \uD544\uC694\uD558\uC9C0 \uC54A\uC73C\uBA74 \uBE44\uC6CC\uB3C4 \uB429\uB2C8\uB2E4" })] }), decryptStatus && _jsx("div", { className: "status-bar info", children: decryptStatus }), decryptError && _jsx("div", { className: "status-bar error", children: decryptError }), decryptBusy && _jsx("div", { className: "progress-bar", children: _jsx("div", { className: "progress-fill" }) }), _jsxs("div", { className: "btn-row", children: [_jsx("button", { className: "btn btn-ghost", onClick: () => setDecryptStep(2), children: "\uC774\uC804" }), _jsx("button", { className: "btn btn-primary", disabled: decryptBusy || (decryptPrivateKeySource === "manual" && !decryptPrivateKeyInput.trim()) || (decryptPrivateKeySource === "security" && !decryptionToken), onClick: handleDecryptSubmit, children: decryptBusy ? "복호화 중..." : "복호화" })] })] }))] }, `dec-step-${decryptStep}`));
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
    return (_jsxs("div", { className: "page", children: [_jsxs("div", { className: "topbar", children: [_jsxs("div", { className: "topbar-left", children: [_jsx("span", { className: "topbar-brand", children: "YAS" }), _jsx("span", { className: "topbar-user", children: authUsername })] }), _jsxs("div", { className: "topbar-right", children: [_jsx("button", { className: "theme-toggle", onClick: () => setThemeMode(prev => prev === "system" ? (resolvedDark ? "light" : "dark") : prev === "light" ? "dark" : "system"), title: themeMode === "system" ? "시스템 테마" : resolvedDark ? "다크 모드" : "라이트 모드", children: themeMode === "system" ? (_jsxs("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("rect", { x: "2", y: "3", width: "20", height: "14", rx: "2" }), _jsx("path", { d: "M8 21h8" }), _jsx("path", { d: "M12 17v4" })] })) : resolvedDark ? (_jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: _jsx("path", { d: "M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" }) })) : (_jsxs("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("circle", { cx: "12", cy: "12", r: "5" }), _jsx("path", { d: "M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" })] })) }), _jsx("button", { className: "topbar-logout", onClick: handleSignOut, children: "\uB85C\uADF8\uC544\uC6C3" })] })] }), _jsx("nav", { className: "pill-nav", children: _jsx("div", { className: "pill-nav-inner", ref: navInnerRef, children: ["keys", "contacts", "encrypt", "decrypt"].map((t) => {
                        const ref = { contacts: navContactsRef, keys: navKeysRef, encrypt: navEncryptRef, decrypt: navDecryptRef }[t];
                        const Icon = { contacts: IconContacts, keys: IconKey, encrypt: IconEncrypt, decrypt: IconDecrypt }[t];
                        const title = { contacts: "주소록", keys: "내 키", encrypt: "암호화", decrypt: "복호화" }[t];
                        return (_jsx("button", { ref: ref, className: `pill-nav-item ${tab === t ? "active" : ""}`, onClick: () => { setPressedTab(null); setTab(t); }, onPointerDown: () => { if (t !== tab)
                                setPressedTab(t); }, onPointerUp: () => setPressedTab(null), onPointerLeave: () => setPressedTab(null), onPointerCancel: () => setPressedTab(null), title: title, children: _jsx(Icon, { active: tab === t }) }, t));
                    }) }) }), _jsx("div", { className: "view-animate", children: renderTabContent() }, tab), toastMsg && _jsx("div", { className: "toast-message", children: toastMsg }), (contactModalOpen || contactModalClosing) && (_jsx("div", { className: `modal-overlay ${contactModalClosing ? "closing" : ""}`, onClick: (e) => { if (e.target === e.currentTarget)
                    closeContactModal(); }, children: _jsxs("div", { className: `modal-box ${contactModalClosing ? "closing" : ""}`, children: [_jsx("h3", { className: "modal-title", children: contactModalMode === "add" ? "연락처 추가" : "연락처 수정" }), _jsxs("form", { onSubmit: handleContactSubmit, children: [_jsxs("div", { className: "form-group", children: [_jsxs("label", { className: "form-label", children: ["\uC0AC\uC6A9\uC790 \uC544\uC774\uB514", _jsxs("div", { className: "help-icon-wrapper", children: [_jsxs("svg", { className: "help-icon", width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", onMouseEnter: () => setShowUsernameTooltip(true), onMouseLeave: () => setShowUsernameTooltip(false), onClick: () => setShowUsernameTooltip(!showUsernameTooltip), children: [_jsx("circle", { cx: "12", cy: "12", r: "10" }), _jsx("path", { d: "M12 16v-4M12 8h.01" })] }), showUsernameTooltip && (_jsx("div", { className: "tooltip", children: "\uC0C1\uB300\uBC29\uC774 \uC11C\uBE44\uC2A4\uC5D0 \uAC00\uC785\uD560 \uB54C \uC0AC\uC6A9\uD55C \uC2E4\uC81C \uC544\uC774\uB514(username)\uB97C \uC815\uD655\uD788 \uC785\uB825\uD574\uC57C \uD569\uB2C8\uB2E4." }))] })] }), _jsx("input", { type: "text", value: contactForm.contactUsername, onChange: (e) => setContactForm((prev) => ({ ...prev, contactUsername: e.target.value })), placeholder: "\uC544\uC774\uB514", required: true })] }), _jsxs("div", { className: "form-group", children: [_jsx("label", { className: "form-label", children: "\uBA54\uBAA8 (\uC120\uD0DD)" }), _jsx("input", { type: "text", value: contactForm.notes, onChange: (e) => setContactForm((prev) => ({ ...prev, notes: e.target.value })), placeholder: "\uAC04\uB2E8\uD55C \uBA54\uBAA8" })] }), contactModalError && _jsx("div", { className: "status-bar error", children: contactModalError }), _jsxs("div", { className: "modal-footer", children: [_jsx("button", { type: "button", className: "btn btn-ghost", onClick: closeContactModal, children: "\uCDE8\uC18C" }), _jsx("button", { type: "submit", className: "btn btn-primary", disabled: contactBusy || !contactForm.contactUsername.trim(), children: contactBusy ? "저장 중..." : contactModalMode === "add" ? "저장" : "수정" })] })] })] }) }))] }));
}
export default App;
