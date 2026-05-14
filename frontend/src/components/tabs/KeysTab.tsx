import { maskKey, truncateKey } from "../../helpers";
import type { AccountRecord } from "../../types";
import type { AsymAlgo } from "../../crypto";

type KeysTabProps = {
	storedAccount: AccountRecord | null;
	showKeySection: boolean;
	status: string | null;
	error: string | null;
	copyPublicStatus: "idle" | "copied" | "error";
	copyPrivateStatus: "idle" | "copied" | "error";
	keyGenStep: number;
	keyAlgo: AsymAlgo;
	publicKeyPem: string;
	privateKeyPem: string;
	canUpload: boolean;
	busy: boolean;
	onSetKeyAlgo: (algo: AsymAlgo) => void;
	onGenerateKeys: () => void;
	onUpload: () => void;
	onRegenerate: () => void;
	onCopyPublicKey: (value?: string) => void;
	onCopyPrivateKey: (value?: string) => void;
	onSetKeyGenStep: (step: number) => void;
	onSetShowKeySection: (show: boolean) => void;
	onRevealPrivateKey?: () => void;
	webauthnAvailable?: boolean;
};

export const KeysTab = ({
	storedAccount,
	showKeySection,
	status,
	error,
	copyPublicStatus,
	copyPrivateStatus,
	keyGenStep,
	keyAlgo,
	publicKeyPem,
	privateKeyPem,
	canUpload,
	busy,
	onSetKeyAlgo,
	onGenerateKeys,
	onUpload,
	onRegenerate,
	onCopyPublicKey,
	onCopyPrivateKey,
	onSetKeyGenStep,
	onSetShowKeySection,
	onRevealPrivateKey,
	webauthnAvailable,
}: KeysTabProps) => {
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
							<button
								className={`btn btn-ghost btn-sm ${copyPublicStatus === "copied" ? "copy-feedback" : ""}`}
								onClick={() => onCopyPublicKey(storedAccount?.publicKey)}
							>
								{copyPublicStatus === "copied" ? "복사됨 ✓" : "복사"}
							</button>
						</div>
					</div>
					<div className="key-item">
						<span className="key-label">개인키</span>
						{privateKeyPem ? (
							<div className="key-full">
								{maskKey(privateKeyPem)}
								<button
									className={`key-copy-btn ${copyPrivateStatus === "copied" ? "copied" : ""}`}
									onClick={() => onCopyPrivateKey(privateKeyPem)}
								>
									{copyPrivateStatus === "copied" ? "복사됨" : "복사"}
								</button>
							</div>
						) : (
							<div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
								<span className="text-hint">서버에 암호화되어 저장됨</span>
								<button
									className="btn btn-secondary btn-sm"
									onClick={onRevealPrivateKey}
									disabled={busy || !webauthnAvailable}
								>
									{busy ? "인증 중..." : "패스키로 인증하여 보기"}
								</button>
							</div>
						)}
					</div>
				</div>
				{status && <div className="status-bar success">{status}</div>}
				{error && <div className="status-bar error">{error}</div>}
				<div className="btn-row">
					<button className="btn btn-secondary" onClick={onRegenerate}>
						키 재생성
					</button>
				</div>
			</>
		);
	}

	return (
		<>
			<h2 className="section-title">키 생성</h2>
			<p className="section-desc">암호화에 사용할 키 쌍을 생성하고 서버에 안전하게 저장합니다.</p>

			{keyGenStep === 1 ? (
				<div className="card">
					<div className="form-group">
						<label className="form-label">키 알고리즘</label>
						<div className="option-cards">
							<button className={`option-card ${keyAlgo === "pqc1" ? "selected" : ""}`} onClick={() => onSetKeyAlgo("pqc1")}>
								<span className="option-title">PQC</span>
								<span className="option-desc">차세대 표준 양자내성 암호</span>
							</button>
							<button className={`option-card ${keyAlgo === "ecc1" ? "selected" : ""}`} onClick={() => onSetKeyAlgo("ecc1")}>
								<span className="option-title">Curve448</span>
								<span className="option-desc">타원곡선 암호</span>
							</button>
							<button className={`option-card ${keyAlgo === "rsa1" ? "selected" : ""}`} onClick={() => onSetKeyAlgo("rsa1")}>
								<span className="option-title">RSA-2048</span>
								<span className="option-desc">호환성 우선</span>
							</button>
							<button className={`option-card ${keyAlgo === "rsa2" ? "selected" : ""}`} onClick={() => onSetKeyAlgo("rsa2")}>
								<span className="option-title">RSA-4096</span>
								<span className="option-desc">추가 보안 (대용량 키)</span>
							</button>
						</div>
					</div>
					<div className="btn-row">
						{storedAccount && (
							<button className="btn btn-secondary" onClick={() => onSetShowKeySection(false)}>
								이전
							</button>
						)}
						<button className="btn btn-secondary" onClick={onGenerateKeys} style={{ marginLeft: "auto" }}>
							키 쌍 생성
						</button>
					</div>
					{status && <div className="status-bar success mt-3">{status}</div>}
					{error && <div className="status-bar error mt-3">{error}</div>}
				</div>
			) : (
				<div className="card" key="step2">
					<div className="step-header">
						<h3 style={{ fontSize: 16, fontWeight: 600 }}>생성된 키</h3>
					</div>
					<div className="key-item">
						<span className="key-label">공개키</span>
						<div className="key-full">
							{maskKey(publicKeyPem)}
							{publicKeyPem && (
								<button
									className={`key-copy-btn ${copyPublicStatus === "copied" ? "copied" : ""}`}
									onClick={() => onCopyPublicKey(publicKeyPem)}
								>
									{copyPublicStatus === "copied" ? "복사됨" : "복사"}
								</button>
							)}
						</div>
					</div>
					<div className="key-item">
						<span className="key-label">개인키 (평문)</span>
						<div className="key-full">
							{maskKey(privateKeyPem)}
							{privateKeyPem && (
								<button
									className={`key-copy-btn ${copyPrivateStatus === "copied" ? "copied" : ""}`}
									onClick={() => onCopyPrivateKey(privateKeyPem)}
								>
									{copyPrivateStatus === "copied" ? "복사됨" : "복사"}
								</button>
							)}
						</div>
					</div>
					<p className="text-hint mt-2">개인키는 브라우저에서 암호화된 후 서버에 안전하게 저장됩니다.</p>
					<div className="btn-row" style={{ marginTop: 20 }}>
						<button className="btn btn-secondary" onClick={() => onSetKeyGenStep(1)}>
							이전
						</button>
						<div style={{ display: "flex", gap: "10px", marginLeft: "auto" }}>
							<button className="btn btn-secondary" onClick={() => onSetKeyGenStep(1)}>
								다시 생성
							</button>
							<button className="btn btn-primary" onClick={onUpload} disabled={!canUpload || busy}>
								{busy ? "처리 중..." : "암호화하여 저장"}
							</button>
						</div>
					</div>
					{status && <div className="status-bar success mt-3">{status}</div>}
					{error && <div className="status-bar error mt-3">{error}</div>}
				</div>
			)}
		</>
	);
};
