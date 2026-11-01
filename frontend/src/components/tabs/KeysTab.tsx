import { truncateKey } from "../../helpers";
import type { AccountRecord } from "../../types";

type KeysTabProps = {
	storedAccount: AccountRecord | null;
	showKeySection: boolean;
	copyPublicStatus: "idle" | "copied" | "error";
	copyPrivateStatus: "idle" | "copied" | "error";
	keyGenStep: number;
	publicKeyPem: string;
	privateKeyPem: string;
	canUpload: boolean;
	busy: boolean;
	onGenerateKeys: () => void;
	onUpload: () => void;
	onRegenerate: () => void;
	onCopyPublicKey: (value?: string) => void;
	onCopyPrivateKey: (value?: string) => void;
	onSetKeyGenStep: (step: number) => void;
	onSetShowKeySection: (show: boolean) => void;
	onRevealPrivateKey?: () => void;
	onHidePrivateKey?: () => void;
	webauthnAvailable?: boolean;
};

export const KeysTab = ({
	storedAccount,
	showKeySection,
	copyPublicStatus,
	copyPrivateStatus,
	keyGenStep,
	publicKeyPem,
	privateKeyPem,
	canUpload,
	busy,
	onGenerateKeys,
	onUpload,
	onRegenerate,
	onCopyPublicKey,
	onCopyPrivateKey,
	onSetKeyGenStep,
	onSetShowKeySection,
	onRevealPrivateKey,
	onHidePrivateKey,
	webauthnAvailable,
}: KeysTabProps) => {
	const hasStoredKey = Boolean(storedAccount?.publicKey && storedAccount?.encryptedPrivateKey?.cipherText);

	if (hasStoredKey && !showKeySection) {
		return (
			<>
				<h2 className="section-title">내 키</h2>
				<p className="section-desc">키가 서버에 안전하게 저장되어 있어요.</p>
				<div className="key-card">
					<div className="key-row">
						<div className="key-info">
							<span className="key-row-label">공개키</span>
							<code className="key-code">{truncateKey(storedAccount!.publicKey)}</code>
						</div>
						<div className="key-actions">
							<button
								type="button"
								className={`btn btn-ghost btn-sm ${copyPublicStatus === "copied" ? "copy-feedback" : ""}`}
								onClick={() => onCopyPublicKey(storedAccount?.publicKey)}
							>
								{copyPublicStatus === "copied" ? "✓ 복사됨" : "복사"}
							</button>
						</div>
					</div>

					<div className="key-row">
						<div className="key-info">
							<span className="key-row-label">개인키</span>
							{privateKeyPem ? (
								<code className="key-code">{truncateKey(privateKeyPem)}</code>
							) : (
								<span className="key-masked">••••••••••••••••••••••••</span>
							)}
						</div>
						<div className="key-actions">
							{privateKeyPem ? (
								<>
									<button
										type="button"
										className={`btn btn-ghost btn-sm ${copyPrivateStatus === "copied" ? "copy-feedback" : ""}`}
										onClick={() => onCopyPrivateKey(privateKeyPem)}
									>
										{copyPrivateStatus === "copied" ? "✓ 복사됨" : "복사"}
									</button>
									{onHidePrivateKey && (
										<button
											type="button"
											className="btn btn-ghost btn-sm"
											onClick={onHidePrivateKey}
										>
											숨기기
										</button>
									)}
								</>
							) : (
								<button
									type="button"
									className="btn btn-secondary btn-sm"
									onClick={onRevealPrivateKey}
									disabled={busy || !webauthnAvailable}
								>
									{busy ? "인증 중..." : "패스키로 인증하여 보기"}
								</button>
							)}
						</div>
					</div>
				</div>
				<div className="btn-row btn-row-right">
					<button className="btn btn-secondary" onClick={onRegenerate} disabled={busy}>
						{busy ? "생성 중..." : "키 재생성"}
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
					<p className="text-hint" style={{ marginBottom: 16 }}>
						새로운 보안 키 쌍을 생성합니다.
					</p>
					<div className="btn-row">
						{storedAccount && (
							<button className="btn btn-secondary" onClick={() => onSetShowKeySection(false)}>
								이전
							</button>
						)}
						<button className="btn btn-primary" onClick={onGenerateKeys} style={{ marginLeft: storedAccount ? "auto" : 0 }}>
							키 쌍 생성
						</button>
					</div>
				</div>
			) : (
				<div className="key-card" key="step2">
					<div className="key-row">
						<div className="key-info">
							<span className="key-row-label">공개키</span>
							<code className="key-code">{truncateKey(publicKeyPem)}</code>
						</div>
						<div className="key-actions">
							{publicKeyPem && (
								<button
									type="button"
									className={`btn btn-ghost btn-sm ${copyPublicStatus === "copied" ? "copy-feedback" : ""}`}
									onClick={() => onCopyPublicKey(publicKeyPem)}
								>
									{copyPublicStatus === "copied" ? "✓ 복사됨" : "복사"}
								</button>
							)}
						</div>
					</div>

					<div className="key-row">
						<div className="key-info">
							<span className="key-row-label">개인키</span>
							<code className="key-code">{truncateKey(privateKeyPem)}</code>
						</div>
						<div className="key-actions">
							{privateKeyPem && (
								<button
									type="button"
									className={`btn btn-ghost btn-sm ${copyPrivateStatus === "copied" ? "copy-feedback" : ""}`}
									onClick={() => onCopyPrivateKey(privateKeyPem)}
								>
									{copyPrivateStatus === "copied" ? "✓ 복사됨" : "복사"}
								</button>
							)}
						</div>
					</div>
				</div>
			)}

			{keyGenStep === 2 && (
				<>
					<p className="text-hint mt-2">개인키는 브라우저에서 암호화된 후 서버에 안전하게 저장됩니다.</p>
					<div className="btn-row" style={{ marginTop: 20 }}>
						<button
							className="btn btn-secondary"
							onClick={() => {
								if (storedAccount) {
									onSetShowKeySection(false);
								} else {
									onSetKeyGenStep(1);
								}
							}}
						>
							이전
						</button>
						<button className="btn btn-primary" onClick={onUpload} disabled={!canUpload || busy}>
							{busy ? "처리 중..." : "암호화하여 저장"}
						</button>
					</div>
				</>
			)}
		</>
	);
};
