import { useState } from "react";
import { truncateKey } from "../../helpers";
import type { AccountRecord } from "../../types";

type KeysTabProps = {
	storedAccount: AccountRecord | null;
	showKeySection: boolean;
	copyPublicStatus: "idle" | "copied" | "error";
	copyPrivateStatus: "idle" | "copied" | "error";
	keyGenStep?: number;
	publicKeyPem: string;
	privateKeyPem: string;
	canUpload?: boolean;
	busy: boolean;
	onGenerateKeys: () => void;
	onUpload?: () => void;
	onRegenerate: () => void;
	onCopyPublicKey: (value?: string) => void;
	onCopyPrivateKey: (value?: string) => void;
	onSetKeyGenStep?: (step: number) => void;
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
	publicKeyPem,
	privateKeyPem,
	busy,
	onGenerateKeys,
	onRegenerate,
	onCopyPublicKey,
	onCopyPrivateKey,
	onSetShowKeySection,
	onRevealPrivateKey,
	onHidePrivateKey,
	webauthnAvailable,
}: KeysTabProps) => {
	const [confirmingRegenerate, setConfirmingRegenerate] = useState(false);
	const hasStoredKey = Boolean(storedAccount?.publicKey && storedAccount?.encryptedPrivateKey?.cipherText);

	if (hasStoredKey && confirmingRegenerate) {
		return (
			<>
				<h2 className="section-title">키 재생성 확인</h2>
				<p className="section-desc">키를 새로 생성하기 전에 주의사항을 확인하세요.</p>
				<p style={{ fontSize: 14, lineHeight: 1.6, color: "var(--text)", marginBottom: 20 }}>
					키를 재생성하면 <strong>모든 기존 키가 초기화</strong>됩니다.<br />
					이전에 저장된 키로 암호화된 메시지나 파일은 더 이상 복호화할 수 없게 됩니다. 계속 진행하시겠습니까?
				</p>
				<div className="btn-row">
					<button
						className="btn btn-secondary"
						onClick={() => setConfirmingRegenerate(false)}
						disabled={busy}
					>
						이전
					</button>
					<button
						className="btn btn-primary"
						onClick={async () => {
							await onRegenerate();
							setConfirmingRegenerate(false);
						}}
						disabled={busy}
					>
						{busy ? "처리 중..." : "확인"}
					</button>
				</div>
			</>
		);
	}

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
					<button className="btn btn-secondary" onClick={() => setConfirmingRegenerate(true)} disabled={busy}>
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

			<div className="btn-row">
				{storedAccount && (
					<button className="btn btn-secondary" onClick={() => onSetShowKeySection(false)} disabled={busy}>
						이전
					</button>
				)}
				<button
					className="btn btn-primary"
					onClick={onGenerateKeys}
					disabled={busy}
					style={{ marginLeft: storedAccount ? "auto" : 0 }}
				>
					{busy ? "생성 및 저장 중..." : "키 쌍 생성"}
				</button>
			</div>
		</>
	);
};
