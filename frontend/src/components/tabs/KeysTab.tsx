import { useState, useEffect } from "react";
import { truncateKey } from "../../helpers";
import { generateKeyPair } from "../../crypto";
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
	onGenerateKeys?: () => void;
	onSaveManualKeys?: (pub: string, pri: string) => Promise<void>;
	onSaveKeys?: (pub: string, pri: string) => Promise<void>;
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
	onSaveManualKeys,
	onSaveKeys,
	onCopyPublicKey,
	onCopyPrivateKey,
	onSetShowKeySection,
	onRevealPrivateKey,
	onHidePrivateKey,
	webauthnAvailable,
}: KeysTabProps) => {
	const [confirmingRegenerate, setConfirmingRegenerate] = useState(false);
	const [keyMode, setKeyMode] = useState<"generate" | "manual">("generate");
	const [previewPublic, setPreviewPublic] = useState("");
	const [previewPrivate, setPreviewPrivate] = useState("");
	const [generatingPreview, setGeneratingPreview] = useState(false);
	const [manualPublicKey, setManualPublicKey] = useState("");
	const [manualPrivateKey, setManualPrivateKey] = useState("");
	const [localCopyPublic, setLocalCopyPublic] = useState<"idle" | "copied">("idle");
	const [localCopyPrivate, setLocalCopyPrivate] = useState<"idle" | "copied">("idle");

	const hasStoredKey = Boolean(storedAccount?.publicKey && storedAccount?.encryptedPrivateKey?.cipherText);
	const saveHandler = onSaveKeys || onSaveManualKeys;

	async function handleCreatePreview() {
		setGeneratingPreview(true);
		try {
			const pair = await generateKeyPair();
			setPreviewPublic(pair.publicKey);
			setPreviewPrivate(pair.privateKey);
		} catch (err) {
			console.error("Failed to generate preview key pair:", err);
		} finally {
			setGeneratingPreview(false);
		}
	}

	// 자동 생성 탭 선택 시 미리보기 키 쌍이 없으면 즉시 생성
	useEffect(() => {
		if (showKeySection && keyMode === "generate" && !previewPublic && !generatingPreview) {
			handleCreatePreview();
		}
	}, [showKeySection, keyMode]);

	async function handleCopyPreviewKey(text: string, type: "public" | "private") {
		if (!text) return;
		try {
			await navigator.clipboard.writeText(text);
			if (type === "public") {
				setLocalCopyPublic("copied");
				setTimeout(() => setLocalCopyPublic("idle"), 2000);
			} else {
				setLocalCopyPrivate("copied");
				setTimeout(() => setLocalCopyPrivate("idle"), 2000);
			}
		} catch (err) {
			console.error("Copy failed:", err);
		}
	}

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
						onClick={() => {
							setConfirmingRegenerate(false);
							setKeyMode("generate");
							setPreviewPublic("");
							setPreviewPrivate("");
							onSetShowKeySection(true);
						}}
						disabled={busy}
					>
						확인
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
			<h2 className="section-title">{storedAccount ? "키 재생성" : "키 생성"}</h2>
			<p className="section-desc">
				{storedAccount
					? "새로운 키 쌍을 생성하거나 직접 입력하여 교체합니다."
					: "암호화에 사용할 키 쌍을 생성하거나 직접 입력하여 서버에 안전하게 저장합니다."}
			</p>

			<div className="tab-toggle mb-3">
				<button
					type="button"
					className={keyMode === "generate" ? "active" : ""}
					onClick={() => setKeyMode("generate")}
					disabled={busy || generatingPreview}
				>
					자동 생성
				</button>
				<button
					type="button"
					className={keyMode === "manual" ? "active" : ""}
					onClick={() => setKeyMode("manual")}
					disabled={busy || generatingPreview}
				>
					직접 입력
				</button>
			</div>

			{keyMode === "generate" ? (
				<>
					{generatingPreview ? (
						<div className="key-card" style={{ padding: "32px 20px", textAlign: "center" }}>
							<p className="text-hint">새로운 키 쌍을 생성하고 있습니다...</p>
						</div>
					) : previewPublic && previewPrivate ? (
						<>
							<div className="key-card">
								<div className="key-row">
									<div className="key-info">
										<span className="key-row-label">공개키</span>
										<code className="key-code">{truncateKey(previewPublic)}</code>
									</div>
									<div className="key-actions">
										<button
											type="button"
											className={`btn btn-ghost btn-sm ${localCopyPublic === "copied" ? "copy-feedback" : ""}`}
											onClick={() => handleCopyPreviewKey(previewPublic, "public")}
										>
											{localCopyPublic === "copied" ? "✓ 복사됨" : "복사"}
										</button>
									</div>
								</div>

								<div className="key-row">
									<div className="key-info">
										<span className="key-row-label">개인키</span>
										<code className="key-code">{truncateKey(previewPrivate)}</code>
									</div>
									<div className="key-actions">
										<button
											type="button"
											className={`btn btn-ghost btn-sm ${localCopyPrivate === "copied" ? "copy-feedback" : ""}`}
											onClick={() => handleCopyPreviewKey(previewPrivate, "private")}
										>
											{localCopyPrivate === "copied" ? "✓ 복사됨" : "복사"}
										</button>
									</div>
								</div>
							</div>
							<p className="text-hint mt-2">개인키는 브라우저에서 안전하게 암호화된 후 서버에 저장됩니다.</p>
						</>
					) : (
						<div className="key-card" style={{ padding: "28px 20px", textAlign: "center" }}>
							<button
								type="button"
								className="btn btn-secondary"
								onClick={handleCreatePreview}
								disabled={busy || generatingPreview}
							>
								키 쌍 생성
							</button>
						</div>
					)}

					<div className="btn-row" style={{ marginTop: 20 }}>
						{storedAccount ? (
							<button
								className="btn btn-secondary"
								onClick={() => {
									setPreviewPublic("");
									setPreviewPrivate("");
									onSetShowKeySection(false);
								}}
								disabled={busy || generatingPreview}
							>
								이전
							</button>
						) : <div />}
						<div style={{ display: "flex", gap: 10 }}>
							{previewPublic && previewPrivate && (
								<button
									type="button"
									className="btn btn-secondary"
									onClick={handleCreatePreview}
									disabled={busy || generatingPreview}
								>
									다시 생성
								</button>
							)}
							<button
								className="btn btn-primary"
								onClick={async () => {
									if (previewPublic && previewPrivate && saveHandler) {
										await saveHandler(previewPublic, previewPrivate);
										setPreviewPublic("");
										setPreviewPrivate("");
									}
								}}
								disabled={busy || generatingPreview || !previewPublic || !previewPrivate}
							>
								{busy ? "암호화 및 저장 중..." : "키 저장"}
							</button>
						</div>
					</div>
				</>
			) : (
				<>
					<div className="form-group">
						<label className="form-label">공개키</label>
						<textarea
							value={manualPublicKey}
							onChange={(e) => setManualPublicKey(e.target.value)}
							placeholder="공개키를 입력하세요..."
							rows={4}
							disabled={busy}
							style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace", fontSize: 13, wordBreak: "break-all" }}
						/>
					</div>
					<div className="form-group">
						<label className="form-label">개인키</label>
						<textarea
							value={manualPrivateKey}
							onChange={(e) => setManualPrivateKey(e.target.value)}
							placeholder="개인키를 입력하세요..."
							rows={5}
							disabled={busy}
							style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace", fontSize: 13, wordBreak: "break-all" }}
						/>
					</div>
					<div className="btn-row">
						{storedAccount && (
							<button
								className="btn btn-secondary"
								onClick={() => {
									setManualPublicKey("");
									setManualPrivateKey("");
									onSetShowKeySection(false);
								}}
								disabled={busy}
							>
								이전
							</button>
						)}
						<button
							className="btn btn-primary"
							onClick={async () => {
								if (saveHandler) {
									await saveHandler(manualPublicKey, manualPrivateKey);
									setManualPublicKey("");
									setManualPrivateKey("");
								}
							}}
							disabled={busy || !manualPublicKey.trim() || !manualPrivateKey.trim()}
							style={{ marginLeft: storedAccount ? undefined : "auto" }}
						>
							{busy ? "검증 및 저장 중..." : "키 등록 및 저장"}
						</button>
					</div>
				</>
			)}
		</>
	);
};
