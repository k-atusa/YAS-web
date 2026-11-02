import { useState, useEffect } from "react";
import { truncateKey } from "../../helpers";
import { generateKeyPair } from "../../crypto";
import type { AccountRecord, PasskeyCredentialItem } from "../../types";

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
	onRevealWithMasterKey?: () => void;
	onHidePrivateKey?: () => void;
	webauthnAvailable?: boolean;
	passkeys?: PasskeyCredentialItem[];
	passkeysBusy?: boolean;
	onAddPasskey?: () => void;
	onDeletePasskey?: (credentialId: string, name: string) => void;
	onDeleteAccount?: () => void;
};

export const KeysTab = ({
	storedAccount,
	showKeySection,
	copyPublicStatus,
	copyPrivateStatus,
	privateKeyPem,
	busy,
	onSaveManualKeys,
	onSaveKeys,
	onCopyPublicKey,
	onCopyPrivateKey,
	onSetShowKeySection,
	onRevealPrivateKey,
	onRevealWithMasterKey,
	onHidePrivateKey,
	webauthnAvailable,
	passkeys = [],
	passkeysBusy = false,
	onAddPasskey,
	onDeletePasskey,
	onDeleteAccount,
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

	const hasStoredKey = Boolean(
		storedAccount?.publicKey && (storedAccount?.hasPrivateKey || storedAccount?.encryptedPrivateKey?.cipherText)
	);
	const hasUsablePasskey = Boolean(webauthnAvailable && passkeys.some((p) => p.hasMasterKey));
	const saveHandler = onSaveKeys || onSaveManualKeys;

	function renderPasskeyAndAccountSection() {
		return (
			<div style={{ marginTop: 32, paddingTop: 24, borderTop: "1px solid var(--border)" }}>
				<div className="section-header" style={{ marginBottom: 6 }}>
					<h3 className="section-title" style={{ fontSize: 16 }}>패스키 관리</h3>
					{onAddPasskey && (
						<button
							type="button"
							className="btn btn-secondary btn-sm"
							onClick={onAddPasskey}
							disabled={busy || passkeysBusy || !webauthnAvailable}
						>
							{passkeysBusy ? "처리 중..." : "+ 패스키 추가"}
						</button>
					)}
				</div>
				<p className="section-desc" style={{ marginBottom: 12 }}>
					여러 기기의 패스키를 등록해두면 각 기기에서 패스키 인증만으로 마스터키를 복호화하여 개인키를 사용할 수 있습니다.
				</p>

				{passkeys.length === 0 ? (
					<div className="key-card" style={{ padding: "18px 16px", textAlign: "center" }}>
						<p className="text-hint" style={{ margin: 0 }}>
							{webauthnAvailable
								? "등록된 패스키가 없습니다. '+ 패스키 추가'를 눌러 현재 기기를 등록하세요."
								: "현재 브라우저 환경에서는 WebAuthn 패스키를 사용할 수 없습니다."}
						</p>
					</div>
				) : (
					<div className="contact-list">
						{passkeys.map((pk) => (
							<div key={pk.id} className="contact-row">
								<div className="contact-info">
									<div className="contact-name-row" style={{ display: "flex", alignItems: "center", gap: 8 }}>
										<span className="contact-name">{pk.name}</span>
										<span
											style={{
												fontSize: 11,
												padding: "2px 6px",
												borderRadius: 6,
												background: pk.hasMasterKey ? "rgba(34, 197, 94, 0.14)" : "rgba(234, 179, 8, 0.15)",
												color: pk.hasMasterKey ? "var(--success, #22c55e)" : "var(--text-muted)",
											}}
										>
											{pk.hasMasterKey ? "마스터키 암호화 연동됨" : "마스터키 미연동"}
										</span>
									</div>
								</div>
								<div className="contact-btns">
									{onDeletePasskey && (
										<button
											type="button"
											className="btn-ghost btn-sm btn-danger"
											onClick={() => onDeletePasskey(pk.id, pk.name)}
											disabled={busy || passkeysBusy}
										>
											삭제
										</button>
									)}
								</div>
							</div>
						))}
					</div>
				)}

				{onDeleteAccount && (
					<div
						style={{
							marginTop: 28,
							paddingTop: 18,
							borderTop: "1px solid var(--border)",
							display: "flex",
							justifyContent: "space-between",
							alignItems: "center",
						}}
					>
						<div>
							<span style={{ fontSize: 13, fontWeight: 500, color: "var(--text-muted)" }}>계정 관리</span>
							<p className="text-hint" style={{ margin: "2px 0 0 0", fontSize: 12 }}>
								계정 탈퇴 시 저장된 키, 패스키, 주소록이 모두 영구 삭제됩니다.
							</p>
						</div>
						<button
							type="button"
							className="btn-ghost btn-sm btn-danger"
							onClick={onDeleteAccount}
							disabled={busy || passkeysBusy}
						>
							계정 탈퇴
						</button>
					</div>
				)}
			</div>
		);
	}

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
								<div style={{ display: "flex", gap: 6 }}>
									{hasUsablePasskey && (
										<button
											type="button"
											className="btn btn-secondary btn-sm"
											onClick={onRevealPrivateKey}
											disabled={busy}
										>
											{busy ? "인증 중..." : "패스키로 보기"}
										</button>
									)}
									<button
										type="button"
										className="btn btn-secondary btn-sm"
										onClick={onRevealWithMasterKey || onRevealPrivateKey}
										disabled={busy}
									>
										{busy && !hasUsablePasskey ? "확인 중..." : "마스터키로 보기"}
									</button>
								</div>
							)}
						</div>
					</div>
				</div>
				<div className="btn-row btn-row-right">
					<button className="btn btn-secondary" onClick={() => setConfirmingRegenerate(true)} disabled={busy}>
						{busy ? "생성 중..." : "키 재생성"}
					</button>
				</div>
				{renderPasskeyAndAccountSection()}
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
			{renderPasskeyAndAccountSection()}
		</>
	);
};
