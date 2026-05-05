import { detectPublicKeyAlgo, formatBytes } from "../../helpers";
import { StepDots } from "../StepDots";
import type { AsymAlgo, EncAlgo, KdfMethod, AuthMode } from "../../crypto";
import type { ContactRecord } from "../../types";

type EncryptTabProps = {
	encryptedBlob: Uint8Array | null;
	encryptAuthMode: AuthMode;
	encryptEncAlgo: EncAlgo;
	encryptAsymAlgo: AsymAlgo | null;
	encryptKdfMethod: KdfMethod;
	encryptPassword: string;
	encryptRecipientId: string;
	encryptMsg: string;
	encryptSmsg: string;
	encryptMode: "text" | "file";
	encryptFile: File | null;
	isFileDragActive: boolean;
	encryptSignWithKey: boolean;
	encryptBusy: boolean;
	encryptStatus: string | null;
	encryptResultLink: string | null;
	encryptError: string | null;
	shareExpiresDate: string;
	shareExpiresTime: string;
	shareMaxDownloads: string;
	showShareOptions: boolean;
	encryptStep: number;
	contacts: ContactRecord[];
	webauthnAuthBusy: boolean;
	onSetEncryptAuthMode: (mode: AuthMode) => void;
	onSetEncryptStep: (step: number) => void;
	onSetEncryptKdfMethod: (method: KdfMethod) => void;
	onSetEncryptEncAlgo: (algo: EncAlgo) => void;
	onSetEncryptAsymAlgo: (algo: AsymAlgo | null) => void;
	onSetEncryptPassword: (value: string) => void;
	onSetEncryptRecipientId: (value: string) => void;
	onSetEncryptMsg: (value: string) => void;
	onSetEncryptSmsg: (value: string) => void;
	onSetShareExpiresDate: (value: string) => void;
	onSetShareExpiresTime: (value: string) => void;
	onSetShareMaxDownloads: (value: string) => void;
	onToggleSignWithKey: (checked: boolean) => void;
	onEncryptionModeChange: (mode: "text" | "file") => void;
	onApplySelectedEncryptFile: (file: File | null) => void;
	onFileDragEnter: (e: React.DragEvent<HTMLDivElement>) => void;
	onFileDragOver: (e: React.DragEvent<HTMLDivElement>) => void;
	onFileDragLeave: (e: React.DragEvent<HTMLDivElement>) => void;
	onFileDrop: (e: React.DragEvent<HTMLDivElement>) => void;
	onEncryptFileChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
	onEncryptSubmit: () => void;
	onDownloadEncryptedBlob: () => void;
	onCopyEncryptedBase64: () => void;
	onOpenShareOptions: () => void;
	onCloseShareOptions: () => void;
	onShareConfirm: () => void;
	onResetEncryptionForm: () => void;
	onSetEncryptError: (value: string | null) => void;
	onSetEncryptStatus: (value: string | null) => void;
};

export const EncryptTab = ({
	encryptedBlob,
	encryptAuthMode,
	encryptEncAlgo,
	encryptAsymAlgo,
	encryptKdfMethod,
	encryptPassword,
	encryptRecipientId,
	encryptMsg,
	encryptSmsg,
	encryptMode,
	encryptFile,
	isFileDragActive,
	encryptSignWithKey,
	encryptBusy,
	encryptStatus,
	encryptResultLink,
	encryptError,
	shareExpiresDate,
	shareExpiresTime,
	shareMaxDownloads,
	showShareOptions,
	encryptStep,
	contacts,
	webauthnAuthBusy,
	onSetEncryptAuthMode,
	onSetEncryptStep,
	onSetEncryptKdfMethod,
	onSetEncryptEncAlgo,
	onSetEncryptAsymAlgo,
	onSetEncryptPassword,
	onSetEncryptRecipientId,
	onSetEncryptMsg,
	onSetEncryptSmsg,
	onSetShareExpiresDate,
	onSetShareExpiresTime,
	onSetShareMaxDownloads,
	onToggleSignWithKey,
	onEncryptionModeChange,
	onApplySelectedEncryptFile,
	onFileDragEnter,
	onFileDragOver,
	onFileDragLeave,
	onFileDrop,
	onEncryptFileChange,
	onEncryptSubmit,
	onDownloadEncryptedBlob,
	onCopyEncryptedBase64,
	onOpenShareOptions,
	onCloseShareOptions,
	onShareConfirm,
	onResetEncryptionForm,
	onSetEncryptError,
	onSetEncryptStatus,
}: EncryptTabProps) => {
	if (encryptedBlob) {
		return (
			<>
				<h2 className="section-title">암호화 완료</h2>
				<br />
				<div className="card">
					<div className="result-grid">
						<div className="result-item">
							<span className="result-label">방식</span>
							<span className="result-value">{encryptAuthMode === "password" ? "비밀번호" : "공개키"}</span>
						</div>
						<div className="result-item">
							<span className="result-label">크기</span>
							<span className="result-value">{formatBytes(encryptedBlob.length)}</span>
						</div>
						<div className="result-item">
							<span className="result-label">알고리즘</span>
							<span className="result-value">{encryptEncAlgo === "gcmx1" ? "대용량" : "표준"}</span>
						</div>
					</div>
					<div className="btn-row">
						{encryptedBlob.length < 10240 && (
							<button className="btn btn-secondary btn-sm" onClick={onCopyEncryptedBase64}>
								Base64 복사
							</button>
						)}
						<button className="btn btn-secondary btn-sm" onClick={onDownloadEncryptedBlob}>
							다운로드
						</button>
						<button className="btn btn-primary btn-sm" onClick={onOpenShareOptions}>
							공유하기
						</button>
					</div>
				</div>
				{showShareOptions && (
					<div className="card mt-3">
						<h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>공유 설정</h3>
						<div className="form-group">
							<label className="form-label">만료 날짜</label>
							<input
								type="date"
								min={new Date().toISOString().split("T")[0]}
								max="9999-12-31"
								value={shareExpiresDate}
								onChange={(e) => {
									let val = e.target.value;
									if (val && val.length > 10) {
										const parts = val.split("-");
										if (parts.length > 0 && parts[0].length > 4) {
											parts[0] = parts[0].slice(0, 4);
											val = parts.join("-");
										}
									}
									onSetShareExpiresDate(val);
								}}
								onKeyDown={(e) => {
									if (e.key >= "0" && e.key <= "9") {
										const input = e.target as HTMLInputElement;
										if (input.value.length >= 10 && input.selectionStart === 10) e.preventDefault();
									}
								}}
								autoFocus
								className="form-input"
							/>
						</div>
						<div className="form-group">
							<label className="form-label">만료 시각</label>
							<input
								type="time"
								value={shareExpiresTime}
								onChange={(e) => onSetShareExpiresTime(e.target.value)}
								className="form-input"
							/>
						</div>
						<div className="form-group">
							<label className="form-label">다운로드 횟수 제한</label>
							<input
								type="number"
								min={1}
								step={1}
								value={shareMaxDownloads}
								onChange={(e) => onSetShareMaxDownloads(e.target.value)}
								placeholder="예: 3"
								className="form-input"
							/>
							<span className="form-hint">설정한 횟수만큼 다운로드되면 링크가 자동 만료됩니다.</span>
						</div>
						<div className="btn-row">
							<button className="btn btn-secondary" onClick={onCloseShareOptions}>
								취소
							</button>
							<button className="btn btn-primary" onClick={onShareConfirm}>
								확인
							</button>
						</div>
						{encryptError && <div className="status-bar error mt-3">{encryptError}</div>}
					</div>
				)}
				{encryptStatus && <div className="status-bar success mt-3">{encryptStatus}</div>}
				{encryptResultLink && (
					<div className="card mt-3">
						<h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>다운로드 링크 (Tor Onion)</h3>
						<input type="text" readOnly className="form-input" value={encryptResultLink} style={{ fontSize: "14px", marginTop: "4px" }} />
					</div>
				)}
				<div className="btn-row mt-3">
					<button className="btn btn-primary" onClick={onResetEncryptionForm}>
						처음으로
					</button>
				</div>
			</>
		);
	}

	return (
		<div className="view-animate" key={`enc-step-${encryptStep}`}>
			<StepDots total={4} current={encryptStep} />

			{encryptStep === 1 && (
				<>
					<h2 className="section-title">암호화</h2>
					<p className="section-desc">어떤 방식으로 데이터를 보호할까요?</p>
					<div className="option-cards">
						<button
							className="option-card"
							onClick={() => {
								onSetEncryptAuthMode("password");
								onSetEncryptStep(2);
							}}
						>
							<span className="option-title">🔑 비밀번호</span>
							<span className="option-desc">비밀번호를 아는 사람만 열 수 있어요.</span>
						</button>
						<button
							className="option-card"
							onClick={() => {
								onSetEncryptAuthMode("publickey");
								onSetEncryptStep(2);
							}}
						>
							<span className="option-title">👤 공개키</span>
							<span className="option-desc">지정한 상대방만 열 수 있도록 보호해요. 먼저 주소록에 상대방의 공개키를 등록해주세요.</span>
						</button>
					</div>
				</>
			)}

			{encryptStep === 2 && encryptAuthMode === "password" && (
				<>
					<h2 className="section-title">비밀번호 설정</h2>
					<p className="section-desc">암호화에 사용할 비밀번호를 입력하세요.</p>
					<div className="form-group">
						<label className="form-label">비밀번호</label>
						<input type="password" value={encryptPassword} onChange={(e) => onSetEncryptPassword(e.target.value)} placeholder="비밀번호 입력" autoFocus />
					</div>
					<div className="form-group">
						<label className="form-label">키 유도 방식</label>
						<div className="option-cards row-layout">
							<button className={`option-card ${encryptKdfMethod === "arg1" ? "selected" : ""}`} onClick={() => onSetEncryptKdfMethod("arg1")}>
								<span className="option-title">Argon2id</span>
								<span className="option-desc">높은 보안 강도 (추천)</span>
							</button>
							<button className={`option-card ${encryptKdfMethod === "pbk1" ? "selected" : ""}`} onClick={() => onSetEncryptKdfMethod("pbk1")}>
								<span className="option-title">PBKDF2</span>
								<span className="option-desc">호환성 우선</span>
							</button>
						</div>
					</div>
					<div className="btn-row">
						<button className="btn btn-secondary" onClick={() => onSetEncryptStep(1)}>
							이전
						</button>
						<button className="btn btn-primary" disabled={!encryptPassword} onClick={() => onSetEncryptStep(3)}>
							다음
						</button>
					</div>
				</>
			)}

			{encryptStep === 2 && encryptAuthMode === "publickey" && (
				<>
					<h2 className="section-title">수신자 설정</h2>
					<p className="section-desc">암호화된 데이터를 받을 사람을 선택하세요.</p>
					<div className="form-group">
						<label className="form-label">수신자</label>
						<select
							value={encryptRecipientId}
							onChange={(e) => {
								const value = e.target.value;
								onSetEncryptRecipientId(value);
								if (value) {
									const selected = contacts.find((c) => c.id === value);
									if (selected) {
										const detectedAlgo = detectPublicKeyAlgo(selected.publicKey);
										onSetEncryptAsymAlgo(detectedAlgo);
									}
								} else {
									onSetEncryptAsymAlgo(null);
								}
							}}
						>
							<option value="">연락처에서 선택...</option>
							{contacts.map((c) => (
								<option key={c.id} value={c.id}>
									{c.contactUsername}
								</option>
							))}
						</select>
						{contacts.length === 0 && <span className="text-hint">주소록에 연락처를 먼저 추가하세요.</span>}
					</div>
					<div className="form-group">
						<label className="form-label">비대칭 알고리즘</label>
						<div className="option-cards">
							<button className={`option-card ${encryptAsymAlgo === "pqc1" ? "selected" : ""}`} disabled>
								<span className="option-title">PQC</span>
								<span className="option-desc">양자내성 하이브리드</span>
								{encryptAsymAlgo === "pqc1" && <span className="option-badge">자동 선택</span>}
							</button>
							<button className={`option-card ${encryptAsymAlgo === "ecc1" ? "selected" : ""}`} disabled>
								<span className="option-title">Curve448</span>
								<span className="option-desc">높은 보안 강도 (추천)</span>
								{encryptAsymAlgo === "ecc1" && <span className="option-badge">자동 선택</span>}
							</button>
							<button className={`option-card ${encryptAsymAlgo === "rsa1" ? "selected" : ""}`} disabled>
								<span className="option-title">RSA-2048</span>
								<span className="option-desc">호환성 우선</span>
								{encryptAsymAlgo === "rsa1" && <span className="option-badge">자동 선택</span>}
							</button>
						</div>
						<span className="form-hint">상대방의 공개키 형식에 따라 자동으로 선택됩니다</span>
					</div>
					<label className="checkbox-row">
						<input
							type="checkbox"
							checked={encryptSignWithKey}
							onChange={(e) => onToggleSignWithKey(e.target.checked)}
							disabled={encryptBusy || webauthnAuthBusy}
						/>
						<div className="checkbox-label-with-help">
							<span className="checkbox-text">내 개인키로 서명하기</span>
							<div className="help-icon-wrapper">
								<svg
									className="help-icon"
									width="14"
									height="14"
									viewBox="0 0 24 24"
									fill="none"
									stroke="currentColor"
									strokeWidth="2"
									strokeLinecap="round"
									strokeLinejoin="round"
									onMouseEnter={() => onSetEncryptStatus(null)}
									onMouseLeave={() => onSetEncryptStatus(null)}
								>
									<circle cx="12" cy="12" r="10" />
									<path d="M12 16v-4M12 8h.01" />
								</svg>
								<div className="tooltip">
									내 개인키로 암호문에 서명하여 상대방은 이것이 진짜 나로부터 온 메시지임을 확인할 수 있어요.
								</div>
							</div>
						</div>
					</label>
					<div className="btn-row">
						<button className="btn btn-secondary" onClick={() => onSetEncryptStep(1)}>
							이전
						</button>
						<button className="btn btn-primary" disabled={!encryptRecipientId} onClick={() => onSetEncryptStep(3)}>
							다음
						</button>
					</div>
				</>
			)}

			{encryptStep === 3 && (
				<>
					<h2 className="section-title">암호화 방식</h2>
					<p className="section-desc">데이터를 암호화할 방식을 선택하세요.</p>
					<div className="option-cards">
						<button className="option-card" onClick={() => { onSetEncryptEncAlgo("gcm1"); onSetEncryptStep(4); }}>
							<span className="option-title">표준 (AES-GCM)</span>
							<span className="option-desc">일반적인 텍스트와 파일에 적합합니다</span>
						</button>
						<button className="option-card" onClick={() => { onSetEncryptEncAlgo("gcmx1"); onSetEncryptStep(4); }}>
							<span className="option-title">대용량 파일 전용 (AES-GCM 청크)</span>
							<span className="option-desc">대용량 파일을 효율적으로 처리합니다</span>
						</button>
					</div>
					<div className="btn-row">
						<button className="btn btn-secondary" onClick={() => onSetEncryptStep(2)}>
							이전
						</button>
					</div>
				</>
			)}

			{encryptStep === 4 && (
				<>
					<h2 className="section-title">데이터 입력</h2>
					<p className="section-desc">암호화할 내용을 입력하세요.</p>

					<div className="form-group">
						<label className="form-label">공개 메시지 (선택)</label>
						<input type="text" value={encryptMsg} onChange={(e) => onSetEncryptMsg(e.target.value)} placeholder="암호화 없이 표시되는 메시지" />
						<span className="form-hint">이 메시지는 복호화 없이도 볼 수 있어요</span>
					</div>

					<div className="tab-toggle">
						<button className={encryptMode === "text" ? "active" : ""} onClick={() => onEncryptionModeChange("text")}>
							텍스트
						</button>
						<button className={encryptMode === "file" ? "active" : ""} onClick={() => onEncryptionModeChange("file")}>
							파일
						</button>
					</div>

					{encryptMode === "text" ? (
						<div className="form-group">
							<label className="form-label">비밀 메시지</label>
							<textarea
								value={encryptSmsg}
								onChange={(e) => {
									onSetEncryptSmsg(e.target.value);
									onSetEncryptError(null);
								}}
								placeholder="암호화할 메시지 입력"
							/>
						</div>
					) : (
						<div className="form-group">
							<div
								className={`file-drop ${isFileDragActive ? "active" : ""}`}
								onDragEnter={onFileDragEnter}
								onDragOver={onFileDragOver}
								onDragLeave={onFileDragLeave}
								onDrop={onFileDrop}
							>
								<input id="encrypt-file" type="file" onChange={onEncryptFileChange} disabled={encryptBusy} className="sr-only" />
								<label htmlFor="encrypt-file" style={{ cursor: "pointer" }}>
									<div className="file-drop-icon">📁</div>
									<p className="file-drop-text">파일을 끌어놓거나 클릭하세요</p>
									<p className="file-drop-hint">브라우저에서 암호화됩니다</p>
								</label>
							</div>
							{encryptFile && (
								<div className="file-info-bar">
									<div>
										<span className="file-info-name">{encryptFile.name}</span>
										<span className="file-info-size"> · {formatBytes(encryptFile.size)}</span>
									</div>
									<button className="btn-ghost btn-sm" onClick={() => onApplySelectedEncryptFile(null)}>
										제거
									</button>
								</div>
							)}
						</div>
					)}

					{encryptError && <div className="status-bar error">{encryptError}</div>}
					{encryptBusy && (
						<div className="progress-bar">
							<div className="progress-fill" />
						</div>
					)}

					<div className="btn-row">
						<button className="btn btn-secondary" onClick={() => onSetEncryptStep(3)}>
							이전
						</button>
						<button className="btn btn-primary" disabled={encryptBusy} onClick={onEncryptSubmit}>
							{encryptBusy ? "암호화 중..." : "암호화"}
						</button>
					</div>
				</>
			)}
		</div>
	);
};
