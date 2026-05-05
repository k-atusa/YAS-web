import type { FormEvent } from "react";

export type ContactFormState = { contactUsername: string; notes: string };

type ContactModalProps = {
	isOpen: boolean;
	isClosing: boolean;
	mode: "add" | "edit";
	contactForm: ContactFormState;
	setContactForm: (next: ContactFormState | ((prev: ContactFormState) => ContactFormState)) => void;
	contactModalError: string | null;
	contactBusy: boolean;
	onClose: () => void;
	onSubmit: (e: FormEvent) => void;
	showUsernameTooltip: boolean;
	setShowUsernameTooltip: (value: boolean) => void;
};

export const ContactModal = ({
	isOpen,
	isClosing,
	mode,
	contactForm,
	setContactForm,
	contactModalError,
	contactBusy,
	onClose,
	onSubmit,
	showUsernameTooltip,
	setShowUsernameTooltip,
}: ContactModalProps) => {
	if (!isOpen && !isClosing) return null;

	return (
		<div
			className={`modal-overlay ${isClosing ? "closing" : ""}`}
			onClick={(e) => {
				if (e.target === e.currentTarget) onClose();
			}}
		>
			<div className={`modal-box ${isClosing ? "closing" : ""}`}>
				<h3 className="modal-title">{mode === "add" ? "연락처 추가" : "연락처 수정"}</h3>
				<form onSubmit={onSubmit}>
					<div className="form-group">
						<label className="form-label">
							사용자 아이디
							<div className="help-icon-wrapper">
								<svg
									className="help-icon"
									width="16"
									height="16"
									viewBox="0 0 24 24"
									fill="none"
									stroke="currentColor"
									strokeWidth="2"
									strokeLinecap="round"
									strokeLinejoin="round"
									onMouseEnter={() => setShowUsernameTooltip(true)}
									onMouseLeave={() => setShowUsernameTooltip(false)}
									onClick={() => setShowUsernameTooltip(!showUsernameTooltip)}
								>
									<circle cx="12" cy="12" r="10" />
									<path d="M12 16v-4M12 8h.01" />
								</svg>
								{showUsernameTooltip && (
									<div className="tooltip">
										상대방이 서비스에 가입할 때 사용한 실제 아이디(username)를 정확히 입력해야 합니다.
									</div>
								)}
							</div>
						</label>
						<input
							type="text"
							value={contactForm.contactUsername}
							onChange={(e) => setContactForm((prev) => ({ ...prev, contactUsername: e.target.value }))}
							placeholder="아이디"
							required
						/>
					</div>
					<div className="form-group">
						<label className="form-label">메모 (선택)</label>
						<input
							type="text"
							value={contactForm.notes}
							onChange={(e) => setContactForm((prev) => ({ ...prev, notes: e.target.value }))}
							placeholder="간단한 메모"
						/>
					</div>
					{contactModalError && <div className="status-bar error">{contactModalError}</div>}
					<div className="modal-footer">
						<button type="button" className="btn btn-ghost" onClick={onClose}>
							취소
						</button>
						<button type="submit" className="btn btn-primary" disabled={contactBusy || !contactForm.contactUsername.trim()}>
							{contactBusy ? "저장 중..." : mode === "add" ? "저장" : "수정"}
						</button>
					</div>
				</form>
			</div>
		</div>
	);
};
