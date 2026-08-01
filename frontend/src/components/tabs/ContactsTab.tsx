import { detectPublicKeyAlgo } from "../../helpers";
import type { ContactRecord } from "../../types";

type ContactsTabProps = {
	contacts: ContactRecord[];
	contactError: string | null;
	contactsLoading: boolean;
	copyPublicStatus: "idle" | "copied" | "error";
	onCopyPublicKey: (value?: string) => void;
	onOpenAdd: () => void;
	onOpenEdit: (contact: ContactRecord) => void;
	onDelete: (id: string) => void;
};

export const ContactsTab = ({
	contacts,
	contactError,
	contactsLoading,
	copyPublicStatus,
	onCopyPublicKey,
	onOpenAdd,
	onOpenEdit,
	onDelete,
}: ContactsTabProps) => (
	<>
		<div className="section-header">
			<h2 className="section-title">주소록</h2>
			<button className="btn btn-secondary btn-sm" onClick={onOpenAdd}>
				+ 추가
			</button>
		</div>
		<p className="section-desc">상대방의 공개키를 관리하여 안전하게 암호화된 메시지를 주고받으세요.</p>

		{contactError && <div className="status-bar error">{contactError}</div>}

		{contactsLoading ? (
			<p className="text-hint text-center mt-4">불러오는 중...</p>
		) : contacts.length === 0 ? (
			<div className="empty-state">
				<p>저장된 연락처가 없습니다</p>
				<p className="text-hint">연락처를 추가하면 공개키 암호화를 시작할 수 있어요.</p>
			</div>
		) : (
			<div className="contact-list">
				{contacts.map((c) => (
					<div key={c.id} className="contact-row">
						<div className="contact-info">
							<div className="contact-name-row">
								<span className="contact-name">{c.contactUsername}</span>
								<span className={`contact-algo-badge algo-${detectPublicKeyAlgo(c.publicKey)}`}>
									{detectPublicKeyAlgo(c.publicKey) === "pqc1" ? "PQC" : detectPublicKeyAlgo(c.publicKey) === "ecc1" ? "ECC" : "RSA"}
								</span>
							</div>
							{c.notes && (
								<div className="contact-meta-row">
									<span className="contact-note">{c.notes}</span>
								</div>
							)}
						</div>
						<div className="contact-btns">
							<span className="contact-pk-preview" style={{ marginRight: "12px", opacity: 0.6 }}>
								{c.publicKey && c.publicKey.length > 20 ? `${c.publicKey.slice(0, 6)}…${c.publicKey.slice(-5)}` : c.publicKey}
							</span>
							<button
								className={`btn-ghost btn-sm ${copyPublicStatus === "copied" ? "copy-feedback" : ""}`}
								onClick={() => onCopyPublicKey(c.publicKey)}
							>
								{copyPublicStatus === "copied" ? "✓ 복사됨" : "복사"}
							</button>
							<button className="btn-ghost btn-sm" onClick={() => onOpenEdit(c)}>
								수정
							</button>
							<button className="btn-ghost btn-sm btn-danger" onClick={() => onDelete(c.id)}>
								삭제
							</button>
						</div>
					</div>
				))}
			</div>
		)}
	</>
);
