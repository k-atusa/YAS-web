type MessagesTabProps = {
	inboxFiles: any[];
	decryptedTorLinks: Record<string, string>;
	copiedTorFileId: string | null;
	decryptTorLoadingId: string | null;
	onRefresh: () => void;
	onCopyTorLink: (fileId: string, value?: string) => void;
	onUnlockTorDomain: (fileId: string) => void;
};

export const MessagesTab = ({
	inboxFiles,
	decryptedTorLinks,
	copiedTorFileId,
	decryptTorLoadingId,
	onRefresh,
	onCopyTorLink,
	onUnlockTorDomain,
}: MessagesTabProps) => (
	<>
		<div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
			<h2 className="section-title" style={{ margin: 0 }}>메시지함</h2>
			<button
				className="btn btn-secondary btn-sm"
				onClick={onRefresh}
				style={{ display: "flex", gap: "6px", alignItems: "center" }}
			>
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
					<polyline points="23 4 23 10 17 10"></polyline>
					<polyline points="1 20 1 14 7 14"></polyline>
					<path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
				</svg>
				새로고침
			</button>
		</div>
		<p className="section-desc" style={{ marginTop: "10px" }}>수신된 암호화 파일 목록입니다.</p>
		{inboxFiles.length === 0 ? (
			<div className="status-bar info">수신된 파일이 없습니다.</div>
		) : (
			<div className="card" style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
				{inboxFiles.map((f: any) => {
					const decryptedLink = decryptedTorLinks[f._id];
					return (
						<div key={f._id} style={{ borderBottom: "1px solid var(--border)", paddingBottom: "14px" }}>
							<div style={{ fontWeight: "bold", marginBottom: "7px" }}>파일명: {f.filename}</div>
							<div style={{ fontSize: "13px", color: "var(--text-sub)" }}>만료시간: {new Date(f.expiresAt).toLocaleString()}</div>
							<div style={{ fontSize: "13px", color: "var(--text-sub)", marginTop: "5px" }}>
								다운로드 횟수: {Number(f.downloadCount ?? 0)} / {Number(f.maxDownloads ?? 1)}
							</div>
							<div style={{ marginTop: "10px" }}>
								<label style={{ fontSize: "12px" }}>오니온 링크 (Tor)</label>
								<div style={{ display: "flex", gap: "8px", marginTop: "4px", alignItems: "center" }}>
									{decryptedLink ? (
										<>
											<input type="text" readOnly className="form-input" value={decryptedLink} style={{ fontSize: "11px", marginTop: 0 }} />
											<button className="btn btn-secondary btn-sm" onClick={() => { void onCopyTorLink(f._id, decryptedLink); }}>
												{copiedTorFileId === f._id ? "복사됨" : "복사"}
											</button>
										</>
									) : (
										<>
											<input type="password" readOnly className="form-input" value="••••••••••••••••••••••••••••••••" style={{ fontSize: "11px", marginTop: 0 }} />
											<button className="btn btn-primary btn-sm" onClick={() => onUnlockTorDomain(f._id)} disabled={decryptTorLoadingId === f._id}>
												{decryptTorLoadingId === f._id ? "해제 중..." : "🔐 잠금 해제"}
											</button>
										</>
									)}
								</div>
							</div>
						</div>
					);
				})}
			</div>
		)}
	</>
);
