import type { FormEvent } from "react";

type AuthView = "landing" | "login" | "signup";

type AuthScreenProps = {
	view: AuthView;
	setView: (view: AuthView) => void;
	error: string | null;
	setError: (value: string | null) => void;
	loginUsername: string;
	setLoginUsername: (value: string) => void;
	loginPass: string;
	setLoginPass: (value: string) => void;
	loginPassConfirm: string;
	setLoginPassConfirm: (value: string) => void;
	loginBusy: boolean;
	canLogin: boolean;
	onLogin: (e: FormEvent) => void;
	onSignup: (e: FormEvent) => void;
};

export const AuthScreen = ({
	view,
	setView,
	error,
	setError,
	loginUsername,
	setLoginUsername,
	loginPass,
	setLoginPass,
	loginPassConfirm,
	setLoginPassConfirm,
	loginBusy,
	canLogin,
	onLogin,
	onSignup,
}: AuthScreenProps) => {
	if (view === "login") {
		return (
			<div className="auth-page" key="login">
				<div className="auth-card view-animate">
					<h1 className="auth-title">로그인</h1>
					<form className="auth-form" onSubmit={onLogin}>
						<div className="form-group">
							<label className="form-label">아이디</label>
							<input
								type="text"
								value={loginUsername}
								onChange={(e) => setLoginUsername(e.target.value)}
								placeholder="아이디 입력"
								autoComplete="username"
							/>
						</div>
						<div className="form-group">
							<label className="form-label">비밀번호</label>
							<input
								type="password"
								value={loginPass}
								onChange={(e) => setLoginPass(e.target.value)}
								placeholder="비밀번호 입력"
								autoComplete="current-password"
							/>
						</div>
						{error && <div className="status-bar error">{error}</div>}
						<button type="submit" className="btn btn-primary btn-full" disabled={!canLogin || loginBusy}>
							{loginBusy ? "로그인 중..." : "로그인"}
						</button>
					</form>
					<p className="auth-hint">
						<button
							onClick={() => {
								setView("landing");
								setError(null);
							}}
						>
							← 돌아가기
						</button>
					</p>
				</div>
			</div>
		);
	}

	if (view === "signup") {
		return (
			<div className="auth-page" key="signup">
				<div className="auth-card view-animate">
					<h1 className="auth-title">회원가입</h1>
					<form className="auth-form" onSubmit={onSignup}>
						<div className="form-group">
							<label className="form-label">아이디</label>
							<input
								type="text"
								value={loginUsername}
								onChange={(e) => setLoginUsername(e.target.value)}
								placeholder="사용할 아이디"
								autoComplete="username"
							/>
						</div>
						<div className="form-group">
							<label className="form-label">비밀번호</label>
							<input
								type="password"
								value={loginPass}
								onChange={(e) => setLoginPass(e.target.value)}
								placeholder="비밀번호 입력"
								autoComplete="new-password"
							/>
						</div>
						<div className="form-group">
							<label className="form-label">비밀번호 확인</label>
							<input
								type="password"
								value={loginPassConfirm}
								onChange={(e) => setLoginPassConfirm(e.target.value)}
								placeholder="비밀번호 다시 입력"
								autoComplete="new-password"
							/>
						</div>
						{error && <div className="status-bar error">{error}</div>}
						<button type="submit" className="btn btn-primary btn-full" disabled={!canLogin || loginBusy}>
							{loginBusy ? "처리 중..." : "가입하기"}
						</button>
					</form>
					<p className="auth-hint">
						<button
							onClick={() => {
								setView("landing");
								setError(null);
							}}
						>
							← 돌아가기
						</button>
					</p>
				</div>
			</div>
		);
	}

	return (
		<div className="landing" key="landing">
			<div className="view-animate">
				<h1 className="brand">
					Yet<br />Another<br />Security
				</h1>
			</div>
			<div className="landing-buttons view-animate">
				<button
					className="btn btn-primary btn-full"
					onClick={() => {
						setView("login");
						setError(null);
						setLoginUsername("");
						setLoginPass("");
					}}
				>
					로그인
				</button>
				<button
					className="btn btn-secondary btn-full"
					onClick={() => {
						setView("signup");
						setError(null);
						setLoginUsername("");
						setLoginPass("");
						setLoginPassConfirm("");
					}}
				>
					회원가입
				</button>
			</div>
		</div>
	);
};
