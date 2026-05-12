const fs = require('fs');

let content = fs.readFileSync('frontend/src/App.tsx', 'utf-8');

const anchor = '/* ─── Main layout ─── */';

const uiCode = `
\tasync function doWebauthnSignupFlow() {
\t\ttry {
\t\t\tsetWebauthnAuthBusy(true);
\t\t\tsetError(null);
\t\t\tconst optionsResp = await getWebAuthnRegisterOptions(authToken!);
\t\t\tconst registration = await registerWebAuthnCredential({
\t\t\t\tchallenge: optionsResp.options.challenge, rp: optionsResp.options.rp, user: optionsResp.options.user,
\t\t\t\tpubKeyCredParams: optionsResp.options.pubKeyCredParams, timeout: optionsResp.options.timeout,
\t\t\t\tattestation: optionsResp.options.attestation, authenticatorSelection: optionsResp.options.authenticatorSelection,
\t\t\t});
\t\t\tawait verifyWebAuthnRegistration(authToken!, registration.credentialId, registration.publicKey, registration.counter, registration.transports);
\t\t\t
\t\t\tsetStatus("패스키 등록 완료. 개인키를 생성합니다...");
\t\t\tconst { publicKey, privateKey } = await generateKeyPair(keyAlgo);
\t\t\tsetPublicKeyPem(publicKey);
\t\t\tsetPrivateKeyPem(privateKey);
\t\t\t
\t\t\tconst payload = await buildAccountPayload(authUsername!, publicKey, privateKey, undefined);
\t\t\tconst result = await saveAccount(payload, authToken!);
\t\t\tconst record = { ...payload, id: result.id, createdAt: result.createdAt };
\t\t\tsetStoredAccount(record);
\t\t\t
\t\t\tsetStatus("가입 및 키 생성이 완료되었습니다.");
\t\t\tsetWebauthnPending(null);
\t\t\tsetShowKeySection(false);
\t\t} catch (err) {
\t\t\tsetError((err as Error).message);
\t\t} finally {
\t\t\tsetWebauthnAuthBusy(false);
\t\t}
\t}

\tasync function doWebauthnLoginFlow() {
\t\ttry {
\t\t\tsetWebauthnAuthBusy(true);
\t\t\tsetError(null);
\t\t\tconst optionsResp = await getWebAuthnAuthenticateOptions(authToken!);
\t\t\tconst authentication = await authenticateWithWebAuthn({
\t\t\t\tchallenge: optionsResp.options.challenge, allowCredentials: optionsResp.options.allowCredentials || [],
                timeout: optionsResp.options.timeout, userVerification: optionsResp.options.userVerification,
\t\t\t});
\t\t\tconst verifyResp = await verifyWebAuthnAuthentication(authToken!, authentication.credentialId, authentication.counter);
\t\t\t
\t\t\tsetStatus("패스키 인증 완료. 개인키를 복호화 합니다...");
\t\t\tconst decResp = await decryptStoredPrivateKey(authUsername!, verifyResp.token);
\t\t\tsetPrivateKeyPem(decResp.privateKey);
\t\t\t
\t\t\tconst account = await getAccountByUsername(authUsername!, authToken!);
\t\t\tif (account) {
\t\t\t\tsetPublicKeyPem(account.publicKey);
\t\t\t\tsetStoredAccount(account);
\t\t\t}
\t\t\tsetStatus("로그인 및 키 복호화가 완료되었습니다.");
\t\t\tsetWebauthnPending(null);
\t\t\tsetShowKeySection(false);
\t\t} catch (err) {
\t\t\tsetError((err as Error).message);
\t\t} finally {
\t\t\tsetWebauthnAuthBusy(false);
\t\t}
\t}

\tif (webauthnPending) {
\t\treturn (
\t\t\t<div className="auth-page" key="webauthn">
\t\t\t\t<div className="auth-card view-animate">
\t\t\t\t\t<h1 className="auth-title">{webauthnPending === "register" ? "패스키 등록" : "패스키 인증"}</h1>
\t\t\t\t\t<p className="section-desc">
\t\t\t\t\t\t{webauthnPending === "register" 
\t\t\t\t\t\t\t? "계정 보호를 위해 사용할 기기의 생체 인식(지문/Face ID)이나 패스키를 등록합니다. 이 패스키로 회원님의 개인키가 자동으로 생성 및 보호됩니다." 
\t\t\t\t\t\t\t: "본인 확인 및 개인키 복호화를 위해 패스키 인증이 필요합니다."}
\t\t\t\t\t</p>
\t\t\t\t\t
\t\t\t\t\t{error && <div className="status-bar error">{error}</div>}
\t\t\t\t\t{(status || webauthnAuthBusy) && <div className="status-bar">{status || "처리 중..."}</div>}
\t\t\t\t\t
\t\t\t\t\t<button className="btn btn-primary btn-full mt-4" 
\t\t\t\t\t\tdisabled={webauthnAuthBusy}
\t\t\t\t\t\tonClick={webauthnPending === "register" ? doWebauthnSignupFlow : doWebauthnLoginFlow}>
\t\t\t\t\t\t{webauthnPending === "register" ? "패스키 생성 및 계정 설정 완료하기" : "패스키로 인증하기"}
\t\t\t\t\t</button>
                    <p className="auth-hint">
                            <button onClick={handleSignOut}>로그아웃</button>
                    </p>
\t\t\t\t</div>
\t\t\t</div>
\t\t);
\t}

`;

if (!content.includes('if (webauthnPending) {')) {
  content = content.replace(anchor, uiCode + anchor);
  fs.writeFileSync('frontend/src/App.tsx', content);
  console.log("Patched WebAuthn UI");
} else {
  console.log("Already patched");
}
