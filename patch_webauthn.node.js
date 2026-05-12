const fs = require('fs');

let content = fs.readFileSync('frontend/src/App.tsx', 'utf-8');

// 1. Add webauthnPending state
content = content.replace(
  'const [webauthnAuthBusy, setWebauthnAuthBusy] = useState(false);',
  'const [webauthnAuthBusy, setWebauthnAuthBusy] = useState(false);\n\tconst [webauthnPending, setWebauthnPending] = useState<"register" | "authenticate" | null>(null);'
);

// 2. Modify handleLogin
content = content.replace(
  'setAuthUsername(result.user.username);',
  'setAuthUsername(result.user.username);\n\t\t\tsetWebauthnPending("authenticate");'
);

// 3. Modify handleSignup (wait, we need to make sure we only match the one inside handleSignup)
content = content.replace(
  'setAuthToken(result.token);\n\t\t\tsetAuthUsername(result.user.username);\n\t\t} catch (err) {\n\t\t\tsetError((err as Error).message || "회원가입에 실패했습니다");',
  'setAuthToken(result.token);\n\t\t\tsetAuthUsername(result.user.username);\n\t\t\tsetWebauthnPending("register");\n\t\t} catch (err) {\n\t\t\tsetError((err as Error).message || "회원가입에 실패했습니다");'
);

// 4. Modify handleSignOut
content = content.replace(
  'setAuthUsername(null);',
  'setAuthUsername(null);\n\t\tsetWebauthnPending(null);'
);

// 5. In useEffect for loadStored (refresh restoring)
content = content.replace(
  'setStoredAccount(record);\n\t\t\t\t\t\t\t\t\tsetShowKeySection(!record);\n\t\t\t\t\t\t\t\t\tif (record) { setPublicKeyPem(record.publicKey); setStatus(null); }',
  'setStoredAccount(record);\n\t\t\t\t\t\t\t\t\tsetShowKeySection(!record);\n\t\t\t\t\t\t\t\t\tif (record) { setPublicKeyPem(record.publicKey); setStatus(null); setWebauthnPending("authenticate"); }'
);

// 6. Rewrite startWebAuthnRegistration to automatically generate keys on success!
// And authenticateWithWebAuthn to pull the keys!
fs.writeFileSync('frontend/src/App.tsx', content);
