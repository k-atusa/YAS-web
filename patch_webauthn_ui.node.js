const fs = require('fs');

let content = fs.readFileSync('frontend/src/App.tsx', 'utf-8');

// modify doWebauthnSignupFlow
content = content.replace(
`\t\t\tsetStatus("패스키 등록 완료. 개인키를 생성합니다...");
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
\t\t\tsetShowKeySection(false);`,
`\t\t\tsetWebauthnPending(null);`
);

// modify doWebauthnLoginFlow
content = content.replace(
`\t\t\t\t\tsetStoredAccount(account);
\t\t\t\t}
\t\t\t\tsetStatus("로그인 및 키 복호화가 완료되었습니다.");
\t\t\t\tsetWebauthnPending(null);
\t\t\t\tsetShowKeySection(false);`,
`\t\t\t\t\tsetStoredAccount(account);
\t\t\t\t}
\t\t\t\tsetStatus(null);
\t\t\t\tsetWebauthnPending(null);
\t\t\t\tsetShowKeySection(false);`
);

// also let's check the text inside the button
content = content.replace(
`{webauthnPending === "register" ? "패스키 생성 및 계정 설정 완료하기" : "패스키로 인증하기"}`,
`{webauthnPending === "register" ? "패스키 등록 완료하기" : "패스키로 인증하기"}`
);

fs.writeFileSync('frontend/src/App.tsx', content);
