const fetch = require('node-fetch');
fetch('http://localhost:7001/api/files/upload', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ filename: 'test', encryptedData: 'base64', expiresAt: 'expires' })
}).then(r => r.json()).then(console.log);
