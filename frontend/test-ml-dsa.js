import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const { publicKey, secretKey } = ml_dsa87.keygen();
const msg = new Uint8Array([1, 2, 3]);

try {
  // Test 3: sign(secretKey, msg) and verify(sig, msg, publicKey)
  const sig = ml_dsa87.sign(secretKey, msg);
  const v = ml_dsa87.verify(sig, msg, publicKey);
  if (v) console.log('Order: sign(secretKey, msg) and verify(sig, msg, publicKey) succeeded');
} catch (e) {
  console.log('Test 3 failed:', e.message);
}

try {
  // Test 4: sign(msg, secretKey) and verify(sig, msg, publicKey)
  const sig = ml_dsa87.sign(msg, secretKey);
  const v = ml_dsa87.verify(sig, msg, publicKey);
  if (v) console.log('Order: sign(msg, secretKey) and verify(sig, msg, publicKey) succeeded');
} catch (e) {
  console.log('Test 4 failed:', e.message);
}
