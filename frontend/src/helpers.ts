import type { AsymAlgo } from "./crypto";

export const formatBytes = (bytes: number): string => {
	if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
	const units = ["B", "KB", "MB", "GB", "TB"];
	let value = bytes;
	let idx = 0;
	while (value >= 1024 && idx < units.length - 1) {
		value /= 1024;
		idx += 1;
	}
	const digits = value < 10 && idx > 0 ? 1 : 0;
	return `${value.toFixed(digits)} ${units[idx]}`;
};

export const truncateKey = (key: string): string => {
	if (key.length <= 15) return key;
	return `${key.slice(0, 6)}…${key.slice(-6)}`;
};

export const maskKey = (keyPem: string): string => {
	if (!keyPem) return "";
	if (keyPem.length <= 150) return keyPem;

	const firstPart = keyPem.substring(0, 60).trim();
	const lastPart = keyPem.substring(keyPem.length - 60).trim();

	return `${firstPart}\n\n... [ ${(keyPem.length - 120).toLocaleString()}자 생략됨 ] ...\n\n${lastPart}`;
};

export const detectPublicKeyAlgo = (_publicKeyB64: string): AsymAlgo => {
	return "pqc1";
};

export const detectPrivateKeyAlgo = (_privateKeyB64: string): AsymAlgo => {
	return "pqc1";
};
