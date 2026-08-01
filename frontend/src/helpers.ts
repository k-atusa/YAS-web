import { base64ToU8 } from "./crypto";
import type { AsymAlgo } from "./crypto";

export const get24HoursLater = () => {
	const d = new Date(Date.now() + 24 * 60 * 60 * 1000);
	const pad = (n: number) => n.toString().padStart(2, "0");
	return {
		dateStr: `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`,
		timeStr: `${pad(d.getHours())}:${pad(d.getMinutes())}`
	};
};

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

export const detectPublicKeyAlgo = (publicKeyB64: string): AsymAlgo => {
	try {
		const u8 = base64ToU8(publicKeyB64);
		// PQC1 public key is exactly 4273 bytes
		if (u8.length === 4273) return "pqc1";
		// Curve448 public key is exactly 113 bytes
		if (u8.length === 113) return "ecc1";
		// Default to ecc1 (only remaining option)
		return "ecc1";
	} catch {
		return "ecc1";
	}
};

export const detectPrivateKeyAlgo = (privateKeyB64: string): AsymAlgo => {
	try {
		const u8 = base64ToU8(privateKeyB64);
		// PQC1 private key is exactly 8177 bytes
		if (u8.length === 8177) return "pqc1";
		// Curve448 private key is exactly 113 bytes
		if (u8.length === 113) return "ecc1";
		// Default to ecc1
		return "ecc1";
	} catch {
		return "ecc1";
	}
};
