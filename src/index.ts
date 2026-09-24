export async function hmacSha1({ key, msg }: {
	key: Uint8Array<ArrayBuffer>;
	msg: Uint8Array<ArrayBuffer>;
}) {
	if (key.length > 64) {
		key = await hash(key);
	}

	if (key.length < 64) {
		const padded = new Uint8Array(64);
		padded.set(key, 0);
		key = padded;
	}

	const oKeyPad = new Uint8Array(key);
	const iKeyPad = new Uint8Array(key);
	for (let i = 0; i < key.length; i++) {
		oKeyPad[i]! ^= 0x5c;
		iKeyPad[i]! ^= 0x36;
	}

	const iPre = new Uint8Array(key.length + msg.length);
	iPre.set(iKeyPad, 0);
	iPre.set(msg, key.length);
	const iImg = await hash(iPre);

	const oPre = new Uint8Array(key.length + iImg.length);
	oPre.set(oKeyPad, 0);
	oPre.set(iImg, key.length);
	const oImg = await hash(oPre);

	return oImg;

	async function hash(it: BufferSource): Promise<Uint8Array<ArrayBuffer>> {
		return new Uint8Array(await crypto.subtle.digest('SHA-1', it));
	}
}

export async function hotp({ key, ctr, length }: {
	key: Uint8Array<ArrayBuffer>;
	ctr: bigint;
	length: number;
}): Promise<string> {
	const msg = new Uint8Array(8);
	new DataView(msg.buffer).setBigUint64(0, ctr, /* le?: */ false);

	const mac = await hmacSha1({ key, msg });

	const offset = mac[mac.length - 1]! & 0xf;
	const truncated = mac.slice(offset, offset + 4);
	truncated[0]! &= 0x7f;

	const value =
		new DataView(truncated.buffer).getUint32(0, /* le?: */ false) %
		10 ** length;

	return value.toString().padStart(length, '0');
}

export async function totp({ key, periodMs = 30_000n, length }: {
	key: Uint8Array<ArrayBuffer>;
	periodMs?: bigint;
	length: number;
}): Promise<string> {
	const ctr = BigInt(new Date().getTime()) / periodMs;
	return await hotp({ key, ctr, length });
}

// https://datatracker.ietf.org/doc/html/rfc4648#section-6
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encode RFC 4648 Base32 (https://www.rfc-editor.org/info/rfc4648/#section-6)
 * without padding. This is the format that HOTP and TOTP implementations expect
 * the shared secret to be in.
 */
export function b32encode(buf: Uint8Array<ArrayBuffer>): string {
	const bufLen = BigInt(buf.length);
	const outLen = bufLen / 5n * 8n +
		[0n, 2n, 4n, 5n, 7n][Number(bufLen % 5n)]!;

	const out = new Uint8Array(Number(outLen));
	let outIdx = 0n;
	for (let byteIdx = 0; byteIdx < buf.length; byteIdx++) {
		for (let bitIdx = 0; bitIdx < 8; bitIdx++) {
			const bit = !!((buf[byteIdx]! << bitIdx) & 0b1000_0000);
			if (bit) {
				const outByteIdx = Number(outIdx / 5n);
				const outBitIdx = outIdx % 5n;
				out[outByteIdx]! |= 1 << (4 - Number(outBitIdx));
			}
			outIdx++;
		}
	}

	let outStr = '';
	for (const el of out) {
		outStr += B32_ALPHABET[el]!;
	}
	return outStr;
}

/**
 * Decode RFC 4648 Base32 (https://www.rfc-editor.org/info/rfc4648/#section-6)
 * without padding. This is the format that HOTP and TOTP implementations expect
 * the shared secret to be in.
 */
export function b32decode(encoded: string): Uint8Array<ArrayBuffer> {
	const encLen = BigInt(encoded.length);
	const remainder =
		[0n, null, 1n, null, 2n, 3n, null, 4n][Number(encLen % 8n)]!;
	if (remainder === null) {
		throw new Error('Invalid Base32 encoded string length');
	}
	const decLen = encLen / 8n * 5n + remainder;

	const decoded = new Uint8Array(Number(decLen));
	let decIdx = 0n;
	for (const encCh of encoded) {
		const encEl = B32_ALPHABET.indexOf(encCh);
		if (encEl === -1) {
			throw new Error(
				`Invalid Base32 character: ${JSON.stringify(encCh)}`,
			);
		}
		for (let i = 0; i < 5; i++) {
			const bit = !!((encEl >> (4 - i)) & 1);
			const decByteIdx = Number(decIdx / 8n);
			if (decByteIdx >= decoded.length && bit) {
				throw new Error(
					'Invalid Base32 encoding: out-of-bounds bits must be zero',
				);
			}
			if (bit) {
				const decBitIdx = decIdx % 8n;
				decoded[decByteIdx]! |= 1 << (7 - Number(decBitIdx));
			}
			decIdx++;
		}
	}

	return decoded;
}
