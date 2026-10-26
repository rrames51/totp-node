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

/**
 * Returns the expected HOTP value for the given key, counter, and length. Does
 * not check a given token; the user is expected to perform the comparison
 * themselves.
 *
 * @see {@link totp} - Performs the same calculation but based on the current
 * time rather than a counter.
 * @see {@link checkTotp} - Checks a given TOTP token against the expected value
 * with an optional grace period.
 */
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

/**
 * Returns the expected TOTP value for the given key, period, and length. Does
 * not check a given token; the user is expected to perform the comparison
 * themselves.
 *
 * @see {@link hotp} - Performs the same calculation but based on a counter
 * rather than the current time.
 * @see {@link checkTotp} - Checks a given TOTP token against the expected value
 * with an optional grace period.
 */
export async function totp({ key, periodMs = 30_000n, length }: {
	key: Uint8Array<ArrayBuffer>;
	periodMs?: bigint;
	length: number;
}): Promise<string> {
	const ctr = BigInt(new Date().getTime()) / periodMs;
	return await hotp({ key, ctr, length });
}

/**
 * Checks a given TOTP token against the expected value for the current time,
 * allowing for an optional grace period. If a time other than `BigInt(new
 * Date().getTime())` is desired, it can be provided via the `nowMs` parameter.
 *
 * The first parameter (`token`) is the user-provided TOTP token to check, and
 * should be the only field the user can control. The second parameter is an
 * object containing all other parameters, and must be controlled by the library
 * consumer.
 *
 * @returns The timestamp of the next valid period if the token is valid, or
 * null if it is not. Some applications may wish to use this value to prevent
 * replay attacks, by ensuring that tokens are only accepted once per period.
 *
 * @example
 *
 * ```ts
 * const token = '123456';
 * const result1 = await checkTotp(token, { key, length: 6 });
 * if (result1 === null) {
 *     throw new Error('Invalid TOTP token');
 * }
 * const result2 =
 *     await checkTotp(token, { key, length: 6, cutoffMs: result1 });
 * if (result2 !== null) {
 *     throw new Error('Replay attack succeeded');
 * }
 * console.log('Replay attack thwarted');
 * ```
 */
export async function checkTotp(token: string, {
	key,
	nowMs,
	cutoffMs,
	periodMs = 30_000n,
	gracePeriodMs = 0n,
	length,
}: {
	key: Uint8Array<ArrayBuffer>;
	nowMs?: bigint;
	cutoffMs?: bigint;
	periodMs?: bigint;
	gracePeriodMs?: bigint;
	length: number;
}): Promise<bigint | null> {
	/* istanbul ignore next */
	const now = nowMs ?? BigInt(new Date().getTime());

	// start should be the start of the first period that is within the grace
	// period and after the specified cutoff (if any).
	let start = (now - gracePeriodMs) / periodMs * periodMs;
	if (cutoffMs !== undefined) {
		start = bigintMax(start, ceilDiv(cutoffMs, periodMs) * periodMs);
	}

	const end = now + gracePeriodMs;

	let result = null;
	for (let t = start; t <= end; t += periodMs) {
		const ctr = t / periodMs;
		const expected = await hotp({ key, ctr, length });
		if (expected === token && result === null) {
			result = t + periodMs;
		}
	}
	return result;
}

export function ceilDiv(a: bigint, b: bigint): bigint {
	const remainder = a % b;
	if (remainder === 0n) {
		return a / b;
	}
	return a / b + 1n;
}

export function bigintMax(a: bigint, b: bigint): bigint {
	return a > b ? a : b;
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
	// dprint-ignore
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
