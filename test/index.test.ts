import jsc from 'jsverify';
import { describe, expect, it } from 'vitest';

import * as totp from '../src';

describe('hmacSha1', () => {
	it('should compute HMAC SHA-1 correctly', async () => {
		// https://datatracker.ietf.org/doc/html/rfc2202
		const testCases = [{
			key: repeat(0x0b, 20),
			msg: new TextEncoder().encode('Hi There'),
			expected: 'b617318655057264e28bc0b6fb378c8ef146be00',
		}, {
			key: new TextEncoder().encode('Jefe'),
			msg: new TextEncoder().encode('what do ya want for nothing?'),
			expected: 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79',
		}, {
			key: repeat(0xaa, 20),
			msg: repeat(0xdd, 50),
			expected: '125d7342b9ac11cd91a39af48aa17b4f63f175d3',
		}, {
			key: hexDecode(
				'0102030405060708090a0b0c0d0e0f10111213141516171819',
			),
			msg: repeat(0xcd, 50),
			expected: '4c9007f4026250c6bc8414f9bf50c86c2d7235da',
		}, {
			key: repeat(0x0c, 20),
			msg: new TextEncoder().encode('Test With Truncation'),
			expected: '4c1a03424b55e07fe7f27be1d58bb9324a9a5a04',
		}, {
			key: repeat(0xaa, 80),
			msg: new TextEncoder().encode(
				'Test Using Larger Than Block-Size Key - Hash Key First',
			),
			expected: 'aa4ae5e15272d00e95705637ce8a3b55ed402112',
		}, {
			key: repeat(0xaa, 80),
			msg: new TextEncoder().encode(
				'Test Using Larger Than Block-Size Key and Larger ' +
					'Than One Block-Size Data',
			),
			expected: 'e8e99d0f45237d786d6bbaa7965c7808bbff1a91',
		}, {
			key: repeat(0xaa, 80),
			msg: new TextEncoder().encode(
				'Test Using Larger Than Block-Size Key - Hash Key First',
			),
			expected: 'aa4ae5e15272d00e95705637ce8a3b55ed402112',
		}, {
			key: repeat(0xaa, 80),
			msg: new TextEncoder().encode(
				'Test Using Larger Than Block-Size Key and Larger ' +
					'Than One Block-Size Data',
			),
			expected: 'e8e99d0f45237d786d6bbaa7965c7808bbff1a91',
		}];

		// Coverage
		testCases.push({
			key: repeat(0x00, 64),
			msg: new TextEncoder().encode('Hello, world!'),
			expected: '70f499ea525a6843e4b65c58a27f2ff71d1e04db',
		});

		for (const { key, msg, expected } of testCases) {
			const result = await totp.hmacSha1({ key, msg });
			const hex = hexEncode(result);
			expect(hex).toBe(expected);
		}
	});
});

describe('hotp', () => {
	// https://datatracker.ietf.org/doc/html/rfc4226#appendix-D
	it('should generate the correct HOTP value', async () => {
		const key = new TextEncoder().encode('12345678901234567890');
		const length = 6;

		// dprint-ignore
		const expected = [
			'755224', '287082', '359152', '969429', '338314',
			'254676', '287922', '162583', '399871', '520489',
		];

		for (let i = 0; i < expected.length; i++) {
			const result = await totp.hotp({ key, ctr: BigInt(i), length });
			expect(result).toBe(expected[i]);
		}
	});
});

describe('totp', () => {
	// Because TOTP is just a trivial wrapper around HOTP that takes the current
	// system time into consideration, there's both no particular reason to
	// extensively test it, and no particular edge cases need to be considered.
	it("doesn't crash", async () => {
		const key = new TextEncoder().encode('12345678901234567890');
		const length = 6;
		const result = await totp.totp({ key, length });
		expect(result).toHaveLength(length);
	});
});

describe('base32', () => {
	it('should correctly round-trip random Base32 strings', () => {
		jsc.assert(jsc.forall('string', (str: string) => {
			const encoded = totp.b32encode(new TextEncoder().encode(str));
			const decoded = totp.b32decode(encoded);
			const decodedStr = new TextDecoder().decode(decoded);
			return decodedStr === str;
		}));
	});

	// N.B.: Python's base64.b32encode is RFC 4648 compliant; it generates
	// padding, but it's possible to manually trim that padding.
	//
	// msg = b'Hello, world!'
	// for l in range(len(msg)):
	//     print(repr(msg[:l]), base64.b32encode(msg[:l]).replace(b'=', b''))

	const testCases = [
		{ decoded: '', encoded: '' },
		{ decoded: 'H', encoded: 'JA' },
		{ decoded: 'He', encoded: 'JBSQ' },
		{ decoded: 'Hel', encoded: 'JBSWY' },
		{ decoded: 'Hell', encoded: 'JBSWY3A' },
		{ decoded: 'Hello', encoded: 'JBSWY3DP' },
		{ decoded: 'Hello,', encoded: 'JBSWY3DPFQ' },
		{ decoded: 'Hello, ', encoded: 'JBSWY3DPFQQA' },
		{ decoded: 'Hello, w', encoded: 'JBSWY3DPFQQHO' },
		{ decoded: 'Hello, wo', encoded: 'JBSWY3DPFQQHO3Y' },
		{ decoded: 'Hello, wor', encoded: 'JBSWY3DPFQQHO33S' },
		{ decoded: 'Hello, worl', encoded: 'JBSWY3DPFQQHO33SNQ' },
		{ decoded: 'Hello, world', encoded: 'JBSWY3DPFQQHO33SNRSA' },
	];

	it('should correctly encode fixed test cases', () => {
		for (const { decoded, encoded } of testCases) {
			const result = totp.b32encode(new TextEncoder().encode(decoded));
			expect(result).toBe(encoded);
		}
	});

	it('should correctly decode fixed test cases', () => {
		for (const { decoded, encoded } of testCases) {
			const result = totp.b32decode(encoded);
			const decodedStr = new TextDecoder().decode(result);
			expect(decodedStr).toBe(decoded);
		}
	});

	it('should reject invalid Base32 encoded strings', () => {
		expect(() => totp.b32decode('A')).toThrow(
			'Invalid Base32 encoded string length',
		);
		expect(() => totp.b32decode('!!')).toThrow('Invalid Base32 character');
		expect(() => totp.b32decode('77')).toThrow(
			'out-of-bounds bits must be zero',
		);
	});
});

function repeat(byte: number, length: number): Uint8Array<ArrayBuffer> {
	const result = new Uint8Array(length);
	result.fill(byte);
	return result;
}

function hexDecode(hex: string): Uint8Array<ArrayBuffer> {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
	}
	return bytes;
}

function hexEncode(bytes: Uint8Array<ArrayBuffer>): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
