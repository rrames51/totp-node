# `totp-node`

A tiny (&lt;1 KiB minified/gzipped), self-contained (zero runtime dependencies)
implementation of [HMAC-based one-time-password][hotp] (HOTP) and [Time-based
one-time password][totp] (TOTP) for Node.js and the web.

[hotp]: https://en.wikipedia.org/wiki/HMAC-based_one-time_password
[totp]: https://en.wikipedia.org/wiki/Time-based_one-time_password

## Table of Contents

1. [Prior art (and thanks!)](#prior-art-and-thanks)
2. [Usage](#usage)
   1. [`totp.hmacSha1({ key, msg })`](#totphmacsha1-key-msg-)
   2. [`totp.hotp({ key, ctr, length })`](#totphotp-key-ctr-length-)
   3. [`totp.totp({ key, periodMs, length })`](#totptotp-key-periodms-length-)
   4. [`totp.b32encode(buf)`](#totpb32encodebuf)
   5. [`totp.b32decode(encoded)`](#totpb32decodeencoded)
3. [License](#license)
4. [Generative AI usage disclaimer](#generative-ai-usage-disclaimer)

## Prior art (and thanks!)

This package is similar in scope to [`otplib`][otplib] by Gerald Yeo.
`totp-node`, by comparison, is substantially smaller and more self-contained. It
provides "just enough" functionality to implement HOTP and TOTP authentication
in Node.js and the web, eschewing features such as:

[otplib]: https://otplib.yeojz.dev/

* A command-line interface
* Hash functions other than SHA-1 (while SHA-1 is [widely][sha1_shattered]
  [considered][sha1_cryptose] [broken][sha1_wikipedia], these attacks don't
  affect the security model of HOTP or TOTP where the hash function is used only
  for stretching a shared secret key)
* Crypto implementations other than Web Crypto, or a synchronous API (insofar as
  most Web Crypto functions are async)

[sha1_shattered]: https://web.archive.org/web/20180515222208/http://shattered.io/static/shattered.pdf
[sha1_cryptose]: https://crypto.stackexchange.com/questions/3690/why-is-sha-1-considered-broken
[sha1_wikipedia]: https://en.wikipedia.org/wiki/SHA-1#SHAttered_%E2%80%93_first_public_collision

Conversely, `totp-node` is *far* less battle-tested than `otplib`. Before you try out this library, you might want to see if `otplib` suits your needs better.

## Usage

```ts
import * as totp from 'totp-node';
```

### `totp.hmacSha1({ key, msg })`

HMAC SHA-1 built on Web Crypto. Used as a building block for other functions,
and exposed for convenience. As with Web Crypto itself, this function is
asynchronous and returns a `Promise<Uint8Array<ArrayBuffer>>`.

### `totp.hotp({ key, ctr, length })`

Computes the HOTP (HMAC-based one-time password) value for the given key,
counter, and length. The length is typically 6 digits, and must be encoded as a
`Number`; the counter must be encoded as a `BigInt`.

### `totp.totp({ key, periodMs, length })`

Computes the TOTP (time-based one-time password) value for the given key,
period, and length. The length is typically 6 digits, and must be encoded as a
`Number`; the period is typically `30_000n` (30 seconds) and must be encoded as
a `BigInt`.

This is a trivial wrapper around `totp.hotp({ key, ctr, length })`, where the
counter `ctr` is derived from the current time (via `new Date().getTime()`) and
the specified period.

### `totp.b32encode(buf)`

Encodes the given `Uint8Array` buffer into an RFC 4648 Base32 string without
padding. This is the format that HOTP and TOTP implementations expect the shared
secret to be in. Use this for implementing the `otpauth://` URI scheme used by
Google Authenticator and other TOTP clients.

### `totp.b32decode(encoded)`

Decodes the given RFC 4648 Base32 string into a `Uint8Array` buffer without
padding. This is the format that HOTP and TOTP implementations expect the shared
secret to be in. Use this for reading the `otpauth://` URI scheme used by
Google Authenticator and other TOTP clients.

## License

This software package is provided under the [Unlicense][unlicense], a
public-domain equivalent license that allows anyone (including you, for free, no
strings attached!) to use, share and remix the software in any way they like.

[unlicense]: https://spdx.org/licenses/Unlicense.html

## Generative AI usage disclaimer

I, Rohan Ramesh, the author of `totp-node`, wish to disclose the following uses
of generative AI in the creation of this software package:

* **Autocomplete-style code generation** was used while writing
  `test/index.test.ts`.

This statement is provided in a best-effort, good-faith manner and does not
constitute a legal or binding declaration.
