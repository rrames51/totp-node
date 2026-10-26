# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `totp.checkTotp` function to validate TOTP tokens with a grace period.

## [0.1.0] - 2026-09-23

### Added

- Initial release with `totp.hmacSha1`, `totp.hotp`, `totp.totp`, and
  `totp.b32encode`/`totp.b32decode` functions.

[Unreleased]: https://github.com/rrames51/totp-node/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rrames51/totp-node/releases/tag/v0.1.0
