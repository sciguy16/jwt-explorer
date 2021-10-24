# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
* Added signature type `RETAIN` to copy the original signature straight into the re-encoded token
* Added button to copy all attacks to clipboard
* Added support for ES256, ES384, and ES512 ECDSA signatures

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [v0.3.1]
### Fixed
* Fixed broken Windows build

## [v0.3.0]
### Added
* Add UI buttons to delete generated tokens and clear the entire list
* Add UI button to clear log entries

## [v0.2.0]
### Changed
* If no secret provided then guess common values *before* validating the signature
* Include build version and date in the title
* Added `libxcb-render0` to deb dependencies

## [v0.1.0]
Initial release. Features:

* Decode JWTs and inspect the headers and claims
* Automatically try some common secrets
* Generate `alg:none` attack payloads
* Easily update `iat` and `exp` with various offsets
* Sign and encode tokens with common algorithms
* Accept and encode invalid JSON payloads