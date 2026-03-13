# Changelog

## 1.2

- Add self-describing encrypted header format (v2) for better long-term recovery.
- Keep backward compatibility for decrypting older v1 `.enc` files.
- Keep command palette label consistent in English to avoid mixed-language display.

## 1.1

- Open decrypted file immediately after right-click decrypt.
- Add inline passphrase input and decrypt button in encrypted placeholder view.
- Improve locale consistency so Chinese UI no longer mixes English labels.

## 1.0

- Stable manual workflow release.
- Keep one command: `Encrypt current file`.
- Add right-click file/folder encrypt/decrypt actions.
- Block direct editing of `.enc` with a placeholder view.
- Add bilingual UI text (English/Chinese by app locale).
- Fixed crypto output writing with exact ArrayBuffer slicing.
