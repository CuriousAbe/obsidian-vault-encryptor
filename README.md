# Vault Encryptor

[English](#english) | [中文](#中文)

## English

Manual encryption plugin for Obsidian.

Vault Encryptor encrypts files as `.enc` using AES-256-GCM with PBKDF2-SHA256.
This plugin is intentionally manual-first and conservative.

### Features

- Command palette: `Encrypt current file`
- File explorer right-click:
  - `Vault Encryptor: Encrypt this file`
  - `Vault Encryptor: Decrypt this file`
  - `Vault Encryptor: Encrypt folder` (recursive)
  - `Vault Encryptor: Decrypt folder` (recursive)
- `.enc` opens in a blocked placeholder view and cannot be edited directly

### Security Notes

- Cipher: AES-256-GCM
- KDF: PBKDF2-SHA256
- Iterations: 210000 (fixed)
- Displaying algorithm parameters does not expose your passphrase
- No overwrite: if output path exists, operation fails and asks for manual conflict handling

### Behavior

- Encrypt: `file.ext -> file.ext.enc`, then delete plaintext
- Decrypt: `file.ext.enc -> file.ext`, then delete encrypted file

## 中文

Obsidian 手动加密插件。

Vault Encryptor 使用 AES-256-GCM + PBKDF2-SHA256 将文件加密为 `.enc`。
插件采用纯手工、保守策略。

### 功能

- 命令面板：`加密当前文件`
- 文件树右键：
  - `Vault Encryptor：加密此文件`
  - `Vault Encryptor：解密此文件`
  - `Vault Encryptor：加密文件夹`（递归）
  - `Vault Encryptor：解密文件夹`（递归）
- `.enc` 文件会进入阻断占位视图，不能直接编辑

### 安全说明

- 算法：AES-256-GCM
- 密钥派生：PBKDF2-SHA256
- 迭代次数：210000（固定）
- 显示算法参数不会泄露你的密码
- 不覆盖输出：若目标文件已存在，直接失败并提示手动处理冲突

### 行为

- 加密：`file.ext -> file.ext.enc`，然后删除明文
- 解密：`file.ext.enc -> file.ext`，然后删除密文
