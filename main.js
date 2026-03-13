const {
  ItemView,
  Modal,
  Notice,
  Plugin,
  PluginSettingTab,
  Setting,
  TFile,
  TFolder,
  normalizePath,
} = require("obsidian");

const MAGIC_BYTES = new Uint8Array([79, 67, 69, 78, 67, 49]);
const VERSION = 1;
const PBKDF2_ITERATIONS = 210000;
const VIEW_TYPE_ENCRYPTED = "vault-encryptor-encrypted-view";

class VaultEncryptorPlugin extends Plugin {
  async onload() {
    this.crypto = await getWebCrypto();
    this.locale = resolveLocale(this.app);

    this.registerView(
      VIEW_TYPE_ENCRYPTED,
      (leaf) =>
        new EncryptedFileView(
          leaf,
          () => this.t("encryptedViewTitle"),
          () => this.t("encryptedViewDescription")
        )
    );
    this.registerExtensions(["enc"], VIEW_TYPE_ENCRYPTED);

    this.addSettingTab(new VaultEncryptorSettingTab(this.app, this));
    this.registerEvent(
      this.app.workspace.on("file-menu", (menu, file) => this.handleFileMenu(menu, file))
    );

    this.addCommand({
      id: "encrypt-current-file",
      name: this.t("commandEncryptCurrent"),
      callback: async () => {
        await this.encryptCurrentFile();
      },
    });
  }

  onunload() {
    this.app.workspace.getLeavesOfType(VIEW_TYPE_ENCRYPTED).forEach((leaf) => {
      leaf.setViewState({ type: "empty" });
    });
  }

  t(key, vars = {}) {
    const dict = I18N[this.locale] || I18N.en;
    const template = dict[key] || I18N.en[key] || key;
    return template.replace(/\{(\w+)\}/g, (_m, name) => String(vars[name] ?? ""));
  }

  handleFileMenu(menu, file) {
    if (!(file instanceof TFile || file instanceof TFolder)) {
      return;
    }
    if (isProtectedPath(file.path)) {
      return;
    }

    if (file instanceof TFile) {
      if (file.path.endsWith(".enc")) {
        menu.addItem((item) => {
          item
            .setTitle(this.t("menuDecryptFile"))
            .setIcon("unlock")
            .onClick(() => {
              void this.runForTargets("decrypt", [file.path], this.t("labelDecryptFile"));
            });
        });
      } else {
        menu.addItem((item) => {
          item
            .setTitle(this.t("menuEncryptFile"))
            .setIcon("lock")
            .onClick(() => {
              void this.runForTargets("encrypt", [file.path], this.t("labelEncryptFile"));
            });
        });
      }
      return;
    }

    menu.addItem((item) => {
      item
        .setTitle(this.t("menuEncryptFolder"))
        .setIcon("lock")
        .onClick(() => {
          void this.runForTargets("encrypt", [file.path], this.t("labelEncryptFolder"));
        });
    });

    menu.addItem((item) => {
      item
        .setTitle(this.t("menuDecryptFolder"))
        .setIcon("unlock")
        .onClick(() => {
          void this.runForTargets("decrypt", [file.path], this.t("labelDecryptFolder"));
        });
    });
  }

  async encryptCurrentFile() {
    const file = this.app.workspace.getActiveFile();
    if (!file) {
      new Notice(this.t("noticeNoActiveFile"));
      return;
    }
    if (isProtectedPath(file.path)) {
      new Notice(this.t("noticeProtectedPath"));
      return;
    }
    if (file.path.endsWith(".enc")) {
      new Notice(this.t("noticeAlreadyEncrypted"));
      return;
    }

    const passphrase = await this.getPassphrase(true);
    if (!passphrase) {
      return;
    }

    const result = await this.encryptFile(file.path, passphrase);
    if (result.ok) {
      new Notice(this.t("noticeEncrypted", { path: file.path }));
    } else {
      new Notice(this.t("noticeEncryptFailed", { reason: result.reason }));
    }
  }

  async runForTargets(mode, targetPaths, label) {
    const targets = collectTargets(this.app, targetPaths, mode);
    if (targets.errors.length > 0) {
      new Notice(this.t("noticeTargetInvalid"));
      console.warn("[Vault Encryptor] Target errors:", targets.errors);
    }
    if (targets.files.length === 0) {
      new Notice(
        this.t("noticeNoFiles", {
          mode: mode === "encrypt" ? this.t("wordEncrypt") : this.t("wordDecrypt"),
        })
      );
      return;
    }

    const passphrase = await this.getPassphrase(mode === "encrypt");
    if (!passphrase) {
      return;
    }

    let success = 0;
    let skipped = 0;
    let failed = 0;
    const failures = [];

    for (const path of targets.files) {
      const result =
        mode === "encrypt"
          ? await this.encryptFile(path, passphrase)
          : await this.decryptFile(path, passphrase);

      if (result.ok) {
        success += 1;
      } else if (result.skipped) {
        skipped += 1;
      } else {
        failed += 1;
        failures.push(`${path}: ${result.reason}`);
      }
    }

    new Notice(
      this.t("noticeFinished", {
        label,
        mode: mode === "encrypt" ? this.t("wordEncrypt") : this.t("wordDecrypt"),
        success,
        skipped,
        failed,
      })
    );
    if (failures.length > 0) {
      console.warn("[Vault Encryptor] Failures:", failures);
    }
  }

  async getPassphrase(confirmIfEncrypt) {
    const first = await openPassphraseModal(this.app, {
      title: this.t("promptEnterPassphrase"),
      placeholder: this.t("promptPassphrase"),
      confirmText: this.t("promptContinue"),
      cancelText: this.t("promptCancel"),
      emptyText: this.t("noticePassphraseEmpty"),
    });
    if (!first) {
      return null;
    }

    if (confirmIfEncrypt) {
      const second = await openPassphraseModal(this.app, {
        title: this.t("promptConfirmPassphrase"),
        placeholder: this.t("promptPassphraseAgain"),
        confirmText: this.t("promptConfirm"),
        cancelText: this.t("promptCancel"),
        emptyText: this.t("noticePassphraseEmpty"),
      });
      if (!second) {
        return null;
      }
      if (first !== second) {
        new Notice(this.t("noticePassphraseMismatch"));
        return null;
      }
    }

    return first;
  }

  async encryptFile(path, passphrase) {
    if (isProtectedPath(path)) {
      return { ok: false, skipped: true, reason: "protected path" };
    }
    if (path.endsWith(".enc")) {
      return { ok: false, skipped: true, reason: "already encrypted" };
    }

    const outputPath = `${path}.enc`;
    const outputExists = await this.app.vault.adapter.exists(outputPath);
    if (outputExists) {
      return {
        ok: false,
        reason: this.t("reasonOutputExists", { path: outputPath }),
      };
    }

    try {
      const input = new Uint8Array(await this.app.vault.adapter.readBinary(path));
      const encrypted = await encryptBytes(this.crypto, passphrase, input, PBKDF2_ITERATIONS);
      await this.app.vault.adapter.writeBinary(outputPath, toExactArrayBuffer(encrypted));
      await this.app.vault.adapter.remove(path);
      return { ok: true };
    } catch (error) {
      return { ok: false, reason: errorToMessage(error) };
    }
  }

  async decryptFile(path, passphrase) {
    if (isProtectedPath(path)) {
      return { ok: false, skipped: true, reason: "protected path" };
    }
    if (!path.endsWith(".enc")) {
      return { ok: false, skipped: true, reason: "not an .enc file" };
    }

    const outputPath = path.slice(0, -4);
    const outputExists = await this.app.vault.adapter.exists(outputPath);
    if (outputExists) {
      return {
        ok: false,
        reason: this.t("reasonOutputExists", { path: outputPath }),
      };
    }

    try {
      const input = new Uint8Array(await this.app.vault.adapter.readBinary(path));
      const decrypted = await decryptBytes(this.crypto, passphrase, input);
      await this.app.vault.adapter.writeBinary(outputPath, toExactArrayBuffer(decrypted));
      await this.app.vault.adapter.remove(path);
      return { ok: true };
    } catch (error) {
      return { ok: false, reason: errorToMessage(error) };
    }
  }
}

class VaultEncryptorSettingTab extends PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display() {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl("h2", { text: this.plugin.t("settingTitle") });

    new Setting(containerEl)
      .setName(this.plugin.t("settingManualModeName"))
      .setDesc(this.plugin.t("settingManualModeDesc"));

    new Setting(containerEl)
      .setName(this.plugin.t("settingSecurityName"))
      .setDesc(this.plugin.t("settingSecurityDesc", { iterations: PBKDF2_ITERATIONS }));
  }
}

class EncryptedFileView extends ItemView {
  constructor(leaf, getTitle, getDescription) {
    super(leaf);
    this.getTitleText = getTitle;
    this.getDescriptionText = getDescription;
  }

  getViewType() {
    return VIEW_TYPE_ENCRYPTED;
  }

  getDisplayText() {
    return this.getTitleText();
  }

  async onOpen() {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.addClass("vault-encryptor-block-view");
    containerEl.createEl("h3", { text: this.getTitleText() });
    containerEl.createEl("p", { text: this.getDescriptionText() });
  }
}

class PassphraseModal extends Modal {
  constructor(app, options) {
    super(app);
    this.options = options;
    this.value = null;
    this.onSubmit = null;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h3", { text: this.options.title });
    const input = contentEl.createEl("input", { type: "password" });
    input.placeholder = this.options.placeholder;
    input.style.width = "100%";
    input.style.marginBottom = "12px";

    const buttonRow = contentEl.createDiv();
    buttonRow.style.display = "flex";
    buttonRow.style.gap = "8px";
    buttonRow.style.justifyContent = "flex-end";

    const cancelBtn = buttonRow.createEl("button", {
      text: resolveButtonText(this.options.cancelText, "Cancel"),
    });
    const okBtn = buttonRow.createEl("button", {
      text: resolveButtonText(this.options.confirmText, "OK"),
    });
    okBtn.classList.add("mod-cta");

    cancelBtn.onclick = () => {
      this.value = null;
      this.close();
    };
    okBtn.onclick = () => {
      const value = input.value;
      if (!value) {
        new Notice(resolveButtonText(this.options.emptyText, "Passphrase cannot be empty."));
        return;
      }
      this.value = value;
      this.close();
    };
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        okBtn.click();
      }
    });
    window.setTimeout(() => input.focus(), 10);
  }

  onClose() {
    this.contentEl.empty();
    if (this.onSubmit) {
      this.onSubmit(this.value);
    }
  }
}

function openPassphraseModal(app, options) {
  return new Promise((resolve) => {
    const modal = new PassphraseModal(app, options);
    modal.onSubmit = resolve;
    modal.open();
  });
}

function collectTargets(app, configuredTargets, mode) {
  const files = [];
  const errors = [];
  const seen = new Set();

  for (const rawTarget of configuredTargets) {
    const target = normalizePath(String(rawTarget || "").trim());
    if (!target) {
      continue;
    }

    const entry = app.vault.getAbstractFileByPath(target);
    if (!entry) {
      if (mode === "decrypt" && !target.endsWith(".enc")) {
        const encEntry = app.vault.getAbstractFileByPath(`${target}.enc`);
        if (encEntry instanceof TFile) {
          maybeAddPath(files, seen, encEntry.path, mode);
          continue;
        }
      }
      errors.push(`Target not found: ${target}`);
      continue;
    }

    if (entry instanceof TFile) {
      maybeAddPath(files, seen, entry.path, mode);
      continue;
    }

    if (entry instanceof TFolder) {
      collectFromFolder(entry, files, seen, mode);
    }
  }

  return { files, errors };
}

function collectFromFolder(folder, files, seen, mode) {
  for (const child of folder.children) {
    if (child instanceof TFolder) {
      if (!isProtectedPath(child.path)) {
        collectFromFolder(child, files, seen, mode);
      }
      continue;
    }
    if (child instanceof TFile) {
      maybeAddPath(files, seen, child.path, mode);
    }
  }
}

function maybeAddPath(files, seen, path, mode) {
  if (isProtectedPath(path)) {
    return;
  }
  if (mode === "encrypt" && path.endsWith(".enc")) {
    return;
  }
  if (mode === "decrypt" && !path.endsWith(".enc")) {
    return;
  }
  if (seen.has(path)) {
    return;
  }
  seen.add(path);
  files.push(path);
}

function isProtectedPath(path) {
  return path === ".obsidian" || path.startsWith(".obsidian/");
}

async function getWebCrypto() {
  if (globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  try {
    const nodeCrypto = require("crypto");
    if (nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle) {
      return nodeCrypto.webcrypto;
    }
  } catch (_error) {
    // no-op
  }
  throw new Error("Web Crypto API is not available in this environment.");
}

async function encryptBytes(webCrypto, passphrase, plainBytes, iterations) {
  const salt = randomBytes(webCrypto, 16);
  const iv = randomBytes(webCrypto, 12);
  const key = await deriveAesKey(webCrypto, passphrase, salt, iterations);
  const encrypted = new Uint8Array(
    await webCrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainBytes)
  );
  return packEncryptedPayload({ salt, iv, iterations, encrypted });
}

async function decryptBytes(webCrypto, passphrase, encryptedPayload) {
  const payload = unpackEncryptedPayload(encryptedPayload);
  const key = await deriveAesKey(webCrypto, passphrase, payload.salt, payload.iterations);
  const plain = new Uint8Array(
    await webCrypto.subtle.decrypt({ name: "AES-GCM", iv: payload.iv }, key, payload.encrypted)
  );
  return plain;
}

async function deriveAesKey(webCrypto, passphrase, salt, iterations) {
  const keyMaterial = await webCrypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return webCrypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function packEncryptedPayload(payload) {
  const saltLen = payload.salt.length;
  const ivLen = payload.iv.length;
  const encLen = payload.encrypted.length;

  const headerLen = MAGIC_BYTES.length + 1 + 2 + 2 + 4 + 4;
  const out = new Uint8Array(headerLen + saltLen + ivLen + encLen);

  let offset = 0;
  out.set(MAGIC_BYTES, offset);
  offset += MAGIC_BYTES.length;

  out[offset] = VERSION;
  offset += 1;

  writeUint16(out, offset, saltLen);
  offset += 2;

  writeUint16(out, offset, ivLen);
  offset += 2;

  writeUint32(out, offset, payload.iterations);
  offset += 4;

  writeUint32(out, offset, encLen);
  offset += 4;

  out.set(payload.salt, offset);
  offset += saltLen;

  out.set(payload.iv, offset);
  offset += ivLen;

  out.set(payload.encrypted, offset);

  return out;
}

function unpackEncryptedPayload(data) {
  if (data.length < MAGIC_BYTES.length + 1 + 2 + 2 + 4 + 4) {
    throw new Error("Encrypted file is too short.");
  }

  let offset = 0;
  for (let i = 0; i < MAGIC_BYTES.length; i += 1) {
    if (data[offset + i] !== MAGIC_BYTES[i]) {
      throw new Error("Invalid encrypted file header.");
    }
  }
  offset += MAGIC_BYTES.length;

  const version = data[offset];
  offset += 1;
  if (version !== VERSION) {
    throw new Error(`Unsupported encrypted format version: ${version}`);
  }

  const saltLen = readUint16(data, offset);
  offset += 2;
  const ivLen = readUint16(data, offset);
  offset += 2;
  const iterations = readUint32(data, offset);
  offset += 4;
  const encLen = readUint32(data, offset);
  offset += 4;

  const expected = offset + saltLen + ivLen + encLen;
  if (expected !== data.length) {
    throw new Error("Encrypted payload length mismatch.");
  }

  const salt = data.slice(offset, offset + saltLen);
  offset += saltLen;
  const iv = data.slice(offset, offset + ivLen);
  offset += ivLen;
  const encrypted = data.slice(offset, offset + encLen);

  return { salt, iv, iterations, encrypted };
}

function randomBytes(webCrypto, length) {
  const bytes = new Uint8Array(length);
  webCrypto.getRandomValues(bytes);
  return bytes;
}

function writeUint16(target, offset, value) {
  target[offset] = (value >>> 8) & 0xff;
  target[offset + 1] = value & 0xff;
}

function writeUint32(target, offset, value) {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

function readUint16(source, offset) {
  return (source[offset] << 8) | source[offset + 1];
}

function readUint32(source, offset) {
  return (
    source[offset] * 16777216 +
    (source[offset + 1] << 16) +
    (source[offset + 2] << 8) +
    source[offset + 3]
  );
}

function toExactArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function errorToMessage(error) {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function resolveButtonText(value, fallback) {
  if (typeof value === "string" && value.trim().length > 0) {
    return value;
  }
  return fallback;
}

function resolveLocale(app) {
  try {
    const configured = app?.vault?.getConfig?.("locale");
    if (typeof configured === "string" && configured.trim().length > 0) {
      return configured.toLowerCase().startsWith("zh") ? "zh" : "en";
    }
  } catch (_error) {
    // no-op
  }

  const navLang = (globalThis.navigator && globalThis.navigator.language) || "en";
  return String(navLang).toLowerCase().startsWith("zh") ? "zh" : "en";
}

const I18N = {
  en: {
    commandEncryptCurrent: "Encrypt current file",
    menuEncryptFile: "Vault Encryptor: Encrypt this file",
    menuDecryptFile: "Vault Encryptor: Decrypt this file",
    menuEncryptFolder: "Vault Encryptor: Encrypt folder",
    menuDecryptFolder: "Vault Encryptor: Decrypt folder",
    labelEncryptFile: "Encrypt file",
    labelDecryptFile: "Decrypt file",
    labelEncryptFolder: "Encrypt folder",
    labelDecryptFolder: "Decrypt folder",
    noticeNoActiveFile: "No active file.",
    noticeProtectedPath: "Refusing to process files in .obsidian.",
    noticeAlreadyEncrypted: "Active file is already encrypted (.enc).",
    noticeEncrypted: "Encrypted: {path}",
    noticeEncryptFailed: "Encrypt failed: {reason}",
    noticeTargetInvalid: "Some targets are invalid. Check console for details.",
    noticeNoFiles: "No files to {mode}.",
    noticeFinished: "{label}: {mode} finished. OK {success}, skipped {skipped}, failed {failed}.",
    noticePassphraseMismatch: "Passphrases do not match.",
    noticePassphraseEmpty: "Passphrase cannot be empty.",
    promptEnterPassphrase: "Vault Encryptor: Enter passphrase",
    promptConfirmPassphrase: "Vault Encryptor: Confirm passphrase",
    promptPassphrase: "Passphrase",
    promptPassphraseAgain: "Passphrase again",
    promptContinue: "Continue",
    promptConfirm: "Confirm",
    promptCancel: "Cancel",
    settingTitle: "Vault Encryptor",
    settingManualModeName: "Manual mode",
    settingManualModeDesc:
      "Use file explorer right-click menu to encrypt/decrypt files and folders. .enc files are read-only in Obsidian.",
    settingSecurityName: "Security profile",
    settingSecurityDesc:
      "Algorithm details are public by design and do not expose your key. AES-256-GCM + PBKDF2-SHA256, fixed at {iterations} iterations.",
    encryptedViewTitle: "Encrypted file",
    encryptedViewDescription:
      "This file is encrypted and cannot be edited directly. Right-click the file and choose 'Decrypt this file'.",
    reasonOutputExists: "Output already exists ({path}). Resolve filename conflict manually.",
    wordEncrypt: "encrypt",
    wordDecrypt: "decrypt",
  },
  zh: {
    commandEncryptCurrent: "加密当前文件",
    menuEncryptFile: "Vault Encryptor：加密此文件",
    menuDecryptFile: "Vault Encryptor：解密此文件",
    menuEncryptFolder: "Vault Encryptor：加密文件夹",
    menuDecryptFolder: "Vault Encryptor：解密文件夹",
    labelEncryptFile: "加密文件",
    labelDecryptFile: "解密文件",
    labelEncryptFolder: "加密文件夹",
    labelDecryptFolder: "解密文件夹",
    noticeNoActiveFile: "当前没有活动文件。",
    noticeProtectedPath: "拒绝处理 .obsidian 目录中的文件。",
    noticeAlreadyEncrypted: "当前文件已是加密文件（.enc）。",
    noticeEncrypted: "已加密：{path}",
    noticeEncryptFailed: "加密失败：{reason}",
    noticeTargetInvalid: "部分目标路径无效，请查看控制台详情。",
    noticeNoFiles: "没有可{mode}的文件。",
    noticeFinished: "{label}：{mode}完成。成功 {success}，跳过 {skipped}，失败 {failed}。",
    noticePassphraseMismatch: "两次输入的密码不一致。",
    noticePassphraseEmpty: "密码不能为空。",
    promptEnterPassphrase: "Vault Encryptor：输入密码",
    promptConfirmPassphrase: "Vault Encryptor：确认密码",
    promptPassphrase: "密码",
    promptPassphraseAgain: "再次输入密码",
    promptContinue: "继续",
    promptConfirm: "确认",
    promptCancel: "取消",
    settingTitle: "Vault Encryptor",
    settingManualModeName: "手动模式",
    settingManualModeDesc:
      "通过文件树右键菜单手动加密/解密文件和文件夹。.enc 文件在 Obsidian 中为只读提示视图。",
    settingSecurityName: "安全配置",
    settingSecurityDesc:
      "算法参数公开不会泄露密钥。AES-256-GCM + PBKDF2-SHA256，固定迭代次数 {iterations}。",
    encryptedViewTitle: "加密文件",
    encryptedViewDescription:
      "此文件已加密，不能直接编辑。请在文件树中右键该文件并选择“解密此文件”。",
    reasonOutputExists: "输出文件已存在（{path}），请手动处理重名冲突。",
    wordEncrypt: "加密",
    wordDecrypt: "解密",
  },
};

module.exports = VaultEncryptorPlugin;
