"use strict";

// ─── Utility helpers ──────────────────────────────────────────────────────────

function $(id)   { return document.getElementById(id); }
function show(el) { el.classList.remove("hidden"); }
function hide(el) { el.classList.add("hidden"); }

function sendMsg(data) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(data, response => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

// Flash a temporary success/error message
function flashMsg(el, msg, durationMs = 2500) {
  el.textContent = msg;
  show(el);
  setTimeout(() => hide(el), durationMs);
}

// ─── DOM references ───────────────────────────────────────────────────────────

const lockScreen  = $("lock-screen");
const mainScreen  = $("main-screen");
const masterInput = $("master-password");
const lockError   = $("lock-error");
const unlockBtn   = $("unlock-btn");
const toggleMasterPw = $("toggle-master-pw");

const lockBtn = $("lock-btn");

const tabBtns    = document.querySelectorAll(".tab-btn");
const tabContents = document.querySelectorAll(".tab-content");

// Vault tab
const searchInput    = $("search-input");
const credentialList = $("credential-list");

// Add tab
const addUrl      = $("add-url");
const addUsername = $("add-username");
const addPassword = $("add-password");
const toggleAddPw = $("toggle-add-pw");
const saveBtn     = $("save-btn");
const addError    = $("add-error");
const addSuccess  = $("add-success");
const fillGenBtn  = $("fill-generated-btn");
const checkBreachBtn = $("check-breach-btn");
const breachResult   = $("breach-result");

// Generator tab
const pwLength        = $("pw-length");
const lengthDisplay   = $("length-display");
const generatedPw     = $("generated-password");
const generateBtn     = $("generate-btn");
const copyPwBtn       = $("copy-pw-btn");
const copyMsg         = $("copy-msg");

// Modal
const detailModal     = $("detail-modal");
const detailUrl       = $("detail-url");
const detailUsername  = $("detail-username");
const detailPassword  = $("detail-password");
const toggleDetailPw  = $("toggle-detail-pw");
const copyDetailPwBtn = $("copy-detail-pw-btn");
const deleteCredentialBtn = $("delete-credential-btn");
const closeModalBtn   = $("close-modal-btn");

// ─── State ────────────────────────────────────────────────────────────────────

let allEntries    = [];   // full list from vault
let activeEntryId = null; // selected entry in modal

// ─── Initialise ───────────────────────────────────────────────────────────────

(async () => {
  const { locked } = await sendMsg({ action: "isLocked" });
  if (locked) {
    showLockScreen();
  } else {
    await showMainScreen();
  }

  // Pre-fill URL from active tab
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && addUrl.value === "") {
      addUrl.value = new URL(tab.url).origin;
    }
  } catch { /* tabs permission may not be granted yet */ }
})();

// ─── Screen helpers ───────────────────────────────────────────────────────────

function showLockScreen() {
  show(lockScreen);
  hide(mainScreen);
  masterInput.value = "";
  masterInput.focus();
}

async function showMainScreen() {
  hide(lockScreen);
  show(mainScreen);
  await loadCredentials();
  switchTab("vault");
}

// ─── Lock / Unlock ────────────────────────────────────────────────────────────

unlockBtn.addEventListener("click", async () => {
  hide(lockError);
  const pw = masterInput.value.trim();
  if (!pw) {
    lockError.textContent = "Please enter your master password.";
    show(lockError);
    return;
  }

  unlockBtn.disabled = true;
  unlockBtn.textContent = "Unlocking…";

  try {
    const res = await sendMsg({ action: "unlock", masterPassword: pw });
    if (res.success) {
      await showMainScreen();
    } else {
      lockError.textContent = res.error || "Incorrect master password.";
      show(lockError);
    }
  } catch (err) {
    lockError.textContent = "Error: " + err.message;
    show(lockError);
  } finally {
    unlockBtn.disabled = false;
    unlockBtn.textContent = "Unlock Vault";
  }
});

masterInput.addEventListener("keydown", e => {
  if (e.key === "Enter") unlockBtn.click();
});

toggleMasterPw.addEventListener("click", () => toggleVisibility(masterInput, toggleMasterPw));

lockBtn.addEventListener("click", async () => {
  await sendMsg({ action: "lock" });
  showLockScreen();
});

// ─── Tabs ─────────────────────────────────────────────────────────────────────

function switchTab(name) {
  tabBtns.forEach(btn => btn.classList.toggle("active", btn.dataset.tab === name));
  tabContents.forEach(tc => {
    tc.classList.toggle("active", tc.id === `tab-${name}`);
    tc.classList.toggle("hidden", tc.id !== `tab-${name}`);
  });
}

tabBtns.forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

// ─── Vault Tab ────────────────────────────────────────────────────────────────

async function loadCredentials() {
  const res = await sendMsg({ action: "getCredentials" });
  allEntries = res.success ? res.entries : [];
  renderList(allEntries);
}

function renderList(entries) {
  credentialList.innerHTML = "";
  if (!entries.length) {
    credentialList.innerHTML = '<li class="empty-state">No saved credentials yet.</li>';
    return;
  }
  entries.forEach(entry => {
    const li = document.createElement("li");
    li.className = "credential-item";
    li.dataset.id = entry.id;

    let domain = entry.url;
    try { domain = new URL(entry.url).hostname.replace(/^www\./, ""); } catch { /**/ }

    const initial = domain.charAt(0).toUpperCase();

    li.innerHTML = `
      <div class="cred-icon">${initial}</div>
      <div class="cred-info">
        <div class="cred-url">${escapeHtml(domain)}</div>
        <div class="cred-username">${escapeHtml(entry.username)}</div>
      </div>
    `;
    li.addEventListener("click", () => openDetail(entry));
    credentialList.appendChild(li);
  });
}

searchInput.addEventListener("input", () => {
  const q = searchInput.value.toLowerCase();
  const filtered = allEntries.filter(e =>
    e.url.toLowerCase().includes(q) ||
    e.username.toLowerCase().includes(q)
  );
  renderList(filtered);
});

// ─── Detail Modal ─────────────────────────────────────────────────────────────

function openDetail(entry) {
  activeEntryId = entry.id;
  detailUrl.textContent      = entry.url;
  detailUsername.textContent = entry.username;

  // Store the plain password as a data attribute (safe — stays in local JS memory)
  detailPassword.dataset.plain = entry.password;
  detailPassword.textContent   = "••••••••";
  detailPassword.classList.add("blurred");

  show(detailModal);
}

toggleDetailPw.addEventListener("click", () => {
  if (detailPassword.classList.contains("blurred")) {
    detailPassword.textContent = detailPassword.dataset.plain;
    detailPassword.classList.remove("blurred");
    toggleDetailPw.textContent = "🙈";
  } else {
    detailPassword.textContent = "••••••••";
    detailPassword.classList.add("blurred");
    toggleDetailPw.textContent = "👁";
  }
});

copyDetailPwBtn.addEventListener("click", async () => {
  await navigator.clipboard.writeText(detailPassword.dataset.plain);
  copyDetailPwBtn.textContent = "✅ Copied";
  setTimeout(() => { copyDetailPwBtn.textContent = "📋 Copy"; }, 1500);
});

deleteCredentialBtn.addEventListener("click", async () => {
  if (!activeEntryId) return;
  await sendMsg({ action: "deleteCredential", id: activeEntryId });
  hide(detailModal);
  await loadCredentials();
});

closeModalBtn.addEventListener("click", () => hide(detailModal));

detailModal.addEventListener("click", e => {
  if (e.target === detailModal) hide(detailModal);
});

// ─── Add Tab ──────────────────────────────────────────────────────────────────

toggleAddPw.addEventListener("click", () => toggleVisibility(addPassword, toggleAddPw));

saveBtn.addEventListener("click", async () => {
  hide(addError);
  hide(addSuccess);
  hide(breachResult);

  const url      = addUrl.value.trim();
  const username = addUsername.value.trim();
  const password = addPassword.value;

  if (!url || !username || !password) {
    addError.textContent = "All fields are required.";
    show(addError);
    return;
  }

  saveBtn.disabled = true;
  saveBtn.textContent = "Saving…";

  const res = await sendMsg({ action: "addCredential", url, username, password });
  if (res.success) {
    show(addSuccess);
    addUsername.value = "";
    addPassword.value = "";
    await loadCredentials();
    setTimeout(() => hide(addSuccess), 2500);
  } else {
    addError.textContent = res.error || "Failed to save.";
    show(addError);
  }
  saveBtn.disabled = false;
  saveBtn.textContent = "Save Credential";
});

fillGenBtn.addEventListener("click", () => {
  const pw = generatedPw.value;
  if (pw) {
    addPassword.value = pw;
    switchTab("add");
  } else {
    switchTab("generator");
  }
});

checkBreachBtn.addEventListener("click", async () => {
  const pw = addPassword.value;
  if (!pw) {
    addError.textContent = "Enter a password to check.";
    show(addError);
    return;
  }
  hide(addError);
  breachResult.textContent = "Checking…";
  breachResult.className   = "breach-msg";
  show(breachResult);

  const res = await sendMsg({ action: "checkBreach", password: pw });
  if (!res.success) {
    breachResult.textContent = "⚠ Could not check (API unavailable).";
    breachResult.classList.add("breach-unknown");
  } else if (res.count === 0) {
    breachResult.textContent = "✅ Not found in known breaches.";
    breachResult.classList.add("breach-safe");
  } else {
    breachResult.textContent = `⛔ Found ${res.count.toLocaleString()} times in breaches! Choose a different password.`;
    breachResult.classList.add("breach-pwned");
  }
});

// ─── Generator Tab ────────────────────────────────────────────────────────────

pwLength.addEventListener("input", () => {
  lengthDisplay.textContent = pwLength.value;
});

generateBtn.addEventListener("click", async () => {
  const res = await sendMsg({ action: "generatePassword", length: parseInt(pwLength.value, 10) });
  if (res.success) generatedPw.value = res.password;
});

copyPwBtn.addEventListener("click", async () => {
  const pw = generatedPw.value;
  if (!pw) return;
  await navigator.clipboard.writeText(pw);
  flashMsg(copyMsg, "Copied to clipboard!", 2000);
});

// ─── Shared helpers ───────────────────────────────────────────────────────────

function toggleVisibility(input, btn) {
  if (input.type === "password") {
    input.type    = "text";
    btn.textContent = "🙈";
  } else {
    input.type    = "password";
    btn.textContent = "👁";
  }
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
