const loginSection = document.getElementById("loginSection");
const vaultSection = document.getElementById("vaultSection");

const masterPassword = document.getElementById("masterPassword");
const unlockBtn = document.getElementById("unlockBtn");
const lockBtn = document.getElementById("lockBtn");

const website = document.getElementById("website");
const username = document.getElementById("username");
const entryPassword = document.getElementById("entryPassword");

const generateBtn = document.getElementById("generateBtn");
const addBtn = document.getElementById("addBtn");
const refreshBtn = document.getElementById("refreshBtn");

const passwordList = document.getElementById("passwordList");

const loginMessage = document.getElementById("loginMessage");
const addMessage = document.getElementById("addMessage");
const securityMessage = document.getElementById("securityMessage");

let unlocked = false;


// -------------------------
// UNLOCK VAULT
// -------------------------

unlockBtn.addEventListener("click", async () => {

    const password = masterPassword.value;

    if (!password) {
        loginMessage.textContent = "Please enter your master password.";
        return;
    }

    loginMessage.textContent = "Unlocking vault...";

    try {

        const response = await fetch("/api/unlock", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                masterPassword: password
            })
        });

        const result = await response.json();

        if (!response.ok) {
            loginMessage.textContent = result.message;
            return;
        }

        unlocked = true;

        lockBtn.classList.remove("hidden");
        loginSection.classList.add("hidden");
        vaultSection.classList.remove("hidden");

        loginMessage.textContent = "";
        masterPassword.value = "";

        await loadPasswords();

    } catch (error) {

        loginMessage.textContent =
            "Could not connect to the password manager server.";
    }
});


// -------------------------
// LOCK VAULT
// -------------------------

lockBtn.addEventListener("click", async () => {

    try {
        await fetch("/api/lock", { method: "POST" });
    } catch (error) {
        // UI is cleared below either way.
    }

    unlocked = false;

    lockBtn.classList.add("hidden");
    vaultSection.classList.add("hidden");
    loginSection.classList.remove("hidden");

    masterPassword.value = "";
    entryPassword.value = "";

    passwordList.innerHTML = `
        <p class="empty-message">
            No passwords loaded.
        </p>
    `;

    loginMessage.textContent = "Vault locked.";
});


// -------------------------
// GENERATE PASSWORD
// -------------------------

generateBtn.addEventListener("click", async () => {

    if (!unlocked) {
        addMessage.textContent = "Unlock the vault first.";
        return;
    }

    try {

        const response = await fetch("/api/generate", {
            method: "POST"
        });

        const result = await response.json();

        if (!response.ok) {
            addMessage.textContent = result.message;
            return;
        }

        entryPassword.value = result.password;

        addMessage.textContent =
            "Strong password generated successfully.";

    } catch (error) {

        addMessage.textContent =
            "Could not generate password.";
    }
});


// -------------------------
// ADD PASSWORD
// -------------------------

addBtn.addEventListener("click", async () => {

    if (!unlocked) {
        addMessage.textContent = "Unlock the vault first.";
        return;
    }

    const site = website.value.trim();
    const user = username.value.trim();
    const password = entryPassword.value;

    if (!site || !user || !password) {
        addMessage.textContent =
            "Please fill in website, username and password.";
        return;
    }

    addMessage.textContent = "Saving password...";

    try {

        const response = await fetch("/api/add", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                website: site,
                username: user,
                password: password
            })
        });

        const result = await response.json();

        if (!response.ok) {
            addMessage.textContent = result.message;
            return;
        }

        addMessage.textContent =
            "Password added successfully.";

        website.value = "";
        username.value = "";
        entryPassword.value = "";

        await loadPasswords();

    } catch (error) {

        addMessage.textContent =
            "Could not save the password.";
    }
});


// -------------------------
// LOAD STORED PASSWORDS
// -------------------------

const listMessage = document.getElementById("listMessage");

const MASK = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";


// Small helper: create an element with a class and text.
function el(tag, className, text) {

    const node = document.createElement(tag);

    if (className) {
        node.className = className;
    }

    if (text !== undefined) {
        node.textContent = text;
    }

    return node;
}


function showEmpty(text) {

    passwordList.innerHTML = "";
    passwordList.appendChild(el("p", "empty-message", text));
}


async function loadPasswords() {

    if (!unlocked) {
        return;
    }

    showEmpty("Loading passwords...");

    try {

        const response = await fetch("/api/passwords");

        const result = await response.json();

        if (!response.ok) {
            showEmpty(result.message);
            return;
        }

        const passwords = result.passwords;

        if (!passwords || passwords.length === 0) {
            showEmpty("No passwords stored yet.");
            return;
        }

        passwordList.innerHTML = "";

        passwords.forEach((item) => {
            passwordList.appendChild(renderEntry(item));
        });

    } catch (error) {
        showEmpty("Could not load stored passwords.");
    }
}


// -------------------------
// ONE STORED ENTRY
// (built with textContent only, so stored values are never parsed as HTML)
// -------------------------

function renderEntry(item) {

    const card = el("div", "password-item");

    // ---- View mode ----
    const view = el("div", "entry-view");

    const head = el("div", "entry-head");
    head.appendChild(el("h3", "", item.website));

    const actions = el("div", "entry-actions");
    const editBtn = el("button", "secondary-btn btn-sm", "Edit");
    const deleteBtn = el("button", "danger-soft-btn btn-sm", "Delete");
    actions.append(editBtn, deleteBtn);
    head.appendChild(actions);

    const userRow = el("p", "entry-row");
    userRow.append(el("strong", "", "Username"), el("span", "", item.username));

    const passRow = el("p", "entry-row");
    const secret = el("span", "secret-value", MASK);
    const showBtn = el("button", "link-btn", "Show");
    const copyBtn = el("button", "link-btn", "Copy");
    passRow.append(el("strong", "", "Password"), secret, showBtn, copyBtn);

    view.append(head, userRow, passRow);

    // ---- Edit mode ----
    const form = el("div", "entry-edit hidden");

    const grid = el("div", "form-grid");

    const fields = [
        ["Website", "text", item.website],
        ["Username / Email", "text", item.username],
        ["Password", "password", item.password],
    ];

    const inputs = fields.map(([labelText, type, value]) => {
        const wrap = el("div");
        const label = el("label", "", labelText);
        const input = document.createElement("input");
        input.type = type;
        input.value = value;
        wrap.append(label, input);
        grid.appendChild(wrap);
        return input;
    });

    const [siteInput, userInput, passInput] = inputs;

    const formButtons = el("div", "button-row");
    const saveBtn = el("button", "primary-btn", "Save Changes");
    const genBtn = el("button", "secondary-btn", "Generate Password");
    const cancelBtn = el("button", "secondary-btn", "Cancel");
    formButtons.append(saveBtn, genBtn, cancelBtn);

    form.append(grid, formButtons);

    card.append(view, form);

    // ---- Behaviour ----

    showBtn.addEventListener("click", () => {
        const hidden = secret.textContent === MASK;
        secret.textContent = hidden ? item.password : MASK;
        showBtn.textContent = hidden ? "Hide" : "Show";
    });

    copyBtn.addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText(item.password);
            listMessage.textContent = "Password copied.";
        } catch (error) {
            listMessage.textContent = "Copy is not available in this browser.";
        }
    });

    editBtn.addEventListener("click", () => {
        view.classList.add("hidden");
        form.classList.remove("hidden");
        listMessage.textContent = "";
        siteInput.focus();
    });

    cancelBtn.addEventListener("click", () => {
        siteInput.value = item.website;
        userInput.value = item.username;
        passInput.value = item.password;
        form.classList.add("hidden");
        view.classList.remove("hidden");
    });

    genBtn.addEventListener("click", async () => {
        try {
            const response = await fetch("/api/generate", { method: "POST" });
            const result = await response.json();
            if (response.ok) {
                passInput.value = result.password;
                passInput.type = "text";
            }
        } catch (error) {
            listMessage.textContent = "Could not generate password.";
        }
    });

    saveBtn.addEventListener("click", async () => {

        if (!siteInput.value.trim() || !userInput.value.trim() || !passInput.value) {
            listMessage.textContent = "Website, username and password are required.";
            return;
        }

        try {

            const { ok, result } = await postJson("/api/edit", {
                id: item.id,
                website: siteInput.value.trim(),
                username: userInput.value.trim(),
                password: passInput.value
            });

            listMessage.textContent = result.message;

            if (ok) {
                await loadPasswords();
            }

        } catch (error) {
            listMessage.textContent = "Could not update the entry.";
        }
    });

    deleteBtn.addEventListener("click", async () => {

        const sure = window.confirm(
            `Delete ${item.website}? This cannot be undone.`
        );

        if (!sure) {
            return;
        }

        try {

            const { ok, result } = await postJson("/api/delete", {
                id: item.id
            });

            listMessage.textContent = result.message;

            if (ok) {
                await loadPasswords();
            }

        } catch (error) {
            listMessage.textContent = "Could not delete the entry.";
        }
    });

    return card;
}


// -------------------------
// REFRESH BUTTON
// -------------------------

refreshBtn.addEventListener("click", async () => {

    if (!unlocked) {
        return;
    }

    await loadPasswords();
});


// -------------------------
// BASIC HTML ESCAPING
// -------------------------

function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

// -------------------------
// SECURITY ACTIONS
// -------------------------

const changeMasterBtn = document.getElementById("changeMasterBtn");
const backupBtn = document.getElementById("backupBtn");
const restoreBtn = document.getElementById("restoreBtn");

const changeMasterForm = document.getElementById("changeMasterForm");
const currentMaster = document.getElementById("currentMaster");
const newMaster = document.getElementById("newMaster");
const confirmMaster = document.getElementById("confirmMaster");
const saveMasterBtn = document.getElementById("saveMasterBtn");
const cancelMasterBtn = document.getElementById("cancelMasterBtn");

const restoreForm = document.getElementById("restoreForm");
const backupPassword = document.getElementById("backupPassword");
const confirmRestoreBtn = document.getElementById("confirmRestoreBtn");
const cancelRestoreBtn = document.getElementById("cancelRestoreBtn");


function clearSecurityForms() {

    currentMaster.value = "";
    newMaster.value = "";
    confirmMaster.value = "";
    backupPassword.value = "";

    changeMasterForm.classList.add("hidden");
    restoreForm.classList.add("hidden");
}


async function postJson(url, body) {

    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(body || {})
    });

    const result = await response.json();

    return { ok: response.ok, result };
}


// Clear password fields whenever the vault is locked.
lockBtn.addEventListener("click", () => {
    clearSecurityForms();
    securityMessage.textContent = "";
    listMessage.textContent = "";
});


// ---- Change master password ----

changeMasterBtn.addEventListener("click", () => {

    if (!unlocked) {
        securityMessage.textContent = "Unlock the vault first.";
        return;
    }

    restoreForm.classList.add("hidden");
    changeMasterForm.classList.remove("hidden");
    securityMessage.textContent = "";
    currentMaster.focus();
});

cancelMasterBtn.addEventListener("click", () => {
    clearSecurityForms();
    securityMessage.textContent = "Master password not changed.";
});

saveMasterBtn.addEventListener("click", async () => {

    if (!currentMaster.value || !newMaster.value || !confirmMaster.value) {
        securityMessage.textContent = "Please fill in all three password fields.";
        return;
    }

    if (newMaster.value !== confirmMaster.value) {
        securityMessage.textContent = "New passwords do not match.";
        return;
    }

    securityMessage.textContent = "Re-encrypting vault...";

    try {

        const { ok, result } = await postJson("/api/change-master", {
            currentPassword: currentMaster.value,
            newPassword: newMaster.value,
            confirmPassword: confirmMaster.value
        });

        if (!ok) {
            const tips = result.tips && result.tips.length
                ? " " + result.tips.join(" ")
                : "";
            securityMessage.textContent = result.message + tips;
            return;
        }

        clearSecurityForms();
        securityMessage.textContent = result.message;

    } catch (error) {
        securityMessage.textContent = "Could not change the master password.";
    }
});


// ---- Backup ----

backupBtn.addEventListener("click", async () => {

    if (!unlocked) {
        securityMessage.textContent = "Unlock the vault first.";
        return;
    }

    clearSecurityForms();
    securityMessage.textContent = "Creating encrypted backup...";

    try {

        const { result } = await postJson("/api/backup");
        securityMessage.textContent = result.message;

    } catch (error) {
        securityMessage.textContent = "Backup could not be created.";
    }
});


// ---- Restore ----

restoreBtn.addEventListener("click", () => {

    if (!unlocked) {
        securityMessage.textContent = "Unlock the vault first.";
        return;
    }

    changeMasterForm.classList.add("hidden");
    restoreForm.classList.remove("hidden");
    securityMessage.textContent = "";
    backupPassword.focus();
});

cancelRestoreBtn.addEventListener("click", () => {
    clearSecurityForms();
    securityMessage.textContent = "Restore cancelled.";
});

confirmRestoreBtn.addEventListener("click", async () => {

    if (!backupPassword.value) {
        securityMessage.textContent = "Enter the backup's master password.";
        return;
    }

    const sure = window.confirm(
        "Replace the current vault with the backup? " +
        "Entries added after the backup was made will no longer be in the vault " +
        "(a safety copy of the current vault is kept)."
    );

    if (!sure) {
        securityMessage.textContent = "Restore cancelled.";
        return;
    }

    securityMessage.textContent = "Verifying backup...";

    try {

        const { ok, result } = await postJson("/api/restore", {
            backupPassword: backupPassword.value
        });

        securityMessage.textContent = result.message;

        if (ok) {
            clearSecurityForms();
            securityMessage.textContent = result.message;
            await loadPasswords();
        }

    } catch (error) {
        securityMessage.textContent = "Could not restore the backup.";
    }
});