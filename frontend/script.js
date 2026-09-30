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

lockBtn.addEventListener("click", () => {

    unlocked = false;

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

async function loadPasswords() {

    if (!unlocked) {
        return;
    }

    passwordList.innerHTML = `
        <p class="empty-message">
            Loading passwords...
        </p>
    `;

    try {

        const response = await fetch("/api/passwords");

        const result = await response.json();

        if (!response.ok) {
            passwordList.innerHTML = `
                <p class="empty-message">
                    ${result.message}
                </p>
            `;
            return;
        }

        const passwords = result.passwords;

        if (!passwords || passwords.length === 0) {

            passwordList.innerHTML = `
                <p class="empty-message">
                    No passwords stored yet.
                </p>
            `;

            return;
        }

        passwordList.innerHTML = "";

        passwords.forEach((item) => {

            const passwordItem = document.createElement("div");

            passwordItem.className = "password-item";

            passwordItem.innerHTML = `
                <h3>${escapeHtml(item.website)}</h3>
                <p>
                    <strong>Username:</strong>
                    ${escapeHtml(item.username)}
                </p>
                <p>
                    <strong>Password:</strong>
                    ${escapeHtml(item.password)}
                </p>
            `;

            passwordList.appendChild(passwordItem);
        });

    } catch (error) {

        passwordList.innerHTML = `
            <p class="empty-message">
                Could not load stored passwords.
            </p>
        `;
    }
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