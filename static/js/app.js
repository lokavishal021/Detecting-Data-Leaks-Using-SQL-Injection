// Global Application State
let appState = {
    isLoggedIn: false,
    username: null,
    userId: null,
    capabilities: [],
    authTab: 'login',
    wafEnabled: true,
    parameterizedEnabled: true,
    decryptionEnabled: true,
    capabilityCheckEnabled: true
};

// Auto-run on load
document.addEventListener("DOMContentLoaded", () => {
    checkSession();
    // Initialize toggles from DOM
    appState.wafEnabled = document.getElementById("toggle-waf").checked;
    appState.parameterizedEnabled = document.getElementById("toggle-parameterized").checked;
    appState.decryptionEnabled = document.getElementById("toggle-decryption").checked;
    appState.capabilityCheckEnabled = document.getElementById("toggle-capability").checked;
    
    // Poll SOC logs periodically (every 5 seconds)
    fetchSecurityLogs();
    setInterval(fetchSecurityLogs, 5000);
});

// Check if user session exists
async function checkSession() {
    try {
        const response = await fetch("/api/profile");
        if (response.ok) {
            const data = await response.json();
            setLoggedInState(true, data.username, data.user_id);
        } else {
            setLoggedInState(false);
        }
    } catch (e) {
        console.error("Session check failed", e);
        setLoggedInState(false);
    }
}

function setLoggedInState(loggedIn, username = null, userId = null) {
    appState.isLoggedIn = loggedIn;
    appState.username = username;
    appState.userId = userId;
    
    const authSection = document.getElementById("auth-section");
    const sessionInfo = document.getElementById("session-info");
    const capList = document.getElementById("cap-tokens-list");
    
    if (loggedIn) {
        authSection.classList.add("hidden");
        sessionInfo.innerHTML = `
            <span class="user-details"><i class="fa-solid fa-user-shield"></i> ${username}</span>
            <button class="btn btn-sm btn-outline" style="margin-left: 10px;" onclick="handleLogout()">Logout</button>
        `;
        fetchCapabilities();
        fetchVaultItems();
    } else {
        authSection.classList.remove("hidden");
        sessionInfo.innerHTML = `
            <span class="anon-user"><i class="fa-solid fa-user-secret"></i> Anonymous (Simulator Mode)</span>
        `;
        capList.innerHTML = `<div class="empty-state">Register or Log in to mint capability tokens.</div>`;
        document.getElementById("vault-items-list").innerHTML = `<div class="empty-state">Please log in to view database records.</div>`;
    }
}

// Switch between Login and Register tabs
function switchAuthTab(tab) {
    appState.authTab = tab;
    document.getElementById("tab-login").classList.toggle("active", tab === 'login');
    document.getElementById("tab-register").classList.toggle("active", tab === 'register');
    
    document.getElementById("auth-title").innerText = tab === 'login' ? "System Access" : "Create Guard Account";
    document.getElementById("auth-btn").innerText = tab === 'login' ? "Authenticate" : "Register Credentials";
    document.getElementById("auth-error-msg").innerText = "";
}

// Authenticate / Register form submit
async function handleAuthSubmit(event) {
    event.preventDefault();
    const userEl = document.getElementById("auth-username");
    const passEl = document.getElementById("auth-password");
    const errEl = document.getElementById("auth-error-msg");
    
    const username = userEl.value.trim();
    const password = passEl.value.trim();
    errEl.innerText = "";
    
    const endpoint = appState.authTab === 'login' ? "/api/login" : "/api/register";
    
    try {
        const response = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        if (response.ok) {
            if (appState.authTab === 'login') {
                setLoggedInState(true, data.username);
                userEl.value = "";
                passEl.value = "";
            } else {
                errEl.style.color = "var(--color-success)";
                errEl.innerText = "Account created. Switching to login...";
                setTimeout(() => {
                    switchAuthTab('login');
                    errEl.style.color = "var(--color-danger)";
                    errEl.innerText = "";
                }, 1500);
            }
        } else {
            errEl.innerText = data.error || "Authentication failed.";
        }
    } catch (e) {
        errEl.innerText = "Network connection failed.";
    }
    fetchSecurityLogs();
}

async function handleLogout() {
    await fetch("/api/logout", { method: "POST" });
    setLoggedInState(false);
}

// Accordion toggle helper
function toggleAccordion(id) {
    const el = document.getElementById(id);
    el.classList.toggle("hidden");
}

// Fetch capability tokens
async function fetchCapabilities() {
    if (!appState.isLoggedIn) return;
    try {
        const response = await fetch("/api/capabilities");
        if (response.ok) {
            const data = await response.json();
            appState.capabilities = data;
            renderCapabilities();
        }
    } catch (e) {
        console.error("Failed to fetch capabilities", e);
    }
}

function renderCapabilities() {
    const listEl = document.getElementById("cap-tokens-list");
    if (appState.capabilities.length === 0) {
        listEl.innerHTML = `<div class="empty-state">No active tokens. Create one.</div>`;
        return;
    }
    
    listEl.innerHTML = appState.capabilities.map(cap => `
        <div class="cap-item">
            <div class="cap-details">
                <span class="cap-scope">${cap.scope}</span>
                <span class="cap-code" title="Click to copy" onclick="navigator.clipboard.writeText('${cap.code}'); alert('Token copied!');">${cap.code}</span>
            </div>
            <button class="btn btn-sm btn-danger-outline" onclick="revokeCapability('${cap.code}')"><i class="fa-solid fa-trash"></i></button>
        </div>
    `).join("");
}

async function generateNewCapCode() {
    const scopes = ["vault:read", "vault:write", "vault:delete"];
    const scope = prompt(`Enter scope index (1: vault:read, 2: vault:write, 3: vault:delete):`);
    if (!scope) return;
    
    const selectedScope = scopes[parseInt(scope) - 1];
    if (!selectedScope) {
        alert("Invalid selection");
        return;
    }
    
    try {
        const response = await fetch("/api/capabilities", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scope: selectedScope })
        });
        if (response.ok) {
            fetchCapabilities();
        } else {
            const err = await response.json();
            alert(err.error);
        }
    } catch (e) {
        alert("Minting failed");
    }
}

async function revokeCapability(code) {
    if (!confirm("Are you sure you want to revoke this capability token?")) return;
    try {
        const response = await fetch("/api/capabilities", {
            method: "DELETE",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code })
        });
        if (response.ok) {
            fetchCapabilities();
        }
    } catch (e) {
        alert("Revocation failed");
    }
}

// Autofill capability code into various fields
function autofillCapCode(action) {
    let scopeNeeded = `vault:${action}`;
    let match = appState.capabilities.find(c => c.scope === scopeNeeded);
    if (!match) {
        // Find generic any
        match = appState.capabilities[0];
    }
    
    if (match) {
        if (action === 'read') {
            document.getElementById("sim-capability").value = match.code;
            document.getElementById("vault-read-cap").value = match.code;
        } else if (action === 'write') {
            document.getElementById("vault-write-cap").value = match.code;
        }
    } else {
        alert("No suitable capability token found in your account. Generate one first.");
    }
}

// --- SECURE VAULT DATA HANDLERS ---

async function fetchVaultItems() {
    if (!appState.isLoggedIn) return;
    const readCap = document.getElementById("vault-read-cap").value.trim();
    const itemsList = document.getElementById("vault-items-list");
    
    let url = "/api/vault";
    if (readCap) {
        url += `?capability_code=${encodeURIComponent(readCap)}`;
    }
    
    // Pass capability check header toggle to showcase bypass
    const headers = {
        "X-Enable-WAF": appState.wafEnabled ? "true" : "false",
        "X-Enable-Capability": appState.capabilityCheckEnabled ? "true" : "false"
    };
    
    try {
        const response = await fetch(url, { headers });
        if (response.ok) {
            const data = await response.json();
            renderVaultItems(data);
        } else {
            const err = await response.json();
            itemsList.innerHTML = `<div class="empty-state text-danger">${err.error}</div>`;
        }
    } catch (e) {
        itemsList.innerHTML = `<div class="empty-state text-danger">Server fetch failure.</div>`;
    }
}

function renderVaultItems(items) {
    const listEl = document.getElementById("vault-items-list");
    if (items.length === 0) {
        listEl.innerHTML = `<div class="empty-state">No records found.</div>`;
        return;
    }
    
    listEl.innerHTML = items.map(item => {
        const isDecrypted = !item.content.startsWith("[Decryption Failed") && !item.content.includes("Error");
        return `
            <div class="vault-item">
                <div class="vault-item-header">
                    <span class="vault-item-title">${item.title}</span>
                    <span class="vault-item-badge ${isDecrypted ? 'badge-decrypted' : 'badge-encrypted'}">
                        ${isDecrypted ? 'AES Decrypted' : 'Encrypted Hex'}
                    </span>
                </div>
                <div class="vault-item-content">
                    ${isDecrypted ? item.content : item.encrypted_raw}
                </div>
                <button class="btn btn-sm btn-danger-outline margin-top-xs" onclick="deleteVaultItem(${item.id})">
                    <i class="fa-solid fa-trash-can"></i> Delete
                </button>
            </div>
        `;
    }).join("");
}

async function addVaultItem() {
    const cap = document.getElementById("vault-write-cap").value.trim();
    const title = document.getElementById("vault-title").value.trim();
    const content = document.getElementById("vault-content").value.trim();
    
    if (!title || !content) {
        alert("Title and content are required.");
        return;
    }
    
    const headers = {
        "Content-Type": "application/json",
        "X-Enable-WAF": appState.wafEnabled ? "true" : "false",
        "X-Enable-Capability": appState.capabilityCheckEnabled ? "true" : "false"
    };
    
    try {
        const response = await fetch("/api/vault", {
            method: "POST",
            headers,
            body: JSON.stringify({ capability_code: cap, title, content })
        });
        
        const data = await response.json();
        if (response.ok) {
            document.getElementById("vault-title").value = "";
            document.getElementById("vault-content").value = "";
            alert("Saved and encrypted in DB!");
            fetchVaultItems();
        } else {
            alert(data.error);
        }
    } catch (e) {
        alert("Failed to save item.");
    }
    fetchSecurityLogs();
}

async function deleteVaultItem(id) {
    const cap = prompt("Provide delete capability code:");
    if (!cap) return;
    
    const headers = {
        "Content-Type": "application/json",
        "X-Enable-WAF": appState.wafEnabled ? "true" : "false",
        "X-Enable-Capability": appState.capabilityCheckEnabled ? "true" : "false"
    };
    
    try {
        const response = await fetch("/api/vault", {
            method: "DELETE",
            headers,
            body: JSON.stringify({ capability_code: cap, item_id: id })
        });
        
        if (response.ok) {
            alert("Deleted successfully.");
            fetchVaultItems();
        } else {
            const err = await response.json();
            alert(err.error);
        }
    } catch (e) {
        alert("Delete failed.");
    }
    fetchSecurityLogs();
}

// --- SOC SECURITY LOGS TABLE ---

async function fetchSecurityLogs() {
    try {
        const response = await fetch("/api/logs");
        if (response.ok) {
            const logs = await response.json();
            renderSecurityLogs(logs);
        }
    } catch (e) {
        console.error("SOC fetch failure", e);
    }
}

function renderSecurityLogs(logs) {
    const tableBody = document.getElementById("soc-logs-table-body");
    
    // Update dashboard statistics
    const totalBlocks = logs.filter(l => l.action_taken.includes("BLOCKED")).length;
    document.getElementById("stat-total-blocks").innerText = totalBlocks;
    
    let maxScore = 0;
    if (logs.length > 0) {
        maxScore = Math.max(...logs.map(l => l.threat_score));
    }
    document.getElementById("stat-max-score").innerText = `${maxScore} / 5`;
    
    const statusEl = document.getElementById("stat-status");
    if (logs.some(l => l.action_taken === "PASSED" && l.threat_score >= 3)) {
        statusEl.innerText = "CRITICAL LEAK";
        statusEl.className = "stat-value text-red";
        document.getElementById("protection-status").innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Compromised!`;
        document.getElementById("protection-status").className = "status-indicator-badge danger-status";
    } else if (maxScore >= 3) {
        statusEl.innerText = "ATTACKS BLOCKED";
        statusEl.className = "stat-value text-yellow";
        document.getElementById("protection-status").innerHTML = `<i class="fa-solid fa-circle-half-stroke"></i> Threat Blocked`;
        document.getElementById("protection-status").className = "status-indicator-badge warning-status";
    } else {
        statusEl.innerText = "SAFE";
        statusEl.className = "stat-value text-green";
        document.getElementById("protection-status").innerHTML = `<i class="fa-solid fa-circle-check"></i> Layer 1 & 2 Active`;
        document.getElementById("protection-status").className = "status-indicator-badge";
    }
    
    if (logs.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="6" class="table-empty">No security incidents logged. Simulate attacks above.</td></tr>`;
        return;
    }
    
    tableBody.innerHTML = logs.map(log => {
        const date = new Date(log.timestamp);
        const timeStr = date.toLocaleTimeString();
        
        let actionBadge = `<span class="threat-badge badge-blocked">Blocked</span>`;
        if (log.action_taken === "PASSED") {
            // Check if threat score is high (SQLi passed through WAF)
            actionBadge = log.threat_score >= 3 
                ? `<span class="threat-badge badge-leak">DATA LEAK</span>` 
                : `<span class="threat-badge badge-passed">Allowed</span>`;
        } else if (log.action_taken.includes("CAPABILITY")) {
            actionBadge = `<span class="threat-badge badge-blocked">Auth Blocked</span>`;
        }
        
        let scoreClass = "";
        if (log.threat_score >= 4) scoreClass = "score-high";
        else if (log.threat_score >= 2) scoreClass = "score-med";
        
        return `
            <tr>
                <td>${timeStr}</td>
                <td>${log.username || 'Guest'}</td>
                <td>${log.ip_address}</td>
                <td style="font-family: var(--font-mono); font-size: 0.8rem; word-break: break-all;">${log.payload}</td>
                <td><span class="threat-score-pill ${scoreClass}">${log.threat_score}</span></td>
                <td>${actionBadge}</td>
            </tr>
        `;
    }).join("");
}

async function clearSecurityLogs() {
    if (!confirm("Reset threat logs database table?")) return;
    try {
        await fetch("/api/logs", { method: "DELETE" });
        fetchSecurityLogs();
    } catch (e) {
        alert("Failed to clear logs");
    }
}


// --- INTERACTIVE SIMULATION PANEL ---

function loadSamplePayload(type) {
    const payloadEl = document.getElementById("sim-payload");
    if (type === 'normal') {
        payloadEl.value = "SSN";
    } else if (type === 'tautology') {
        payloadEl.value = "Grades' OR '1'='1";
    } else if (type === 'union') {
        payloadEl.value = "SSN' UNION SELECT 1, 999, 'Credit Card Hack', '9999-8888-7777-6666', '2026-06-13' --";
    } else if (type === 'stack') {
        payloadEl.value = "SSN'; UPDATE vault_data SET title = 'PWNED' WHERE id = 1; --";
    }
}

// Update settings state from toggles
function updateSystemStatus() {
    appState.wafEnabled = document.getElementById("toggle-waf").checked;
    appState.parameterizedEnabled = document.getElementById("toggle-parameterized").checked;
    appState.decryptionEnabled = document.getElementById("toggle-decryption").checked;
    appState.capabilityCheckEnabled = document.getElementById("toggle-capability").checked;
    
    // Change protection status class
    const badge = document.getElementById("protection-status");
    if (!appState.wafEnabled && !appState.parameterizedEnabled) {
        badge.className = "status-indicator-badge danger-status";
        badge.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> Vulnerable!`;
    } else if (!appState.wafEnabled || !appState.parameterizedEnabled || !appState.capabilityCheckEnabled) {
        badge.className = "status-indicator-badge warning-status";
        badge.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Weakened Protection`;
    } else {
        badge.className = "status-indicator-badge";
        badge.innerHTML = `<i class="fa-solid fa-circle-check"></i> Layer 1 & 2 Active`;
    }
}

// Execute simulator
async function runSimulation() {
    const payload = document.getElementById("sim-payload").value;
    const capabilityCode = document.getElementById("sim-capability").value.trim();
    const term = document.getElementById("sim-terminal");
    
    // Add command print to terminal
    term.innerHTML += `
        <div class="terminal-line input-cmd">
            $ python search_vault.py --search="${payload}" --cap="${capabilityCode || 'None'}"
        </div>
    `;
    
    const reqBody = {
        payload,
        capability_code: capabilityCode,
        waf_enabled: appState.wafEnabled,
        parameterized_enabled: appState.parameterizedEnabled,
        decryption_enabled: appState.decryptionEnabled,
        capability_check_enabled: appState.capabilityCheckEnabled
    };
    
    try {
        const response = await fetch("/api/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(reqBody)
        });
        
        if (response.ok) {
            const data = await response.json();
            
            // Render detailed terminal output based on returned simulation status
            term.innerHTML += `
                <div class="terminal-line system-msg">> Engine: Generating SQL query...</div>
                <div class="terminal-line system-msg">> SQL Executed: <span style="color: #F59E0B;">${data.query_executed}</span></div>
            `;
            
            if (data.status === "BLOCKED") {
                term.innerHTML += `
                    <div class="terminal-line output-danger">
                        🛑 [BLOCKED] Layer 1 Security WAF intercepted SQL Injection payload!
                        <br>Threat Score: ${data.threat_score}/5
                        <br>Rules Triggered: ${data.rules_triggered.join(", ")}
                    </div>
                `;
            } else if (data.status === "UNAUTHORIZED") {
                term.innerHTML += `
                    <div class="terminal-line output-danger">
                        🚫 [BLOCKED] Layer 2 Capability Code failed authorization check.
                    </div>
                `;
            } else if (data.status === "SQL_ERROR") {
                term.innerHTML += `
                    <div class="terminal-line output-alert">
                        ⚠️ [SQL EXCEPTION ERROR] SQL engine threw compile error. Query aborted.
                        <br>SQLite Message: "${data.message}"
                    </div>
                `;
            } else if (data.status === "SUCCESS") {
                term.innerHTML += `
                    <div class="terminal-line output-success">
                        ✅ [SUCCESS] Query executed safely.
                    </div>
                `;
                
                // Show records returned
                if (data.results.length === 0) {
                    term.innerHTML += `<div class="terminal-line system-msg">No rows returned.</div>`;
                } else {
                    term.innerHTML += `<div class="terminal-line system-msg">> Returned ${data.results.length} rows. Rendering schema data:</div>`;
                    
                    // Format table
                    let tableStr = `<div style="background: rgba(0,0,0,0.5); padding: 0.5rem; border-radius: 4px; overflow-x: auto; margin-top: 0.5rem;">`;
                    tableStr += `<table style="width: 100%; border-collapse: collapse; font-size: 0.75rem; text-align: left;">`;
                    
                    // Headers
                    const headers = Object.keys(data.results[0]).filter(k => k !== 'is_decrypted');
                    tableStr += `<tr>` + headers.map(h => `<th style="padding: 2px 8px; border-bottom: 1px solid rgba(255,255,255,0.2); font-weight:bold;">${h}</th>`).join("") + `</tr>`;
                    
                    // Rows
                    data.results.forEach(row => {
                        // Detect if there's data belonging to another user (demonstrating dynamic SQL leakage)
                        let isDataLeak = false;
                        if (appState.isLoggedIn && row.user_id && row.user_id !== appState.userId) {
                            isDataLeak = true;
                        }
                        
                        tableStr += `<tr style="${isDataLeak ? 'background: rgba(239, 68, 68, 0.2); color: #EF4444;' : ''}">`;
                        headers.forEach(h => {
                            let cellVal = row[h];
                            
                            // Highlight if it's ciphertext
                            if (h === 'encrypted_content' && !row.is_decrypted) {
                                cellVal = `<span style="color: #F59E0B; font-style: italic;">[Ciphertext: ${cellVal.substring(0, 15)}...]</span>`;
                            }
                            
                            tableStr += `<td style="padding: 2px 8px; border-bottom: 1px solid rgba(255,255,255,0.05);">${cellVal}</td>`;
                        });
                        tableStr += `</tr>`;
                    });
                    
                    tableStr += `</table></div>`;
                    term.innerHTML += tableStr;
                    
                    // Check for severe leaks
                    const containsOtherUsers = data.results.some(row => appState.isLoggedIn && row.user_id && row.user_id !== appState.userId);
                    const isDecrypted = data.results.some(row => row.is_decrypted);
                    
                    if (containsOtherUsers && isDecrypted) {
                        term.innerHTML += `
                            <div class="terminal-line output-danger" style="margin-top: 0.5rem; font-weight: bold; animation: pulse 1s infinite;">
                                ☣️ [DATA LEAK ALERT] Attacker extracted plaintext data belonging to other system users! Layer 1 and Layer 2 are both compromised.
                            </div>
                        `;
                    } else if (containsOtherUsers && !isDecrypted) {
                        term.innerHTML += `
                            <div class="terminal-line output-alert" style="margin-top: 0.5rem;">
                                🔒 [ENCRYPTION SHIELD ACTIVE] Although SQLi bypassed query validation and fetched rows, the sensitive contents remain secure. The leaked content is AES-256 encrypted!
                            </div>
                        `;
                    }
                }
            }
        }
        
        // Scroll terminal to bottom
        term.scrollTop = term.scrollHeight;
    } catch (e) {
        term.innerHTML += `<div class="terminal-line output-danger">> Error making connection to simulator server.</div>`;
    }
    
    // Refresh SOC log
    fetchSecurityLogs();
}
