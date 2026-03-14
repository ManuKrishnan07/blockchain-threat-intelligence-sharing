const API = "http://127.0.0.1:8000";

// ════════════════════════════════════════════
//  NAVIGATION
// ════════════════════════════════════════════
function showPage(id) {
    document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
    document.querySelectorAll("nav ul li").forEach(l => l.classList.remove("active"));
    document.getElementById("page-" + id).classList.add("active");
    document.getElementById("nav-" + id).classList.add("active");

    if (id === "dashboard")   loadDashboard();
    if (id === "feed")        loadFeed();
    if (id === "leaderboard") loadLeaderboard();
}

// ════════════════════════════════════════════
//  DASHBOARD
// ════════════════════════════════════════════
let charts = {};

async function loadDashboard() {
    try {
        const [statsRes, feedRes] = await Promise.all([
            fetch(`${API}/stats`),
            fetch(`${API}/threat-feed?limit=5`)
        ]);
        const stats = await statsRes.json();
        const feed  = await feedRes.json();

        document.getElementById("s-total").textContent    = stats.total_indicators;
        document.getElementById("s-critical").textContent = stats.by_severity.critical;
        document.getElementById("s-high").textContent     = stats.by_severity.high;
        document.getElementById("s-7d").textContent       = stats.last_7_days;

        renderDashboardCharts(stats);
        renderRecentTable(feed);
    } catch (e) {
        console.error("Dashboard load error:", e);
    }
}

function renderDashboardCharts(stats) {
    // Destroy old chart instances if they exist
    if (charts.severity) charts.severity.destroy();
    if (charts.types)    charts.types.destroy();

    const severityCtx = document.getElementById("chart-severity").getContext("2d");
    charts.severity = new Chart(severityCtx, {
        type: "doughnut",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                data: [
                    stats.by_severity.critical,
                    stats.by_severity.high,
                    stats.by_severity.medium,
                    stats.by_severity.low
                ],
                backgroundColor: ["#f85149", "#e67e22", "#f1c40f", "#2ecc71"],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { labels: { color: "#c9d1d9" } } }
        }
    });

    const typesCtx = document.getElementById("chart-types").getContext("2d");
    charts.types = new Chart(typesCtx, {
        type: "bar",
        data: {
            labels: ["IP Address", "Domain", "File Hash"],
            datasets: [{
                label: "Count",
                data: [stats.by_type.ip, stats.by_type.domain, stats.by_type.hash],
                backgroundColor: ["#58a6ff", "#bc8cff", "#ff7b72"],
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: "#8b949e" }, grid: { color: "#21262d" } },
                y: { ticks: { color: "#8b949e", precision: 0 }, grid: { color: "#21262d" } }
            }
        }
    });
}

function renderRecentTable(items) {
    const container = document.getElementById("dash-recent");
    if (!items.length) { container.innerHTML = "<p style='color:#8b949e'>No indicators yet.</p>"; return; }

    container.innerHTML = `<table>
        <thead><tr><th>Type</th><th>Value</th><th>Category</th><th>Severity</th><th>Hash</th></tr></thead>
        <tbody>
        ${items.map(i => `<tr>
            <td>${i.indicator_type}</td>
            <td>${i.indicator_value}</td>
            <td>${i.threat_category}</td>
            <td><span class="sev sev-${i.severity}">${i.severity.toUpperCase()}</span></td>
            <td><code>${i.data_hash.substring(0, 12)}...</code></td>
        </tr>`).join("")}
        </tbody>
    </table>`;
}

// ════════════════════════════════════════════
//  SUBMIT IOC
// ════════════════════════════════════════════
document.getElementById("submitForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn    = document.getElementById("submit-btn");
    const result = document.getElementById("submit-result");

    btn.disabled    = true;
    btn.textContent = "⏳ Writing to blockchain...";
    result.style.display = "none";

    const payload = {
        indicator_type:  document.getElementById("f-type").value,
        indicator_value: document.getElementById("f-value").value.trim(),
        threat_category: document.getElementById("f-category").value.trim(),
        severity:        document.getElementById("f-severity").value,
        reporter_id:     document.getElementById("f-reporter").value.trim() || "anonymous",
        description:     document.getElementById("f-desc").value.trim(),
    };

    try {
        const res  = await fetch(`${API}/submit-indicator`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify(payload)
        });
        const data = await res.json();

        if (res.ok) {
            result.className   = "result success";
            result.innerHTML   = `
                <strong>✅ Indicator anchored to blockchain!</strong><br>
                <strong>Data Hash:</strong> <code>${data.data_hash}</code><br>
                <strong>TX Hash:</strong> <code>${data.tx_hash}</code><br>
                <em>Copy your Data Hash to verify integrity later.</em>
            `;
            document.getElementById("submitForm").reset();
        } else {
            throw new Error(data.detail || "Submission failed.");
        }
    } catch (err) {
        result.className = "result error";
        result.innerHTML = `❌ ${err.message}`;
    } finally {
        result.style.display = "block";
        btn.disabled    = false;
        btn.textContent = "⛓️ Submit to Blockchain";
    }
});

// ════════════════════════════════════════════
//  SEARCH
// ════════════════════════════════════════════
async function searchIndicator() {
    const val    = document.getElementById("search-input").value.trim();
    const target = document.getElementById("search-result");
    if (!val) return;

    target.innerHTML = "<p>Searching...</p>";
    try {
        const res  = await fetch(`${API}/indicator/${encodeURIComponent(val)}`);
        const data = await res.json();

        if (res.ok) {
            target.innerHTML = `
                <div class="result info">
                    <strong>📌 ${data.indicator_type.toUpperCase()}: ${data.indicator_value}</strong><br>
                    <strong>Category:</strong> ${data.threat_category}<br>
                    <strong>Severity:</strong> <span class="sev sev-${data.severity}">${data.severity.toUpperCase()}</span><br>
                    <strong>Reporter:</strong> ${data.reporter_id}<br>
                    <strong>Description:</strong> ${data.description}<br>
                    <strong>Blockchain Status:</strong> ${data.blockchain_status === "confirmed" ? "✅ Confirmed" : "⚠️ Unconfirmed"}<br>
                    <strong>Data Hash:</strong> <code>${data.data_hash}</code><br>
                    <button onclick="prefillVerify('${data.data_hash}')" style="margin-top:10px">Verify This Hash</button>
                </div>`;
        } else {
            target.innerHTML = `<div class="result error">❌ ${data.detail}</div>`;
        }
    } catch (e) {
        target.innerHTML = `<div class="result error">❌ Network error.</div>`;
    }
}

function prefillVerify(hash) {
    document.getElementById("verify-input").value = hash;
    document.getElementById("verify-input").scrollIntoView({ behavior: "smooth" });
}

// ════════════════════════════════════════════
//  VERIFY
// ════════════════════════════════════════════
async function verifyIndicator() {
    const hash   = document.getElementById("verify-input").value.trim();
    const target = document.getElementById("verify-result");
    if (!hash) return;

    target.innerHTML = "<p>Querying blockchain...</p>";
    try {
        const res  = await fetch(`${API}/verify/${encodeURIComponent(hash)}`);
        const data = await res.json();

        const statusMap = {
            VALID:        { cls: "success", icon: "✅", label: "Integrity Verified — Data matches blockchain record." },
            TAMPERED:     { cls: "error",   icon: "🚨", label: "TAMPERED — Database record has been modified!" },
            NOT_ON_CHAIN: { cls: "warning", icon: "⚠️", label: "Not found on blockchain." }
        };
        const s = statusMap[data.status] || { cls: "info", icon: "ℹ️", label: data.status };

        target.innerHTML = `
            <div class="result ${s.cls}">
                ${s.icon} <strong>${s.label}</strong><br>
                ${data.blockchain_reporter ? `<strong>On-Chain Reporter:</strong> ${data.blockchain_reporter}<br>` : ""}
                ${data.blockchain_timestamp ? `<strong>On-Chain Timestamp:</strong> ${new Date(data.blockchain_timestamp * 1000).toUTCString()}<br>` : ""}
                ${data.detail ? `<em>${data.detail}</em>` : ""}
            </div>`;
    } catch (e) {
        target.innerHTML = `<div class="result error">❌ Network error.</div>`;
    }
}

// ════════════════════════════════════════════
//  THREAT FEED
// ════════════════════════════════════════════
async function loadFeed() {
    const severity = document.getElementById("feed-severity").value;
    const type     = document.getElementById("feed-type").value;
    const tbody    = document.getElementById("feed-body");

    tbody.innerHTML = "<tr><td colspan='6' style='text-align:center;color:#8b949e'>Loading...</td></tr>";

    let url = `${API}/threat-feed?limit=50`;
    if (severity) url += `&severity=${severity}`;
    if (type)     url += `&ioc_type=${type}`;

    try {
        const res  = await fetch(url);
        const data = await res.json();

        tbody.innerHTML = data.length
            ? data.map(i => `<tr>
                <td>${i.indicator_type}</td>
                <td><code>${i.indicator_value}</code></td>
                <td>${i.threat_category}</td>
                <td><span class="sev sev-${i.severity}">${i.severity.toUpperCase()}</span></td>
                <td>${i.reporter_id}</td>
                <td><code title="${i.data_hash}">${i.data_hash.substring(0, 12)}...</code></td>
            </tr>`).join("")
            : "<tr><td colspan='6' style='text-align:center;color:#8b949e'>No results.</td></tr>";
    } catch (e) {
        tbody.innerHTML = "<tr><td colspan='6'>Error loading feed.</td></tr>";
    }
}

async function exportSTIX() {
    window.open(`${API}/export/stix`, "_blank");
}

// ════════════════════════════════════════════
//  LEADERBOARD
// ════════════════════════════════════════════
async function loadLeaderboard() {
    const tbody = document.getElementById("leaderboard-body");
    tbody.innerHTML = "<tr><td colspan='5' style='text-align:center;color:#8b949e'>Loading...</td></tr>";

    try {
        const res  = await fetch(`${API}/leaderboard`);
        const data = await res.json();

        tbody.innerHTML = data.map((r, i) => `<tr>
            <td>${["🥇","🥈","🥉"][i] || (i + 1)}</td>
            <td>${r.reporter_id}</td>
            <td>${r.submissions}</td>
            <td>${r.verified_count}</td>
            <td><strong>${r.reputation_score.toFixed(1)}</strong></td>
        </tr>`).join("") || "<tr><td colspan='5' style='text-align:center;color:#8b949e'>No contributors yet.</td></tr>";
    } catch (e) {
        tbody.innerHTML = "<tr><td colspan='5'>Error loading leaderboard.</td></tr>";
    }
}

async function lookupReporter() {
    const id     = document.getElementById("reporter-input").value.trim();
    const target = document.getElementById("reporter-result");
    if (!id) return;

    try {
        const res  = await fetch(`${API}/reporter/${id}`);
        const data = await res.json();

        target.innerHTML = `<div class="result info">
            <strong>${data.reporter_id}</strong><br>
            Submissions: <strong>${data.submissions}</strong> &nbsp;|&nbsp;
            Verified: <strong>${data.verified_count}</strong> &nbsp;|&nbsp;
            Score: <strong>${data.reputation_score.toFixed(1)}</strong><br>
            Last Submission: ${data.last_submission ? new Date(data.last_submission * 1000).toLocaleString() : "N/A"}
        </div>`;
    } catch (e) {
        target.innerHTML = `<div class="result error">Reporter not found.</div>`;
    }
}

// ════════════════════════════════════════════
//  BOOT
// ════════════════════════════════════════════
loadDashboard();