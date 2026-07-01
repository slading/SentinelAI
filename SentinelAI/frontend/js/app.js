document.addEventListener("DOMContentLoaded", () => {
    fetchStats();
    fetchHistory();
    setupWebSocket();

    // Attach simulation buttons
    document.querySelectorAll("[data-scenario]").forEach(btn => {
        btn.addEventListener("click", () => {
            const scenario = btn.getAttribute("data-scenario");
            simulateTransaction(scenario);
        });
    });
});

async function fetchStats() {
    try {
        const res = await fetch("/api/v1/stats");
        const data = await res.json();
        document.getElementById("kpi-tx").innerText = data.total_buffered_transactions || 0;
        document.getElementById("kpi-audit").innerText = data.total_audit_events || 0;
        document.getElementById("kpi-tickets").innerText = data.incidents_escalated || 0;
        document.getElementById("kpi-crit").innerText = data.critical_alerts || 0;
    } catch (e) {
        console.error("Failed to fetch stats", e);
    }
}

async function fetchHistory() {
    try {
        const res = await fetch("/api/v1/history?limit=5");
        const data = await res.json();
        // Just refresh stats after initial load
    } catch (e) {
        console.error("Failed to fetch history", e);
    }
}

async function simulateTransaction(scenario) {
    const feed = document.getElementById("incident-feed");
    const loader = document.createElement("div");
    loader.className = "incident-card";
    loader.innerHTML = `<p style="color: #60a5fa;">⏳ Running Pandas statistical filter & Groq AI LPU reasoning for <strong>${scenario}</strong>...</p>`;
    feed.prepend(loader);

    try {
        const res = await fetch(`/api/v1/simulate?scenario=${scenario}`, { method: "POST" });
        const data = await res.json();
        loader.remove();
        renderIncident(data);
        fetchStats();
    } catch (e) {
        loader.innerHTML = `<p style="color: #ef4444;">❌ Simulation failed: ${e.message}</p>`;
    }
}

function setupWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    try {
        const ws = new WebSocket(wsUrl);
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            renderIncident(data);
            fetchStats();
        };
        ws.onclose = () => {
            setTimeout(setupWebSocket, 3000);
        };
    } catch (e) {
        console.log("WS fallback mode active");
    }
}

function renderIncident(data) {
    const feed = document.getElementById("incident-feed");
    const tx = data.transaction;
    const verdict = data.verdict;
    const pandas = data.pandas_analysis;
    const auto = data.automation;

    const card = document.createElement("div");
    card.className = "incident-card";

    let autoText = `<span class="action-badge">Ticketing: PASS</span>`;
    if (auto.ticket_id) {
        autoText = `
            <span class="action-badge" style="color: #f59e0b;">🎫 Ticket: ${auto.ticket_id}</span>
            <span class="action-badge" style="color: #60a5fa;">📧 Email Sent</span>
            <span class="action-badge" style="color: #10b981;">📄 Report Saved</span>
        `;
    }

    card.innerHTML = `
        <div class="incident-header">
            <div>
                <span class="trace-id">${tx.trace_id}</span> &bull; 
                <strong style="color: #f8fafc;">${tx.user_id}</strong>
            </div>
            <span class="risk-tag risk-${verdict.risk_level}">${verdict.risk_level} (${(verdict.confidence_score * 100).toFixed(0)}%)</span>
        </div>
        
        <div class="incident-body">
            <div>
                <div style="color: #94a3b8;">Amount Attempted:</div>
                <div style="font-size: 16px; font-weight: bold; color: #f8fafc;">$${tx.amount.toLocaleString('en-US', {minimumFractionDigits: 2})} ${tx.currency}</div>
                <div style="font-size: 11px; color: #64748b;">Merchant: ${tx.merchant}</div>
            </div>
            <div>
                <div style="color: #94a3b8;">Location & Device:</div>
                <div style="color: #e2e8f0;">${tx.device.city}, ${tx.device.country_code}</div>
                <div style="font-size: 11px; color: #64748b;">Typology: ${verdict.fraud_typology}</div>
            </div>
        </div>

        <div class="reasoning-box">
            <strong style="color: #60a5fa;">🤖 Groq AI Verdict Reasoning:</strong><br>
            ${verdict.reasoning}
        </div>

        <div style="font-size: 12px; color: #94a3b8; margin-bottom: 10px;">
            <strong>Pandas Statistical Filter:</strong> Z-Score: <code>${pandas.z_score}</code> | 1h Count: <code>${pandas.velocity_1h_count}</code> | Triggered Rules: <code>${pandas.triggered_rules.length ? pandas.triggered_rules.join(', ') : 'None'}</code>
        </div>

        <div class="actions-row">
            <span class="action-badge" style="background: #0f172a; border: 1px solid #334155; color: #e2e8f0;">Action: ${verdict.recommended_action}</span>
            ${autoText}
        </div>
    `;

    feed.prepend(card);
}
