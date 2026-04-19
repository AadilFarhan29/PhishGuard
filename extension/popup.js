document.addEventListener("DOMContentLoaded", async () => {
  const statusBanner = document.getElementById("statusBanner");
  const statusText = document.getElementById("statusText");
  const urlEl = document.getElementById("url");
  const verdictEl = document.getElementById("verdict");
  const riskLevelEl = document.getElementById("riskLevel");
  const scoreEl = document.getElementById("score");
  const summaryEl = document.getElementById("summary");
  const verdictCard = document.getElementById("verdictCard");
  const miniStatusEl = document.getElementById("miniStatus");

  function setVisualState(type) {
    statusBanner.className = "status-banner";
    verdictCard.className = "verdict-card";
    miniStatusEl.className = "metric-value mini-status";

    if (type === "safe") {
      statusBanner.classList.add("status-safe");
      verdictCard.classList.add("verdict-safe");
      miniStatusEl.classList.add("safe");
      miniStatusEl.textContent = "SAFE";
    } else if (type === "warning") {
      statusBanner.classList.add("status-warning");
      verdictCard.classList.add("verdict-warning");
      miniStatusEl.classList.add("warning");
      miniStatusEl.textContent = "REVIEW";
    } else if (type === "danger") {
      statusBanner.classList.add("status-danger");
      verdictCard.classList.add("verdict-danger");
      miniStatusEl.classList.add("danger");
      miniStatusEl.textContent = "RISK";
    } else {
      statusBanner.classList.add("status-neutral");
      verdictCard.classList.add("verdict-neutral");
      miniStatusEl.classList.add("neutral");
      miniStatusEl.textContent = "READY";
    }
  }

  try {
    const data = await chrome.storage.local.get("phishguardLastScan");
    const scan = data.phishguardLastScan;

    if (!scan) {
      statusText.textContent = "No scan yet.";
      setVisualState("neutral");
      return;
    }

    urlEl.textContent = scan.scannedUrl || "—";

    if (scan.status === "loading") {
      statusText.textContent = "Scanning in progress...";
      verdictEl.textContent = "SCANNING";
      riskLevelEl.textContent = "Awaiting result";
      scoreEl.textContent = "—";
      summaryEl.textContent = "Please wait while PhishGuard checks the selected link.";
      setVisualState("neutral");
      return;
    }

    if (scan.status === "error") {
      statusText.textContent = "Scan failed.";
      verdictEl.textContent = "ERROR";
      riskLevelEl.textContent = "System error";
      scoreEl.textContent = "—";
      summaryEl.textContent = scan.message || scan.response?.error || "Unknown error.";
      setVisualState("danger");
      return;
    }

    const result = scan.response?.result || {};
    const verdict = (result.result || "Unknown").trim();
    const riskLevel = (result.risk_level || "Unknown").trim();
    const score = result.final_score ?? "—";

    statusText.textContent = "Scan complete.";
    verdictEl.textContent = verdict.toUpperCase();
    riskLevelEl.textContent = riskLevel.toUpperCase();
    scoreEl.textContent = score;

    if (result.top_findings && result.top_findings.length > 0) {
      summaryEl.textContent = result.top_findings[0];
    } else if (result.reasons && result.reasons.length > 0) {
      summaryEl.textContent = result.reasons[0];
    } else {
      summaryEl.textContent = "No summary available.";
    }

    const verdictLower = verdict.toLowerCase();
    const riskLower = riskLevel.toLowerCase();

    if (verdictLower.includes("safe") || riskLower.includes("low")) {
      setVisualState("safe");
    } else if (verdictLower.includes("suspicious") || riskLower.includes("medium")) {
      setVisualState("warning");
    } else if (verdictLower.includes("phishing") || riskLower.includes("high")) {
      setVisualState("danger");
    } else {
      setVisualState("neutral");
    }

  } catch (error) {
    statusText.textContent = "Popup error.";
    verdictEl.textContent = "ERROR";
    riskLevelEl.textContent = "System error";
    scoreEl.textContent = "—";
    summaryEl.textContent = error.message || "Could not load scan result.";
    setVisualState("danger");
  }
});