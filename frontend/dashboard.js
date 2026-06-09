const API_BASE = "/api";
const POLL_INTERVAL = 5051;
const PAGE_SIZE = 8;

const state = {
  report: null,
  history: null,
  findings: [],
  filtered: [],
  page: 1,
  sortField: "severity",
  sortDirection: "desc",
  lastGeneratedAt: null,
  offline: false,
};

const severityPriority = {
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const severityLabels = {
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};

const severityColors = {
  HIGH: "#ef566d",
  MEDIUM: "#f1c40f",
  LOW: "#3dd6f0",
};

let severityChart = null;
let moduleChart = null;
let timelineChart = null;

const elements = {
  statusBackend: document.getElementById("backend-status"),
  reportFreshness: document.getElementById("report-freshness"),
  pageIndicator: document.getElementById("page-indicator"),
  findingsTableBody: document.getElementById("findings-table-body"),
  totalFindings: document.getElementById("total-findings"),
  highFindings: document.getElementById("high-findings"),
  mediumFindings: document.getElementById("medium-findings"),
  lowFindings: document.getElementById("low-findings"),
  topFiles: document.getElementById("top-files"),
  topTechniques: document.getElementById("top-techniques"),
  searchInput: document.getElementById("search-input"),
  severityFilter: document.getElementById("severity-filter"),
  moduleFilter: document.getElementById("module-filter"),
  prevPage: document.getElementById("prev-page"),
  nextPage: document.getElementById("next-page"),
  detailDrawer: document.getElementById("detail-drawer"),
  detailBody: document.getElementById("detail-body"),
  closeDetail: document.getElementById("close-detail"),
  cronMonitor: document.getElementById("cron-monitor"),
  systemdMonitor: document.getElementById("systemd-monitor"),
  startupMonitor: document.getElementById("startup-monitor"),
  sshMonitor: document.getElementById("ssh-monitor"),
  toastContainer: document.getElementById("toast-container"),
  downloadJSON: document.getElementById("download-json"),
  downloadCSV: document.getElementById("download-csv"),
  downloadPDF: document.getElementById("download-pdf"),
};

function toTitleCase(value) {
  return String(value)
    .toLowerCase()
    .replace(/\b(\w)/g, (match) => match.toUpperCase());
}

function clampPage(page, total) {
  if (page < 1) return 1;
  if (page > total) return total;
  return page;
}

function pluralize(count, singular, plural = null) {
  return `${count} ${count === 1 ? singular : plural || singular + "s"}`;
}

function formatTime(isoString) {
  if (!isoString) return "n/a";
  const date = new Date(isoString);
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function renderMonitorCard(container, statusData) {
  container.innerHTML = `
    <h3>${statusData.monitor}</h3>
    <p>${statusData.detail}</p>
    <span class="monitor-status ${statusData.status.toLowerCase().replace(/\s+/g, "-")}">${statusData.status}</span>
  `;
}

function updateMonitorCards(report) {
  const monitors = report.monitors || [];
  renderMonitorCard(elements.cronMonitor, monitors.find((item) => item.monitor === "Cron Monitor") || { monitor: "Cron Monitor", status: "Healthy", detail: "No findings detected" });
  renderMonitorCard(elements.systemdMonitor, monitors.find((item) => item.monitor === "Systemd Monitor") || { monitor: "Systemd Monitor", status: "Healthy", detail: "No findings detected" });
  renderMonitorCard(elements.startupMonitor, monitors.find((item) => item.monitor === "Startup Monitor") || { monitor: "Startup Monitor", status: "Healthy", detail: "No findings detected" });
  renderMonitorCard(elements.sshMonitor, monitors.find((item) => item.monitor === "SSH Monitor") || { monitor: "SSH Monitor", status: "Healthy", detail: "No findings detected" });
}

function updateSummaryCards(report) {
  elements.totalFindings.textContent = report.total_findings;
  elements.highFindings.textContent = report.severity_counts.HIGH;
  elements.mediumFindings.textContent = report.severity_counts.MEDIUM;
  elements.lowFindings.textContent = report.severity_counts.LOW;
  elements.reportFreshness.textContent = `Last scan: ${formatTime(report.generated_at)}`;
  // Keep the status-band findings pill in sync
  const countPill = document.getElementById("active-scan-count");
  if (countPill) countPill.textContent = `Findings: ${report.total_findings}`;
}

function updateTopLists(report) {
  const fileItems = report.top_affected_files || [];
  const techniqueItems = report.top_techniques || [];

  elements.topFiles.innerHTML = fileItems.length
    ? fileItems.map((item) => `<li>${item.path} <strong>${item.count}</strong></li>`).join("")
    : `<li>No affected files detected</li>`;

  elements.topTechniques.innerHTML = techniqueItems.length
    ? techniqueItems.map((item) => `<li>${item.technique} <strong>${item.count}</strong></li>`).join("")
    : `<li>No persistence techniques detected</li>`;
}

function buildMonitorStatusText(status) {
  return status === "Healthy" ? "green" : status === "Warning" ? "gold" : "red";
}

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const aValue = a[state.sortField];
    const bValue = b[state.sortField];
    if (state.sortField === "severity") {
      return state.sortDirection === "asc"
        ? severityPriority[a.severity] - severityPriority[b.severity]
        : severityPriority[b.severity] - severityPriority[a.severity];
    }
    return state.sortDirection === "asc" ? String(aValue).localeCompare(String(bValue)) : String(bValue).localeCompare(String(aValue));
  });
}

function filterFindings() {
  const search = elements.searchInput.value.trim().toLowerCase();
  const severity = elements.severityFilter.value;
  const module = elements.moduleFilter.value;

  state.filtered = state.findings.filter((item) => {
    if (severity !== "all" && item.severity !== severity) return false;
    if (module !== "all" && item.module !== module) return false;

    if (!search) return true;
    return [item.severity, item.module, item.path, item.description, item.evidence]
      .join(" ")
      .toLowerCase()
      .includes(search);
  });
}

function renderTable() {
  filterFindings();
  const sorted = sortFindings(state.filtered);
  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  state.page = clampPage(state.page, totalPages);

  const start = (state.page - 1) * PAGE_SIZE;
  const rows = sorted.slice(start, start + PAGE_SIZE);

  if (rows.length === 0) {
    elements.findingsTableBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="5" style="text-align:center; padding: 28px 12px; color: #aab4d3;">
          No findings match the current filters.
        </td>
      </tr>`;
  } else {
    elements.findingsTableBody.innerHTML = rows
      .map(
        (item, index) => `
      <tr class="${item.severity.toLowerCase()}" data-index="${start + index}">
        <td>${item.severity}</td>
        <td>${item.module}</td>
        <td>${item.path}</td>
        <td>${item.description}</td>
        <td>${formatTime(item.detection_time)}</td>
      </tr>`
      )
      .join("");

    [...elements.findingsTableBody.querySelectorAll("tr")].forEach((row) => {
      row.addEventListener("click", () => openDetailPanel(sorted[Number(row.dataset.index)]));
    });
  }

  elements.pageIndicator.textContent = `Page ${state.page} of ${totalPages}`;
}

function updateModuleFilter(report) {
  const modules = Array.from(new Set(report.findings.map((item) => item.module)));
  elements.moduleFilter.innerHTML = `<option value="all">Module: All</option>${modules
    .map((module) => `<option value="${module}">${module}</option>`)
    .join("")}`;
}

function renderDetailPanel(item) {
  if (!item) {
    elements.detailBody.innerHTML = `<p class="empty-state">Select a finding to review remediation guidance and evidence.</p>`;
    return;
  }

  const recommendations = {
    HIGH: "Investigate immediately, isolate affected systems, and remove persistence artifacts.",
    MEDIUM: "Review the finding and validate whether the activity is authorized. Harden configuration if needed.",
    LOW: "Document and monitor the behavior. Confirm whether the detected setting matches policy.",
  };

  elements.detailBody.innerHTML = `
    <dl>
      <dt>Severity</dt>
      <dd>${item.severity}</dd>
      <dt>Module</dt>
      <dd>${item.module}</dd>
      <dt>Path</dt>
      <dd>${item.path}</dd>
      <dt>Rule</dt>
      <dd>${item.rule}</dd>
      <dt>Description</dt>
      <dd>${item.description}</dd>
      <dt>Evidence</dt>
      <dd>${item.evidence || "N/A"}</dd>
      <dt>Detection Time</dt>
      <dd>${formatTime(item.detection_time)}</dd>
      <dt>Recommended Remediation</dt>
      <dd>${recommendations[item.severity] || recommendations.LOW}</dd>
    </dl>`;
}

function openDetailPanel(item) {
  renderDetailPanel(item);
  elements.detailDrawer.classList.add("open");
  elements.detailDrawer.setAttribute("aria-hidden", "false");
}

function closeDetailPanel() {
  elements.detailDrawer.classList.remove("open");
  elements.detailDrawer.setAttribute("aria-hidden", "true");
}

function createChart(chartElement, config) {
  return new Chart(chartElement, config);
}

function renderCharts(report, history) {
  const severityLabels = ["HIGH", "MEDIUM", "LOW"];
  const severityData = severityLabels.map((key) => report.severity_counts[key] || 0);

  const moduleLabels = Object.keys(report.module_counts || {});
  const moduleData = Object.values(report.module_counts || {});

  const timelineLabels = (history.scans || []).map((scan) => formatTime(scan.generated_at));
  const highSeries = (history.scans || []).map((scan) => scan.severity_counts.HIGH || 0);
  const mediumSeries = (history.scans || []).map((scan) => scan.severity_counts.MEDIUM || 0);
  const lowSeries = (history.scans || []).map((scan) => scan.severity_counts.LOW || 0);

  if (severityChart) severityChart.destroy();
  if (moduleChart) moduleChart.destroy();
  if (timelineChart) timelineChart.destroy();

  severityChart = createChart(document.getElementById("severity-chart"), {
    type: "doughnut",
    data: {
      labels: severityLabels,
      datasets: [
        {
          data: severityData,
          backgroundColor: [severityColors.HIGH, severityColors.MEDIUM, severityColors.LOW],
          hoverOffset: 8,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { position: "bottom", labels: { color: "#dbe3f1" } } },
    },
  });

  moduleChart = createChart(document.getElementById("module-chart"), {
    type: "bar",
    data: {
      labels: moduleLabels,
      datasets: [
        {
          label: "Findings",
          data: moduleData,
          backgroundColor: moduleLabels.map((module) => {
            if (module === "Cron") return "#4f9cff";
            if (module === "Systemd") return "#eb7b3f";
            if (module === "Startup") return "#8a5cf6";
            return "#3dd6f0";
          }),
        },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#c1d4f7" } },
        y: { ticks: { color: "#c1d4f7" }, beginAtZero: true },
      },
    },
  });

  timelineChart = createChart(document.getElementById("timeline-chart"), {
    type: "line",
    data: {
      labels: timelineLabels,
      datasets: [
        {
          label: "HIGH",
          data: highSeries,
          borderColor: severityColors.HIGH,
          tension: 0.32,
          fill: false,
        },
        {
          label: "MEDIUM",
          data: mediumSeries,
          borderColor: severityColors.MEDIUM,
          tension: 0.32,
          fill: false,
        },
        {
          label: "LOW",
          data: lowSeries,
          borderColor: severityColors.LOW,
          tension: 0.32,
          fill: false,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: "#dbe3f1" } } },
      scales: {
        x: { ticks: { color: "#c1d4f7" } },
        y: { ticks: { color: "#c1d4f7" }, beginAtZero: true },
      },
    },
  });
}

function detailTextForFinding(finding) {
  return finding.evidence || finding.description || "No evidence available.";
}

function publishToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<strong>${type === "danger" ? "Alert" : type === "warning" ? "Warning" : "Info"}</strong><span>${message}</span>`;
  elements.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 5500);
}

function detectAlerts(previous, current) {
  if (!previous) return;
  const previousKeys = new Set(previous.findings.map((item) => `${item.module}|${item.path}|${item.description}`));
  const currentKeys = new Set(current.findings.map((item) => `${item.module}|${item.path}|${item.description}`));

  current.findings.forEach((item) => {
    const key = `${item.module}|${item.path}|${item.description}`;
    if (!previousKeys.has(key) && item.severity === "HIGH") {
      publishToast(`New HIGH finding detected in ${item.module}: ${item.path}`, "danger");
    }
  });

  current.findings.forEach((item) => {
    const matching = previous.findings.find(
      (previousItem) => previousItem.module === item.module && previousItem.path === item.path && previousItem.description === item.description
    );
    if (matching && severityPriority[item.severity] > severityPriority[matching.severity]) {
      publishToast(`Severity increased for ${item.path} from ${matching.severity} to ${item.severity}.`, "warning");
    }
  });

  const previousModules = new Set(previous.findings.map((item) => item.module));
  current.findings.forEach((item) => {
    if (!previousModules.has(item.module)) {
      publishToast(`New persistence technique detected: ${item.module}`, "warning");
    }
  });
}

async function fetchJson(endpoint) {
  const response = await fetch(`${API_BASE}${endpoint}`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Backend responded with ${response.status}`);
  }
  return response.json();
}

function updateStatus(isConnected) {
  const previousOffline = state.offline;
  state.offline = !isConnected;
  elements.statusBackend.textContent = isConnected ? "Backend: Connected" : "Backend: Offline — retrying";
  elements.statusBackend.style.color = isConnected ? "#7fffd4" : "#f5a623";
  return previousOffline !== state.offline;
}

async function refreshDashboard() {
  // --- Network / API layer ---
  let report, history;
  try {
    const [reportResponse, historyResponse] = await Promise.all([fetchJson("/report"), fetchJson("/history")]);
    if (reportResponse.status !== "ok" || historyResponse.status !== "ok") {
      throw new Error("Bad API response");
    }
    report = reportResponse.report;
    history = historyResponse.history;
  } catch (error) {
    console.error("[dashboard] fetch error:", error);
    const statusChanged = updateStatus(false);
    if (statusChanged) {
      publishToast("Unable to reach backend. Reconnecting...", "warning");
    }
    return;
  }

  // Connection is confirmed good at this point
  updateStatus(true);

  if (state.lastGeneratedAt && state.lastGeneratedAt !== report.generated_at) {
    detectAlerts(state.report, report);
  }

  state.lastGeneratedAt = report.generated_at;
  state.report = report;
  state.history = history;
  state.findings = report.findings || [];
  state.page = 1;

  // --- UI rendering layer (errors here must NOT flip status to offline) ---
  try {
    updateSummaryCards(report);
    updateMonitorCards(report);
    updateTopLists(report);
    updateModuleFilter(report);
    renderCharts(report, history);
    renderTable();
  } catch (renderError) {
    console.error("[dashboard] render error:", renderError);
    // Still try to render the table even if charts fail
    try { renderTable(); } catch (_) {}
  }
}

function wireEvents() {
  elements.searchInput.addEventListener("input", () => {
    state.page = 1;
    renderTable();
  });

  elements.severityFilter.addEventListener("change", () => {
    state.page = 1;
    renderTable();
  });

  elements.moduleFilter.addEventListener("change", () => {
    state.page = 1;
    renderTable();
  });

  elements.prevPage.addEventListener("click", () => {
    state.page -= 1;
    renderTable();
  });

  elements.nextPage.addEventListener("click", () => {
    state.page += 1;
    renderTable();
  });

  document.querySelectorAll("th[data-sort]").forEach((header) => {
    header.addEventListener("click", () => {
      const field = header.dataset.sort;
      if (state.sortField === field) {
        state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
      } else {
        state.sortField = field;
        state.sortDirection = "desc";
      }
      renderTable();
    });
  });

  elements.closeDetail.addEventListener("click", closeDetailPanel);
  elements.downloadJSON.addEventListener("click", () => (window.location.href = `${API_BASE}/export/json`));
  elements.downloadCSV.addEventListener("click", () => (window.location.href = `${API_BASE}/export/csv`));
  elements.downloadPDF.addEventListener("click", () => (window.location.href = `${API_BASE}/export/pdf`));
}

async function startPolling() {
  await refreshDashboard();
  setInterval(refreshDashboard, POLL_INTERVAL);
}

window.addEventListener("DOMContentLoaded", () => {
  wireEvents();
  startPolling();
});
