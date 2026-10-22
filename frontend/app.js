/*
 * SmartGuard AI - frontend controller.
 *
 * Drives Module 1 (upload / paste) and renders the Module 2 report.
 */
const API = "http://127.0.0.1:8000";

const SAMPLE_SOURCE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function unsafeDelegate(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}`;

const state = {
  mode: "upload",
  file: null,
  filter: "all",
  result: null,
};

const $ = (id) => document.getElementById(id);

/* ------------------------------------------------------------------ */
/* Tabs                                                                */
/* ------------------------------------------------------------------ */
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    state.mode = tab.dataset.tab;
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === tab));
    document.querySelectorAll(".tab-body").forEach((b) => {
      b.classList.toggle("active", b.id === `tab-${state.mode}`);
    });
  });
});

/* ------------------------------------------------------------------ */
/* File handling                                                       */
/* ------------------------------------------------------------------ */
const dropzone = $("dropzone");
const fileInput = $("file-input");

dropzone.addEventListener("click", () => fileInput.click());

["dragenter", "dragover"].forEach((evt) =>
  dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropzone.classList.add("drag");
  })
);
["dragleave", "drop"].forEach((evt) =>
  dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag");
  })
);

dropzone.addEventListener("drop", (e) => {
  const files = e.dataTransfer.files;
  if (files.length) setFile(files[0]);
});

fileInput.addEventListener("change", () => {
  if (fileInput.files.length) setFile(fileInput.files[0]);
});

function setFile(file) {
  state.file = file;
  $("file-name").textContent = `${file.name}  (${formatBytes(file.size)})`;
  $("file-chip").classList.remove("hidden");
  dropzone.classList.add("hidden");
}

$("file-clear").addEventListener("click", (e) => {
  e.stopPropagation();
  state.file = null;
  fileInput.value = "";
  $("file-chip").classList.add("hidden");
  dropzone.classList.remove("hidden");
});

$("load-sample").addEventListener("click", () => {
  $("source-input").value = SAMPLE_SOURCE;
});

/* ------------------------------------------------------------------ */
/* Analysis                                                            */
/* ------------------------------------------------------------------ */
$("analyze-btn").addEventListener("click", async () => {
  const button = $("analyze-btn");
  const errorBox = $("error-msg");

  errorBox.classList.add("hidden");
  button.disabled = true;
  button.textContent = "Analyzing…";

  try {
    let response;

    if (state.mode === "upload") {
      if (!state.file) {
        throw new Error("Please choose a .sol file first.");
      }
      const form = new FormData();
      form.append("file", state.file);
      response = await fetch(`${API}/api/analyze/upload`, { method: "POST", body: form });

      if (response.ok) {
        const receipt = await response.json();
        // The upload endpoint scans in the background, so poll for the
        // finished analysis instead of rendering the receipt.
        state.result = await pollAnalysis(receipt.analysis_id);
        render(state.result);
        return;
      }
    } else {
      const content = $("source-input").value;
      if (!content.trim()) {
        throw new Error("Please paste Solidity source code first.");
      }
      response = await fetch(`${API}/api/scan/sync`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, filename: "contract.sol" }),
      });
    }

    const payload = await response.json();

    if (!response.ok) {
      const detail = payload.detail;
      const message =
        typeof detail === "string" ? detail : detail?.message || "Analysis failed.";
      throw new Error(message);
    }

    state.result = payload;
    render(payload);
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove("hidden");
  } finally {
    button.disabled = false;
    button.textContent = "Analyze Contract";
  }
});

/**
 * Poll the analysis endpoint until the background scan finishes.
 */
async function pollAnalysis(analysisId, attempts = 120, intervalMs = 1000) {
  for (let i = 0; i < attempts; i++) {
    const res = await fetch(`${API}/api/analysis/${analysisId}`);
    if (!res.ok) {
      const payload = await res.json().catch(() => ({}));
      const detail = payload.detail;
      throw new Error(
        typeof detail === "string" ? detail : detail?.message || "Analysis failed."
      );
    }
    const payload = await res.json();
    if (payload.status === "completed" || payload.status === "failed") {
      return payload;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error("Analysis timed out. Please try again.");
}

/* ------------------------------------------------------------------ */
/* Rendering                                                           */
/* ------------------------------------------------------------------ */
function render(result) {
  $("placeholder").classList.add("hidden");
  $("results").classList.remove("hidden");

  if (result.status === "failed") {
    $("r-contract").textContent = result.contract_name || "-";
    $("r-detectors").textContent = "-";
    $("r-duration").textContent = "-";
    $("r-total").textContent = "-";
    $("summary").innerHTML = "";
    $("filter-row").innerHTML = "";
    $("findings").innerHTML = `<div class="finding high"><strong>Analysis failed</strong><p class="finding-desc">${
      escapeHtml(result.error || "Unknown error")
    }</p></div>`;
    return;
  }

  $("r-contract").textContent = result.contract_name;
  $("r-detectors").textContent = result.detectors_ran;
  $("r-duration").textContent = `${result.scan_duration_seconds}s`;
  $("r-total").textContent = result.summary.total;

  const summary = result.summary;
  $("summary").innerHTML = ["critical", "high", "medium", "low", "informational"]
    .map(
      (k) =>
        `<div class="stat ${k}"><div class="n">${summary[k]}</div><div class="l">${k}</div></div>`
    )
    .join("");

  const levels = ["all", "critical", "high", "medium", "low", "informational"];
  $("filter-row").innerHTML = levels
    .map(
      (l) =>
        `<button class="chip ${l === state.filter ? "active" : ""}" data-level="${l}">${l}</button>`
    )
    .join("");

  $("filter-row")
    .querySelectorAll(".chip")
    .forEach((chip) =>
      chip.addEventListener("click", () => {
        state.filter = chip.dataset.level;
        renderFindings(result);
        $("filter-row")
          .querySelectorAll(".chip")
          .forEach((c) => c.classList.toggle("active", c === chip));
      })
    );

  renderFindings(result);
}

function renderFindings(result) {
  const findings = result.findings.filter(
    (f) => state.filter === "all" || f.severity === state.filter
  );

  if (!findings.length) {
    $("findings").innerHTML = `<div class="placeholder">No findings match this filter.</div>`;
    return;
  }

  $("findings").innerHTML = findings
    .map(
      (f) => `
      <div class="finding ${f.severity}">
        <div class="finding-head">
          <code>${escapeHtml(f.detector)}</code>
          <span class="badge ${f.severity}">${f.severity}</span>
          <span class="badge ${f.severity}" style="opacity:.55">${escapeHtml(f.impact)} impact</span>
        </div>
        <p class="finding-desc">${escapeHtml(f.description)}</p>
        <div class="finding-meta">
          <span>Contract: <strong>${escapeHtml(f.contract)}</strong></span>
          <span>Function: <strong>${escapeHtml(f.function || "-")}</strong></span>
          <span>Line: <strong>${f.line ?? "-"}</strong></span>
          <span>Confidence: <strong>${escapeHtml(f.confidence || "-")}</strong></span>
        </div>
      </div>`
    )
    .join("");
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
function escapeHtml(text) {
  return String(text ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}
