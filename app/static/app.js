const SAMPLE_TEXT = `Incident #4092 - Customer Support Escalation
Customer: Aarav Sharma (aarav.sharma@acme-fintech.in)
Phone: +91-9876543210 | UPI: aarav.sharma@okicici
PAN: ABCDE1234F | Client IP: 203.0.113.42
Auth Header leaked in log: Bearer sk-proj-99887766554433221100aabbcc
Note: Please keep aarav.sharma@acme-fintech.in consistent across tickets.`;

async function loadAirgapStatus() {
  const pill = document.getElementById("airgap-pill");
  try {
    const res = await fetch("/api/v1/airgap-check");
    const data = await res.json();
    pill.textContent = `AIR-GAPPED (${data.backend}) | Outbound: ${data.outbound_network_calls}`;
  } catch (err) {
    pill.textContent = "Offline API unreachable";
  }
}

function renderBadges(containerId, counts, total, backend) {
  const el = document.getElementById(containerId);
  el.innerHTML = "";
  const totalBadge = document.createElement("span");
  totalBadge.className = "badge";
  totalBadge.textContent = `Detected: ${total} (${backend})`;
  el.appendChild(totalBadge);

  Object.entries(counts || {}).forEach(([entity, count]) => {
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = `${entity}: ${count}`;
    el.appendChild(badge);
  });
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
  });
});

document.getElementById("btn-load-sample").addEventListener("click", () => {
  document.getElementById("raw-text").value = SAMPLE_TEXT;
});

document.getElementById("btn-scrub-text").addEventListener("click", async () => {
  const text = document.getElementById("raw-text").value;
  const mode = document.getElementById("text-mode").value;
  const salt = document.getElementById("text-salt").value.trim() || null;

  const res = await fetch("/api/v1/scrub/text", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, mode, salt }),
  });
  const data = await res.json();
  document.getElementById("scrubbed-text").value = data.scrubbed_text || "";
  renderBadges("text-metrics", data.entity_counts, data.findings_count, data.backend);
});

document.getElementById("btn-copy-text").addEventListener("click", async () => {
  const out = document.getElementById("scrubbed-text").value;
  if (out) {
    await navigator.clipboard.writeText(out);
  }
});

let lastScrubbedFilename = "scrubbed.txt";
let lastScrubbedContent = "";

document.getElementById("btn-scrub-file").addEventListener("click", async () => {
  const fileInput = document.getElementById("file-input");
  if (!fileInput.files.length) return;
  const form = new FormData();
  form.append("file", fileInput.files[0]);
  form.append("mode", document.getElementById("file-mode").value);

  const res = await fetch("/api/v1/scrub/file", { method: "POST", body: form });
  const data = await res.json();
  if (!res.ok) {
    document.getElementById("file-output").value = `Error: ${data.detail}`;
    return;
  }
  lastScrubbedFilename = `scrubbed_${data.filename}`;
  lastScrubbedContent = data.scrubbed_content;
  document.getElementById("file-output").value = lastScrubbedContent;
  document.getElementById("btn-download-file").disabled = false;
  renderBadges("file-metrics", data.entity_counts, data.findings_count, data.backend);
});

document.getElementById("btn-download-file").addEventListener("click", () => {
  const blob = new Blob([lastScrubbedContent], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = lastScrubbedFilename;
  a.click();
  URL.revokeObjectURL(url);
});

document.getElementById("btn-inspect-db").addEventListener("click", async () => {
  const source_dsn = document.getElementById("db-source").value.trim();
  const reportEl = document.getElementById("db-report");
  reportEl.textContent = "Inspecting schema...";
  const res = await fetch("/api/v1/db/inspect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source_dsn }),
  });
  const data = await res.json();
  reportEl.textContent = JSON.stringify(data, null, 2);
});

document.getElementById("btn-anonymize-db").addEventListener("click", async () => {
  const source_dsn = document.getElementById("db-source").value.trim();
  const target_dsn = document.getElementById("db-target").value.trim();
  const mode = document.getElementById("db-mode").value;
  const reportEl = document.getElementById("db-report");
  reportEl.textContent = "Running FK-safe deterministic anonymization...";
  const res = await fetch("/api/v1/db/anonymize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source_dsn, target_dsn, mode }),
  });
  const data = await res.json();
  reportEl.textContent = JSON.stringify(data, null, 2);
});

loadAirgapStatus();
