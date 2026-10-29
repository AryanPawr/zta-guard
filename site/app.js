const sampleScenarios = [
  { id: "scenario-01-legitimate-contractor", identity: "ctr-ana", resource: "inventory-read", decision: "ALLOW", check: "All 10 checks", reason: "Active contractor with a valid lifecycle, explicit grant, verified MFA, compliant device, approved path and complete telemetry.", policy: "D3-PARTNER-001 through 010", action: "Continue time-bound access and re-evaluate on each request." },
  { id: "scenario-02-ineligible-resource", identity: "ctr-ana", resource: "finance-admin", decision: "DENY", check: "Role eligibility", reason: "The finance administration resource is outside the contractor role boundary.", policy: "D3-PARTNER-005-ROLE-ELIGIBLE-RESOURCE", action: "Remove the request or review the approved role-to-resource model." },
  { id: "scenario-03-ended-engagement", identity: "ctr-ben", resource: "inventory-read", decision: "DENY", check: "Engagement status", reason: "The account is enabled even though the contractor engagement is marked ended.", policy: "D3-PARTNER-002-ENGAGEMENT-ACTIVE", action: "Disable the account, remove grants and review access since the engagement ended." },
  { id: "scenario-04-not-yet-started", identity: "ctr-chen", resource: "inventory-read", decision: "DENY", check: "Engagement dates", reason: "The engagement start date is later than the evaluation date.", policy: "D3-PARTNER-003-WITHIN-ENGAGEMENT-DATES", action: "Keep the account disabled until the approved start date." },
  { id: "scenario-05-legitimate-delivery-partner", identity: "dp-delta", resource: "delivery-portal", decision: "ALLOW", check: "All 10 checks", reason: "The delivery partner has an active engagement, eligible explicit grant and valid request context.", policy: "D3-PARTNER-001 through 010", action: "Continue time-bound access and re-evaluate on each request." },
  { id: "scenario-06-mfa-failure", identity: "dp-delta", resource: "delivery-portal", decision: "DENY", check: "MFA evidence", reason: "MFA verification is false for this request.", policy: "D3-PARTNER-007-MFA-VERIFIED", action: "Require successful MFA before re-evaluating the request." },
  { id: "scenario-07-unmanaged-device", identity: "dp-delta", resource: "delivery-portal", decision: "DENY", check: "Device posture", reason: "The unmanaged device posture is not allowed by the sample policy.", policy: "D3-PARTNER-008-DEVICE-POSTURE", action: "Use an allowed device or remediate the device before access." },
  { id: "scenario-08-disabled-account", identity: "ctr-disabled", resource: "inventory-read", decision: "DENY", check: "Account state", reason: "The account is disabled, even though the engagement dates are valid.", policy: "D3-PARTNER-004-ACCOUNT-ENABLED", action: "Keep access denied unless the engagement owner approves reactivation." },
  { id: "scenario-09-missing-lifecycle-date", identity: "ctr-malformed", resource: "inventory-read", decision: "DENY", check: "Lifecycle evidence", reason: "The engagement record is missing its required end date.", policy: "D3-PARTNER-001-LIFECYCLE-DATA-VALID", action: "Correct and confirm the lifecycle record before granting access." },
  { id: "scenario-10-not-explicitly-granted", identity: "dp-delta", resource: "shipment-status", decision: "DENY", check: "Explicit grant", reason: "The resource is role eligible but is not explicitly granted to this account.", policy: "D3-PARTNER-006-EXPLICIT-ACCOUNT-GRANT", action: "Request an owner-approved, time-bound grant if access is required." },
  { id: "scenario-11-expired-active-record", identity: "dp-expired", resource: "delivery-portal", decision: "DENY", check: "Lifecycle and expiry", reason: "The record claims to be active after its engagement end date.", policy: "D3-PARTNER-001 and D3-PARTNER-003", action: "Disable the account, remove grants and review post-expiry access." },
  { id: "scenario-12-inactive-engagement", identity: "ctr-inactive", resource: "work-order-update", decision: "DENY", check: "Engagement status", reason: "The engagement status is inactive.", policy: "D3-PARTNER-002-ENGAGEMENT-ACTIVE", action: "Keep the account disabled until a new engagement is approved." },
  { id: "scenario-13-segmentation-path-denied", identity: "dp-delta", resource: "delivery-portal", decision: "DENY", check: "Segmentation path", reason: "The corporate source zone is not an approved path to the partner resource zone.", policy: "D3-PARTNER-009-SEGMENTATION-PATH", action: "Use the approved third-party partner access path." },
  { id: "scenario-14-monitoring-evidence-missing", identity: "ctr-ana", resource: "inventory-read", decision: "DENY", check: "Monitoring evidence", reason: "Required network telemetry is missing from the request context.", policy: "D3-PARTNER-010-MONITORING-EVIDENCE", action: "Restore the required evidence before re-evaluating access." },
  { id: "scenario-15-conditional-device", identity: "dp-delta", resource: "delivery-portal", decision: "CONDITIONAL", check: "Device posture", reason: "The managed device is allowed only with restriction or step-up in the sample policy.", policy: "D3-PARTNER-008-DEVICE-POSTURE", action: "Restrict the session and require a compliant device for full access." },
  { id: "scenario-16-pending-engagement", identity: "ctr-pending", resource: "inventory-read", decision: "DENY", check: "Engagement status", reason: "The engagement is pending and access is not yet authorised.", policy: "D3-PARTNER-002-ENGAGEMENT-ACTIVE", action: "Keep the account disabled until the engagement becomes active." },
  { id: "scenario-17-suspended-engagement", identity: "ctr-suspended", resource: "work-order-update", decision: "DENY", check: "Engagement status", reason: "The engagement is suspended.", policy: "D3-PARTNER-002-ENGAGEMENT-ACTIVE", action: "Keep the account disabled and require owner review before reinstatement." },
  { id: "scenario-18-unknown-identity", identity: "unknown-partner", resource: "inventory-read", decision: "DENY", check: "Identity match", reason: "No account record matches the request identity.", policy: "D3-PARTNER-001-LIFECYCLE-DATA-VALID", action: "Deny access and reconcile the identity with the authoritative source." }
];

const sampleAudit = [
  { id: "ctr-ben:ended-enabled", identity: "ctr-ben", resource: "Account lifecycle", decision: "FINDING", priority: "P1", check: "Ended engagement", reason: "Account remains enabled although the engagement is ended.", policy: "D3-PARTNER-AUDIT-001", action: "Disable the account, remove grants and review access since the engagement ended." },
  { id: "ctr-chen:invalid-lifecycle", identity: "ctr-chen", resource: "Account lifecycle", decision: "FINDING", priority: "P1", check: "Invalid lifecycle", reason: "The enabled account is marked active before its start date.", policy: "D3-PARTNER-AUDIT-003", action: "Disable the account and correct the lifecycle evidence." },
  { id: "ctr-inactive:inactive-enabled", identity: "ctr-inactive", resource: "Account lifecycle", decision: "FINDING", priority: "P1", check: "Inactive engagement", reason: "The account is enabled although the engagement is inactive.", policy: "D3-PARTNER-AUDIT-007", action: "Disable the account until a new engagement is approved." },
  { id: "ctr-malformed:invalid-lifecycle", identity: "ctr-malformed", resource: "Account lifecycle", decision: "FINDING", priority: "P1", check: "Invalid lifecycle", reason: "The enabled account has incomplete lifecycle data.", policy: "D3-PARTNER-AUDIT-003", action: "Disable the account and confirm valid lifecycle data with the owner." },
  { id: "ctr-pending:pending-enabled", identity: "ctr-pending", resource: "Account lifecycle", decision: "FINDING", priority: "P1", check: "Pending engagement", reason: "The account is enabled while the engagement is pending.", policy: "D3-PARTNER-AUDIT-007", action: "Disable the account until the engagement becomes active." },
  { id: "ctr-suspended:suspended-enabled", identity: "ctr-suspended", resource: "Account lifecycle", decision: "FINDING", priority: "P1", check: "Suspended engagement", reason: "The account is enabled while the engagement is suspended.", policy: "D3-PARTNER-AUDIT-007", action: "Disable the account and require owner review before reinstatement." },
  { id: "dp-expired:expired-enabled", identity: "dp-expired", resource: "Account lifecycle", decision: "FINDING", priority: "P1", check: "Expired engagement", reason: "The account remains enabled after the engagement end date.", policy: "D3-PARTNER-AUDIT-002", action: "Disable the account, remove grants and review post-expiry access." },
  { id: "ctr-ana:ineligible-grants", identity: "ctr-ana", resource: "finance-admin", decision: "FINDING", priority: "P2", check: "Excess grant", reason: "An explicit grant exceeds the contractor role boundary.", policy: "D3-PARTNER-AUDIT-006", action: "Remove the ineligible grant or review the approved role model." }
];

const checkGroups = [
  { icon: "ID", title: "Identity", description: "Verify the account, lifecycle record, state and MFA evidence.", checks: [["001", "Lifecycle data valid"], ["004", "Account enabled"], ["007", "MFA verified"]] },
  { icon: "DP", title: "Device posture", description: "Use device evidence to allow, restrict or deny the request.", checks: [["008", "Device posture allowed"]] },
  { icon: "NS", title: "Segmentation", description: "Limit partner traffic to an approved source and resource-zone path.", checks: [["009", "Segmentation path allowed"]] },
  { icon: "PA", title: "Partner access", description: "Enforce active dates and least privilege at role and account level.", checks: [["002", "Engagement active"], ["003", "Within dates"], ["005", "Role eligible"], ["006", "Explicit grant"]] },
  { icon: "MO", title: "Monitoring", description: "Require synthetic identity, device, access and network evidence.", checks: [["010", "Monitoring evidence present"]] }
];

const state = { view: "scenarios", filter: "ALL", query: "", scenarios: sampleScenarios, audit: sampleAudit, custom: false };
const list = document.querySelector("#result-list");
const template = document.querySelector("#result-template");

function normaliseEvaluation(report) {
  return (report.decisions || []).map((item, index) => ({
    id: item.request_id || `request-${index + 1}`,
    identity: item.identity_id || "unknown",
    resource: item.resource || "unknown resource",
    decision: item.decision || "DENY",
    check: (item.reasons && item.reasons[0] && item.reasons[0].code) || "Policy result",
    reason: (item.reasons || []).map(reason => reason.message).join(" ") || "No explanation supplied.",
    policy: (item.matched_policies || []).join(", ") || "Not supplied",
    action: (item.recommended_actions || []).join(" ") || "Review the result."
  }));
}

function normaliseAudit(report) {
  return (report.findings || []).map((item, index) => ({
    id: item.finding_id || `finding-${index + 1}`,
    identity: item.identity_id || "unknown",
    resource: item.partner_type || item.category || "Account record",
    decision: "FINDING",
    priority: item.priority || item.severity || "P1",
    check: item.title || item.check_id || "Audit finding",
    reason: item.explanation || (item.reasons || []).join(" ") || "No explanation supplied.",
    policy: item.check_id || item.matched_policy || "Not supplied",
    action: item.remediation || item.recommended_action || "Review the finding."
  }));
}

function renderMetrics() {
  const counts = state.scenarios.reduce((acc, item) => { acc[item.decision] = (acc[item.decision] || 0) + 1; return acc; }, {});
  const total = state.scenarios.length || 1;
  document.querySelector("#metric-requests").textContent = state.scenarios.length;
  document.querySelector("#metric-findings").textContent = state.audit.length;
  document.querySelector("#metric-matches").textContent = state.custom ? "Loaded" : "18/18";
  document.querySelector("#donut-total").textContent = state.scenarios.length;
  document.querySelector("#legend-allow").textContent = counts.ALLOW || 0;
  document.querySelector("#legend-conditional").textContent = counts.CONDITIONAL || 0;
  document.querySelector("#legend-deny").textContent = counts.DENY || 0;
  const allowEnd = ((counts.ALLOW || 0) / total) * 100;
  const conditionalEnd = allowEnd + ((counts.CONDITIONAL || 0) / total) * 100;
  document.querySelector("#decision-donut").style.background = `conic-gradient(var(--aqua) 0 ${allowEnd}%, var(--yellow) ${allowEnd}% ${conditionalEnd}%, var(--red) ${conditionalEnd}% 100%)`;
  document.querySelector("#decision-donut").setAttribute("aria-label", `${counts.ALLOW || 0} allowed, ${counts.CONDITIONAL || 0} conditional and ${counts.DENY || 0} denied requests`);
  document.querySelector("#scenario-tab span").textContent = state.scenarios.length;
  document.querySelector("#audit-tab span").textContent = state.audit.length;
}

function currentItems() { return state.view === "scenarios" ? state.scenarios : state.audit; }

function renderResults() {
  const query = state.query.trim().toLowerCase();
  const items = currentItems().filter(item => {
    const matchesFilter = state.view === "audit" || state.filter === "ALL" || item.decision === state.filter;
    const haystack = `${item.id} ${item.identity} ${item.resource} ${item.check} ${item.reason} ${item.policy}`.toLowerCase();
    return matchesFilter && (!query || haystack.includes(query));
  });
  list.replaceChildren();
  items.forEach(item => {
    const fragment = template.content.cloneNode(true);
    const card = fragment.querySelector(".result-card");
    const button = fragment.querySelector(".result-main");
    fragment.querySelector(".result-icon").textContent = state.view === "audit" ? "!" : item.identity.slice(0, 2).toUpperCase();
    fragment.querySelector(".result-identity strong").textContent = item.identity;
    fragment.querySelector(".result-identity small").textContent = item.id;
    fragment.querySelector(".result-resource").textContent = item.resource;
    fragment.querySelector(".result-check").textContent = item.check;
    const status = fragment.querySelector(".result-status");
    status.textContent = state.view === "audit" ? item.priority : item.decision;
    status.classList.add(state.view === "audit" ? "DENY" : item.decision);
    fragment.querySelector(".detail-reason").textContent = item.reason;
    fragment.querySelector(".detail-policy").textContent = item.policy;
    fragment.querySelector(".detail-action").textContent = item.action;
    const detail = fragment.querySelector(".result-detail");
    button.addEventListener("click", () => {
      const expanded = button.getAttribute("aria-expanded") === "true";
      button.setAttribute("aria-expanded", String(!expanded));
      detail.hidden = expanded;
    });
    list.append(card);
  });
  if (!items.length) list.innerHTML = '<div class="empty-state">No results match this search and filter.</div>';
  document.querySelector("#visible-count").textContent = `${items.length} result${items.length === 1 ? "" : "s"}`;
  document.querySelector("#active-filter-label").textContent = state.view === "audit" ? "Audit findings" : state.filter === "ALL" ? "All decisions" : `${state.filter.toLowerCase()} decisions`;
}

document.querySelectorAll(".view-tab").forEach(tab => tab.addEventListener("click", () => {
  state.view = tab.dataset.view;
  document.querySelectorAll(".view-tab").forEach(item => { item.classList.toggle("active", item === tab); item.setAttribute("aria-selected", String(item === tab)); });
  document.querySelector("#decision-filters").hidden = state.view === "audit";
  renderResults();
}));

document.querySelectorAll(".filter").forEach(button => button.addEventListener("click", () => {
  state.filter = button.dataset.filter;
  document.querySelectorAll(".filter").forEach(item => item.classList.toggle("active", item === button));
  renderResults();
}));

document.querySelector("#result-search").addEventListener("input", event => { state.query = event.target.value; renderResults(); });

document.querySelector("#report-upload").addEventListener("change", async event => {
  const file = event.target.files[0];
  if (!file) return;
  try {
    const report = JSON.parse(await file.text());
    if (report.command === "partner evaluate" || Array.isArray(report.decisions)) {
      state.scenarios = normaliseEvaluation(report);
      state.view = "scenarios";
    } else if (report.command === "partner audit" || Array.isArray(report.findings)) {
      state.audit = normaliseAudit(report);
      state.view = "audit";
    } else {
      throw new Error("This does not look like a ZTA Guard partner report.");
    }
    state.custom = true;
    state.filter = "ALL";
    state.query = "";
    document.querySelector("#result-search").value = "";
    document.querySelector("#reset-sample").hidden = false;
    document.querySelector("#data-source-note").textContent = `Showing ${file.name}. The file was read locally in your browser.`;
    document.querySelectorAll(".view-tab").forEach(item => { const active = item.dataset.view === state.view; item.classList.toggle("active", active); item.setAttribute("aria-selected", String(active)); });
    document.querySelector("#decision-filters").hidden = state.view === "audit";
    renderMetrics();
    renderResults();
    document.querySelector("#explorer").scrollIntoView({ behavior: "smooth" });
  } catch (error) {
    alert(`Could not load report: ${error.message}`);
  } finally {
    event.target.value = "";
  }
});

document.querySelector("#reset-sample").addEventListener("click", () => {
  Object.assign(state, { view: "scenarios", filter: "ALL", query: "", scenarios: sampleScenarios, audit: sampleAudit, custom: false });
  document.querySelector("#result-search").value = "";
  document.querySelector("#reset-sample").hidden = true;
  document.querySelector("#data-source-note").textContent = "Showing the verified synthetic sample: 18/18 expected outcomes matched.";
  document.querySelectorAll(".view-tab").forEach(item => { const active = item.dataset.view === "scenarios"; item.classList.toggle("active", active); item.setAttribute("aria-selected", String(active)); });
  document.querySelectorAll(".filter").forEach(item => item.classList.toggle("active", item.dataset.filter === "ALL"));
  document.querySelector("#decision-filters").hidden = false;
  renderMetrics();
  renderResults();
});

document.querySelectorAll(".copy-button").forEach(button => button.addEventListener("click", async () => {
  await navigator.clipboard.writeText(button.dataset.copy);
  const original = button.textContent;
  button.textContent = "Copied";
  setTimeout(() => { button.textContent = original; }, 1400);
}));

const checkGrid = document.querySelector("#check-grid");
checkGroups.forEach(group => {
  const article = document.createElement("article");
  article.className = "check-group";
  article.innerHTML = `<span class="category-icon">${group.icon}</span><h3>${group.title}</h3><p>${group.description}</p><div class="check-list">${group.checks.map(([id, label]) => `<div class="check-item"><code>${id}</code><span>${label}</span></div>`).join("")}</div>`;
  checkGrid.append(article);
});

renderMetrics();
renderResults();
