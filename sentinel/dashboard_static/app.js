async function getJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status} ${response.statusText}${body ? `: ${body.slice(0, 160)}` : ""}`);
  }
  return response.json();
}

function text(value, fallback = "n/a") {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function classToken(value) {
  return text(value).toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
}

function set(id, value) {
  document.getElementById(id).textContent = text(value, "0");
}

function node(tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value !== undefined) element.textContent = text(value);
  return element;
}

function emptyNode(message) {
  const item = node("div", "compact-item empty");
  item.append(node("span", "muted", message));
  return item;
}

function setStatus(message, kind = "ok") {
  const status = document.getElementById("systemStatus");
  status.className = `system-status ${classToken(kind)}`;
  status.textContent = message;
}

async function refresh() {
  setStatus("Refreshing live security data...", "loading");
  const responses = await Promise.allSettled([
    getJson("/api/dashboard/summary"),
    getJson("/api/dashboard/findings"),
    getJson("/api/dashboard/activity"),
    getJson("/api/dashboard/admin"),
  ]);
  const [summaryResult, findingsResult, activityResult, adminResult] = responses;

  if (summaryResult.status === "fulfilled") {
    const summary = summaryResult.value;
    set("provider", summary.provider);
    set("totalAlerts", summary.total_alerts);
    set("criticalAlerts", summary.critical);
    set("vulnerabilities", summary.vulnerabilities);
    set("pullRequests", summary.pull_requests);
    set("milestones", summary.milestones);
    set("sources", `${summary.connected_sources} / ${summary.total_sources}`);
    renderSources(summary.source_health);
  }
  if (findingsResult.status === "fulfilled") {
    const findings = findingsResult.value;
    renderFindings(findings.alerts);
    renderVulnerabilities(findings.vulnerabilities, findings.supply_chain, findings.mcp);
  }
  if (activityResult.status === "fulfilled") {
    const activity = activityResult.value;
    renderActivity(activity.audit_events);
    renderVectorCounts(activity.vector_counts);
  }
  if (adminResult.status === "fulfilled") {
    const admin = adminResult.value;
    renderPullRequests(admin.pull_requests);
    renderMilestones(admin.milestones);
  }

  const failures = responses.filter((result) => result.status === "rejected");
  if (failures.length) {
    setStatus(`${failures.length} dashboard data request(s) failed. Retrying automatically.`, "error");
    return;
  }
  setStatus(`Live data refreshed ${new Date().toLocaleTimeString()}`, "ok");
}

function renderSources(sources) {
  const root = document.getElementById("sourceHealth");
  root.replaceChildren(...sources.map((source) => {
    const row = node("div", "source-row");
    const name = node("div", "source-name");
    name.append(node("b", "", source.name));
    name.append(node("span", "muted", source.detail));
    row.append(name);
    row.append(node("span", `status ${classToken(source.status)}`, source.status));
    return row;
  }));
}

function renderActivity(events) {
  const root = document.getElementById("activityList");
  const rows = events.slice(0, 12).map((event) => ({
    title: `${text(event.actor_login)} ${text(event.action)}`,
    meta: `${text(event.repository)} | ${text(event.head_sha)} | ${text(event.created_at)}`,
  }));
  root.replaceChildren(...(rows.length ? rows.map((row) => {
    const item = node("div", "timeline-item");
    item.append(node("strong", "", row.title));
    item.append(node("span", "muted", row.meta));
    return item;
  }) : [emptyNode("No repository activity has been recorded yet.")]));
}

function renderFindings(alerts) {
  const root = document.getElementById("findingList");
  root.replaceChildren(...(alerts.length ? alerts.slice(0, 12).map((alert) => {
    const item = node("div", "finding");
    item.append(node("span", `pill ${classToken(alert.severity)}`, alert.severity));
    const details = node("div");
    details.append(node("strong", "", alert.vector_type));
    details.append(node("span", "muted", `${text(alert.actor_login)} | ${text(alert.summary)}`));
    item.append(details);
    item.append(node("span", "muted score", alert.score));
    return item;
  }) : [emptyNode("No active detections are currently recorded.")]));
}

function renderVulnerabilities(vulnerabilities, supplyChain, mcp) {
  const root = document.getElementById("vulnerabilityList");
  const rows = [
    ...vulnerabilities.map((item) => ({
      severity: item.severity,
      title: `${text(item.package_name)} ${text(item.vuln_id)}`,
      meta: `${text(item.ecosystem)} | commit ${text(item.commit_sha)} | ${text(item.written_at)}`,
    })),
    ...supplyChain.map((item) => ({
      severity: item.severity,
      title: `${text(item.package_name)} ${text(item.version, "")}`,
      meta: `${text(item.ecosystem)} | ${text(item.issue_type)} | provider ${text(item.provider)}`,
    })),
    ...mcp.map((item) => ({
      severity: item.severity,
      title: `${text(item.skill_name)}: ${text(item.finding_type)}`,
      meta: `${text(item.file_path)} | scanned ${text(item.scanned_at)}`,
    })),
  ].slice(0, 12);
  root.replaceChildren(...(rows.length ? rows.map((row) => {
    const item = node("div", "risk-row");
    item.append(node("span", `pill ${classToken(row.severity)}`, row.severity));
    const details = node("div");
    details.append(node("strong", "", row.title));
    details.append(node("span", "muted", row.meta));
    item.append(details);
    return item;
  }) : [emptyNode("No vulnerability, supply-chain, or agent-config findings are currently recorded.")]));
}

function renderPullRequests(pullRequests) {
  const root = document.getElementById("pullRequestList");
  root.replaceChildren(...(pullRequests.length ? pullRequests.map((pr) => {
    const item = node("div", `pr-row ${classToken(pr.risk_level)}`);
    const header = node("div", "pr-header");
    const title = node("strong", "", `#${text(pr.number)} ${text(pr.title)}`);
    if (String(pr.url || "").startsWith("https://github.com/")) {
      const link = node("a", "external-link", "Open");
      link.href = pr.url;
      link.rel = "noreferrer";
      link.target = "_blank";
      header.append(title, link);
    } else {
      header.append(title);
    }
    const meta = node("div", "pr-meta");
    meta.append(node("span", "", pr.repository));
    meta.append(node("span", "", pr.actor_login));
    meta.append(node("span", "", pr.status));
    meta.append(node("span", "", `${text(pr.open_alerts, "0")} alerts`));
    meta.append(node("span", "", `${text(pr.vulnerabilities, "0")} vulnerabilities`));
    const milestone = node("div", "muted", `Milestone: ${text(pr.milestone)}${pr.milestone_due_on ? ` | due ${pr.milestone_due_on}` : ""}`);
    item.append(header, meta, milestone);
    return item;
  }) : [emptyNode("No pull request events have been recorded yet.")]));
}

function renderMilestones(milestones) {
  const root = document.getElementById("milestoneList");
  root.replaceChildren(...(milestones.length ? milestones.map((milestone) => {
    const item = node("div", `milestone-row ${classToken(milestone.status)}`);
    const header = node("div", "milestone-header");
    header.append(node("strong", "", milestone.name));
    header.append(node("span", `status ${classToken(milestone.status)}`, milestone.status));
    const meta = node("div", "pr-meta");
    meta.append(node("span", "", milestone.repository));
    meta.append(node("span", "", `${text(milestone.pull_requests, "0")} PRs`));
    meta.append(node("span", "", `${text(milestone.open_alerts, "0")} alerts`));
    meta.append(node("span", "", `${text(milestone.vulnerabilities, "0")} vulnerabilities`));
    if (milestone.due_on) meta.append(node("span", "", `Due ${milestone.due_on}`));
    item.append(header, meta);
    return item;
  }) : [emptyNode("No PR milestones have been recorded yet.")]));
}

function renderVectorCounts(vectorCounts) {
  const root = document.getElementById("vectorList");
  const rows = Object.entries(vectorCounts || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  root.replaceChildren(...(rows.length ? rows.map(([vector, count]) => {
    const item = node("div", "source-row");
    item.append(node("b", "", vector));
    item.append(node("span", "status connected", count));
    return item;
  }) : [emptyNode("No detection vectors have been counted yet.")]));
}

async function askSentinel() {
  const button = document.getElementById("askButton");
  const output = document.getElementById("sentinelResponse");
  const query = document.getElementById("intentInput").value.trim();
  if (!query) {
    output.textContent = "Enter a release, credential, workflow, actor, or supply-chain question.";
    return;
  }
  button.disabled = true;
  output.textContent = "Querying fixed Sentinel macro...";
  try {
    const response = await getJson("/commands/sentinel", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, roles: ["Security-Team"] }),
    });
    output.textContent = JSON.stringify(response, null, 2);
  } catch (error) {
    output.textContent = `Unable to complete query. ${error.message}`;
  } finally {
    button.disabled = false;
  }
}

async function boot() {
  renderSources([]);
  renderActivity([]);
  renderFindings([]);
  renderVulnerabilities([], [], []);
  renderPullRequests([]);
  renderMilestones([]);
  renderVectorCounts({});
  document.getElementById("askButton").addEventListener("click", askSentinel);
  document.getElementById("refreshButton").addEventListener("click", () => {
    refresh().catch((error) => setStatus(`Dashboard refresh failed: ${error.message}`, "error"));
  });
  await refresh();
  setInterval(() => {
    refresh().catch((error) => setStatus(`Dashboard refresh failed: ${error.message}`, "error"));
  }, 10000);
}

boot().catch((error) => {
  setStatus(`Dashboard failed to initialize: ${error.message}`, "error");
  document.getElementById("sentinelResponse").textContent = "Dashboard initialization failed. Check the local server logs.";
});
