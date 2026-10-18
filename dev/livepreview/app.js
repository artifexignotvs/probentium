/* Eadem tabula, nulla interpretatio occulta. */
"use strict";
const token = document.querySelector('meta[name="preview-token"]').content;
const pane = document.getElementById("console");
const screen = document.getElementById("screen");
const status = document.getElementById("connection");
const navigation = {overview: "1", evidence: "2", timeline: "3", controls: "4", incident: "5", filings: "6", changes: "7", claims: "8", scenarios: "9", review: "0", help: "?"};
let chain = Promise.resolve();
function put(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value;
}
function dimensions() {
  const box = document.getElementById("measure").getBoundingClientRect();
  const style = getComputedStyle(pane);
  const width = pane.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
  const height = pane.clientHeight - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom);
  return {width: Math.max(80, Math.min(220, Math.floor(width / box.width))), height: Math.max(24, Math.min(70, Math.floor(height / box.height) + 6))};
}
function draw(frame) {
  /* Limites communes servantur; tituli in margine semel ostenduntur. */
  const rows = frame.lines.slice(4, -2);
  const lines = rows.map((row, index) => {
    const element = document.createElement("div");
    element.className = "line " + ({normal: "normal", strong: "strong", dim: "dim", inverse: "inverse"}[row.style] || "normal");
    if (index === 0) element.classList.add("view-heading");
    if (index === rows.length - 1) element.classList.add("console-message");
    element.textContent = row.text;
    return element;
  });
  screen.replaceChildren(...lines);
  const summary = frame.summary || {};
  put("active-view", frame.view);
  put("case-label", summary.case_name || "Case unavailable");
  put("case-revision", "REV " + frame.revision);
  put("case-state", "Integrity / " + (summary.integrity || "not checked"));
  put("case-origin", summary.origin || "Origin unavailable");
  for (const name of ["sources", "events", "controls", "filings"]) {
    const value = summary.counts && summary.counts[name];
    put("count-" + name, Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString("en-US") : "—");
  }
  document.querySelectorAll("button[data-key]").forEach(button => {
    if (button.dataset.key === navigation[frame.view]) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  status.textContent = frame.closed ? "SESSION CLOSED / any key resumes" : "LOCAL SESSION";
  status.dataset.state = frame.closed ? "closed" : "connected";
  document.title = "PROBENTIUM / " + frame.view;
}
async function request(key) {
  const size = dimensions();
  const headers = {"X-Preview-Token": token};
  let response;
  if (key === undefined) {
    response = await fetch("/api/frame?" + new URLSearchParams(size), {headers, cache: "no-store"});
  } else {
    headers["Content-Type"] = "application/json";
    response = await fetch("/api/key", {method: "POST", headers, body: JSON.stringify({key, ...size})});
  }
  if (!response.ok) throw new Error("local_request_failed");
  draw(await response.json());
}
function enqueue(key) {
  chain = chain.then(() => request(key)).catch(() => {
    status.textContent = "CONNECTION UNAVAILABLE / reload";
    status.dataset.state = "unavailable";
    put("case-state", "Integrity / current state unavailable");
  });
}
window.addEventListener("keydown", event => {
  if (event.ctrlKey || event.metaKey || event.altKey || event.key === "Tab" || event.key === "Shift") return;
  if (event.target.closest("button") && ["Enter", " "].includes(event.key)) return;
  event.preventDefault();
  enqueue(event.key);
});
document.querySelectorAll("button[data-key]").forEach(button => button.addEventListener("click", () => {
  enqueue(button.dataset.key);
  pane.focus({preventScroll: true});
}));
let resizeTimer;
window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => enqueue(), 120); });
enqueue();
pane.focus();
