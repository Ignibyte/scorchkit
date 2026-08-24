(() => {
  "use strict";
  const root = document.querySelector("[data-event-after]");
  const state = document.querySelector("[data-stream-state]");
  if (!root || !state || typeof EventSource !== "function") return;
  const after = Number.parseInt(root.dataset.eventAfter || "0", 10);
  const source = new EventSource(`/events?after=${Number.isSafeInteger(after) ? after : 0}`);
  source.addEventListener("open", () => {
    state.textContent = "Live updates connected";
    state.classList.add("ok");
  });
  source.addEventListener("error", () => {
    state.textContent = "Live updates reconnecting";
    state.classList.remove("ok");
  });
  source.addEventListener("reset", () => {
    state.textContent = "Event history moved; refresh required";
    source.close();
  });
  source.addEventListener("control", (message) => {
    let event;
    try { event = JSON.parse(message.data); } catch (_) { return; }
    if (!event || event.resourceType !== "job" || typeof event.resourceId !== "string") return;
    const card = document.querySelector(`[data-job-id="${CSS.escape(event.resourceId)}"]`);
    const badge = card && card.querySelector("[data-job-state]");
    const next = event.payload && event.payload.state;
    if (badge && typeof next === "string") badge.textContent = next;
  });
})();
