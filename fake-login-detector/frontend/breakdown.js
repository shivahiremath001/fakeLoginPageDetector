export function renderBreakdown(signals = []) {
  const available = signals.filter((signal) => signal.available !== false);

  const unavailable = signals.filter((signal) => signal.available === false);

  const rows = available
    .map((signal) => {
      const points = Number(signal.points || 0);
      const max = Number(signal.max || 0);
      const pct =
        max > 0 ? Math.min(100, Math.max(0, (points / max) * 100)) : 0;

      return `
      <div class="bar-row">
        <div class="bar-label">
          <span>${escapeHtml(signal.label)}</span>
          <span>${points.toFixed(1).replace(/\.0$/, "")} / ${max.toFixed(1).replace(/\.0$/, "")} points</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%"></div>
        </div>
      </div>
    `;
    })
    .join("");

  const unavailableMessage = unavailable.length
    ? `<p class="domain-note">Unavailable: ${unavailable.map((s) => escapeHtml(s.label)).join(", ")}. These analyzers were not included in the score.</p>`
    : "";

  return `
    <div class="card">
      <h3>Score breakdown</h3>
      ${rows || "<p>No analyzer breakdown is available.</p>"}
      ${unavailableMessage}
    </div>
  `;
}

function escapeHtml(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character],
  );
}
