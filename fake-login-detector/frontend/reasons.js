const LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info"
};

export function renderReasons(reasons) {
  const items = reasons.map(r => `
    <li class="reason">
      <span class="badge ${r.severity}">${LABELS[r.severity]}</span>
      <div>
        <strong>${r.title}</strong>
        <p>${r.detail}</p>
      </div>
    </li>
  `).join("");

  return `
    <div class="card">
      <h3>Why we think so</h3>
      <ul class="reasons">${items}</ul>
    </div>
  `;
}