const COLORS = {
  genuine: { main: "#20ffad", glow: "#00c985", label: "LOW RISK" },
  low_risk: { main: "#20ffad", glow: "#00c985", label: "LOW RISK" },
  suspicious: { main: "#ffb547", glow: "#f97316", label: "ELEVATED RISK" },
  likely_clone: { main: "#ff5575", glow: "#ef244f", label: "HIGH RISK" },
  unrelated: { main: "#67d8ff", glow: "#168cce", label: "UNCERTAIN" },
};

export function renderGauge(score, verdict = "") {
  const safeScore = Number.isFinite(Number(score))
    ? Math.min(100, Math.max(0, Number(score)))
    : 0;

  const theme =
    COLORS[verdict] ||
    (safeScore >= 70
      ? COLORS.likely_clone
      : safeScore >= 20
        ? COLORS.suspicious
        : COLORS.low_risk);

  const radius = 65;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - safeScore / 100);
  const scoreText = Number.isInteger(safeScore)
    ? String(safeScore)
    : safeScore.toFixed(1);

  return `
    <div
      class="gauge risk-gauge"
      role="img"
      aria-label="Risk score ${scoreText} out of 100"
      style="--risk-color:${theme.main};--risk-glow:${theme.glow}"
    >
      <div class="gauge-orbit">
        <svg
          class="gauge-svg"
          viewBox="0 0 160 160"
          aria-hidden="true"
        >
          <defs>
            <linearGradient id="riskGradient-${verdict || "default"}"
              x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="${theme.main}" />
              <stop offset="100%" stop-color="${theme.glow}" />
            </linearGradient>
            <filter id="riskGlow-${verdict || "default"}"
              x="-60%" y="-60%" width="220%" height="220%">
              <feGaussianBlur stdDeviation="3.5" result="blur"/>
              <feMerge>
                <feMergeNode in="blur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>

          <circle
            class="gauge-track"
            cx="80" cy="80" r="${radius}"
            fill="none"
            stroke-width="11"
          />

          <circle
            class="gauge-progress"
            cx="80" cy="80" r="${radius}"
            fill="none"
            stroke="url(#riskGradient-${verdict || "default"})"
            stroke-width="11"
            stroke-linecap="round"
            stroke-dasharray="${circumference}"
            stroke-dashoffset="${offset}"
            transform="rotate(-90 80 80)"
            filter="url(#riskGlow-${verdict || "default"})"
          />

          <circle
            cx="80" cy="80" r="51"
            fill="rgba(1, 18, 24, 0.55)"
            stroke="rgba(170, 255, 222, 0.08)"
            stroke-width="1"
          />

          <text
            class="gauge-number"
            x="80" y="82"
            text-anchor="middle"
            dominant-baseline="middle"
            fill="${theme.main}"
          >${scoreText}</text>

          <text
            class="gauge-unit"
            x="80" y="105"
            text-anchor="middle"
          >/ 100</text>
        </svg>
      </div>

      <div class="gauge-caption">
        <span class="gauge-status-dot"></span>
        <span>${theme.label}</span>
      </div>

      <div class="gauge-meter">
        <div class="gauge-meter-label">
          <span>RISK SCORE</span>
          <strong>${scoreText}%</strong>
        </div>
        <div
          class="gauge-meter-track"
          role="progressbar"
          aria-label="Risk score"
          aria-valuemin="0"
          aria-valuemax="100"
          aria-valuenow="${safeScore}"
        >
          <div
            class="gauge-meter-fill"
            style="width:${safeScore}%"
          ></div>
        </div>
        <div class="gauge-scale">
          <span>0 · LOWER RISK</span>
          <span>HIGHER RISK · 100</span>
        </div>
      </div>
    </div>
  `;
}
