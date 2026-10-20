const esc = s => String(s).replace(/[&<>"]/g, c => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]
));

export function renderAttackPath(suspectHost, form) {
  return `
    <div class="card">
      <h3>Where your password goes</h3>

      <div class="path">
        <div class="path-line"><span class="path-dot"></span></div>

        <div class="path-nodes">
          <div class="node">
            <div class="node-icon">👤</div>
            <strong>You</strong>
            <small>type your password</small>
          </div>

          <div class="node bad">
            <div class="node-icon">⚠️</div>
            <strong>Fake page</strong>
            <small>${esc(suspectHost)}</small>
          </div>

          <div class="node worst">
            <div class="node-icon">💀</div>
            <strong>Attacker</strong>
            <small>${esc(form.fake_target)}</small>
          </div>
        </div>
      </div>

      <p class="path-note">
        A real login would send it to ${esc(form.real_target)}.
      </p>
    </div>
  `;
}