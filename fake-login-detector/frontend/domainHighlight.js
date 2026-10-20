// Escape text so it is safe to show inside HTML.
const esc = (s) =>
  String(s).replace(
    /[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c],
  );

// Finds which letters of `fake` also appear (in order) in `real`.
function matchedLetters(real, fake) {
  const n = real.length;
  const m = fake.length;
  const dp = Array.from({ length: n + 1 }, () => Array(m + 1).fill(0));

  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] =
        real[i] === fake[j]
          ? dp[i + 1][j + 1] + 1
          : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const same = Array(m).fill(false);
  let i = 0;
  let j = 0;

  while (i < n && j < m) {
    if (real[i] === fake[j]) {
      same[j] = true;
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      i++;
    } else {
      j++;
    }
  }

  return same;
}

export function renderDomain(genuineHost, suspectHost) {
  const real = String(genuineHost || "");
  const suspect = String(suspectHost || "");

  // Identical hostnames should never highlight any characters.
  const identical = real.toLowerCase() === suspect.toLowerCase();

  const same = identical
    ? Array(suspect.length).fill(true)
    : matchedLetters(real, suspect);

  const fakeHtml = Array.from(suspect)
    .map((ch, k) =>
      same[k] ? esc(ch) : `<span class="bad-char">${esc(ch)}</span>`,
    )
    .join("");

  return `
    <div class="card">
      <h3>Web address check</h3>
      <p class="domain-label">Real address</p>
      <p class="domain real">${esc(real)}</p>
      <p class="domain-label">Address you scanned</p>
      <p class="domain fake">${fakeHtml}</p>
      ${
        identical
          ? '<p class="domain-note">The hostnames match exactly.</p>'
          : '<p class="domain-note">Red letters indicate characters that differ from the real address.</p>'
      }
    </div>
  `;
}
