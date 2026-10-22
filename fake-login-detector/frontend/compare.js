export function renderCompare(images = {}) {
  console.log("[Compare] Received images:", images);
  console.log("[Compare] Difference image:", images.diff);
  const shots = [
    { title: "Genuine page", src: images.genuine },
    { title: "Suspect page", src: images.suspect },
    { title: "Differences (red)", src: images.diff },
  ].filter((item) => typeof item.src === "string" && item.src.length > 0);

  if (shots.length === 0) {
    return `
      <div class="card">
        <h3>Side-by-side comparison</h3>
        <p>No comparison screenshots are available for this scan.</p>
      </div>
    `;
  }

  return `
    <div class="card">
      <h3>Side-by-side comparison</h3>
      <div class="compare-grid">
        ${shots
      .map(
        (shot) => `
          <figure class="shot">
            <div class="shot-title">${shot.title}</div>
            <img src="${shot.src}" alt="${shot.title}" loading="lazy">
          </figure>
        `,
      )
      .join("")}
      </div>
    </div>
  `;
}
