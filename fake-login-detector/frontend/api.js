const API_BASE = "http://127.0.0.1:8001";

export async function scanUrl(url, genuineUrl = "") {
  let response;

  try {
    response = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      // body: JSON.stringify({
      //   url,
      //   genuine_url: "http://localhost:5001/login",
      //   mode: "full",
      // }),
      body: JSON.stringify({
        url,
        ...(genuineUrl.trim() ? { genuine_url: genuineUrl.trim() } : {}),
        mode: "full",
      }),
    });
  } catch {
    throw new Error(
      "Cannot connect to the backend. Start the FastAPI server on port 8000.",
    );
  }

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    throw new Error(
      data?.message ||
      data?.detail ||
      `Scan failed with HTTP ${response.status}.`,
    );
  }

  if (!data || typeof data.score !== "number" || !data.verdict) {
    throw new Error("The backend returned an unexpected scan result.");
  }

  function artifactUrl(filePath) {
    if (!filePath) return null;

    const normalized = String(filePath).replaceAll("\\", "/");
    const marker = "/artifacts/";
    const index = normalized.toLowerCase().lastIndexOf(marker);

    if (index === -1) return null;

    const relativePath = normalized
      .slice(index + marker.length)
      .split("/")
      .map(encodeURIComponent)
      .join("/");

    return `${API_BASE}/artifacts/${relativePath}`;
  }

  const signals = Object.entries(data.signals || {}).map(([name, signal]) => ({
    label: name.replaceAll("_", " ").toUpperCase(),
    points: Number(signal.contribution || 0),
    max: Number(signal.weight_used || 0) * 100,
    available: signal.available !== false,
    unavailableReason: signal.unavailable_reason || "",
  }));

  let suspectHost = data.suspect_url || url;

  try {
    suspectHost = new URL(suspectHost).hostname;
  } catch {
    // Keep the original URL if it cannot be parsed.
  }

  return {
    ...data,

    images: {
      genuine: artifactUrl(data.images?.genuine),
      suspect: artifactUrl(data.images?.suspect),
      diff: artifactUrl(data.images?.diff),
    },

    signals,

    form: {
      real_target: data.form_comparison?.genuine_action || "Not available",
      fake_target: data.form_comparison?.suspect_action || "Not available",
    },

    domains: {
      genuine: data.form_comparison?.genuine_action
        ? new URL(data.form_comparison.genuine_action).origin
        : "",
      suspect: (() => {
        try {
          return new URL(data.suspect_url || url).origin;
        } catch {
          return data.suspect_url || url;
        }
      })(),
    },
  };
}
