export function renderReportButtons() {
  return `
    <div class="card report-card">
      <h3>Report</h3>
      <button id="download-json">Download report (JSON)</button>
      <button id="print-report" class="secondary">Print / save as PDF</button>
    </div>
  `;
}

export function wireReportButtons(data) {
  document.getElementById("download-json").addEventListener("click", () => {
    const { images, ...report } = data;
    report.created_at = new Date().toISOString();

    const blob = new Blob(
      [JSON.stringify(report, null, 2)],
      { type: "application/json" }
    );
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "scan-report.json";
    link.click();
    URL.revokeObjectURL(link.href);
  });

  document.getElementById("print-report").addEventListener("click", () => {
    window.print();
  });
}