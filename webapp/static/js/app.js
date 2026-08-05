function filterTable() {
  const table = document.querySelector('[data-filter-table="findings"]');
  if (!table) return;

  const searchInput = document.getElementById("findingSearch");
  const severitySelect = document.getElementById("severityFilter");
  const categorySelect = document.getElementById("categoryFilter");

  const searchText = (searchInput ? searchInput.value : "").toLowerCase();
  const severity = severitySelect ? severitySelect.value : "";
  const category = categorySelect ? categorySelect.value : "";

  const rows = table.querySelectorAll("tbody tr");
  rows.forEach((row) => {
    const rowText = (row.getAttribute("data-search") || "").toLowerCase();
    const rowSeverity = row.getAttribute("data-severity") || "";
    const rowCategory = row.getAttribute("data-category") || "";

    const matchesSearch = rowText.indexOf(searchText) !== -1;
    const matchesSeverity = !severity || rowSeverity === severity;
    const matchesCategory = !category || rowCategory === category;

    row.style.display = matchesSearch && matchesSeverity && matchesCategory ? "" : "none";
  });
}

function setupFilters() {
  const searchInput = document.getElementById("findingSearch");
  const severitySelect = document.getElementById("severityFilter");
  const categorySelect = document.getElementById("categoryFilter");

  if (searchInput) searchInput.addEventListener("input", filterTable);
  if (severitySelect) severitySelect.addEventListener("change", filterTable);
  if (categorySelect) categorySelect.addEventListener("change", filterTable);
}

function setupFormatToggles() {
  const allCheckbox = document.querySelector('input[data-format="all"]');
  const formatCheckboxes = document.querySelectorAll('input[data-format="single"]');
  if (!allCheckbox) return;

  allCheckbox.addEventListener("change", () => {
    if (allCheckbox.checked) {
      formatCheckboxes.forEach((box) => {
        box.checked = false;
      });
    }
  });

  formatCheckboxes.forEach((box) => {
    box.addEventListener("change", () => {
      if (box.checked) {
        allCheckbox.checked = false;
      }
    });
  });
}

function copyCommand() {
  const command = document.getElementById("cliCommand");
  if (!command) return;
  navigator.clipboard.writeText(command.textContent || "");
}

function setupCopyButton() {
  const button = document.getElementById("copyCommand");
  if (!button) return;
  button.addEventListener("click", copyCommand);
}

function pollRunStatus() {
  const container = document.getElementById("runStatus");
  if (!container) return;

  const statusUrl = container.dataset.statusUrl;
  const redirectUrl = container.dataset.redirectUrl;
  const progressBar = document.getElementById("progressValue");
  const statusLabel = document.getElementById("statusLabel");
  const lastEvent = document.getElementById("lastEvent");

  if (progressBar && progressBar.dataset.progress) {
    const initial = Number(progressBar.dataset.progress);
    progressBar.style.width = `${isNaN(initial) ? 0 : initial}%`;
  }

  function update() {
    fetch(statusUrl)
      .then((response) => response.json())
      .then((data) => {
        if (progressBar) {
          progressBar.style.width = `${data.progress || 0}%`;
        }
        if (statusLabel) {
          statusLabel.textContent = data.status || "";
        }
        if (lastEvent) {
          lastEvent.textContent = data.last_event || "";
        }
        if (data.status === "completed" || data.status === "failed") {
          window.location.href = redirectUrl;
        }
      })
      .catch(() => {});
  }

  update();
  setInterval(update, 2000);
}

document.addEventListener("DOMContentLoaded", () => {
  setupFilters();
  setupFormatToggles();
  setupCopyButton();
  pollRunStatus();
});
