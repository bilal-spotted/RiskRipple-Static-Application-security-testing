# Remove root-level stub files; implementations live in core/, io_utils/, reports/.
# Secret scanner: tools/check_secrets.py (run: python tools/check_secrets.py)
# Run from repo root when no IDE has these files open: .\cleanup_root_stubs.ps1
$stubs = @(
    "analyzer.py", "file_loader.py", "html_report.py", "json_report.py",
    "patch_suggester.py", "repo_loader.py", "report.py", "risk.py",
    "check_secrets.py"
)
foreach ($f in $stubs) {
    if (Test-Path $f) { Remove-Item $f -Force; Write-Host "Removed $f" }
}
Write-Host "Done. Use: core.*, io_utils.*, reports.* and python tools/check_secrets.py"
