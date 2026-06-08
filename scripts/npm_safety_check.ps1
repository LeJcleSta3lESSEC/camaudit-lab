Write-Host "CamAudit npm safety check"
Write-Host "This project should not need npm unless a frontend is later added."

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "npm not found. OK for this Python project."
    exit 0
}

Write-Host "npm version:"
npm --version

Write-Host "Global npm packages:"
npm ls -g --depth=0

Write-Host "ignore-scripts setting:"
npm config get ignore-scripts

Write-Host "If you are inside a Node project, run manually:"
Write-Host "  npm audit"
Write-Host "  npm audit signatures"
Write-Host "  npm ci --ignore-scripts"
