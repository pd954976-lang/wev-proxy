$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is not installed. Install Git for Windows first."
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI is not installed. Run: winget install --id GitHub.cli"
}

$defaultName = "private-web-relay-vercel"
$name = Read-Host "GitHub repository name [$defaultName]"
if ([string]::IsNullOrWhiteSpace($name)) { $name = $defaultName }

$visibility = Read-Host "Visibility: private or public [private]"
if ([string]::IsNullOrWhiteSpace($visibility)) { $visibility = "private" }
if ($visibility -notin @("private", "public")) { throw "Visibility must be private or public." }

try { gh auth status | Out-Null } catch { gh auth login }
if (-not (Test-Path ".git")) { git init }
git add .
$changes = git status --porcelain
if ($changes) { git commit -m "Vercel private web relay" }

$remote = git remote get-url origin 2>$null
if (-not $remote) {
    gh repo create $name --$visibility --source . --remote origin --push
} else {
    git branch -M main
    git push -u origin main
}

gh repo view --web
