# Setup Git hooks for the cybersecurity platform
# This script configures Git to use our custom hooks directory

Write-Host "🔧 Setting up Git hooks for cybersecurity platform..." -ForegroundColor Cyan

# Set Git hooks path to our custom directory
Write-Host "📁 Configuring Git hooks path..." -ForegroundColor Yellow
git config core.hooksPath .githooks

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Git hooks path configured successfully!" -ForegroundColor Green
} else {
    Write-Host "❌ Failed to configure Git hooks path" -ForegroundColor Red
    exit 1
}

# Make the pre-commit hook executable (Windows doesn't need chmod, but we'll create a wrapper)
Write-Host "🔐 Setting up pre-commit hook..." -ForegroundColor Yellow

# Create a batch file wrapper for the PowerShell script
$batchContent = @'
@echo off
powershell.exe -ExecutionPolicy Bypass -File "%~dp0pre-commit.ps1"
exit /b %ERRORLEVEL%
'@

Set-Content -Path ".githooks/pre-commit" -Value $batchContent -Encoding ASCII

Write-Host "✅ Pre-commit hook configured!" -ForegroundColor Green

# Test if gitleaks is available
Write-Host "🔍 Checking for gitleaks installation..." -ForegroundColor Yellow
if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
    Write-Host "✅ gitleaks is installed and ready!" -ForegroundColor Green
} else {
    Write-Host "⚠️  gitleaks is not installed. Please install it:" -ForegroundColor Yellow
    Write-Host "   Option 1: winget install gitleaks" -ForegroundColor Cyan
    Write-Host "   Option 2: Download from https://github.com/zricethezav/gitleaks/releases" -ForegroundColor Cyan
    Write-Host "   Option 3: Use Chocolatey: choco install gitleaks" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "🎉 Git hooks setup complete!" -ForegroundColor Green
Write-Host "   - Pre-commit hook will scan for secrets and unsafe patterns" -ForegroundColor White
Write-Host "   - Configuration file: .gitleaks.toml" -ForegroundColor White
Write-Host "   - Hook files: .githooks/" -ForegroundColor White
Write-Host ""
Write-Host "🧪 To test the setup, try making a commit with a fake API key" -ForegroundColor Cyan