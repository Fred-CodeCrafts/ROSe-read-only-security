# Pre-commit hook for cybersecurity platform (PowerShell version)
# Prevents commits with secrets, credentials, or unsafe content

Write-Host "🔍 Running pre-commit security checks..." -ForegroundColor Cyan

# Check if gitleaks is installed
if (-not (Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-Host "❌ gitleaks is not installed. Please install it:" -ForegroundColor Red
    Write-Host "   - Download from: https://github.com/zricethezav/gitleaks/releases" -ForegroundColor Yellow
    Write-Host "   - Or use: winget install gitleaks" -ForegroundColor Yellow
    exit 1
}

# Run gitleaks to detect secrets
Write-Host "🔐 Scanning for secrets and credentials..." -ForegroundColor Cyan
$gitleaksResult = & gitleaks detect --source . --verbose --redact --no-git
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "🚫 COMMIT BLOCKED: Secrets or credentials detected!" -ForegroundColor Red
    Write-Host ""
    Write-Host "📋 To fix this issue:" -ForegroundColor Yellow
    Write-Host "1. Run 'gitleaks detect --source . --verbose' to see details"
    Write-Host "2. Remove or encrypt the detected secrets"
    Write-Host "3. Add sensitive files to .gitignore"
    Write-Host "4. Use environment variables or secure vaults for credentials"
    Write-Host ""
    Write-Host "🔧 For false positives, add exceptions to .gitleaks.toml"
    exit 1
}

# Check for common unsafe patterns
Write-Host "🛡️  Checking for unsafe patterns..." -ForegroundColor Cyan

# Get staged files
$stagedFiles = & git diff --cached --name-only

# Check for hardcoded IPs (allow private ranges)
foreach ($file in $stagedFiles) {
    if (Test-Path $file -and $file -notmatch "\.md$" -and $file -notmatch "test") {
        $content = Get-Content $file -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -match "192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.") {
            Write-Host "⚠️  Warning: Private IP addresses detected in $file. Ensure these are intentional." -ForegroundColor Yellow
        }
    }
}

# Check for TODO/FIXME with security implications
$gitDiff = & git diff --cached
if ($gitDiff -match "(?i)TODO.*security|FIXME.*security|TODO.*auth|FIXME.*auth") {
    Write-Host "⚠️  Warning: Security-related TODOs detected. Consider addressing before commit." -ForegroundColor Yellow
}

# Check for debug statements that might leak info
if ($gitDiff -match "console\.log|print\(|println\!|fmt\.Print" -and $gitDiff -notmatch "test") {
    Write-Host "⚠️  Warning: Debug statements detected. Ensure they don't leak sensitive information." -ForegroundColor Yellow
}

# Validate synthetic data files
Write-Host "🎭 Validating synthetic data..." -ForegroundColor Cyan
foreach ($file in $stagedFiles) {
    if ($file -match "\.(json|csv|yaml|yml)$" -and $file -notmatch "test" -and (Test-Path $file)) {
        $content = Get-Content $file -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -match "@gmail\.com|@yahoo\.com|@hotmail\.com|real.*email|actual.*data") {
            Write-Host "❌ COMMIT BLOCKED: Potential real data detected in $file" -ForegroundColor Red
            Write-Host "   Only synthetic/mock data should be committed."
            exit 1
        }
    }
}

# Check Docker Compose security
$composeFiles = $stagedFiles | Where-Object { $_ -match "docker-compose" }
if ($composeFiles) {
    Write-Host "🐳 Validating Docker Compose security..." -ForegroundColor Cyan
    foreach ($composeFile in $composeFiles) {
        if (Test-Path $composeFile) {
            $content = Get-Content $composeFile -Raw
            
            # Check for default passwords
            if ($content -match "password.*admin|password.*123|password.*password") {
                Write-Host "⚠️  Warning: Default passwords detected in $composeFile. Consider using environment variables." -ForegroundColor Yellow
            }
            
            # Check for privileged containers
            if ($content -match "privileged.*true") {
                Write-Host "⚠️  Warning: Privileged containers detected in $composeFile. Ensure this is necessary." -ForegroundColor Yellow
            }
        }
    }
}

Write-Host "✅ Pre-commit security checks passed!" -ForegroundColor Green
Write-Host ""