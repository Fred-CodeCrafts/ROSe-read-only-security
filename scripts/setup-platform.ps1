# Complete setup script for AI Cybersecurity Platform
# This script sets up the entire OSS-first cybersecurity analysis platform

param(
    [switch]$SkipDocker,
    [switch]$SkipData,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "[SETUP] Setting up AI-Assisted Cybersecurity Analysis Platform..." -ForegroundColor Green
Write-Host "        OSS-First • $0/month • Complete Local Setup" -ForegroundColor Cyan
Write-Host ""

# Function to check if a command exists
function Test-Command {
    param($Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

# Function to wait for service to be ready
function Wait-ForService {
    param($Url, $ServiceName, $MaxAttempts = 30)
    
    Write-Host "[WAIT] Waiting for $ServiceName to be ready..." -ForegroundColor Yellow
    
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $Url -Method GET -TimeoutSec 5 -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                Write-Host "[OK] $ServiceName is ready!" -ForegroundColor Green
                return $true
            }
        } catch {
            if ($Verbose) {
                Write-Host "     Attempt $i/$MaxAttempts failed: $($_.Exception.Message)" -ForegroundColor Gray
            }
        }
        Start-Sleep -Seconds 2
    }
    
    Write-Host "[ERROR] $ServiceName failed to start within timeout" -ForegroundColor Red
    return $false
}

# Step 1: Check Prerequisites
Write-Host "[1] Checking prerequisites..." -ForegroundColor Cyan

$prerequisites = @{
    "docker" = "Docker"
    "docker-compose" = "Docker Compose"
    "python" = "Python 3.8+"
    "git" = "Git"
}

$missingPrereqs = @()

foreach ($cmd in $prerequisites.Keys) {
    if (Test-Command $cmd) {
        Write-Host "    [OK] $($prerequisites[$cmd]) found" -ForegroundColor Green
    } else {
        Write-Host "    [MISSING] $($prerequisites[$cmd]) not found" -ForegroundColor Red
        $missingPrereqs += $prerequisites[$cmd]
    }
}

if ($missingPrereqs.Count -gt 0) {
    Write-Host ""
    Write-Host "[ERROR] Missing prerequisites: $($missingPrereqs -join ', ')" -ForegroundColor Red
    Write-Host "        Please install missing components and try again." -ForegroundColor Yellow
    Write-Host "        See docs/setup/README.md for installation instructions." -ForegroundColor Cyan
    exit 1
}

# Step 2: Setup Git Hooks
Write-Host ""
Write-Host "[2] Setting up Git security hooks..." -ForegroundColor Cyan

try {
    & .\scripts\setup-git-hooks.ps1
    Write-Host "    [OK] Git hooks configured successfully" -ForegroundColor Green
} catch {
    Write-Host "    [WARN] Git hooks setup failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "           Continuing with setup..." -ForegroundColor Gray
}

# Step 3: Create Required Directories
Write-Host ""
Write-Host "[3] Creating directory structure..." -ForegroundColor Cyan

$directories = @(
    "data/synthetic",
    "data/analysis", 
    "data/mock",
    "config/oss",
    "logs",
    "docs/setup"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "    [CREATED] $dir" -ForegroundColor Green
    } else {
        Write-Host "    [EXISTS] $dir" -ForegroundColor Gray
    }
}

# Step 4: Install Python Dependencies
Write-Host ""
Write-Host "[4] Installing Python dependencies..." -ForegroundColor Cyan

try {
    & python -m pip install --upgrade pip
    & python -m pip install -r requirements.txt
    Write-Host "    [OK] Python dependencies installed" -ForegroundColor Green
} catch {
    Write-Host "    [ERROR] Failed to install Python dependencies: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "            Try running: python -m pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

# Step 5: Generate Synthetic Data
if (-not $SkipData) {
    Write-Host ""
    Write-Host "[5] Generating synthetic data..." -ForegroundColor Cyan
    
    try {
        & .\scripts\generate-synthetic-data.ps1
        Write-Host "    [OK] Synthetic data generated successfully" -ForegroundColor Green
    } catch {
        Write-Host "    [ERROR] Failed to generate synthetic data: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "            You can generate it later with: .\scripts\generate-synthetic-data.ps1" -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "[5] Skipping synthetic data generation (--SkipData)" -ForegroundColor Yellow
}

# Step 6: Start Docker Services
if (-not $SkipDocker) {
    Write-Host ""
    Write-Host "[6] Starting OSS services with Docker Compose..." -ForegroundColor Cyan
    
    try {
        # Pull images first
        Write-Host "    [PULL] Pulling Docker images..." -ForegroundColor Yellow
        & docker-compose pull
        
        # Start services
        Write-Host "    [START] Starting services..." -ForegroundColor Yellow
        & docker-compose up -d
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    [OK] Docker services started" -ForegroundColor Green
            
            # Wait for key services to be ready
            $services = @{
                "http://localhost:9090/-/healthy" = "Prometheus"
                "http://localhost:3000/api/health" = "Grafana"
                "http://localhost:11434/api/version" = "Ollama"
                "http://localhost:9000/minio/health/live" = "MinIO"
            }
            
            Write-Host ""
            Write-Host "    [CHECK] Checking service health..." -ForegroundColor Cyan
            
            foreach ($url in $services.Keys) {
                $serviceName = $services[$url]
                if (Wait-ForService -Url $url -ServiceName $serviceName -MaxAttempts 15) {
                    # Service is ready
                } else {
                    Write-Host "    [WARN] $serviceName may not be fully ready yet" -ForegroundColor Yellow
                }
            }
            
        } else {
            Write-Host "    [ERROR] Failed to start Docker services" -ForegroundColor Red
            Write-Host "            Check logs with: docker-compose logs" -ForegroundColor Yellow
            exit 1
        }
        
    } catch {
        Write-Host "    [ERROR] Docker setup failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "            Try running: docker-compose up -d" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host ""
    Write-Host "[6] Skipping Docker services (--SkipDocker)" -ForegroundColor Yellow
}

# Step 7: Verify Setup
Write-Host ""
Write-Host "[7] Verifying setup..." -ForegroundColor Cyan

$verificationTests = @()

# Check if synthetic data exists
if (Test-Path "data/synthetic/users.json") {
    $verificationTests += "[OK] Synthetic data generated"
} else {
    $verificationTests += "[WARN] Synthetic data not found"
}

# Check if Git hooks are configured
$hooksPath = & git config core.hooksPath
if ($hooksPath -eq ".githooks") {
    $verificationTests += "[OK] Git hooks configured"
} else {
    $verificationTests += "[WARN] Git hooks not configured"
}

# Check if Docker services are running (if not skipped)
if (-not $SkipDocker) {
    try {
        $runningServices = & docker-compose ps --services --filter "status=running"
        if ($runningServices.Count -gt 0) {
            $verificationTests += "[OK] Docker services running ($($runningServices.Count) services)"
        } else {
            $verificationTests += "[ERROR] No Docker services running"
        }
    } catch {
        $verificationTests += "[WARN] Could not check Docker services"
    }
}

foreach ($test in $verificationTests) {
    Write-Host "    $test" -ForegroundColor White
}

# Step 8: Setup Complete
Write-Host ""
Write-Host "[COMPLETE] Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "[SERVICES] Access your services:" -ForegroundColor White
Write-Host "           • Grafana Dashboard: http://localhost:3000 (admin/admin123)" -ForegroundColor Cyan
Write-Host "           • Prometheus Metrics: http://localhost:9090" -ForegroundColor Cyan
Write-Host "           • MinIO Console: http://localhost:9001 (minioadmin/minioadmin123)" -ForegroundColor Cyan
Write-Host "           • Ollama API: http://localhost:11434" -ForegroundColor Cyan
Write-Host ""
Write-Host "[NEXT] Next steps:" -ForegroundColor White
Write-Host "       1. Explore the Grafana dashboards for security analytics" -ForegroundColor Gray
Write-Host "       2. Review the documentation in docs/setup/" -ForegroundColor Gray
Write-Host "       3. Start implementing the AI analysis components" -ForegroundColor Gray
Write-Host "       4. Run your first security analysis workflow" -ForegroundColor Gray
Write-Host ""
Write-Host "[SECURITY] Security features active:" -ForegroundColor Yellow
Write-Host "           • Pre-commit hooks prevent secret commits" -ForegroundColor Gray
Write-Host "           • All data is synthetic and safe for development" -ForegroundColor Gray
Write-Host "           • OSS-first architecture with $0 monthly cost" -ForegroundColor Gray
Write-Host ""
Write-Host "[HELP] Need help? Check docs/setup/README.md or run docker-compose logs" -ForegroundColor Cyan