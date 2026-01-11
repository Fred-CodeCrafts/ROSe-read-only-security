# Generate synthetic data for the cybersecurity platform
# This script creates safe, synthetic datasets for development and testing

Write-Host "🎭 Generating synthetic cybersecurity data..." -ForegroundColor Cyan

# Check if Python is available
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "   Please install Python 3.8+ and try again" -ForegroundColor Yellow
    exit 1
}

# Check if required directories exist
$directories = @("data/synthetic", "data/analysis")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        Write-Host "📁 Creating directory: $dir" -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Install required packages if not already installed
Write-Host "📦 Checking Python dependencies..." -ForegroundColor Yellow
$requiredPackages = @("faker", "faker-security")

foreach ($package in $requiredPackages) {
    $installed = & python -c "import $($package.Replace('-', '_'))" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "   Installing $package..." -ForegroundColor Cyan
        & python -m pip install $package
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Failed to install $package" -ForegroundColor Red
            exit 1
        }
    }
}

# Run the synthetic data generator
Write-Host "🔄 Running synthetic data generator..." -ForegroundColor Cyan
& python data/synthetic/generator.py

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ Synthetic data generation completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📊 Generated datasets:" -ForegroundColor White
    
    # List generated files
    $syntheticFiles = Get-ChildItem "data/synthetic" -Filter "*.json" -ErrorAction SilentlyContinue
    foreach ($file in $syntheticFiles) {
        $size = [math]::Round($file.Length / 1KB, 2)
        Write-Host "   - $($file.Name) ($size KB)" -ForegroundColor Cyan
    }
    
    Write-Host ""
    Write-Host "🔒 Security Notes:" -ForegroundColor Yellow
    Write-Host "   - All data is completely synthetic and safe for development" -ForegroundColor White
    Write-Host "   - No real personal information is included" -ForegroundColor White
    Write-Host "   - Data is validated to prevent accidental real data inclusion" -ForegroundColor White
    Write-Host "   - Safe to commit to version control" -ForegroundColor White
    
} else {
    Write-Host "❌ Synthetic data generation failed" -ForegroundColor Red
    exit 1
}