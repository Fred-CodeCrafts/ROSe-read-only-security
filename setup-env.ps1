# Environment Variables Setup for AI Security Analyst
# Run this script to set up environment variables

Write-Host "🚀 Setting up environment variables for AI Security Analyst..." -ForegroundColor Green

# AWS Configuration
$env:AWS_REGION = "ap-southeast-2"
$env:SECURITY_DATA_BUCKET = "fred-codecrafts-security-data-lake"
$env:ATHENA_RESULTS_BUCKET = "fred-codecrafts-athena-results"
$env:GLUE_DATABASE = "security_analytic"

# Bedrock Token
$env:AWS_BEARER_TOKEN_BEDROCK = "ABSKQmVkcm9ja0FQSUtleS1sZmpyLWF0LTQ1OTQ3MDk5OTk0NzpwWGMzeFRGdFFDN05udElBU3lLakJuK3hmRVRiNHBsa0NQNjJCV1YxbnNOM1F2VWNSbTlKTkYvMWpUOD0="

Write-Host "✅ Environment variables set:" -ForegroundColor Green
Write-Host "   AWS_REGION: $env:AWS_REGION" -ForegroundColor Yellow
Write-Host "   SECURITY_DATA_BUCKET: $env:SECURITY_DATA_BUCKET" -ForegroundColor Yellow
Write-Host "   ATHENA_RESULTS_BUCKET: $env:ATHENA_RESULTS_BUCKET" -ForegroundColor Yellow
Write-Host "   GLUE_DATABASE: $env:GLUE_DATABASE" -ForegroundColor Yellow
Write-Host "   AWS_BEARER_TOKEN_BEDROCK: [SET]" -ForegroundColor Yellow

Write-Host "`n🎉 Environment setup complete!" -ForegroundColor Green
Write-Host "You can now run the AI Security Analyst application." -ForegroundColor Cyan