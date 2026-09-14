$outputDir = Join-Path $PSScriptRoot "output"
$targets = @("findings.json", "evaluation_report.json")

$clearedAny = $false

foreach ($file in $targets) {
    $targetPath = Join-Path $outputDir $file
    if (Test-Path $targetPath) {
        Remove-Item $targetPath -Force
        Write-Host "Removed output\$file" -ForegroundColor Yellow
        $clearedAny = $true
    }
}

if (-not $clearedAny) {
    Write-Host "No generated output files were found."
}
