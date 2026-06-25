$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$crates = @(
    "awol2005ex3-kerberos-constants"
    "awol2005ex3-mit-krb5-ccache"
    "awol2005ex3-red-asn1-derive"
    "awol2005ex3-red-asn1"
    "awol2005ex3-kerberos-crypto"
    "awol2005ex3-kerberos-keytab"
    "awol2005ex3-kerberos-asn1"
    "awol2005ex3-kerberos-ccache"
    "awol2005ex3-kerbeiros"
    "awol2005ex3-kinit-kt"
    "awol2005ex3-klist"
)

foreach ($crate in $crates) {
    Write-Host "`n=== Publishing $crate ===" -ForegroundColor Cyan
    $output = & cmd.exe /c "cargo publish -p $crate --registry crates-io 2>&1"
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        Write-Host "Published $crate, waiting 15s for index update..." -ForegroundColor Yellow
        Start-Sleep -Seconds 15
        continue
    }

    $text = "$output"
    if ($text -match "already exists|is already uploaded") {
        Write-Host "  -> $crate already published, skipping" -ForegroundColor DarkYellow
        continue
    }

    Write-Host "Failed to publish $crate (exit code: $exitCode)" -ForegroundColor Red
    Write-Host $output
    exit $exitCode
}

Write-Host "`nAll crates published successfully!" -ForegroundColor Green
