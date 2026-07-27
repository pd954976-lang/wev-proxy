$bytes = New-Object byte[] 48
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($bytes)
} finally {
    $rng.Dispose()
}
$secret = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
Write-Host ""
Write-Host "Copy this into Vercel as RELAY_API_KEY:" -ForegroundColor Green
Write-Host $secret -ForegroundColor Cyan
Write-Host ""
