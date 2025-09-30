# Test bootstrap endpoint
$headers = @{
    "Content-Type" = "application/json"
}

$body = @{
    subject = "test-host"
    sans = @("test-host")  
    bootstrap_token = "123456"
} | ConvertTo-Json

Write-Host "Testing bootstrap endpoint..."
Write-Host "Body: $body"

try {
    # Skip certificate validation for testing
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-WebRequest -Uri "https://localhost:8443/agent/bootstrap/ott" -Method POST -Body $body -Headers $headers
    Write-Host "Response: $($response.Content)"
} catch {
    Write-Host "Error: $_"
    if ($_.Exception.Response) {
        Write-Host "StatusCode: $($_.Exception.Response.StatusCode)"
    }
}