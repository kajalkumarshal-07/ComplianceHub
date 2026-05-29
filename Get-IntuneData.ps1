<#
.SYNOPSIS
  Fetch Intune compliance & device data from Microsoft Graph API and export to JSON.
.DESCRIPTION
  Uses OAuth2 client credentials to fetch all Intune data and writes to data.json
  for use with the Intune Compliance Dashboard HTML.
.PARAMETER TenantId
  Your Azure AD tenant ID (GUID)
.PARAMETER ClientId
  Your Azure AD app registration client ID (GUID)
.PARAMETER ClientSecret
  Your Azure AD app registration client secret
.PARAMETER OutputPath
  Path to write data.json (default: .\data.json in script directory)
.EXAMPLE
  .\Get-IntuneData.ps1 -TenantId "abc-..." -ClientId "xyz-..." -ClientSecret "mySecret"
#>

param(
  [Parameter(Mandatory = $true)]
  [string]$TenantId,

  [Parameter(Mandatory = $true)]
  [string]$ClientId,

  [Parameter(Mandatory = $true)]
  [string]$ClientSecret,

  [string]$OutputPath
)

if (-not $OutputPath) {
  $OutputPath = Join-Path -Path $PSScriptRoot -ChildPath "data.json"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Intune Compliance Dashboard - Data Collector" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# -------------------------------------------------------------------
# 1. Get OAuth2 token
# -------------------------------------------------------------------
Write-Host "[1/7] Authenticating to Azure AD..." -ForegroundColor Yellow

$body = @{
  grant_type    = "client_credentials"
  client_id     = $ClientId
  client_secret = $ClientSecret
  scope         = "https://graph.microsoft.com/.default"
}

try {
  $tokenResponse = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -Body $body `
    -ErrorAction Stop
}
catch {
  Write-Host "  FAILED: $_" -ForegroundColor Red
  Write-Host "  Check your TenantId, ClientId, and ClientSecret." -ForegroundColor Red
  exit 1
}

$accessToken = $tokenResponse.access_token
$headers = @{
  Authorization = "Bearer $accessToken"
  "Content-Type" = "application/json"
}
Write-Host "  Authenticated successfully" -ForegroundColor Green

# -------------------------------------------------------------------
# 2. Helper: fetch with pagination
# -------------------------------------------------------------------
function Get-GraphPage {
  param([string]$Uri)
  $all = @()
  $nextLink = $Uri
  $page = 0
  do {
    $page++
    Write-Host "    Page $page..." -NoNewline
    try {
      $response = Invoke-RestMethod -Method Get -Uri $nextLink -Headers $headers -ErrorAction Stop
      $count = ($response.value | Measure-Object).Count
      Write-Host " $count items" -ForegroundColor Gray
      $all += $response.value
      $nextLink = $response."@odata.nextLink"
    }
    catch {
      Write-Host " FAILED: $_" -ForegroundColor Red
      break
    }
  } while ($nextLink)
  Write-Host "    Total: $($all.Count) items" -ForegroundColor Green
  return $all
}

# -------------------------------------------------------------------
# 3. Fetch all data
# -------------------------------------------------------------------
$data = @{}

Write-Host "[2/7] Fetching managed devices..." -ForegroundColor Yellow
$data.devices = Get-GraphPage -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"

Write-Host "[3/7] Fetching compliance policies..." -ForegroundColor Yellow
$data.policies = Get-GraphPage -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies"

Write-Host "[4/7] Fetching configuration profiles..." -ForegroundColor Yellow
$data.configs = Get-GraphPage -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations"

Write-Host "[5/7] Fetching mobile apps..." -ForegroundColor Yellow
$data.apps = Get-GraphPage -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps"

Write-Host "[6/7] Fetching update rings, autopilot, health..." -ForegroundColor Yellow
$data.updateRings = Get-GraphPage -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsUpdateForBusinessConfigurations"
$data.autopilot = Get-GraphPage -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities"
try {
  $data.healthScripts = Get-GraphPage -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceHealthScripts"
} catch {
  $data.healthScripts = @()
  Write-Host "    (health scripts skipped - may not be enabled)" -ForegroundColor Gray
}

# -------------------------------------------------------------------
# 4. Add metadata and write output
# -------------------------------------------------------------------
Write-Host "[7/7] Writing data.json..." -ForegroundColor Yellow

$data.timestamp = (Get-Date).ToString("o")
$data._metadata = @{
  exportedBy    = "Get-IntuneData.ps1"
  exportedAt    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  deviceCount   = $data.devices.Count
  policyCount   = $data.policies.Count
  configCount   = $data.configs.Count
  appCount      = $data.apps.Count
  updateRingCount = $data.updateRings.Count
  autopilotCount  = $data.autopilot.Count
}

$json = $data | ConvertTo-Json -Depth 10
$json | Out-File -FilePath $OutputPath -Encoding utf8

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " DONE! Output written to:" -ForegroundColor Green
Write-Host "   $OutputPath" -ForegroundColor White
Write-Host "   Devices: $($data.devices.Count)" -ForegroundColor Gray
Write-Host "   Policies: $($data.policies.Count)" -ForegroundColor Gray
Write-Host "   Config Profiles: $($data.configs.Count)" -ForegroundColor Gray
Write-Host "   Apps: $($data.apps.Count)" -ForegroundColor Gray
Write-Host "   Update Rings: $($data.updateRings.Count)" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Open index.html in your browser to view the dashboard." -ForegroundColor Yellow
