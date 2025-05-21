# Fetch and analyze Azure AD logs for potentially exploitable data

function Get-SensitiveLogData {
    param (
        [int]$MaxRecords = 1000
    )

    Write-Host "Fetching recent Azure AD sign-in and audit logs..."

    # Fetch Sign-in Logs
    $signIns = Get-MgAuditLogSignIn -Top $MaxRecords
    # Fetch Audit Logs
    $auditLogs = Get-MgAuditLogDirectoryAudit -Top $MaxRecords

    $sensitiveEntries = @()

    # Define regex patterns for sensitive data
    $patterns = @{
        Username        = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b'
        Hostnames       = '\b(?:[a-zA-Z0-9-]{1,63}\.){1,}[a-zA-Z]{2,6}\b'
        IPAddress       = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
        PasswordHint    = '(?i)password|pwd|token|secret|key'
    }

    # Analyze Sign-In Logs
    foreach ($entry in $signIns) {
        $details = $entry | ConvertTo-Json -Depth 10
        $matchFound = $false
        foreach ($key in $patterns.Keys) {
            if ($details -match $patterns[$key]) {
                $matchFound = $true
            }
        }
        if ($matchFound) {
            $sensitiveEntries += [PSCustomObject]@{
                LogType     = "Sign-In"
                User        = $entry.UserDisplayName
                IP          = $entry.IpAddress
                App         = $entry.AppDisplayName
                RiskLevel   = $entry.RiskLevelAggregated
                Raw         = $details
            }
        }
    }

    # Analyze Audit Logs
    foreach ($entry in $auditLogs) {
        $details = $entry | ConvertTo-Json -Depth 10
        $matchFound = $false
        foreach ($key in $patterns.Keys) {
            if ($details -match $patterns[$key]) {
                $matchFound = $true
            }
        }
        if ($matchFound) {
            $sensitiveEntries += [PSCustomObject]@{
                LogType     = "Audit"
                User        = $entry.InitiatedBy.User.DisplayName
                Operation   = $entry.OperationName
                Target      = ($entry.TargetResources | Select-Object -First 1).DisplayName
                Raw         = $details
            }
        }
    }

    Write-Host "`nFound $($sensitiveEntries.Count) potentially sensitive entries." -ForegroundColor Yellow

    return $sensitiveEntries
}

# Run the function and export results
$data = Get-SensitiveLogData -MaxRecords 500
$data | Export-Csv -Path "PotentiallySensitiveAzureLogs.csv" -NoTypeInformation
Write-Host "Report saved to 'PotentiallySensitiveAzureLogs.csv'"
