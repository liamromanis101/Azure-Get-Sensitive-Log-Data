# Authenticate to Azure
Write-Host "Authenticating..."
Connect-AzAccount -ErrorAction Stop

# List available subscriptions
$subscriptions = Get-AzSubscription
foreach ($sub in $subscriptions) {
    Write-Host "`nSwitching to subscription: $($sub.Name)"
    Set-AzContext -SubscriptionId $sub.Id

    # Find all Log Analytics Workspaces
    $workspaces = Get-AzOperationalInsightsWorkspace
    if ($workspaces.Count -eq 0) {
        Write-Host "No Log Analytics workspaces found in this subscription."
        continue
    }

    foreach ($workspace in $workspaces) {
        Write-Host "`nProcessing workspace: $($workspace.Name) in resource group $($workspace.ResourceGroupName)"

        try {
            # Simple permissions test: run a lightweight query
            $testQuery = "Heartbeat | take 1"
            $testResult = Invoke-AzOperationalInsightsQuery -WorkspaceName $workspace.Name `
                -ResourceGroupName $workspace.ResourceGroupName -Query $testQuery

            if ($testResult.Results.Count -eq 0 -and $testResult.Error -ne $null) {
                Write-Warning "Insufficient permissions or empty workspace. Skipping..."
                continue
            }

            Write-Host "Permissions OK. Querying log tables..."

            # Query available tables (you can customize this list based on your logs)
            $tables = @(
                "AzureDiagnostics",
                "SigninLogs",
                "SecurityEvent",
                "AuditLogs",
                "AzureActivity"
            )

            # Keywords to search for
            $sensitiveKeywords = @("username", "user", "login", "upn", "password", "pwd", "token", "secret", "key", "bearer", "authorization")

            foreach ($table in $tables) {
                $kql = @"
$table
| where TimeGenerated > ago(1d)
| take 1000
"@

                try {
                    $results = Invoke-AzOperationalInsightsQuery -WorkspaceName $workspace.Name `
                        -ResourceGroupName $workspace.ResourceGroupName -Query $kql

                    if ($results.Results.Count -eq 0) {
                        Write-Host "No results in $table"
                        continue
                    }

                    foreach ($row in $results.Results) {
                        $line = $row | Out-String

                        foreach ($kw in $sensitiveKeywords) {
                            if ($line -match $kw) {
                                Write-Host "[ALERT] Match in ${table}: $line"
                            }
                        }

                        if ($line -match 'ey[A-Za-z0-9_-]{10,}') {
                            Write-Host "[TOKEN DETECTED] ${line}"
                        }

                        if ($line -match '[A-Za-z0-9+/]{30,}={0,2}') {
                            Write-Host "[Base64 DETECTED] ${line}"
                        }
                    }

                } catch {
                    Write-Warning "Failed to query $table: $_"
                }
            }

        } catch {
            Write-Warning "Permission check or workspace query failed: $_"
        }
    }
}
