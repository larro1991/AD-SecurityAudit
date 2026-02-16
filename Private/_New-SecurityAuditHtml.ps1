function _New-SecurityAuditHtml {
    <#
    .SYNOPSIS
        Generates the consolidated HTML security audit dashboard.
    #>
    param(
        [hashtable]$AuditResults,
        [string]$Domain,
        [int]$DaysInactive
    )

    $css = @"
    <style>
        body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #2c3e50; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; }
        .meta { color: #7f8c8d; margin-bottom: 20px; }
        .dashboard { display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 20px; }
        .card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 180px; text-align: center; }
        .card .number { font-size: 36px; font-weight: bold; }
        .card .label { color: #7f8c8d; font-size: 12px; margin-top: 5px; }
        .card.warning .number { color: #e67e22; }
        .card.danger .number { color: #e74c3c; }
        .card.ok .number { color: #27ae60; }
        table { border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }
        th { background: #2c3e50; color: #fff; padding: 10px 8px; text-align: left; font-size: 11px; }
        td { padding: 8px; border-bottom: 1px solid #ecf0f1; font-size: 11px; }
        tr:nth-child(even) { background: #f9f9f9; }
        tr:hover { background: #eaf2f8; }
        .flag { color: #e74c3c; font-weight: bold; }
    </style>
"@

    $staleUserCount = $AuditResults['StaleUsers'].Count
    $staleCompCount = $AuditResults['StaleComputers'].Count
    $privCount = ($AuditResults['PrivilegedGroups'] | Measure-Object -Property MemberCount -Sum).Sum
    $localAdminCount = if ($AuditResults['LocalAdmins']) { @($AuditResults['LocalAdmins'] | Where-Object { $_.Expected -eq $false -and $_.Status -eq 'OK' }).Count } else { 'N/A' }

    $staleUserClass = if ($staleUserCount -gt 20) { 'danger' } elseif ($staleUserCount -gt 5) { 'warning' } else { 'ok' }
    $staleCompClass = if ($staleCompCount -gt 20) { 'danger' } elseif ($staleCompCount -gt 5) { 'warning' } else { 'ok' }

    # Build stale users table rows
    $staleUserRows = ($AuditResults['StaleUsers'] | ForEach-Object {
        "<tr><td>$($_.Name)</td><td>$($_.SAMAccountName)</td><td>$($_.LastLogon)</td><td>$($_.DaysStale)</td><td>$($_.Department)</td><td>$($_.DN)</td></tr>"
    }) -join "`n"

    # Build stale computers table rows
    $staleCompRows = ($AuditResults['StaleComputers'] | ForEach-Object {
        "<tr><td>$($_.Name)</td><td>$($_.LastLogon)</td><td>$($_.DaysStale)</td><td>$($_.Department)</td></tr>"
    }) -join "`n"

    # Build privileged groups rows
    $privRows = ($AuditResults['PrivilegedGroups'] | ForEach-Object {
        $memberList = ($_.Members | ForEach-Object { "$($_.SAMAccountName)$(if($_.Flags){" <span class='flag'>[$($_.Flags)]</span>"})" }) -join '<br>'
        "<tr><td>$($_.GroupName)</td><td>$($_.MemberCount)</td><td>$memberList</td></tr>"
    }) -join "`n"

    @"
<!DOCTYPE html>
<html>
<head><title>AD Security Audit - $Domain</title>$css</head>
<body>
    <h1>Active Directory Security Audit</h1>
    <div class="meta">Domain: $Domain | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm') | Inactive threshold: $DaysInactive days</div>

    <div class="dashboard">
        <div class="card $staleUserClass"><div class="number">$staleUserCount</div><div class="label">Stale Users</div></div>
        <div class="card $staleCompClass"><div class="number">$staleCompCount</div><div class="label">Stale Computers</div></div>
        <div class="card warning"><div class="number">$privCount</div><div class="label">Privileged Accounts</div></div>
        <div class="card"><div class="number">$localAdminCount</div><div class="label">Unexpected Local Admins</div></div>
    </div>

    <h2>Stale User Accounts ($staleUserCount)</h2>
    <table>
        <tr><th>Name</th><th>SAMAccountName</th><th>Last Logon</th><th>Days Stale</th><th>Department</th><th>DN</th></tr>
        $staleUserRows
    </table>

    <h2>Stale Computer Accounts ($staleCompCount)</h2>
    <table>
        <tr><th>Name</th><th>Last Logon</th><th>Days Stale</th><th>Operating System</th></tr>
        $staleCompRows
    </table>

    <h2>Privileged Group Membership</h2>
    <table>
        <tr><th>Group</th><th>Members</th><th>Member Details</th></tr>
        $privRows
    </table>
</body>
</html>
"@
}
