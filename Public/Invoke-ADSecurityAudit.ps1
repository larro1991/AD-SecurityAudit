function Invoke-ADSecurityAudit {
    <#
    .SYNOPSIS
        Runs a comprehensive Active Directory security audit and generates an HTML report.

    .DESCRIPTION
        Executes all audit checks and consolidates results into a single HTML dashboard:
        - Stale user and computer accounts
        - Local administrator audit across domain computers
        - Orphaned SIDs in ACLs
        - Privileged group membership review
        - Password policy compliance

        Designed to support compliance frameworks (SOC2, HIPAA, NIST) by providing
        auditable evidence of AD security posture.

    .PARAMETER OutputPath
        Directory to save the HTML report. Defaults to .\Reports.

    .PARAMETER DaysInactive
        Threshold for flagging stale accounts. Defaults to 90 days.

    .PARAMETER ComputerSearchBase
        OU to scope the local admin audit. Defaults to entire domain.

    .PARAMETER SkipLocalAdminAudit
        Skip the local admin check (useful if network scanning is slow or restricted).

    .PARAMETER SkipOrphanedSIDs
        Skip orphaned SID scanning.

    .PARAMETER SharePaths
        One or more UNC paths to scan for orphaned SIDs. If not specified, orphaned
        SID check is skipped unless specific paths are provided.

    .EXAMPLE
        Invoke-ADSecurityAudit

        Runs all checks with defaults and saves the report to .\Reports.

    .EXAMPLE
        Invoke-ADSecurityAudit -DaysInactive 60 -SkipLocalAdminAudit -OutputPath "\\server\audits"

        Runs stale account and privileged group checks only, with a 60-day threshold.

    .EXAMPLE
        Invoke-ADSecurityAudit -SharePaths "\\fileserver\shared","\\fileserver\departments"

        Includes orphaned SID scanning on the specified share paths.

    .NOTES
        Requires: ActiveDirectory module, appropriate permissions.
        Local admin audit requires network access to target computers.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = '.\Reports',

        [int]$DaysInactive = 90,

        [string]$ComputerSearchBase,

        [switch]$SkipLocalAdminAudit,

        [switch]$SkipOrphanedSIDs,

        [string[]]$SharePaths,

        [string]$LogPath = '.\Logs'
    )

    begin {
        Import-Module ActiveDirectory -ErrorAction Stop

        foreach ($dir in @($OutputPath, $LogPath)) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
            }
        }

        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $logFile = Join-Path $LogPath "SecurityAudit-$timestamp.log"
        Start-Transcript -Path $logFile -Append

        $auditResults = @{}
        $domain = (Get-ADDomain).DNSRoot
    }

    process {
        Write-Verbose "=== AD Security Audit: $domain ==="

        # 1. Stale Accounts
        Write-Verbose "Running stale account check..."
        $staleResults = Get-StaleADObjects -DaysInactive $DaysInactive
        $auditResults['StaleUsers']     = @($staleResults | Where-Object ObjectClass -eq 'user')
        $auditResults['StaleComputers'] = @($staleResults | Where-Object ObjectClass -eq 'computer')

        # 2. Privileged Groups
        Write-Verbose "Running privileged group audit..."
        $auditResults['PrivilegedGroups'] = @(Get-PrivilegedGroupReport)

        # 3. Local Admin Audit (optional)
        if (-not $SkipLocalAdminAudit) {
            Write-Verbose "Running local admin audit (this may take a while)..."
            $localAdminParams = @{}
            if ($ComputerSearchBase) { $localAdminParams['SearchBase'] = $ComputerSearchBase }
            $auditResults['LocalAdmins'] = @(Get-LocalAdminAudit @localAdminParams)
        }

        # 4. Orphaned SIDs (optional)
        if (-not $SkipOrphanedSIDs -and $SharePaths) {
            Write-Verbose "Scanning for orphaned SIDs..."
            $auditResults['OrphanedSIDs'] = @(Get-OrphanedSIDs -Path $SharePaths)
        }

        # 5. Password Policy Summary
        Write-Verbose "Checking password policy..."
        $auditResults['PasswordPolicy'] = Get-ADDefaultDomainPasswordPolicy

        # Generate HTML Report
        $htmlFile = Join-Path $OutputPath "AD-SecurityAudit-$domain-$timestamp.html"
        $htmlContent = _New-SecurityAuditHtml -AuditResults $auditResults -Domain $domain -DaysInactive $DaysInactive
        $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
        Write-Verbose "Report saved: $htmlFile"

        # Output summary to pipeline
        [PSCustomObject]@{
            Domain            = $domain
            AuditDate         = Get-Date -Format 'yyyy-MM-dd HH:mm'
            StaleUsers        = $auditResults['StaleUsers'].Count
            StaleComputers    = $auditResults['StaleComputers'].Count
            PrivilegedMembers = ($auditResults['PrivilegedGroups'] | Measure-Object -Property MemberCount -Sum).Sum
            LocalAdmins       = if ($auditResults['LocalAdmins']) { $auditResults['LocalAdmins'].Count } else { 'Skipped' }
            OrphanedSIDs      = if ($auditResults['OrphanedSIDs']) { $auditResults['OrphanedSIDs'].Count } else { 'Skipped' }
            ReportPath        = $htmlFile
        }
    }

    end {
        Stop-Transcript
    }
}
