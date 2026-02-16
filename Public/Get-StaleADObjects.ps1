function Get-StaleADObjects {
    <#
    .SYNOPSIS
        Finds stale (inactive) user and computer accounts in Active Directory.

    .DESCRIPTION
        Identifies user and computer accounts that have not logged in within the
        specified threshold. Returns objects sorted by last logon date.

    .PARAMETER DaysInactive
        Number of days since last logon to consider an account stale. Defaults to 90.

    .PARAMETER ObjectType
        Filter by object type: User, Computer, or Both. Defaults to Both.

    .PARAMETER SearchBase
        OU to scope the search. Defaults to entire domain.

    .PARAMETER ExcludeOU
        One or more OU distinguished names to exclude from results (e.g., service account OUs).

    .EXAMPLE
        Get-StaleADObjects -DaysInactive 60

    .EXAMPLE
        Get-StaleADObjects -ObjectType User -ExcludeOU "OU=Service Accounts,DC=contoso,DC=com"
    #>
    [CmdletBinding()]
    param(
        [int]$DaysInactive = 90,

        [ValidateSet('User', 'Computer', 'Both')]
        [string]$ObjectType = 'Both',

        [string]$SearchBase,

        [string[]]$ExcludeOU
    )

    $threshold = (Get-Date).AddDays(-$DaysInactive)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $commonProps = @('LastLogonDate', 'PasswordLastSet', 'WhenCreated', 'Enabled', 'Description', 'DistinguishedName')

    # Stale Users
    if ($ObjectType -in @('User', 'Both')) {
        $userParams = @{
            Filter     = "LastLogonDate -lt '$threshold' -or -not LastLogonDate -like '*'"
            Properties = $commonProps + @('Title', 'Department', 'Manager', 'EmailAddress')
        }
        if ($SearchBase) { $userParams['SearchBase'] = $SearchBase }

        Get-ADUser @userParams | Where-Object { $_.Enabled -eq $true } | ForEach-Object {
            $excluded = $false
            if ($ExcludeOU) {
                foreach ($ou in $ExcludeOU) {
                    if ($_.DistinguishedName -like "*$ou") { $excluded = $true; break }
                }
            }
            if (-not $excluded) {
                $results.Add([PSCustomObject]@{
                    ObjectClass     = 'user'
                    Name            = $_.Name
                    SAMAccountName  = $_.SAMAccountName
                    LastLogon       = $_.LastLogonDate
                    PasswordLastSet = $_.PasswordLastSet
                    Created         = $_.WhenCreated
                    Department      = $_.Department
                    Description     = $_.Description
                    DN              = $_.DistinguishedName
                    DaysStale       = if ($_.LastLogonDate) { [math]::Round(((Get-Date) - $_.LastLogonDate).TotalDays) } else { 'Never' }
                })
            }
        }
    }

    # Stale Computers
    if ($ObjectType -in @('Computer', 'Both')) {
        $compParams = @{
            Filter     = "LastLogonDate -lt '$threshold' -or -not LastLogonDate -like '*'"
            Properties = $commonProps + @('OperatingSystem', 'OperatingSystemVersion')
        }
        if ($SearchBase) { $compParams['SearchBase'] = $SearchBase }

        Get-ADComputer @compParams | Where-Object { $_.Enabled -eq $true } | ForEach-Object {
            $excluded = $false
            if ($ExcludeOU) {
                foreach ($ou in $ExcludeOU) {
                    if ($_.DistinguishedName -like "*$ou") { $excluded = $true; break }
                }
            }
            if (-not $excluded) {
                $results.Add([PSCustomObject]@{
                    ObjectClass     = 'computer'
                    Name            = $_.Name
                    SAMAccountName  = $_.SAMAccountName
                    LastLogon       = $_.LastLogonDate
                    PasswordLastSet = $_.PasswordLastSet
                    Created         = $_.WhenCreated
                    Department      = $_.OperatingSystem
                    Description     = $_.Description
                    DN              = $_.DistinguishedName
                    DaysStale       = if ($_.LastLogonDate) { [math]::Round(((Get-Date) - $_.LastLogonDate).TotalDays) } else { 'Never' }
                })
            }
        }
    }

    $results | Sort-Object LastLogon
}
