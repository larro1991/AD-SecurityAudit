function Get-PrivilegedGroupReport {
    <#
    .SYNOPSIS
        Audits membership of privileged Active Directory groups.

    .DESCRIPTION
        Reports on membership of high-privilege AD groups including Domain Admins,
        Enterprise Admins, Schema Admins, Administrators, and custom groups.

        Flags accounts that may be a risk:
        - Service accounts in admin groups
        - Accounts with passwords that never expire
        - Accounts that haven't logged in recently
        - Nested group memberships

    .PARAMETER AdditionalGroups
        Additional group names to include in the audit beyond the defaults.

    .PARAMETER DaysInactive
        Threshold to flag inactive privileged accounts. Defaults to 30 days.

    .EXAMPLE
        Get-PrivilegedGroupReport

    .EXAMPLE
        Get-PrivilegedGroupReport -AdditionalGroups "SQL-Admins","Backup Operators" -DaysInactive 14
    #>
    [CmdletBinding()]
    param(
        [string[]]$AdditionalGroups,

        [int]$DaysInactive = 30
    )

    $defaultGroups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Server Operators',
        'Backup Operators',
        'Print Operators'
    )

    $groupsToAudit = $defaultGroups
    if ($AdditionalGroups) { $groupsToAudit += $AdditionalGroups }

    $inactiveThreshold = (Get-Date).AddDays(-$DaysInactive)

    foreach ($groupName in $groupsToAudit) {
        try {
            $group = Get-ADGroup -Identity $groupName -Properties Members -ErrorAction Stop
        }
        catch {
            Write-Verbose "Group not found: $groupName"
            continue
        }

        $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue

        $memberDetails = foreach ($member in $members) {
            if ($member.objectClass -eq 'user') {
                $user = Get-ADUser -Identity $member -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires, Enabled, Description, WhenCreated

                $flags = [System.Collections.Generic.List[string]]::new()
                if ($user.PasswordNeverExpires)   { $flags.Add('PasswordNeverExpires') }
                if (-not $user.Enabled)           { $flags.Add('Disabled') }
                if ($user.LastLogonDate -and $user.LastLogonDate -lt $inactiveThreshold) { $flags.Add('Inactive') }
                if (-not $user.LastLogonDate)      { $flags.Add('NeverLoggedIn') }
                if ($user.Description -match 'svc|service') { $flags.Add('PossibleServiceAccount') }

                [PSCustomObject]@{
                    MemberName    = $user.Name
                    SAMAccountName = $user.SAMAccountName
                    Type          = 'User'
                    Flags         = $flags -join '; '
                }
            }
            elseif ($member.objectClass -eq 'group') {
                [PSCustomObject]@{
                    MemberName    = $member.Name
                    SAMAccountName = $member.SAMAccountName
                    Type          = 'NestedGroup'
                    Flags         = 'NestedGroup'
                }
            }
        }

        [PSCustomObject]@{
            GroupName   = $groupName
            MemberCount = @($members).Count
            Members     = $memberDetails
            Flags       = @($memberDetails | Where-Object Flags -ne '').Count
        }
    }
}
