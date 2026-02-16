function Get-LocalAdminAudit {
    <#
    .SYNOPSIS
        Audits local administrator group membership across domain computers.

    .DESCRIPTION
        Connects to domain computers and enumerates the local Administrators group.
        Identifies non-standard members that may represent a security risk.

        Uses CIM (WinRM) with fallback to ADSI for maximum compatibility.

    .PARAMETER SearchBase
        OU to scope the computer search. Defaults to entire domain.

    .PARAMETER ComputerName
        Specific computer name(s) to audit instead of querying AD.

    .PARAMETER ExpectedAdmins
        List of accounts that are expected/approved local admins.
        These will be flagged as "Expected" rather than "Unexpected" in results.
        Defaults to: Administrator, Domain Admins.

    .EXAMPLE
        Get-LocalAdminAudit

        Audits all enabled domain computers.

    .EXAMPLE
        Get-LocalAdminAudit -ComputerName "SERVER01","SERVER02"

    .EXAMPLE
        Get-LocalAdminAudit -ExpectedAdmins "Administrator","Domain Admins","IT-LocalAdmins"
    #>
    [CmdletBinding()]
    param(
        [string]$SearchBase,

        [string[]]$ComputerName,

        [string[]]$ExpectedAdmins = @('Administrator', 'Domain Admins')
    )

    # Get computer list
    if ($ComputerName) {
        $computers = $ComputerName
    }
    else {
        $compParams = @{
            Filter     = 'Enabled -eq $true'
            Properties = @('OperatingSystem')
        }
        if ($SearchBase) { $compParams['SearchBase'] = $SearchBase }

        $computers = (Get-ADComputer @compParams).Name
    }

    $total = $computers.Count
    $current = 0

    foreach ($computer in $computers) {
        $current++
        Write-Progress -Activity "Auditing local admins" -Status "$computer ($current/$total)" -PercentComplete (($current / $total) * 100)

        # Test connectivity first
        if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
            [PSCustomObject]@{
                ComputerName = $computer
                Member       = $null
                Type         = $null
                Expected     = $null
                Status       = 'Offline'
            }
            continue
        }

        try {
            # Try CIM first (modern, uses WinRM)
            $admins = Get-CimInstance -ClassName Win32_GroupUser -ComputerName $computer -ErrorAction Stop |
                Where-Object { $_.GroupComponent.Name -eq 'Administrators' } |
                ForEach-Object {
                    $memberName = $_.PartComponent.Name
                    $memberDomain = $_.PartComponent.Domain
                    $fullName = "$memberDomain\$memberName"
                    $isExpected = $ExpectedAdmins -contains $memberName

                    [PSCustomObject]@{
                        ComputerName = $computer
                        Member       = $fullName
                        Type         = $_.PartComponent.CimClass.CimClassName -replace 'Win32_', ''
                        Expected     = $isExpected
                        Status       = 'OK'
                    }
                }

            if ($admins) { $admins } else {
                [PSCustomObject]@{
                    ComputerName = $computer
                    Member       = 'None found'
                    Type         = $null
                    Expected     = $null
                    Status       = 'OK'
                }
            }
        }
        catch {
            # Fallback: try ADSI
            try {
                $group = [ADSI]"WinNT://$computer/Administrators"
                $members = @($group.psbase.Invoke("Members"))

                foreach ($member in $members) {
                    $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                    $isExpected = $ExpectedAdmins -contains $memberName

                    [PSCustomObject]@{
                        ComputerName = $computer
                        Member       = $memberName
                        Type         = 'Unknown (ADSI)'
                        Expected     = $isExpected
                        Status       = 'OK (ADSI fallback)'
                    }
                }
            }
            catch {
                [PSCustomObject]@{
                    ComputerName = $computer
                    Member       = $null
                    Type         = $null
                    Expected     = $null
                    Status       = "Error: $_"
                }
            }
        }
    }

    Write-Progress -Activity "Auditing local admins" -Completed
}
