function Get-OrphanedSIDs {
    <#
    .SYNOPSIS
        Scans file/folder ACLs for orphaned SIDs (deleted accounts that still have permissions).

    .DESCRIPTION
        Recursively scans the specified paths for access control entries that reference
        unresolved SIDs — accounts that have been deleted from AD but still have
        permissions on files and folders.

        Orphaned SIDs are a security risk (unknown access) and a compliance finding.

    .PARAMETER Path
        One or more UNC or local paths to scan.

    .PARAMETER RemoveOrphans
        If specified, removes the orphaned SID entries from ACLs.
        Use with -WhatIf to preview changes.

    .PARAMETER MaxDepth
        Maximum folder recursion depth. Defaults to unlimited.

    .EXAMPLE
        Get-OrphanedSIDs -Path "\\fileserver\shared"

        Scans and reports orphaned SIDs.

    .EXAMPLE
        Get-OrphanedSIDs -Path "\\fileserver\shared" -RemoveOrphans -WhatIf

        Shows which orphaned SIDs would be removed.

    .EXAMPLE
        Get-OrphanedSIDs -Path "\\fileserver\shared" -RemoveOrphans -Confirm

        Removes orphaned SIDs with confirmation prompts.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        [switch]$RemoveOrphans,

        [int]$MaxDepth = 0
    )

    process {
        foreach ($scanPath in $Path) {
            if (-not (Test-Path $scanPath)) {
                Write-Warning "Path not found: $scanPath"
                continue
            }

            Write-Verbose "Scanning: $scanPath"

            $gciParams = @{
                Path    = $scanPath
                Recurse = $true
                Force   = $true
                ErrorAction = 'SilentlyContinue'
            }
            if ($MaxDepth -gt 0) { $gciParams['Depth'] = $MaxDepth }

            # Include the root path itself plus all children
            $items = @(Get-Item $scanPath) + @(Get-ChildItem @gciParams)

            foreach ($item in $items) {
                try {
                    $acl = Get-Acl -Path $item.FullName -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Cannot read ACL: $($item.FullName)"
                    continue
                }

                $orphans = $acl.Access | Where-Object {
                    $_.IdentityReference.Value -match '^S-1-5-\d+-\d+-\d+-\d+-\d+' -and
                    $_.IsInherited -eq $false
                }

                foreach ($orphan in $orphans) {
                    [PSCustomObject]@{
                        Path              = $item.FullName
                        OrphanedSID       = $orphan.IdentityReference.Value
                        AccessType        = $orphan.AccessControlType
                        Rights            = $orphan.FileSystemRights
                        IsInherited       = $orphan.IsInherited
                    }

                    if ($RemoveOrphans) {
                        if ($PSCmdlet.ShouldProcess($item.FullName, "Remove orphaned SID $($orphan.IdentityReference.Value)")) {
                            $acl.PurgeAccessRules($orphan.IdentityReference)
                            Set-Acl -AclObject $acl -Path $item.FullName
                            Write-Verbose "Removed: $($orphan.IdentityReference.Value) from $($item.FullName)"
                        }
                    }
                }
            }
        }
    }
}
