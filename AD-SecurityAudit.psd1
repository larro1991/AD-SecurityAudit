@{
    RootModule        = 'AD-SecurityAudit.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'c0e84bed-4146-476f-9134-ea8f79bc2094'
    Author            = 'Larry Roberts'
    CompanyName       = 'Independent Consultant'
    Copyright         = '(c) 2026 Larry Roberts. All rights reserved.'
    Description       = 'Active Directory security and compliance auditing. Generates HTML dashboard reports covering stale accounts, local admin membership, orphaned SIDs, and privileged group review. Requires the ActiveDirectory RSAT module.'

    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Invoke-ADSecurityAudit',
        'Get-StaleADObjects',
        'Get-LocalAdminAudit',
        'Get-OrphanedSIDs',
        'Get-PrivilegedGroupReport'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Security', 'Audit', 'Compliance', 'HIPAA', 'SOC2')
            LicenseUri = 'https://github.com/larro1991/AD-SecurityAudit/blob/master/LICENSE'
            ProjectUri = 'https://github.com/larro1991/AD-SecurityAudit'
        }
    }
}
