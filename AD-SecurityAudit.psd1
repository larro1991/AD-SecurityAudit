@{
    RootModule        = 'AD-SecurityAudit.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b2c3d4e5-f6a7-8901-bcde-f12345678901'
    Author            = 'Larry Roberts'
    CompanyName       = 'Independent Consultant'
    Copyright         = '(c) 2026 Larry Roberts. All rights reserved.'
    Description       = 'Active Directory security and compliance auditing. Generates HTML reports covering stale accounts, local admins, orphaned SIDs, privileged groups, and password policy compliance.'

    PowerShellVersion = '5.1'
    RequiredModules   = @('ActiveDirectory')

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
            ProjectUri = 'https://github.com/yourGitHub/AD-SecurityAudit'
        }
    }
}
