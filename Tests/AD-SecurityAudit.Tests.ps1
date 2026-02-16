BeforeAll {
    $modulePath = Split-Path -Parent $PSScriptRoot
    Import-Module "$modulePath\AD-SecurityAudit.psd1" -Force
}

Describe 'AD-SecurityAudit Module' {
    Context 'Module Loading' {
        It 'Should import without errors' {
            { Import-Module "$PSScriptRoot\..\AD-SecurityAudit.psd1" -Force } | Should -Not -Throw
        }

        It 'Should export Invoke-ADSecurityAudit' {
            Get-Command -Module AD-SecurityAudit -Name Invoke-ADSecurityAudit | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-StaleADObjects' {
            Get-Command -Module AD-SecurityAudit -Name Get-StaleADObjects | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-LocalAdminAudit' {
            Get-Command -Module AD-SecurityAudit -Name Get-LocalAdminAudit | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-OrphanedSIDs' {
            Get-Command -Module AD-SecurityAudit -Name Get-OrphanedSIDs | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-PrivilegedGroupReport' {
            Get-Command -Module AD-SecurityAudit -Name Get-PrivilegedGroupReport | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Get-StaleADObjects' {
        It 'Should accept DaysInactive parameter' {
            (Get-Command Get-StaleADObjects).Parameters.ContainsKey('DaysInactive') | Should -BeTrue
        }

        It 'Should validate ObjectType values' {
            $validateSet = (Get-Command Get-StaleADObjects).Parameters['ObjectType'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'User'
            $validateSet.ValidValues | Should -Contain 'Computer'
            $validateSet.ValidValues | Should -Contain 'Both'
        }
    }

    Context 'Get-OrphanedSIDs' {
        It 'Should have mandatory Path parameter' {
            (Get-Command Get-OrphanedSIDs).Parameters['Path'].Attributes.Mandatory | Should -Contain $true
        }

        It 'Should support -WhatIf' {
            (Get-Command Get-OrphanedSIDs).Parameters.ContainsKey('WhatIf') | Should -BeTrue
        }

        It 'Should accept pipeline input for Path' {
            (Get-Command Get-OrphanedSIDs).Parameters['Path'].Attributes.ValueFromPipeline | Should -Contain $true
        }
    }
}
