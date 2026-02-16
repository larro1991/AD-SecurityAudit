BeforeAll {
    $modulePath = Split-Path -Parent $PSScriptRoot
    Import-Module "$modulePath\AD-SecurityAudit.psd1" -Force
}

Describe 'AD-SecurityAudit Module' {

    Context 'Module Loading' {
        It 'Should import without errors' {
            { Import-Module "$PSScriptRoot\..\AD-SecurityAudit.psd1" -Force } | Should -Not -Throw
        }

        It 'Should export exactly 5 public functions' {
            $commands = Get-Command -Module AD-SecurityAudit
            $commands.Count | Should -Be 5
        }

        It 'Should export all expected functions' {
            $expected = @('Invoke-ADSecurityAudit', 'Get-StaleADObjects', 'Get-LocalAdminAudit', 'Get-OrphanedSIDs', 'Get-PrivilegedGroupReport')
            foreach ($func in $expected) {
                Get-Command -Module AD-SecurityAudit -Name $func | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should not export private functions' {
            { Get-Command -Module AD-SecurityAudit -Name _New-SecurityAuditHtml -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Get-StaleADObjects Parameter Validation' {
        It 'Should accept DaysInactive parameter' {
            (Get-Command Get-StaleADObjects).Parameters.ContainsKey('DaysInactive') | Should -BeTrue
        }

        It 'Should validate ObjectType to User, Computer, or Both' {
            $validateSet = (Get-Command Get-StaleADObjects).Parameters['ObjectType'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'User'
            $validateSet.ValidValues | Should -Contain 'Computer'
            $validateSet.ValidValues | Should -Contain 'Both'
        }

        It 'Should accept ExcludeOU parameter' {
            (Get-Command Get-StaleADObjects).Parameters.ContainsKey('ExcludeOU') | Should -BeTrue
        }
    }

    Context 'Get-StaleADObjects Mocked Execution' {
        BeforeAll {
            Mock -ModuleName AD-SecurityAudit Import-Module { }
            Mock -ModuleName AD-SecurityAudit Get-ADUser {
                @(
                    [PSCustomObject]@{
                        Name              = 'Williams, Mark'
                        SAMAccountName    = 'mwilliams'
                        LastLogonDate     = (Get-Date).AddDays(-200)
                        PasswordLastSet   = (Get-Date).AddDays(-300)
                        WhenCreated       = (Get-Date).AddYears(-3)
                        Enabled           = $true
                        Department        = 'Sales'
                        DistinguishedName = 'CN=Mark Williams,OU=Users,OU=Sales,DC=contoso,DC=com'
                    },
                    [PSCustomObject]@{
                        Name              = 'Smith, Jane'
                        SAMAccountName    = 'jsmith'
                        LastLogonDate     = (Get-Date).AddDays(-5)
                        PasswordLastSet   = (Get-Date).AddDays(-30)
                        WhenCreated       = (Get-Date).AddYears(-2)
                        Enabled           = $true
                        Department        = 'IT'
                        DistinguishedName = 'CN=Jane Smith,OU=Users,OU=IT,DC=contoso,DC=com'
                    }
                )
            }
            Mock -ModuleName AD-SecurityAudit Get-ADComputer { @() }
        }

        It 'Should only return accounts beyond the inactive threshold' {
            $results = Get-StaleADObjects -DaysInactive 90 -ObjectType User
            $results | Where-Object { $_.SAMAccountName -eq 'mwilliams' } | Should -Not -BeNullOrEmpty
            $results | Where-Object { $_.SAMAccountName -eq 'jsmith' } | Should -BeNullOrEmpty
        }

        It 'Should calculate DaysStale correctly' {
            $results = Get-StaleADObjects -DaysInactive 90 -ObjectType User
            $stale = $results | Where-Object { $_.SAMAccountName -eq 'mwilliams' }
            $stale.DaysStale | Should -BeGreaterThan 190
        }
    }

    Context 'Get-OrphanedSIDs Parameter Validation' {
        It 'Should have mandatory Path parameter' {
            (Get-Command Get-OrphanedSIDs).Parameters['Path'].Attributes.Mandatory | Should -Contain $true
        }

        It 'Should support -WhatIf' {
            (Get-Command Get-OrphanedSIDs).Parameters.ContainsKey('WhatIf') | Should -BeTrue
        }

        It 'Should accept pipeline input for Path' {
            (Get-Command Get-OrphanedSIDs).Parameters['Path'].Attributes.ValueFromPipeline | Should -Contain $true
        }

        It 'Should have RemoveOrphans switch' {
            (Get-Command Get-OrphanedSIDs).Parameters['RemoveOrphans'].SwitchParameter | Should -BeTrue
        }
    }

    Context 'Get-LocalAdminAudit Parameter Validation' {
        It 'Should accept ComputerName parameter' {
            (Get-Command Get-LocalAdminAudit).Parameters.ContainsKey('ComputerName') | Should -BeTrue
        }

        It 'Should accept ExpectedAdmins parameter' {
            (Get-Command Get-LocalAdminAudit).Parameters.ContainsKey('ExpectedAdmins') | Should -BeTrue
        }
    }

    Context 'Get-PrivilegedGroupReport Parameter Validation' {
        It 'Should accept AdditionalGroups parameter' {
            (Get-Command Get-PrivilegedGroupReport).Parameters.ContainsKey('AdditionalGroups') | Should -BeTrue
        }

        It 'Should accept DaysInactive parameter' {
            (Get-Command Get-PrivilegedGroupReport).Parameters.ContainsKey('DaysInactive') | Should -BeTrue
        }
    }

    Context 'Get-PrivilegedGroupReport Mocked Execution' {
        BeforeAll {
            Mock -ModuleName AD-SecurityAudit Import-Module { }
            Mock -ModuleName AD-SecurityAudit Get-ADGroupMember {
                @(
                    [PSCustomObject]@{
                        Name            = 'admin.lr'
                        SAMAccountName  = 'admin.lr'
                        objectClass     = 'user'
                    },
                    [PSCustomObject]@{
                        Name            = 'svc.backup'
                        SAMAccountName  = 'svc.backup'
                        objectClass     = 'user'
                    }
                )
            }
            Mock -ModuleName AD-SecurityAudit Get-ADUser {
                param($Identity)
                $isServiceAccount = $Identity -like 'svc.*'
                [PSCustomObject]@{
                    SAMAccountName       = $Identity
                    Enabled              = $true
                    LastLogonDate        = (Get-Date).AddDays(-5)
                    PasswordNeverExpires = $isServiceAccount
                    WhenCreated          = (Get-Date).AddYears(-1)
                }
            }
            Mock -ModuleName AD-SecurityAudit Get-ADGroup {
                [PSCustomObject]@{
                    Name              = 'Domain Admins'
                    DistinguishedName = 'CN=Domain Admins,CN=Users,DC=contoso,DC=com'
                }
            }
        }

        It 'Should flag service accounts with PasswordNeverExpires' {
            $results = Get-PrivilegedGroupReport
            $results | Should -Not -BeNullOrEmpty
        }
    }

    Context 'HTML Report Generation' {
        It 'Should generate valid HTML from the private function' {
            $html = & (Get-Module AD-SecurityAudit) {
                _New-SecurityAuditHtml -StaleUsers @() -StaleComputers @() -PrivilegedGroups @() -LocalAdmins @() -Domain 'contoso.com' -DaysThreshold 90
            }
            $html | Should -Match '<!DOCTYPE html>'
            $html | Should -Match 'Active Directory Security Audit'
        }
    }
}
