# AD-SecurityAudit

PowerShell module for Active Directory security auditing. Generates HTML dashboard reports covering stale accounts, privileged group membership, local admin sprawl, and orphaned SIDs.

Built for compliance evidence (SOC2, HIPAA, NIST, cyber insurance) and routine security hygiene in enterprise AD environments.

## The Problem

Every compliance audit asks the same questions: Who has Domain Admin? Are there stale accounts? Who's a local admin on your servers? Most teams answer these manually in ADUC or with one-off scripts that nobody maintains.

## What This Module Does

| Function | Purpose |
|----------|---------|
| `Invoke-ADSecurityAudit` | Run all checks, generate a consolidated HTML dashboard |
| `Get-StaleADObjects` | Find inactive users and computers beyond a configurable threshold |
| `Get-LocalAdminAudit` | Audit local admin group membership across domain computers via CIM |
| `Get-OrphanedSIDs` | Scan file/folder ACLs for orphaned SIDs (with optional removal) |
| `Get-PrivilegedGroupReport` | Review Domain Admins, Enterprise Admins, etc. with risk flags |

## Quick Start

```powershell
Import-Module .\AD-SecurityAudit.psd1

# Full audit with HTML dashboard
Invoke-ADSecurityAudit

# Stale accounts (custom threshold)
Get-StaleADObjects -DaysInactive 60 -ObjectType Both

# Local admin audit on specific servers
Get-LocalAdminAudit -ComputerName "SQL01","DC01" -ExpectedAdmins @("CONTOSO\Domain Admins","CONTOSO\admin.lr")

# Scan a share for orphaned SIDs (preview mode)
Get-OrphanedSIDs -Path "\\fileserver\departments" -RemoveOrphans -WhatIf

# Privileged group review
Get-PrivilegedGroupReport | Format-Table Group, Members, MemberDetails -Wrap
```

## Example Output

**Stale Accounts:**
```
Name              SAMAccountName  LastLogon   DaysStale  Department  ObjectType
----              --------------  ---------   ---------  ----------  ----------
Williams, Mark    mwilliams       2025-06-14  246        Sales       User
WS-SALES-014                     2025-04-12  309                    Computer
```

**Privileged Groups:**
```
Group            Members  MemberDetails
-----            -------  -------------
Domain Admins    6        admin.lr, admin.mc, admin.jw, svc.backup [PasswordNeverExpires],
                          admin.sw, ethompson [Inactive]
Enterprise Admins 2       admin.lr, admin.mc
```

**HTML Dashboard:**

See [`Samples/sample-report.html`](Samples/sample-report.html) for the full dashboard output with color-coded severity cards.

## Installation

```powershell
Copy-Item -Path .\AD-SecurityAudit -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\" -Recurse
```

## Requirements

- PowerShell 5.1+
- ActiveDirectory module (RSAT)
- CIM/WinRM access to target computers (for local admin audit)
- Read access to file shares (for orphaned SID scan)

## Design Decisions

- **CIM with ADSI fallback** -- local admin audit uses CIM (WinRM) as primary method. If CIM fails (older OS, firewall), falls back to ADSI. Both methods logged.
- **Risk flagging** -- privileged group report flags: `PasswordNeverExpires`, `Inactive`, `NeverLoggedIn`, `PossibleServiceAccount`, `NestedGroup`. These are the findings auditors look for.
- **-WhatIf on orphaned SID removal** -- scanning is safe, removal requires explicit `-RemoveOrphans` flag and supports `-WhatIf` preview.
- **OU exclusion** -- stale object search supports `-ExcludeOU` for service accounts and other known exceptions.
- **Expected admin comparison** -- local admin audit accepts `-ExpectedAdmins` so findings only show unexpected members.

## Project Structure

```
AD-SecurityAudit/
├── AD-SecurityAudit.psd1              # Module manifest
├── AD-SecurityAudit.psm1              # Root module
├── Public/
│   ├── Invoke-ADSecurityAudit.ps1     # Orchestrator
│   ├── Get-StaleADObjects.ps1         # Inactive account detection
│   ├── Get-LocalAdminAudit.ps1        # Local admin membership audit
│   ├── Get-OrphanedSIDs.ps1           # Orphaned SID scanner
│   └── Get-PrivilegedGroupReport.ps1  # Privileged group reviewer
├── Private/
│   └── _New-SecurityAuditHtml.ps1     # Dashboard HTML generator
├── Tests/
│   └── AD-SecurityAudit.Tests.ps1     # Pester tests
└── Samples/
    └── sample-report.html             # Example dashboard output
```

## Running Tests

```powershell
Invoke-Pester .\Tests\ -Output Detailed
```

## License

MIT
