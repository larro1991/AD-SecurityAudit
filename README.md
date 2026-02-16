# AD-SecurityAudit

PowerShell module for Active Directory security and compliance auditing. Generates HTML dashboard reports suitable for SOC2, HIPAA, and cyber insurance evidence.

## What It Does

| Function | Purpose |
|----------|---------|
| `Invoke-ADSecurityAudit` | Run all checks and generate a consolidated HTML dashboard |
| `Get-StaleADObjects` | Find inactive user and computer accounts |
| `Get-LocalAdminAudit` | Audit local admin group membership across domain computers |
| `Get-OrphanedSIDs` | Detect (and optionally remove) orphaned SIDs in file/folder ACLs |
| `Get-PrivilegedGroupReport` | Review membership of high-privilege AD groups with risk flags |

## Quick Start

```powershell
# Import the module
Import-Module .\AD-SecurityAudit.psd1

# Run a full audit with HTML dashboard
Invoke-ADSecurityAudit

# Run just the stale account check
Get-StaleADObjects -DaysInactive 60

# Audit local admins on specific servers
Get-LocalAdminAudit -ComputerName "SERVER01","SERVER02"

# Scan a file share for orphaned SIDs
Get-OrphanedSIDs -Path "\\fileserver\shared"

# Remove orphaned SIDs (with preview)
Get-OrphanedSIDs -Path "\\fileserver\shared" -RemoveOrphans -WhatIf

# Privileged group review
Get-PrivilegedGroupReport -AdditionalGroups "SQL-Admins"
```

## Installation

```powershell
Copy-Item -Path .\AD-SecurityAudit -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\" -Recurse
```

## Requirements

- PowerShell 5.1 or later
- ActiveDirectory module (RSAT)
- Network access to target computers (for local admin audit)
- Read access to file shares (for orphaned SID scan)

## Sample Report

The `Invoke-ADSecurityAudit` command produces an HTML dashboard with:
- Summary cards showing counts at a glance
- Stale user and computer tables with days-since-logon
- Privileged group membership with risk flags (inactive accounts, password-never-expires, service accounts)
- Color-coded severity indicators

## Running Tests

```powershell
Invoke-Pester .\Tests\
```
