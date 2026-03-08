<#
.SYNOPSIS
    STIG Compliance Checker for Windows Systems
.DESCRIPTION
    Automates DISA STIG compliance checks for Windows 10/11 and Windows Server.
    Checks common security configurations against STIG requirements and generates
    a compliance report in CSV format.
.AUTHOR
    William Mace
.VERSION
    1.0.0
.DATE
    2026-03-08
.NOTES
    Requires: PowerShell 5.1+ and Administrator privileges
    Reference: DISA Windows 10 STIG V2R8, Windows Server 2019 STIG V2R8
#>

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\STIG-Compliance-Report.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

# Initialize results array
$results = @()

function Write-CheckResult {
    param(
        [string]$StigId,
        [string]$Category,
        [string]$Description,
        [string]$Status,
        [string]$Finding
    )
    
    $result = [PSCustomObject]@{
        Date        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        ComputerName = $env:COMPUTERNAME
        STIG_ID     = $StigId
        Category    = $Category
        Description = $Description
        Status      = $Status
        Finding     = $Finding
    }
    
    if ($Verbose) {
        $color = switch ($Status) {
            "PASS"    { "Green" }
            "FAIL"    { "Red" }
            "WARNING" { "Yellow" }
            default   { "White" }
        }
        Write-Host "[$Status] $StigId - $Description" -ForegroundColor $color
    }
    
    return $result
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  STIG Compliance Checker v1.0.0" -ForegroundColor Cyan
Write-Host "  Target: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ============================================
# CHECK 1: Password Policy - Minimum Length
# STIG ID: V-220903
# ============================================
try {
    $secPolicy = net accounts 2>$null
    $minLength = ($secPolicy | Select-String "Minimum password length").ToString().Split(":")[1].Trim()
    
    if ([int]$minLength -ge 14) {
        $results += Write-CheckResult -StigId "V-220903" -Category "Account Policy" `
            -Description "Minimum password length must be 14 characters" `
            -Status "PASS" -Finding "Minimum password length: $minLength"
    } else {
        $results += Write-CheckResult -StigId "V-220903" -Category "Account Policy" `
            -Description "Minimum password length must be 14 characters" `
            -Status "FAIL" -Finding "Minimum password length: $minLength (Required: 14)"
    }
} catch {
    $results += Write-CheckResult -StigId "V-220903" -Category "Account Policy" `
        -Description "Minimum password length must be 14 characters" `
        -Status "WARNING" -Finding "Unable to retrieve password policy: $_"
}

# ============================================
# CHECK 2: Password Policy - Complexity
# STIG ID: V-220904
# ============================================
try {
    $complexity = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ErrorAction Stop).NoLMHash
    
    if ($complexity -eq 1) {
        $results += Write-CheckResult -StigId "V-220904" -Category "Account Policy" `
            -Description "LM hash storage must be disabled" `
            -Status "PASS" -Finding "NoLMHash is enabled (value: $complexity)"
    } else {
        $results += Write-CheckResult -StigId "V-220904" -Category "Account Policy" `
            -Description "LM hash storage must be disabled" `
            -Status "FAIL" -Finding "NoLMHash is not enabled (value: $complexity)"
    }
} catch {
    $results += Write-CheckResult -StigId "V-220904" -Category "Account Policy" `
        -Description "LM hash storage must be disabled" `
        -Status "WARNING" -Finding "Unable to check registry: $_"
}

# ============================================
# CHECK 3: Account Lockout Threshold
# STIG ID: V-220909
# ============================================
try {
    $lockoutThreshold = ($secPolicy | Select-String "Lockout threshold").ToString().Split(":")[1].Trim()
    
    if ([int]$lockoutThreshold -le 3 -and [int]$lockoutThreshold -gt 0) {
        $results += Write-CheckResult -StigId "V-220909" -Category "Account Policy" `
            -Description "Account lockout threshold must be 3 or fewer attempts" `
            -Status "PASS" -Finding "Lockout threshold: $lockoutThreshold"
    } else {
        $results += Write-CheckResult -StigId "V-220909" -Category "Account Policy" `
            -Description "Account lockout threshold must be 3 or fewer attempts" `
            -Status "FAIL" -Finding "Lockout threshold: $lockoutThreshold (Required: 3 or fewer)"
    }
} catch {
    $results += Write-CheckResult -StigId "V-220909" -Category "Account Policy" `
        -Description "Account lockout threshold must be 3 or fewer attempts" `
        -Status "WARNING" -Finding "Unable to retrieve lockout policy: $_"
}

# ============================================
# CHECK 4: Windows Firewall - Domain Profile
# STIG ID: V-220918
# ============================================
try {
    $fwDomain = (Get-NetFirewallProfile -Profile Domain -ErrorAction Stop).Enabled
    
    if ($fwDomain -eq $true) {
        $results += Write-CheckResult -StigId "V-220918" -Category "Firewall" `
            -Description "Windows Firewall must be enabled for Domain profile" `
            -Status "PASS" -Finding "Domain firewall profile is enabled"
    } else {
        $results += Write-CheckResult -StigId "V-220918" -Category "Firewall" `
            -Description "Windows Firewall must be enabled for Domain profile" `
            -Status "FAIL" -Finding "Domain firewall profile is DISABLED"
    }
} catch {
    $results += Write-CheckResult -StigId "V-220918" -Category "Firewall" `
        -Description "Windows Firewall must be enabled for Domain profile" `
        -Status "WARNING" -Finding "Unable to check firewall status: $_"
}

# ============================================
# CHECK 5: Remote Desktop Encryption Level
# STIG ID: V-220930
# ============================================
try {
    $rdpEncrypt = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -ErrorAction Stop).MinEncryptionLevel
    
    if ($rdpEncrypt -ge 3) {
        $results += Write-CheckResult -StigId "V-220930" -Category "Remote Access" `
            -Description "RDP encryption level must be set to High" `
            -Status "PASS" -Finding "RDP encryption level: $rdpEncrypt (High)"
    } else {
        $results += Write-CheckResult -StigId "V-220930" -Category "Remote Access" `
            -Description "RDP encryption level must be set to High" `
            -Status "FAIL" -Finding "RDP encryption level: $rdpEncrypt (Required: 3 - High)"
    }
} catch {
    $results += Write-CheckResult -StigId "V-220930" -Category "Remote Access" `
        -Description "RDP encryption level must be set to High" `
        -Status "WARNING" -Finding "RDP encryption policy not configured or inaccessible"
}

# ============================================
# CHECK 6: Audit Policy - Logon Events
# STIG ID: V-220951
# ============================================
try {
    $auditLogon = auditpol /get /subcategory:"Logon" 2>$null
    $logonSetting = ($auditLogon | Select-String "Logon").ToString()
    
    if ($logonSetting -match "Success and Failure") {
        $results += Write-CheckResult -StigId "V-220951" -Category "Audit Policy" `
            -Description "Logon events must be audited for Success and Failure" `
            -Status "PASS" -Finding "Logon auditing: Success and Failure"
    } else {
        $results += Write-CheckResult -StigId "V-220951" -Category "Audit Policy" `
            -Description "Logon events must be audited for Success and Failure" `
            -Status "FAIL" -Finding "Logon auditing: $logonSetting"
    }
} catch {
    $results += Write-CheckResult -StigId "V-220951" -Category "Audit Policy" `
        -Description "Logon events must be audited for Success and Failure" `
        -Status "WARNING" -Finding "Unable to retrieve audit policy: $_"
}

# ============================================
# CHECK 7: SMBv1 Disabled
# STIG ID: V-220929
# ============================================
try {
    $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    
    if ($smb1 -eq $false) {
        $results += Write-CheckResult -StigId "V-220929" -Category "Network Security" `
            -Description "SMBv1 protocol must be disabled" `
            -Status "PASS" -Finding "SMBv1 is disabled"
    } else {
        $results += Write-CheckResult -StigId "V-220929" -Category "Network Security" `
            -Description "SMBv1 protocol must be disabled" `
            -Status "FAIL" -Finding "SMBv1 is ENABLED - critical security risk"
    }
} catch {
    $results += Write-CheckResult -StigId "V-220929" -Category "Network Security" `
        -Description "SMBv1 protocol must be disabled" `
        -Status "WARNING" -Finding "Unable to check SMBv1 status: $_"
}

# ============================================
# CHECK 8: Guest Account Disabled
# STIG ID: V-220907
# ============================================
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
    
    if ($guest.Enabled -eq $false) {
        $results += Write-CheckResult -StigId "V-220907" -Category "Account Management" `
            -Description "Guest account must be disabled" `
            -Status "PASS" -Finding "Guest account is disabled"
    } else {
        $results += Write-CheckResult -StigId "V-220907" -Category "Account Management" `
            -Description "Guest account must be disabled" `
            -Status "FAIL" -Finding "Guest account is ENABLED"
    }
} catch {
    $results += Write-CheckResult -StigId "V-220907" -Category "Account Management" `
        -Description "Guest account must be disabled" `
        -Status "WARNING" -Finding "Unable to check Guest account: $_"
}

# ============================================
# Generate Report
# ============================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Compliance Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
$warnCount = ($results | Where-Object { $_.Status -eq "WARNING" }).Count
$total = $results.Count

Write-Host "Total Checks: $total" -ForegroundColor White
Write-Host "PASS:         $passCount" -ForegroundColor Green
Write-Host "FAIL:         $failCount" -ForegroundColor Red
Write-Host "WARNING:      $warnCount" -ForegroundColor Yellow

if ($total -gt 0) {
    $complianceRate = [math]::Round(($passCount / $total) * 100, 1)
    Write-Host "Compliance Rate: $complianceRate%`n" -ForegroundColor $(if ($complianceRate -ge 80) { "Green" } elseif ($complianceRate -ge 60) { "Yellow" } else { "Red" })
}

# Export to CSV
try {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
    Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
} catch {
    Write-Host "Error saving report: $_" -ForegroundColor Red
}

Write-Host "`nDone. Review findings and remediate FAIL items per DISA STIG guidance.`n" -ForegroundColor Cyan
