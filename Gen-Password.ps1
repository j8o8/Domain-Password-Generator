<#
.SYNOPSIS
Domain policy compliant password generator 
.DESCRIPTION
Generates a random password subject to all set domain password policies
.EXAMPLE
Gen-Password.ps1 -DC SV-DC01 -UserName admin -HighPriv
.EXAMPLE
Gen-Password.ps1 -DC SV-DC01 -NoSpecial
#>

using namespace System.Management.Automation.Host

[CmdletBinding()] param(
    [Parameter(Mandatory=$true)] ## Domain Controller on which the password policies are stored
    [string[]]$DC,
    [Parameter(Mandatory=$false)] ## Manual password length
    [int]$PasswordLength,
    [Parameter(Mandatory=$false, ValueFromPipeline=$true)] ## Username for password complexity compliance
    [string[]]$UserName,
    [Parameter(Mandatory=$false)] ## Set parameter if the password is being used for a high privilege account (e.g. Administrator)
    [switch]$HighPriv = $false,
    [Parameter(Mandatory=$false)] ## Set if the password must not include special characters
    [switch]$NoSpecial = $false
)

# Function to generate the password
function GeneratePassword($String, $Length) {
    
    -join(Get-Random -Count $Length -InputObject $String)
}

$HighPrivIndicators = @('adm', 'sv', 'srv', 'serv', 'super')
$PasswordPolicy = Invoke-Command -ComputerName $DC -ScriptBlock {Get-ADDefaultDomainPasswordPolicy}
$MinPasswordLength = $PasswordPolicy.MinPasswordLength

# ASCII character set
$CharSet = @{
        Uppercase   = (97..122) | Get-Random -Count 10 | % {[char]$_}
        Lowercase   = (65..90)  | Get-Random -Count 10 | % {[char]$_}
        Numeric     = (48..57)  | Get-Random -Count 10 | % {[char]$_}
        SpecialChar = (33..47)+(58..64)+(91..96)+(123..126) | Get-Random -Count 10 | % {[char]$_}
}

Write-Host "`nDomain Password Generator`n" -ForegroundColor Cyan

# Check if password complexity is enabled
if (-Not $PasswordPolicy.ComplexityEnabled) {
    Write-Host "Password complexity is enabled" -ForegroundColor Yellow
    # Password minimum length with complexity enabled is 6
    if ($MinPasswordLength -lt 6) {
        $MinPasswordLength = 6
    }
    # Password must also not match the username
    if (([string]::IsNullOrEmpty($UserName))) {
        
        $UserName = Read-Host " -> Please enter a username"
    }
} else {
    Write-Host "Password complexity is disabled" -ForegroundColor Yellow
}

# Increase password length if the manual value is to short
if ($PasswordLength -lt $MinPasswordLength) {
    $PasswordLength = $MinPasswordLength
}

# Check for high privilige account indicators
if (-Not $HighPriv) {
    foreach ($Indicator in $HighPrivIndicators) {
        if ($UserName -Match $Indicator) {
            Write-Host "The username $UserName contains indications for a high privilege account" -ForegroundColor Yellow
            $HPAnswer = $Host.UI.PromptForChoice("", "Change generation method to high privilege?", @("&Yes", "&No"), 0)
            if ($HPAnswer -eq 0) {
                $HighPriv = $true
                Write-Host "Changing to high privilege" -ForegroundColor Green
            } else {
                Write-Host "Continuing with low privilege" -ForegroundColor Magenta
            }
            break
        }
    }
}

# Increase password length and add special chars for high privilege accounts
if ($HighPriv) {
    $NoSpecial = $false
    if ($PasswordLength -lt 24) {
        $PasswordLength = 24
    }
}

# Set char set for the password
$StringSet = $CharSet.Uppercase + $CharSet.Lowercase + $CharSet.Numeric
if (-Not $NoSpecial) {
    $StringSet = $StringSet + $CharSet.SpecialChar
}

Write-Host "`nPassword:" -ForegroundColor Cyan
-join(Get-Random -Count $PasswordLength -InputObject $StringSet)
