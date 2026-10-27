# =============================================================================
# ForestEye.ps1
# Active Directory Security Audit Tool - Full IR Edition
# Output: users.csv, computers.csv, domain.csv, acl.csv, gpo.csv,
#         policy.csv, auditpolicy.csv
# Run on a Domain Controller with Domain Admin privileges.
# =============================================================================
#Requires -Module ActiveDirectory

param(
    [string]$OutputPath          = "$env:SystemDrive\AD-Audit\$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [switch]$SkipUsers,
    [switch]$SkipComputers,
    [switch]$SkipACL,
    [switch]$SkipGPO,
    [int]   $AclScoreThreshold  = 12
)

# ##### Console helpers ####################
function Write-Info    { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err     { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }
# Export-Csv -Encoding UTF8 always emits a BOM on Windows PowerShell 5.1, which
# some CSV consumers choke on. Writing BOM-less UTF-8 directly avoids the
# read-back-and-rewrite pass the old Strip-BOM helper attempted (and which never
# actually fired: ReadAllText strips the BOM itself, so its check was dead code).
function Export-CsvNoBom {
    param(
        [Parameter(Mandatory)] $Data,
        [Parameter(Mandatory)] [string] $Path
    )
    $lines = @($Data | ConvertTo-Csv -NoTypeInformation)
    [System.IO.File]::WriteAllLines($Path, $lines, (New-Object System.Text.UTF8Encoding $false))
}

Write-Host ""
Write-Host "  +=============================================+" -ForegroundColor DarkCyan
Write-Host "  |       AD Security Audit Tool  v2.0         |" -ForegroundColor DarkCyan
Write-Host "  |   Users · Computers · Domain · ACL · GPO   |" -ForegroundColor DarkCyan
Write-Host "  |   Policy · AuditPolicy                     |" -ForegroundColor DarkCyan
Write-Host "  +=============================================+" -ForegroundColor DarkCyan
Write-Host ""

# ##### Pre-flight validation #####
function Test-Prerequisites {
    $ok = $true
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Err "ActiveDirectory module not found. Install RSAT (Add-WindowsFeature RSAT-AD-PowerShell)."
        $ok = $false
    }
    try { $null = Get-ADDomain -ErrorAction Stop }
    catch { Write-Err "Cannot connect to Active Directory: $_"; $ok = $false }
    try {
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
        }
        $tf = Join-Path $OutputPath ".write_test"
        [System.IO.File]::WriteAllText($tf, "test")
        Remove-Item $tf -Force
    } catch { Write-Err "Cannot write to output path '$OutputPath': $_"; $ok = $false }
    # auditpol needs an ELEVATED local-admin token (SeSecurityPrivilege); being
    # Domain Admin is not enough. Warn up front instead of letting the failure
    # scroll past halfway through a multi-minute run. Non-fatal: every other
    # section works fine without elevation.
    $script:IsElevated = ([Security.Principal.WindowsPrincipal] `
                          [Security.Principal.WindowsIdentity]::GetCurrent()
                         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $script:IsElevated) {
        Write-Warn "NOT running elevated - auditpolicy.csv will NOT be generated."
        Write-Warn "  Re-run from an ELEVATED PowerShell (Run as Administrator) for the full audit."
    }
    return $ok
}
if (-not (Test-Prerequisites)) { Write-Err "Pre-flight failed. Aborting."; exit 1 }

$OutputPath = Resolve-Path $OutputPath
Write-Info "Output directory: $OutputPath"

try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Write-Err "ActiveDirectory module load failed."; exit 1 }

# ##### Domain base info ###############─
$Domain    = Get-ADDomain
$Forest    = Get-ADForest
$DomainDN  = $Domain.DistinguishedName
$DomainSid = (Get-ADDomain).DomainSID.Value
$RootDSE   = Get-ADRootDSE
$ConfigDN  = [string]$RootDSE.configurationNamingContext
$SchemaDN  = [string]$RootDSE.schemaNamingContext
$ForestDN  = [string]$RootDSE.rootDomainNamingContext
Write-Info "Domain: $($Domain.DNSRoot)"

# ##### DC names list (for non-DC unconstrained delegation check) ########################################─
$DCNames = @()
try { $DCNames = (Get-ADDomainController -Filter * -ErrorAction Stop).Name } catch {}

# ##### OS EOL lookup #########################
$OSEOLTable = @{
    'Windows Server 2003'    = @{EOL='2015-07-14';Risk='CRITICAL'}
    'Windows Server 2008 R2' = @{EOL='2020-01-14';Risk='CRITICAL'}
    'Windows Server 2008'    = @{EOL='2020-01-14';Risk='CRITICAL'}
    'Windows Server 2012 R2' = @{EOL='2023-10-10';Risk='HIGH'}
    'Windows Server 2012'    = @{EOL='2023-10-10';Risk='HIGH'}
    'Windows Server 2016'    = @{EOL='2027-01-12';Risk='MEDIUM'}
    'Windows Server 2019'    = @{EOL='2029-01-09';Risk='LOW'}
    'Windows Server 2022'    = @{EOL='2031-10-14';Risk='OK'}
    'Windows XP'             = @{EOL='2014-04-08';Risk='CRITICAL'}
    'Windows Vista'          = @{EOL='2017-04-11';Risk='CRITICAL'}
    'Windows 7'              = @{EOL='2020-01-14';Risk='CRITICAL'}
    'Windows 8.1'            = @{EOL='2023-01-10';Risk='HIGH'}
    'Windows 8'              = @{EOL='2016-01-12';Risk='CRITICAL'}
    'Windows 10'             = @{EOL='2025-10-14';Risk='MEDIUM'}
    'Windows 11'             = @{EOL='2027-10-14';Risk='OK'}
}
function Get-OSRisk {
    param([string]$OS)
    if (-not $OS) { return @{Risk='Unknown';EOLDate='';IsEOL=$false} }
    foreach ($key in ($OSEOLTable.Keys | Sort-Object { $_.Length } -Descending)) {
        if ($OS -like "*$key*") {
            $e    = $OSEOLTable[$key]
            $isEOL = [DateTime]::Parse($e.EOL) -lt (Get-Date)
            return @{Risk=if($isEOL){$e.Risk}else{'OK'}; EOLDate=$e.EOL; IsEOL=$isEOL}
        }
    }
    return @{Risk='Unknown';EOLDate='';IsEOL=$false}
}

# ##### Privileged group list #####
$PrivGroupNames = @(
    "Domain Admins","Enterprise Admins","Schema Admins",
    "Administrators","Group Policy Creator Owners","DNSAdmins",
    "Domain Controllers","Enterprise Read-only Domain Controllers",
    "Read-only Domain Controllers",
    "Account Operators","Backup Operators","Print Operators",
    "Server Operators","Replicator","Network Configuration Operators",
    "Remote Desktop Users","Remote Management Users",
    "Distributed COM Users","Hyper-V Administrators",
    "Protected Users","Cert Publishers",
    "Enterprise Key Admins","Key Admins",
    "Event Log Readers","Performance Log Users",
    "Performance Monitor Users","Access Control Assistance Operators"
)

Write-Info "Collecting membership of privileged groups..."
$PrivGroupMembership  = @{}   # sam -> List[groupName]
$PrivGroupNestingPath = @{}   # sam -> List[string path]

foreach ($group in $PrivGroupNames) {
    try {
        # Direct members fetched ONCE per group into a set: the nesting path
        # (direct vs nested) is then resolved in-memory. Previously this ran a
        # full Get-ADGroupMember per user per group -> O(members^2) LDAP calls.
        $directSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Get-ADGroupMember $group -ErrorAction SilentlyContinue |
            Where-Object { $_.objectClass -eq 'user' } |
            ForEach-Object { [void]$directSet.Add($_.SamAccountName) }

        $members = Get-ADGroupMember $group -Recursive -ErrorAction Stop |
                   Where-Object { $_.objectClass -eq 'user' }
        foreach ($u in $members) {
            $s = $u.SamAccountName
            if (-not $PrivGroupMembership.ContainsKey($s)) {
                $PrivGroupMembership[$s]  = [System.Collections.Generic.List[string]]::new()
                $PrivGroupNestingPath[$s] = [System.Collections.Generic.List[string]]::new()
            }
            if (-not $PrivGroupMembership[$s].Contains($group)) {
                $PrivGroupMembership[$s].Add($group)
                # Build nesting path: direct parent resolved from the in-memory set
                if ($directSet.Contains($s)) {
                    $PrivGroupNestingPath[$s].Add("$group <- $s (direct)")
                } else {
                    $PrivGroupNestingPath[$s].Add("$group <- (nested) <- $s")
                }
            }
        }
    } catch { Write-Warn "Group '$group' not found or not accessible." }
}

# ##### Domain Admins fast lookup ########################################################################################################################─
$DomainAdmins = @()
try { $DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
                      Select-Object -ExpandProperty SamAccountName } catch {}

# ##### DCSync ACL check (domain NC + config NC) #####################################################################################
Write-Info "Checking DCSync ACL (domain + config NC)..."
$DCSyncAccounts = @{}
$DCSyncGUIDs = @(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c",
    "9923a32a-3607-11d2-b9be-0000f87a36b2"
)
foreach ($checkDN in @($DomainDN, $ConfigDN)) {
    try {
        $ACL = Get-Acl "AD:$checkDN" -ErrorAction Stop
        foreach ($ace in $ACL.Access) {
            if ($DCSyncGUIDs -contains $ace.ObjectType.ToString() -and
                $ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                $identity = $ace.IdentityReference.ToString()
                if ($identity -notmatch 'NT AUTHORITY|SYSTEM|Domain Controllers|Enterprise Domain Controllers|BUILTIN\\Administrators') {
                    $sam = $identity -replace '^.*\\', ''
                    if (-not $DCSyncAccounts.ContainsKey($sam)) {
                        $DCSyncAccounts[$sam] = "$($ace.ActiveDirectoryRights) on $checkDN"
                    }
                }
            }
        }
    } catch { Write-Warn "DCSync check on $checkDN failed: $_" }
}

# ##### AdminSDHolder audit ##########─
Write-Info "Auditing AdminSDHolder ACL..."
$AdminSDHolderBackdoor = @()
try {
    $asdAcl = Get-Acl "AD:CN=AdminSDHolder,CN=System,$DomainDN" -ErrorAction Stop
    foreach ($ace in $asdAcl.Access) {
        $id = $ace.IdentityReference.ToString()
        if ($ace.AccessControlType -eq 'Allow' -and
            $id -notmatch 'SYSTEM|Domain Admins|Enterprise Admins|Administrators|NT AUTHORITY|SELF|CREATOR OWNER') {
            if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') {
                $AdminSDHolderBackdoor += "$id : $($ace.ActiveDirectoryRights)"
            }
        }
    }
    if ($AdminSDHolderBackdoor) { Write-Warn "AdminSDHolder: $($AdminSDHolderBackdoor.Count) suspicious ACE(s) found!" }
    else { Write-Success "AdminSDHolder: no suspicious ACEs" }
} catch { Write-Warn "AdminSDHolder audit failed: $_" }

# ##### Pre-W2K Compatible Access group #########################################################################################################
Write-Info "Checking Pre-Windows 2000 Compatible Access group..."
$PreW2kStatus  = "Empty (OK)"
$PreW2kMembers = ""
$PreW2kCount   = 0
$PreW2kDangCount = 0
try {
    $pw2kAll  = Get-ADGroupMember -Identity 'S-1-5-32-554' -ErrorAction Stop
    $pw2kDang = $pw2kAll | Where-Object { $_.SID.Value -in @('S-1-1-0','S-1-5-7','S-1-5-11') }
    $PreW2kCount    = @($pw2kAll).Count
    $PreW2kDangCount = @($pw2kDang).Count
    $PreW2kMembers  = ($pw2kAll | Select-Object -ExpandProperty SamAccountName) -join "; "
    $PreW2kStatus   = if ($PreW2kDangCount -gt 0) {"CRITICAL"}
                      elseif ($PreW2kCount -gt 0)  {"Members present (review)"}
                      else {"Empty (OK)"}
} catch { Write-Warn "Pre-W2K group check failed: $_" }

# ##### Machine Account Quota #####
Write-Info "Checking Machine Account Quota..."
$MAQ = -1
try { $MAQ = [int](Get-ADObject -Identity $DomainDN -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota' }
catch { Write-Warn "Could not read MAQ: $_" }

# ##### Schema GUIDs for LAPS / gMSA ##############################################################################################################─
$ReadProps  = @{}
$WriteProps_Schema = @{}
$SchemaHas  = @{}   # lDAPDisplayName -> $true, for attributes present in THIS forest
Write-Info "Resolving schema GUIDs (LAPS/gMSA)..."
$schemaAttrs = @('ms-Mcs-AdmPwd','msLAPS-Password','msLAPS-EncryptedPassword',
                 'msLAPS-EncryptedPasswordHistory','msLAPS-EncryptedDSRMPassword',
                 'msDS-ManagedPassword','msDS-GroupMSAMembership')
# Not password material, so kept out of the ACL scoring maps below, but still
# probed: Get-ADComputer -Properties throws on an attribute the schema lacks.
$schemaOptional = @('ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime')
foreach ($attr in ($schemaAttrs + $schemaOptional)) {
    try {
        $sObj = Get-ADObject -SearchBase $SchemaDN -LDAPFilter "(lDAPDisplayName=$attr)" `
                             -Properties lDAPDisplayName,schemaIDGUID -ErrorAction Stop
        if ($sObj) {
            $SchemaHas[$attr] = $true
            if ($schemaAttrs -contains $attr) {
                $guid = (New-Object Guid(,[byte[]]$sObj.schemaIDGUID)).ToString().ToLower()
                $kind = if ($attr -match 'LAPS|AdmPwd') { 'LAPS' } else { 'gMSA' }
                $ReadProps[$guid]         = @{Name=$attr; W=10; Issue="$kind password read"}
                $WriteProps_Schema[$guid] = @{Name=$attr; W=9;  Issue="$kind password write"}
            }
        }
    } catch {}
}
Write-Info "  resolved $($ReadProps.Count) schema attributes"

# ##### ForeignSecurityPrincipals ########################################################################################################################─
$foreignSids = @{}
try {
    Get-ADObject -SearchBase "CN=ForeignSecurityPrincipals,$DomainDN" `
                 -LDAPFilter '(objectClass=foreignSecurityPrincipal)' `
                 -Properties objectSid,distinguishedName -ErrorAction Stop |
    ForEach-Object {
        if ($_.objectSid) {
            # Get-ADObject hands objectSid back as a SecurityIdentifier, not as the
            # raw byte[]: the (byte[], int) constructor then fails with "cannot find
            # an overload ... argument count 2" and every FSP was silently lost.
            $sidObj = $_.objectSid
            if ($sidObj -isnot [System.Security.Principal.SecurityIdentifier]) {
                try   { $sidObj = New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$sidObj), 0) }
                catch { $sidObj = $null }
            }
            if ($sidObj) { $foreignSids[$sidObj.Value] = $_.DistinguishedName }
        }
    }
} catch { Write-Warn "FSP load failed: $_" }
Write-Info "  loaded $($foreignSids.Count) FSP"

# =============================================================================
# 1. USERS  ->  users.csv
# =============================================================================
$UsersCsvPath = Join-Path $OutputPath "users.csv"
$DateLimit    = (Get-Date).AddDays(-365)
$UsersReport  = @()

if (-not $SkipUsers) {
    Write-Host ""; Write-Info "Collecting users data..."
    # NOTE (5.6): LastLogonDate is a replicated attribute updated every ~14 days across DCs.
    # For precise last-logon accuracy during IR, query the non-replicated 'lastLogon' attribute
    # on each DC individually. An account may show 'Never' in LastLogonDate if it only
    # authenticated against one DC and replication has not yet occurred.

    $ADUsers = Get-ADUser -Filter * -Properties `
        SamAccountName,SID,SIDHistory,Description,LastLogonDate,PasswordLastSet,
        PasswordNeverExpires,BadPasswordTime,BadLogonCount,Created,Enabled,
        ServicePrincipalNames,UserAccountControl,PasswordNotRequired,
        TrustedForDelegation,AdminCount,'msDS-SupportedEncryptionTypes',
        AccountExpirationDate,UserWorkstations,DistinguishedName `
        -SearchBase $DomainDN

    $UsersReport = foreach ($User in $ADUsers) {
        $sam = $User.SamAccountName

        # Kerberoastable
        $IsKerberoastable = ($User.ServicePrincipalNames.Count -gt 0 -and
                             $User.Enabled -eq $true -and -not $sam.EndsWith('$'))

        # AS-REP Roastable (UAC bit 0x400000)
        $IsASREP = ($User.UserAccountControl -band 4194304) -ne 0

        # Password checks
        $PwdNeverExpires = if ($User.PasswordNeverExpires) {"Yes"} else {"No"}
        $PwdNotRequired  = if ($User.UserAccountControl -band 32) {"Yes"} else {"No"}
        $OldPassword = "No"
        if (-not $User.PasswordLastSet)               { $OldPassword = "Never Set" }
        elseif ($User.PasswordLastSet -lt $DateLimit) { $OldPassword = "Yes" }

        # Delegation
        $UserDelegation = "No"
        if ($User.TrustedForDelegation)                    { $UserDelegation = "Unconstrained" }
        elseif ($User.UserAccountControl -band 16777216)   { $UserDelegation = "Constrained" }

        # BadPasswordTime
        $BadPwdTime = "N/A"
        if ($User.BadPasswordTime -gt 0) {
            try { $BadPwdTime = [DateTime]::FromFileTime($User.BadPasswordTime).ToString("yyyy-MM-dd HH:mm:ss") }
            catch { $BadPwdTime = "Error" }
        }

        # Privileged groups
        $PrivGroups_str = if ($PrivGroupMembership.ContainsKey($sam)) {
            $PrivGroupMembership[$sam] -join "; "
        } else { "No" }

        $NestingPath_str = if ($PrivGroupNestingPath.ContainsKey($sam)) {
            $PrivGroupNestingPath[$sam] -join " | "
        } else { "" }

        # DCSync
        $HasDCSync = if ($DCSyncAccounts.ContainsKey($sam)) {"Yes"} else {"No"}

        # Description
        $HasDescription = if ($User.Description -and $User.Description.Trim() -ne "") {"Yes"} else {"No"}

        # ##### New fields #####─

        # SID History
        $SIDHistoryCount   = 0
        $SIDHistoryValues  = ""
        $SIDHistoryCritical = "No"
        if ($User.SIDHistory -and $User.SIDHistory.Count -gt 0) {
            $SIDHistoryCount  = $User.SIDHistory.Count
            $SIDHistoryValues = ($User.SIDHistory | ForEach-Object { $_.Value }) -join "; "
            $critRIDs = @(512,518,519,520,544,552)
            foreach ($hs in $User.SIDHistory) {
                $rid = try { [int]($hs.Value -split '-')[-1] } catch { 0 }
                if ($critRIDs -contains $rid) { $SIDHistoryCritical = "CRITICAL"; break }
            }
            if ($SIDHistoryCritical -ne "CRITICAL") { $SIDHistoryCritical = "Yes" }
        }

        # Reversible encryption (UAC 0x80)
        $ReversibleEncryption = if ($User.UserAccountControl -band 0x80) {"CRITICAL"} else {"No"}

        # Sensitive/No-Delegation (UAC 0x100000)
        $SensitiveNoDelegation = if ($User.UserAccountControl -band 0x100000) {"Yes"} else {"No"}
        $PrivMissingNoDel = "N/A"
        if ($PrivGroupMembership.ContainsKey($sam) -or ($DomainAdmins -contains $sam)) {
            $PrivMissingNoDel = if ($SensitiveNoDelegation -eq "No") {"RISK"} else {"OK"}
        }

        # Account expiration
        $ExpirationDate  = ""
        $AccountExpired  = "No"
        $NoExpirationDate = "No"
        if ($User.AccountExpirationDate) {
            $ExpirationDate = $User.AccountExpirationDate.ToString("yyyy-MM-dd")
            if ($User.AccountExpirationDate -lt (Get-Date)) { $AccountExpired = "Yes" }
        } else { $NoExpirationDate = "Yes" }

        # Kerberos encryption types
        $encTypes = $User.'msDS-SupportedEncryptionTypes'
        $KerberosEncryption = "Domain Default (RC4 fallback)"
        $WeakKerberos = "No"
        if ($null -ne $encTypes -and $encTypes -ne 0) {
            $algos = @()
            if ($encTypes -band 1)  { $algos += "DES-CRC" }
            if ($encTypes -band 2)  { $algos += "DES-MD5" }
            if ($encTypes -band 4)  { $algos += "RC4" }
            if ($encTypes -band 8)  { $algos += "AES128" }
            if ($encTypes -band 16) { $algos += "AES256" }
            $KerberosEncryption = $algos -join "+"
            if (($encTypes -band 0x4) -and -not ($encTypes -band 0x18)) {
                $WeakKerberos = if ($IsKerberoastable) {"CRITICAL"} else {"Yes"}
            }
        }

        # AdminCount orphan
        $AdminCountOrphan = if (($User.AdminCount -eq 1) -and ($PrivGroups_str -eq "No") -and ($sam -ne "krbtgt")) {"Yes"} else {"No"}

        # Logon workstation restriction
        $LogonWorkstations = if ($User.UserWorkstations) {$User.UserWorkstations} else {"Unrestricted"}
        $MissingWorkstationRestriction = "N/A"
        if ($PrivGroupMembership.ContainsKey($sam) -or ($DomainAdmins -contains $sam)) {
            $MissingWorkstationRestriction = if (-not $User.UserWorkstations) {"Yes"} else {"No"}
        }

        # Recent password change (<72h)
        $RecentPwdChange = "No"
        if ($User.PasswordLastSet -and ((Get-Date) - $User.PasswordLastSet).TotalHours -lt 72) {
            $RecentPwdChange = "Yes"
        }

        # In default container
        $InDefaultContainer = if ($User.DistinguishedName -match ',CN=(Users|Computers),DC=') {"Yes"} else {"No"}

        # Suspicious SPN (computer-type SPN on user account)
        $SuspiciousSPN = "No"
        if ($User.ServicePrincipalNames.Count -gt 0 -and -not $sam.EndsWith('$')) {
            foreach ($spn in $User.ServicePrincipalNames) {
                if ($spn -match '^(HOST|TERMSRV|WSMAN|RestrictedKrbHost)/') { $SuspiciousSPN = "Yes"; break }
            }
        }

        # Suspicious interdomain trust bit
        $SuspiciousTrustBit = if (($User.UserAccountControl -band 0x800) -and
                                   $User.DistinguishedName -notmatch ',CN=Users,DC=') {"SUSPICIOUS"} else {"No"}

        [PSCustomObject]@{
            SamAccountName               = $sam
            SID                          = $User.SID.Value
            DistinguishedName            = $User.DistinguishedName
            Description                  = $User.Description
            LastLogonDate                = if ($User.LastLogonDate)   {$User.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss")}   else {"Never"}
            PasswordLastSet              = if ($User.PasswordLastSet) {$User.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss")} else {"Never"}
            PasswordNeverExpire          = $PwdNeverExpires
            PasswordNotRequired          = $PwdNotRequired
            OldPassword                  = $OldPassword
            BadPasswordTime              = $BadPwdTime
            BadPasswordCount             = $User.BadLogonCount
            CreationDate                 = if ($User.Created) {$User.Created.ToString("yyyy-MM-dd HH:mm:ss")} else {""}
            IsDomainAdmin                = if ($DomainAdmins -contains $sam) {"Yes"} else {"No"}
            PrivilegedGroups             = $PrivGroups_str
            NestingPath                  = $NestingPath_str
            AdminCount                   = if ($User.AdminCount -eq 1) {"Yes"} else {"No"}
            AccountDisabled              = if ($User.Enabled) {"No"} else {"Yes"}
            Kerberoastable               = if ($IsKerberoastable) {"Yes"} else {"No"}
            ASREPRoastable               = if ($IsASREP)           {"Yes"} else {"No"}
            UserDelegation               = $UserDelegation
            HasDCSync                    = $HasDCSync
            HasDescription               = $HasDescription
            SPNs                         = ($User.ServicePrincipalNames -join "; ")
            UserAccountControl           = $User.UserAccountControl
            SIDHistoryCount              = $SIDHistoryCount
            SIDHistoryValues             = $SIDHistoryValues
            SIDHistoryCritical           = $SIDHistoryCritical
            ReversibleEncryption         = $ReversibleEncryption
            SensitiveNoDelegation        = $SensitiveNoDelegation
            PrivilegedMissingNoDelegation = $PrivMissingNoDel
            AccountExpirationDate        = $ExpirationDate
            AccountExpired               = $AccountExpired
            NoExpirationDate             = $NoExpirationDate
            KerberosEncryption           = $KerberosEncryption
            WeakKerberos                 = $WeakKerberos
            AdminCountOrphan             = $AdminCountOrphan
            LogonWorkstations            = $LogonWorkstations
            MissingWorkstationRestriction = $MissingWorkstationRestriction
            RecentPwdChange              = $RecentPwdChange
            InDefaultContainer           = $InDefaultContainer
            SuspiciousSPN                = $SuspiciousSPN
            SuspiciousTrustBit           = $SuspiciousTrustBit
        }
    }

    Export-CsvNoBom $UsersReport $UsersCsvPath
    Write-Success "Exported users: $($UsersReport.Count) records -> users.csv"
} else {
    Write-Warn "Skipping user collection (-SkipUsers)"
    if (Test-Path $UsersCsvPath) { $UsersReport = Import-Csv $UsersCsvPath; Write-Info "Loaded existing users.csv ($($UsersReport.Count) records)" }
}

# =============================================================================
# 2. COMPUTERS  ->  computers.csv
# =============================================================================
$ComputersCsvPath = Join-Path $OutputPath "computers.csv"
$ComputersReport  = @()

if (-not $SkipComputers) {
    Write-Host ""; Write-Info "Collecting computer data..."

    # LAPS attributes exist only after the schema has been extended (legacy LAPS
    # adds ms-Mcs-AdmPwd*, Windows LAPS adds msLAPS-*). Asking for one the forest
    # does not have makes Get-ADComputer fail with "One or more properties are
    # invalid" and aborts the whole collection, so request only what exists.
    $compProps = @(
        'ServicePrincipalNames','TrustedForDelegation','UserAccountControl',
        'msDS-AllowedToActOnBehalfOfOtherIdentity','msDS-AllowedToDelegateTo',
        'OperatingSystem','LastLogonDate','LastLogonTimestamp','DNSHostName','Description',
        'Enabled','Created','DistinguishedName'
    )
    $lapsProps = @('ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime',
                   'msLAPS-Password','msLAPS-EncryptedPassword','msLAPS-PasswordExpirationTime') |
                 Where-Object { $SchemaHas[$_] }
    if ($lapsProps) {
        $compProps += $lapsProps
    } else {
        Write-Warn "No LAPS attributes in this forest schema - LAPS status will report 'Not Deployed' for every computer."
    }

    $ADComputers = Get-ADComputer -Filter * -Properties $compProps -SearchBase $DomainDN

    $StaleThreshold = (Get-Date).AddDays(-90)

    $ComputersReport = foreach ($Computer in $ADComputers) {
        # LastLogonTimestamp
        $LLTimestamp = "N/A"
        if ($Computer.LastLogonTimestamp -gt 0) {
            try { $LLTimestamp = [DateTime]::FromFileTime($Computer.LastLogonTimestamp).ToString("yyyy-MM-dd HH:mm:ss") }
            catch { $LLTimestamp = "Error" }
        }

        # RBCD
        $RBCD = "No"
        if ($Computer.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
            try {
                $SD       = New-Object System.Security.AccessControl.RawSecurityDescriptor($Computer.'msDS-AllowedToActOnBehalfOfOtherIdentity',0)
                $Trustees = $SD.DiscretionaryAcl | ForEach-Object { $_.SecurityIdentifier.Value }
                $RBCD     = $Trustees -join "; "
            } catch { $RBCD = "Yes (parse error)" }
        }

        # Delegation
        $Unconstrained = if ($Computer.TrustedForDelegation) {"Yes"} else {"No"}
        $Constrained   = if ($Computer.'msDS-AllowedToDelegateTo' -and $Computer.'msDS-AllowedToDelegateTo'.Count -gt 0) {
            ($Computer.'msDS-AllowedToDelegateTo' -join "; ")
        } else {"No"}

        # Stale check
        $IsStale = "No"
        $lastSeen = if ($Computer.LastLogonTimestamp -gt 0) {
            [DateTime]::FromFileTime($Computer.LastLogonTimestamp)
        } elseif ($Computer.LastLogonDate) { $Computer.LastLogonDate }
        else { $null }
        if   (-not $lastSeen)                          { $IsStale = "Never" }
        elseif ($lastSeen -lt $StaleThreshold)         { $IsStale = "Yes" }

        # EOL OS
        $osR      = Get-OSRisk -OS ($Computer.OperatingSystem)
        $OSRisk   = $osR.Risk
        $OSEOLDate = $osR.EOLDate
        $OSIsEOL  = if ($osR.IsEOL) {"Yes"} else {"No"}

        # LAPS
        $LAPSStatus = "Not Deployed"; $LAPSType = ""; $LAPSExpiry = ""; $LAPSExpired = "N/A"
        if ($Computer.'msLAPS-EncryptedPassword' -or $Computer.'msLAPS-Password') {
            $LAPSStatus = "Windows LAPS"; $LAPSType = "Windows LAPS (2023+)"
            if ($Computer.'msLAPS-PasswordExpirationTime') {
                try { $LAPSExpiry = [DateTime]::FromFileTime([long]$Computer.'msLAPS-PasswordExpirationTime').ToString("yyyy-MM-dd") } catch {}
            }
        } elseif ($Computer.'ms-Mcs-AdmPwd') {
            $LAPSStatus = "Legacy LAPS"; $LAPSType = "Microsoft LAPS"
            if ($Computer.'ms-Mcs-AdmPwdExpirationTime') {
                try { $LAPSExpiry = [DateTime]::FromFileTime([long]$Computer.'ms-Mcs-AdmPwdExpirationTime').ToString("yyyy-MM-dd") } catch {}
            }
        }
        if ($LAPSExpiry -and $LAPSStatus -ne "Not Deployed") {
            try { $LAPSExpired = if ([DateTime]::Parse($LAPSExpiry) -lt (Get-Date)) {"Yes"} else {"No"} } catch {}
        }

        # DC / non-DC unconstrained
        $IsDC              = if ($DCNames -contains $Computer.Name) {"True"} else {"False"}
        $NonDCUnconstrained = if ($Computer.TrustedForDelegation -and $IsDC -eq "False") {"CRITICAL"} else {"No"}

        # Constrained delegation targeting DCs
        $DelegationToDC = "No"
        if ($Computer.'msDS-AllowedToDelegateTo') {
            $dcSPNPrefixes = $DCNames | ForEach-Object { "cifs/$_"; "host/$_"; "ldap/$_" }
            foreach ($tgt in $Computer.'msDS-AllowedToDelegateTo') {
                if ($dcSPNPrefixes | Where-Object { $tgt -ilike "$_*" }) { $DelegationToDC = "CRITICAL"; break }
            }
        }

        [PSCustomObject]@{
            Name                    = $Computer.Name
            DNSHostName             = $Computer.DNSHostName
            Description             = $Computer.Description
            OperatingSystem         = $Computer.OperatingSystem
            Enabled                 = $Computer.Enabled
            Created                 = if ($Computer.Created) {$Computer.Created.ToString("yyyy-MM-dd HH:mm:ss")} else {""}
            LastLogonDate           = if ($Computer.LastLogonDate) {$Computer.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss")} else {"Never"}
            LastLogonTimestamp      = $LLTimestamp
            ServicePrincipalNames   = ($Computer.ServicePrincipalNames -join "; ")
            TrustedForDelegation    = $Unconstrained
            ConstrainedDelegation   = $Constrained
            RBCD_AllowedActOnBehalf = $RBCD
            UserAccountControl      = $Computer.UserAccountControl
            DistinguishedName       = $Computer.DistinguishedName
            StaleComputer           = $IsStale
            OSRisk                  = $OSRisk
            OSEOLDate               = $OSEOLDate
            OSIsEOL                 = $OSIsEOL
            LAPSStatus              = $LAPSStatus
            LAPSType                = $LAPSType
            LAPSExpiry              = $LAPSExpiry
            LAPSExpired             = $LAPSExpired
            IsDC                    = $IsDC
            NonDCUnconstrained      = $NonDCUnconstrained
            DelegationToDC          = $DelegationToDC
        }
    }

    Export-CsvNoBom $ComputersReport $ComputersCsvPath
    Write-Success "Exported computers: $($ComputersReport.Count) records -> computers.csv"
} else {
    Write-Warn "Skipping computer collection (-SkipComputers)"
    if (Test-Path $ComputersCsvPath) { $ComputersReport = Import-Csv $ComputersCsvPath; Write-Info "Loaded existing computers.csv" }
}

# =============================================================================
# 3. DOMAIN / DC / TRUST  ->  domain.csv
# =============================================================================
Write-Host ""; Write-Info "Collecting domain, DC and trust information..."
$DomainCsvPath = Join-Path $OutputPath "domain.csv"
$DomainReport  = [System.Collections.Generic.List[PSCustomObject]]::new()

# Domain info
$DomainReport.Add([PSCustomObject]@{
    Category        = "Domain"
    Name            = $Domain.DNSRoot
    Detail          = "NetBIOS: $($Domain.NetBIOSName) | DN: $($Domain.DistinguishedName)"
    FunctionalLevel = $Domain.DomainMode.ToString()
    ForestName      = $Forest.Name
    ForestMode      = $Forest.ForestMode.ToString()
    SchemaMaster    = $Domain.PDCEmulator
    ExtraInfo       = "PDC: $($Domain.PDCEmulator) | RID: $($Domain.RIDMaster) | Infra: $($Domain.InfrastructureMaster)"
})

# Domain Controllers
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    $DCComputer = $null
    try { $DCComputer = Get-ADComputer -Identity $DC.ComputerObjectDN -Properties OperatingSystem,LastLogonDate,Created } catch {}
    $Roles = ($DC.OperationMasterRoles -join ", ")
    if ([string]::IsNullOrEmpty($Roles)) { $Roles = "None" }
    $DomainReport.Add([PSCustomObject]@{
        Category        = "DomainController"
        Name            = $DC.HostName
        Detail          = "Site: $($DC.Site) | IP: $($DC.IPv4Address)"
        FunctionalLevel = $DC.OperatingSystem
        ForestName      = $Forest.Name
        ForestMode      = ""
        SchemaMaster    = if ($DC.IsGlobalCatalog) {"Yes"} else {"No"}
        ExtraInfo       = "FSMO Roles: $Roles | IsGC: $($DC.IsGlobalCatalog) | IsRODC: $($DC.IsReadOnly) | Created: $(if ($DCComputer.Created) {$DCComputer.Created.ToString('yyyy-MM-dd')} else {'N/A'}) | LastLogon: $(if ($DCComputer.LastLogonDate) {$DCComputer.LastLogonDate.ToString('yyyy-MM-dd')} else {'N/A'})"
    })
}

# Trusts
$Trusts = Get-ADTrust -Filter * -Properties * -ErrorAction SilentlyContinue
if ($Trusts) {
    foreach ($Trust in $Trusts) {
        $TrustDirection = switch ($Trust.Direction) {
            "Bidirectional" {"Bidirectional"} "Inbound" {"Inbound (they trust us)"} "Outbound" {"Outbound (we trust them)"} default {$Trust.Direction.ToString()}
        }
        $TrustType = switch ($Trust.TrustType) {
            "External" {"External"} "Forest" {"Forest"} "Shortcut" {"Shortcut"} "Realm" {"Realm (non-Windows)"} "ParentChild" {"Parent-Child"} "CrossLink" {"Cross-Link"} default {$Trust.TrustType.ToString()}
        }
        $TrustAttribs = @()
        if ($Trust.SelectiveAuthentication) { $TrustAttribs += "SelectiveAuth" }
        if ($Trust.ForestTransitive)        { $TrustAttribs += "ForestTransitive" }
        if ($Trust.IntraForest)             { $TrustAttribs += "IntraForest" }
        if ($Trust.SIDFilteringQuarantined) { $TrustAttribs += "SIDFilteringEnabled" }
        else                                { $TrustAttribs += "SIDFilteringDISABLED(!)" }
        $DomainReport.Add([PSCustomObject]@{
            Category="Trust"; Name=$Trust.Name; Detail="Direction: $TrustDirection | Type: $TrustType"
            FunctionalLevel=""; ForestName=$Forest.Name; ForestMode=""; SchemaMaster=""
            ExtraInfo=($TrustAttribs -join " | ")
        })
    }
} else {
    $DomainReport.Add([PSCustomObject]@{
        Category="Trust"; Name="None"; Detail="No trusts configured"
        FunctionalLevel=""; ForestName=$Forest.Name; ForestMode=""; SchemaMaster=""; ExtraInfo=""
    })
}

# Machine Account Quota
$DomainReport.Add([PSCustomObject]@{
    Category="MachineAccountQuota"; Name="ms-DS-MachineAccountQuota"
    Detail="Current value: $MAQ"
    FunctionalLevel=""
    ForestName=$Forest.Name; ForestMode=""; SchemaMaster=""
    ExtraInfo="Risk: $(if($MAQ -gt 0){'HIGH - any user can create computer accounts (RBCD pre-condition)'}else{'OK - non-admins cannot create computer accounts'}) | Recommended: 0"
})

# Pre-W2K Compatible Access
$DomainReport.Add([PSCustomObject]@{
    Category="PreW2000Group"; Name="Pre-Windows 2000 Compatible Access"
    Detail="Total members: $PreW2kCount | Dangerous members: $PreW2kDangCount"
    FunctionalLevel=$PreW2kStatus
    ForestName=$Forest.Name; ForestMode=""; SchemaMaster=""
    ExtraInfo=$PreW2kMembers
})

# AdminSDHolder
$DomainReport.Add([PSCustomObject]@{
    Category="AdminSDHolder"; Name="AdminSDHolder"
    Detail="Suspicious ACEs: $($AdminSDHolderBackdoor.Count)"
    FunctionalLevel=if($AdminSDHolderBackdoor){"CRITICAL"}else{"OK"}
    ForestName=$Forest.Name; ForestMode=""; SchemaMaster=""
    ExtraInfo=($AdminSDHolderBackdoor -join " || ")
})


# --- 3.5 SYSVOL / NETLOGON Write Permission Check ---
$SysvolRisk    = "Unknown"
$NetlogonRisk  = "Unknown"
$SysvolDetail  = ""
try {
    foreach ($shareTuple in @(
        @{ Path="\\$($Domain.DNSRoot)\SYSVOL";   Var="SYSVOL"   },
        @{ Path="\\$($Domain.DNSRoot)\NETLOGON"; Var="NETLOGON" }
    )) {
        $sharePath = $shareTuple.Path
        $shareVar  = $shareTuple.Var
        $shareRisk = "OK"
        $shareDetail = ""
        try {
            $acl = Get-Acl $sharePath -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $trustee = $ace.IdentityReference.Value
                $rights  = [int]$ace.FileSystemRights
                $hasWrite = ($rights -band 2) -or ($rights -band 4) -or ($rights -band 278) -or ($rights -band 1179785)
                if ($hasWrite -and $trustee -match 'Everyone|Authenticated Users|Domain Users|ANONYMOUS|S-1-1-0|S-1-5-11') {
                    $shareRisk   = "CRITICAL"
                    $shareDetail += "WRITE by $trustee; "
                }
            }
        } catch { $shareRisk = "AccessDenied" }
        if ($shareVar -eq "SYSVOL")   { $SysvolRisk  = $shareRisk; $SysvolDetail  = $shareDetail }
        if ($shareVar -eq "NETLOGON") { $NetlogonRisk = $shareRisk }
    }
    $DomainReport.Add([PSCustomObject]@{
        Category="SYSVOLPerms"; Name="SYSVOL + NETLOGON Permissions"
        Detail="SYSVOL: $SysvolRisk | NETLOGON: $NetlogonRisk"
        FunctionalLevel=if($SysvolRisk -eq "CRITICAL" -or $NetlogonRisk -eq "CRITICAL"){"CRITICAL - non-admin write access detected"}else{"OK"}
        ForestName=$Forest.Name; ForestMode=""; SchemaMaster=""
        ExtraInfo=if($SysvolDetail){"Dangerous ACE: $SysvolDetail"}else{"No non-admin write ACEs found. Verify SYSVOL DFSR replication is healthy."}
    })
} catch { Write-Warn "SYSVOL permission check failed: $_" }

Export-CsvNoBom $DomainReport $DomainCsvPath
Write-Success "Exported domain/DC/trust: $($DomainReport.Count) records -> domain.csv"

# =============================================================================
# 3a. PASSWORD POLICY (default + PSOs)  ->  policy.csv
# =============================================================================
Write-Host ""; Write-Info "Collecting password policies..."
$PolicyCsvPath = Join-Path $OutputPath "policy.csv"
$PolicyReport  = [System.Collections.Generic.List[PSCustomObject]]::new()

$dp = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
if ($dp) {
    $PolicyReport.Add([PSCustomObject]@{
        Type="DefaultDomain"; Name="Default Domain Password Policy"
        MinPasswordLength=$dp.MinPasswordLength
        PasswordHistoryCount=$dp.PasswordHistoryCount
        MaxPasswordAge_Days=$dp.MaxPasswordAge.Days
        MinPasswordAge_Days=$dp.MinPasswordAge.Days
        ComplexityEnabled=$dp.ComplexityEnabled
        ReversibleEncryption=$dp.ReversibleEncryptionEnabled
        LockoutThreshold=$dp.LockoutThreshold
        LockoutDuration_Min=[int]$dp.LockoutDuration.TotalMinutes
        LockoutObsWindow_Min=[int]$dp.LockoutObservationWindow.TotalMinutes
        AppliesTo="All domain users (no PSO)"
        Risk_WeakLength=if($dp.MinPasswordLength -lt 14){"Yes"}else{"No"}
        Risk_NoLockout=if($dp.LockoutThreshold -eq 0){"CRITICAL"}elseif($dp.LockoutThreshold -gt 5){"Yes"}else{"No"}
        Risk_WeakHistory=if($dp.PasswordHistoryCount -lt 24){"Yes"}else{"No"}
        Risk_NoComplexity=if(-not $dp.ComplexityEnabled){"Yes"}else{"No"}
        Risk_ReversibleEnc=if($dp.ReversibleEncryptionEnabled){"CRITICAL"}else{"No"}
    })
}
$PSOs = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue
if ($PSOs) {
    foreach ($pso in $PSOs) {
        $appliesTo = @()
        try { $appliesTo = (Get-ADFineGrainedPasswordPolicySubject $pso -ErrorAction Stop).SamAccountName } catch {}
        $PolicyReport.Add([PSCustomObject]@{
            Type="PSO"; Name=$pso.Name
            MinPasswordLength=$pso.MinPasswordLength
            PasswordHistoryCount=$pso.PasswordHistoryCount
            MaxPasswordAge_Days=$pso.MaxPasswordAge.Days
            MinPasswordAge_Days=$pso.MinPasswordAge.Days
            ComplexityEnabled=$pso.ComplexityEnabled
            ReversibleEncryption=$pso.ReversibleEncryptionEnabled
            LockoutThreshold=$pso.LockoutThreshold
            LockoutDuration_Min=[int]$pso.LockoutDuration.TotalMinutes
            LockoutObsWindow_Min=[int]$pso.LockoutObservationWindow.TotalMinutes
            AppliesTo=($appliesTo -join "; ")
            Risk_WeakLength=if($pso.MinPasswordLength -lt 14){"Yes"}else{"No"}
            Risk_NoLockout=if($pso.LockoutThreshold -eq 0){"CRITICAL"}elseif($pso.LockoutThreshold -gt 5){"Yes"}else{"No"}
            Risk_WeakHistory=if($pso.PasswordHistoryCount -lt 24){"Yes"}else{"No"}
            Risk_NoComplexity=if(-not $pso.ComplexityEnabled){"Yes"}else{"No"}
            Risk_ReversibleEnc=if($pso.ReversibleEncryptionEnabled){"CRITICAL"}else{"No"}
        })
    }
}
Export-CsvNoBom $PolicyReport $PolicyCsvPath
Write-Success "Exported policy: $($PolicyReport.Count) records -> policy.csv"

# =============================================================================
# 4. ACL SCAN  ->  acl.csv
# =============================================================================
$AclCsvPath = Join-Path $OutputPath "acl.csv"
$AclReport  = [System.Collections.Generic.List[PSCustomObject]]::new()

if (-not $SkipACL) {
    Write-Host ""; Write-Info "ACL scan (full attack-oriented)..."

    # Risk tables
    $DangerousSids = @{
        'S-1-1-0'      = @{Name='Everyone';                           W=10}
        'S-1-5-7'      = @{Name='Anonymous';                          W=10}
        'S-1-5-11'     = @{Name='Authenticated Users';                W=10}
        'S-1-5-32-545' = @{Name='BUILTIN\Users';                      W=9}
        'S-1-5-32-546' = @{Name='BUILTIN\Guests';                     W=9}
        'S-1-5-32-547' = @{Name='BUILTIN\Power Users';                W=8}
        'S-1-5-32-548' = @{Name='Account Operators';                  W=9}
        'S-1-5-32-549' = @{Name='Server Operators';                   W=7}
        'S-1-5-32-550' = @{Name='Print Operators';                    W=7}
        'S-1-5-32-551' = @{Name='Backup Operators';                   W=9}
        'S-1-5-32-554' = @{Name='Pre-Windows 2000 Compatible Access'; W=10}
        'S-1-5-32-555' = @{Name='Remote Desktop Users';               W=7}
    }
    $DangerousRids = @{513=@{Name='Domain Users';W=10}; 514=@{Name='Domain Guests';W=10}; 515=@{Name='Domain Computers';W=7}}
    $AdminSids = @('S-1-5-18','S-1-5-19','S-1-5-20','S-1-5-9','S-1-5-32-544','S-1-5-32-552','S-1-3-0')
    $AdminRids = @(500,512,516,517,518,519,520,521,522,526,527)

    $ExtRights = @{
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'=@{Name='Replicating-Directory-Changes';W=10;Issue='DCSync'}
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'=@{Name='Replicating-Directory-Changes-All';W=10;Issue='DCSync'}
        '89e95b76-444d-4c62-991a-0facbeda640c'=@{Name='Replicating-Directory-Changes-In-Filtered-Set';W=10;Issue='DCSync'}
        '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2'=@{Name='Replication-Manage-Topology';W=8;Issue='Replication abuse'}
        '00299570-246d-11d0-a768-00aa006e0529'=@{Name='User-Force-Change-Password';W=9;Issue='Force password reset'}
        'ab721a53-1e2f-11d0-9819-00aa0040529b'=@{Name='User-Change-Password';W=5;Issue='Change password'}
        'bf9679c0-0de6-11d0-a285-00aa003049e2'=@{Name='Self-Membership';W=8;Issue='Group hijack (Self-Membership)'}
        '45ec5156-db7e-47bb-b53f-dbeb2d03c40f'=@{Name='Reanimate-Tombstone';W=7;Issue='Tombstone reanimation'}
        'f3a64789-5306-11d1-a9c5-0000f80367c1'=@{Name='Validated-SPN';W=9;Issue='SPN write / RBCD'}
        '72e39547-7b18-11d1-adef-00c04fd8d5cd'=@{Name='Validated-DNS-Host-Name';W=7;Issue='DNS hostname write'}
        'ba33815a-4f93-4c76-87f3-57574bff8109'=@{Name='Migrate-SID-History';W=9;Issue='SID History injection'}
        'edacfd8f-ffb3-11d1-b41d-00a0c968f939'=@{Name='Apply-Group-Policy';W=6;Issue='GPO Apply abuse'}
        '0e10c968-78fb-11d2-90d4-00c04f79dc55'=@{Name='Certificate-Enrollment';W=7;Issue='ADCS enroll'}
        'a05b8cc2-17bc-4802-a710-e7c15ab866a2'=@{Name='Certificate-AutoEnrollment';W=7;Issue='ADCS auto-enroll'}
        '9923a32a-3607-11d2-b9be-0000f87a36b2'=@{Name='DS-Install-Replica';W=8;Issue='Replica install'}
    }
    $WriteProps = @{
        '5b47d60f-6090-40b2-9f37-2a4de88f3063'=@{Name='msDS-KeyCredentialLink';W=10;Issue='Shadow Credentials'}
        '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'=@{Name='msDS-AllowedToActOnBehalfOfOtherIdentity';W=10;Issue='RBCD'}
        '800d94d7-b7a1-42a1-b14d-7cae1423d07f'=@{Name='msDS-AllowedToDelegateTo';W=9;Issue='Constrained Delegation'}
        'f3a64788-5306-11d1-a9c5-0000f80367c1'=@{Name='servicePrincipalName';W=8;Issue='Targeted Kerberoast'}
        'bf967a68-0de6-11d0-a285-00aa003049e2'=@{Name='userAccountControl';W=8;Issue='UAC tampering'}
        'bf9679c0-0de6-11d0-a285-00aa003049e2'=@{Name='member';W=8;Issue='Group hijack (AddMember)'}
        'bf9679a8-0de6-11d0-a285-00aa003049e2'=@{Name='scriptPath';W=8;Issue='Logon script hijack'}
        '28630ebf-41d5-11d1-a9c1-0000f80367c1'=@{Name='gPLink';W=7;Issue='GPO link abuse'}
        'f30e3bbe-9ff0-11d1-b603-0000f80367c1'=@{Name='gPCFileSysPath';W=9;Issue='GPO hijack'}
    }
    # Merge schema WriteProps
    foreach ($k in $WriteProps_Schema.Keys) { $WriteProps[$k] = $WriteProps_Schema[$k] }

    # Discovery
    $AclTargets = New-Object System.Collections.Generic.List[object]
    function Add-AclTarget { param($Obj,[string]$Tier,[string]$Reason)
        if (-not $Obj) { return }
        $AclTargets.Add([pscustomobject]@{DN=$Obj.DistinguishedName;Class=$Obj.objectClass;Name=$Obj.Name;Tier=$Tier;Reason=$Reason;SD=$Obj.nTSecurityDescriptor})
    }
    function Format-AclReason { param($Obj)
        switch ($Obj.objectClass) {
            'user'                            { if ($Obj.Name -eq 'krbtgt') {'krbtgt'} else {"User: $($Obj.Name)"} }
            'group'                           { "Group: $($Obj.Name)" }
            'computer'                        { "Domain Controller: $($Obj.Name)" }
            'organizationalUnit'              { "OU: $($Obj.Name)" }
            'groupPolicyContainer'            { "GPO: $($Obj.Name)" }
            'trustedDomain'                   { "Trust: $($Obj.Name)" }
            'msDS-GroupManagedServiceAccount' { "gMSA: $($Obj.Name)" }
            'pKICertificateTemplate'          { "Cert Template: $($Obj.Name)" }
            'pKIEnrollmentService'            { "ADCS CA: $($Obj.Name)" }
            'dnsZone'                         { "DNS zone: $($Obj.Name)" }
            default                           { "$($Obj.objectClass) : $($Obj.Name)" }
        }
    }

    # Domain NC batch
    $domFilter = '(|(adminCount=1)(samAccountName=krbtgt)(objectClass=groupPolicyContainer)(objectClass=organizationalUnit)(objectClass=trustedDomain)(objectClass=msDS-GroupManagedServiceAccount)(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)))'
    try {
        Get-ADObject -LDAPFilter $domFilter -SearchBase $DomainDN `
                     -Properties Name,DistinguishedName,objectClass,nTSecurityDescriptor -ErrorAction Stop |
        ForEach-Object {
            $tier = if ($_.objectClass -in @('groupPolicyContainer','organizationalUnit')) {'P2'} else {'P1'}
            if ($_.DistinguishedName -eq "OU=Domain Controllers,$DomainDN") { $tier='P1' }
            Add-AclTarget $_ $tier (Format-AclReason $_)
        }
    } catch { Write-Warn "Domain NC scan: $_" }

    # Well-known objects
    $WellKnown = @(
        @{DN=$DomainDN;                               Tier='P1';Reason='Domain Root'},
        @{DN="CN=AdminSDHolder,CN=System,$DomainDN";  Tier='P1';Reason='AdminSDHolder'},
        @{DN="CN=Users,$DomainDN";                    Tier='P1';Reason='Users container'},
        @{DN="CN=Builtin,$DomainDN";                  Tier='P1';Reason='Builtin container'},
        @{DN="CN=System,$DomainDN";                   Tier='P1';Reason='System container'},
        @{DN="CN=Computers,$DomainDN";                Tier='P2';Reason='Computers container'},
        @{DN="CN=Protected Users,CN=Users,$DomainDN"; Tier='P1';Reason='Group: Protected Users'},
        @{DN="CN=Key Admins,CN=Users,$DomainDN";      Tier='P1';Reason='Group: Key Admins'},
        @{DN="CN=Enterprise Key Admins,CN=Users,$ForestDN";Tier='P1';Reason='Group: Enterprise Key Admins'},
        @{DN="CN=DnsAdmins,CN=Users,$DomainDN";       Tier='P1';Reason='Group: DnsAdmins'},
        @{DN="CN=Cert Publishers,CN=Users,$DomainDN"; Tier='P1';Reason='Group: Cert Publishers'},
        @{DN=$ConfigDN;                               Tier='P1';Reason='Configuration NC'},
        @{DN=$SchemaDN;                               Tier='P1';Reason='Schema NC'},
        @{DN="CN=Sites,$ConfigDN";                    Tier='P2';Reason='AD Sites'}
    )
    foreach ($w in $WellKnown) {
        try {
            $obj = Get-ADObject -Identity $w.DN -Properties Name,DistinguishedName,objectClass,nTSecurityDescriptor -ErrorAction Stop
            if ($obj) { Add-AclTarget $obj $w.Tier $w.Reason }
        } catch {}
    }

    # ADCS subtree
    $pkiBase = "CN=Public Key Services,CN=Services,$ConfigDN"
    try {
        Get-ADObject -SearchBase $pkiBase -LDAPFilter '(|(objectClass=pKICertificateTemplate)(objectClass=pKIEnrollmentService)(objectClass=certificationAuthority))' `
                     -Properties Name,DistinguishedName,objectClass,nTSecurityDescriptor -ErrorAction Stop |
        ForEach-Object { Add-AclTarget $_ 'P1' (Format-AclReason $_) }
        foreach ($c in @('NTAuthCertificates','AIA','Certificate Templates','Enrollment Services','Certification Authorities')) {
            try {
                $cobj = Get-ADObject -Identity "CN=$c,$pkiBase" -Properties Name,DistinguishedName,objectClass,nTSecurityDescriptor -ErrorAction Stop
                if ($cobj) { Add-AclTarget $cobj 'P1' "ADCS container: $c" }
            } catch {}
        }
    } catch {}

    # DNS partitions
    foreach ($dnsP in @("DC=DomainDnsZones,$DomainDN","DC=ForestDnsZones,$ForestDN")) {
        try {
            Get-ADObject -SearchBase $dnsP -LDAPFilter '(|(objectClass=dnsZone)(objectClass=domainDNS))' `
                         -Properties Name,DistinguishedName,objectClass,nTSecurityDescriptor -ErrorAction Stop |
            ForEach-Object {
                $tier   = if ($_.DistinguishedName -eq $dnsP) {'P1'} else {'P2'}
                $reason = if ($_.DistinguishedName -eq $dnsP) {"DNS partition: $dnsP"} else {Format-AclReason $_}
                Add-AclTarget $_ $tier $reason
            }
        } catch {}
    }

    Write-Info "Targets discovered: $($AclTargets.Count)"

    # Trustee classifier
    $sidNameCache  = @{}
    $trusteeCache  = @{}
    $sidXlatCache  = @{}   # NTAccount string -> SID, for the Test-AclAce fallback
    function Resolve-SidName { param([System.Security.Principal.SecurityIdentifier]$Sid)
        if ($sidNameCache.ContainsKey($Sid.Value)) { return $sidNameCache[$Sid.Value] }
        try { $n = $Sid.Translate([System.Security.Principal.NTAccount]).Value } catch { $n = $null }
        $sidNameCache[$Sid.Value] = $n; return $n
    }
    function Test-AclTrustee { param([System.Security.Principal.SecurityIdentifier]$Sid)
        $s = $Sid.Value
        if ($trusteeCache.ContainsKey($s)) { return $trusteeCache[$s] }
        $result = & {
            if ($DangerousSids.ContainsKey($s)) { return @{Dangerous=$true;Name=$DangerousSids[$s].Name;W=$DangerousSids[$s].W;Kind='WellKnown'} }
            if ($s.StartsWith("$DomainSid-")) {
                $rid = [int]($s -split '-')[-1]
                if ($DangerousRids.ContainsKey($rid)) { return @{Dangerous=$true;Name=$DangerousRids[$rid].Name;W=$DangerousRids[$rid].W;Kind='DomainRID'} }
                if ($AdminRids -contains $rid)        { return @{Dangerous=$false} }
            }
            if ($AdminSids -contains $s) { return @{Dangerous=$false} }
            $name = Resolve-SidName $Sid
            if (-not $name) {
                if ($foreignSids.ContainsKey($s)) { return @{Dangerous=$true;Name="$s (foreign trust)";W=5;Kind='ForeignTrust'} }
                return @{Dangerous=$true;Name=$Sid.Value;W=6;Kind='OrphanSID'}
            }
            if ($name -match 'NT AUTHORITY\\(SYSTEM|SELF|NETWORK SERVICE|LOCAL SERVICE|ENTERPRISE DOMAIN CONTROLLERS)') { return @{Dangerous=$false} }
            if ($name -match 'BUILTIN\\Administrators$') { return @{Dangerous=$false} }
            try {
                $tObj = Get-ADObject -Identity $s -Properties objectClass,member -ErrorAction Stop
                switch ($tObj.objectClass) {
                    'user'     { return @{Dangerous=$true;Name="$name (user)";W=5;Kind='StandardUser'} }
                    'computer' { return @{Dangerous=$true;Name="$name (computer)";W=5;Kind='ComputerAccount'} }
                    'group'    {
                        $cnt = @($tObj.member).Count
                        if ($cnt -ge 50) { return @{Dangerous=$true;Name="$name (group, $cnt members)";W=6;Kind='BroadGroup'} }
                        else             { return @{Dangerous=$true;Name="$name (group, $cnt members)";W=3;Kind='CustomGroup'} }
                    }
                }
            } catch {}
            return @{Dangerous=$true;Name=$name;W=4;Kind='Unknown'}
        }
        $trusteeCache[$s] = $result; return $result
    }

    function Test-AclAce {
        param($Ace,[string]$TargetReason,[string]$TargetTier,[string]$TargetDN,[string]$TargetClass,[string]$TargetName)
        if ($Ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return }
        # IdentityReference puo' essere NTAccount (default da Get-ADObject) oppure
        # SecurityIdentifier. Il vecchio "-as" cast falliva silenziosamente su NTAccount
        # e scartava OGNI ACE con trustee risolvibile (Everyone, Authenticated Users, ...).
        # The main scan loop already requests SID-keyed rules, so this normally
        # takes the cheap branch. The Translate fallback stays for callers that
        # still pass NTAccount ACEs - memoised, because each miss is an LSA
        # round-trip and the same handful of trustees repeat across every ACE.
        $ir = $Ace.IdentityReference
        if ($ir -is [System.Security.Principal.SecurityIdentifier]) {
            $sid = $ir
        } else {
            $irKey = [string]$ir
            if ($sidXlatCache.ContainsKey($irKey)) {
                $sid = $sidXlatCache[$irKey]
            } else {
                try   { $sid = $ir.Translate([System.Security.Principal.SecurityIdentifier]) }
                catch { $sid = $null }
                $sidXlatCache[$irKey] = $sid
            }
        }
        if (-not $sid) { return }
        $tr = Test-AclTrustee -Sid $sid
        if (-not $tr.Dangerous) { return }
        $rights = [string]$Ace.ActiveDirectoryRights
        $guid   = if ($Ace.ObjectType -ne [Guid]::Empty) {$Ace.ObjectType.ToString().ToLower()} else {$null}
        $permW = 0; $issue = $null; $detail = $null
        if     ($rights -match 'GenericAll')  { $permW=10;$issue='Full Control';$detail='GenericAll' }
        elseif ($rights -match 'WriteDacl')   { $permW=10;$issue='Takeover (WriteDacl)';$detail='WriteDacl' }
        elseif ($rights -match 'WriteOwner') { $permW=10;$issue='Takeover (WriteOwner)';$detail='WriteOwner' }
        if ($rights -match 'ExtendedRight') {
            if ($guid -and $ExtRights.ContainsKey($guid)) {
                $er = $ExtRights[$guid]
                if ($er.W -gt $permW) { $permW=$er.W;$issue=$er.Issue;$detail="ExtendedRight: $($er.Name)" }
            } elseif (-not $guid -and 9 -gt $permW) { $permW=9;$issue='AllExtendedRights';$detail='AllExtendedRights' }
        }
        if ($rights -match 'WriteProperty|Self') {
            if ($guid -and $WriteProps.ContainsKey($guid)) {
                $wp = $WriteProps[$guid]
                if ($wp.W -gt $permW) { $permW=$wp.W;$issue=$wp.Issue;$detail="Write $($wp.Name)" }
            } elseif (-not $guid -and $rights -match 'WriteProperty' -and 8 -gt $permW) { $permW=8;$issue='WriteProperty (all attrs)';$detail='Write all properties' }
        }
        if ($rights -match 'GenericWrite' -and 8 -gt $permW) { $permW=8;$issue='GenericWrite';$detail='GenericWrite' }
        if ($rights -match 'ReadProperty' -and $guid -and $ReadProps.ContainsKey($guid)) {
            $rp = $ReadProps[$guid]
            if ($rp.W -gt $permW) { $permW=$rp.W;$issue=$rp.Issue;$detail="Read $($rp.Name)" }
        }
        if ($rights -match 'CreateChild' -and $TargetDN -match '^OU=Domain Controllers,' -and 10 -gt $permW) {
            $permW=10;$issue='Rogue DC (CreateChild on DC OU)';$detail='CreateChild on DC OU'
        }
        if ($permW -eq 0) { return }
        # Orphan SID: cap permission weight at 5
        if ($tr.Kind -eq 'OrphanSID') { $permW = [Math]::Min($permW, 5); $issue = "Orphan SID + $issue" }
        $objW  = switch ($TargetTier) {'P1'{10}'P2'{6}default{3}}
        $score = $tr.W + $permW + $objW
        $risk  = if ($score -ge 25){'CRITICAL'}elseif($score -ge 20){'HIGH'}elseif($score -ge 15){'MEDIUM'}else{'LOW'}
        [pscustomobject]@{
            Score=$score;Risk=$risk;IssueType=$issue;Trustee=$tr.Name;Target=$TargetReason
            TargetDN=$TargetDN;TargetName=$TargetName;TargetClass=$TargetClass
            Rights=$detail;Inherited=[bool]$Ace.IsInherited
            _trSid=$sid.Value;_guid=$guid;_detail=$detail
        }
    }

    # Main ACE loop
    Write-Info "Analyzing ACEs..."
    $rawFindings = New-Object System.Collections.Generic.List[object]
    $i=0; $totT=$AclTargets.Count; $nOwn=0; $nAce=0
    foreach ($t in $AclTargets) {
        $i++
        if ($i % 200 -eq 0) { Write-Info "ACL scan: $i/$totT targets, $($nOwn+$nAce) raw findings" }
        if (-not $t.SD) { continue }
        # Owner check
        try {
            $oSid = $t.SD.GetOwner([System.Security.Principal.SecurityIdentifier])
            if ($oSid) {
                $tr = Test-AclTrustee -Sid $oSid
                if ($tr.Dangerous) {
                    $objW  = switch ($t.Tier) {'P1'{10}'P2'{6}default{3}}
                    $score = $tr.W + 10 + $objW
                    if ($score -ge $AclScoreThreshold) {
                        $risk = if($score-ge 25){'CRITICAL'}elseif($score-ge 20){'HIGH'}elseif($score-ge 15){'MEDIUM'}else{'LOW'}
                        $rawFindings.Add([pscustomobject]@{
                            Score=$score;Risk=$risk;IssueType='Dangerous Owner';Trustee=$tr.Name
                            Target=$t.Reason;TargetDN=$t.DN;TargetName=$t.Name;TargetClass=$t.Class
                            Rights='Owner (implicit WriteDacl + WriteOwner)';Inherited=$false
                            _trSid=$oSid.Value;_guid=$null;_detail='Owner'
                        })
                        $nOwn++
                    }
                }
            }
        } catch {}
        # Ask for the rules keyed by SID instead of using .Access: .Access hands
        # back NTAccount identities, and turning each one back into a SID costs
        # an LSA round-trip to a DC *per ACE* (tens of thousands of them on a
        # large domain). GetAccessRules with the SID type resolves nothing and
        # stays entirely local.
        foreach ($ace in $t.SD.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $f = Test-AclAce -Ace $ace -TargetReason $t.Reason -TargetTier $t.Tier `
                             -TargetDN $t.DN -TargetClass $t.Class -TargetName $t.Name
            if ($f -and $f.Score -ge $AclScoreThreshold) { $rawFindings.Add($f); $nAce++ }
        }
    }
    Write-Info "Raw findings: $($rawFindings.Count) (Owner: $nOwn, ACE: $nAce)"

    # Group and tidy
    $groups = $rawFindings | Group-Object -Property { "$($_._trSid)|$($_.IssueType)|$($_._guid)|$($_._detail)" }
    $groupsRanked = $groups | ForEach-Object { [pscustomobject]@{Group=$_;MaxScore=($_.Group|Measure-Object Score -Maximum).Maximum} } | Sort-Object MaxScore -Descending

    $gid = 0
    foreach ($gr in $groupsRanked) {
        $gid++
        $g = $gr.Group
        $directGroup    = @($g.Group | Where-Object { -not $_.Inherited })
        $inhGroup       = @($g.Group | Where-Object {       $_.Inherited })
        $groupSize      = $g.Group.Count
        $directCount    = $directGroup.Count
        $inheritedCount = $inhGroup.Count
        $affected       = ($g.Group | Select-Object -ExpandProperty TargetDN -Unique).Count
        $groupMode      = if($directCount-gt 0-and $inheritedCount-gt 0){'Mixed'}elseif($inheritedCount-gt 0){'Inherited'}else{'Direct'}

        foreach ($f in $g.Group | Sort-Object Score -Descending) {
            $inheritedFrom = ''
            if ($f.Inherited) {
                $childDN = $f.TargetDN
                $parents = $directGroup | Where-Object { $childDN -like "*,$($_.TargetDN)" } | Sort-Object { $_.TargetDN.Length } -Descending
                if ($parents) { $inheritedFrom = $parents[0].TargetDN }
            }
            $AclReport.Add([PSCustomObject]@{
                Score=$f.Score; Risk=$f.Risk; GroupId=$gid; GroupSize=$groupSize
                SourcePrincipal=$f.Trustee; Permission=$f.Rights; ObjectClass=$f.TargetClass
                TargetObject=$f.TargetName; TargetDN=$f.TargetDN; AttackPath=$f.IssueType
                Inherited=$f.Inherited; InheritedFrom=$inheritedFrom; InheritanceMode=$groupMode
                AffectedCount=$affected; DirectCount=$directCount; InheritedCount=$inheritedCount
            })
        }
    }

    Export-CsvNoBom ($AclReport | Sort-Object GroupId,@{e='Score';desc=$true}) $AclCsvPath
    $AclTotalGroups = ($AclReport | Select-Object -ExpandProperty GroupId -Unique).Count
    Write-Success "ACL scan: $($AclReport.Count) rows in $AclTotalGroups distinct patterns -> acl.csv"
    Write-Info "  AclScoreThreshold=$AclScoreThreshold | RawFindingsBeforeFilter=$($rawFindings.Count) | AfterFilter=$($AclReport.Count)"
} else {
    Write-Warn "Skipping ACL scan (-SkipACL)"
    if (Test-Path $AclCsvPath) { $AclReport = Import-Csv $AclCsvPath; Write-Info "Loaded existing acl.csv" }
}

# =============================================================================
# 5. GPO  ->  gpo.csv
# =============================================================================
$GpoCsvPath = Join-Path $OutputPath "gpo.csv"
$GpoReport  = @()

if (-not $SkipGPO) {
    Write-Host ""; Write-Info "Collecting GPO information..."
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $AllGPOs = Get-GPO -All -ErrorAction Stop

        # Build GPO link map
        $GpoLinks = @{}
        try {
            Get-ADObject -LDAPFilter '(gpLink=*)' -Properties gpLink,DistinguishedName -SearchBase $DomainDN |
            ForEach-Object {
                $dn = $_.DistinguishedName
                [regex]::Matches($_.gpLink, '\{([0-9A-Fa-f-]+)\}') | ForEach-Object {
                    $guid = $_.Groups[1].Value.ToUpper()
                    if (-not $GpoLinks.ContainsKey($guid)) { $GpoLinks[$guid] = [System.Collections.Generic.List[string]]::new() }
                    $GpoLinks[$guid].Add($dn)
                }
            }
        } catch { Write-Warn "Could not collect GPO links: $_" }

        $GpoReport = foreach ($GPO in $AllGPOs) {
            $GPOPath  = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\{$($GPO.Id)}"
            $GPODN    = "CN={$($GPO.Id)},CN=Policies,CN=System,$DomainDN"
            $guidKey  = $GPO.Id.ToString().ToUpper()
            $linkedTo = if ($GpoLinks.ContainsKey($guidKey)) {$GpoLinks[$guidKey] -join " | "} else {"NOT LINKED"}
            $LinkedCount = if ($GpoLinks.ContainsKey($guidKey)) {$GpoLinks[$guidKey].Count} else {0}
            $wmiFilter = if ($GPO.WmiFilter) {$GPO.WmiFilter.Name} else {""}

            # Orphan risk
            $IsOrphan = $LinkedCount -eq 0
            $SecurityKW = @('hardening','security','restrict','block','firewall','defender','audit','password','lockdown','baseline','protect')
            $nameHasSec = $SecurityKW | Where-Object { $GPO.DisplayName -match $_ }
            $OrphanRisk = if ($IsOrphan -and $nameHasSec) {"HIGH"} elseif ($IsOrphan) {"MEDIUM"} else {"No"}

            # Owner risk
            $OwnerRisk = "OK"
            $ownerSam  = ($GPO.Owner -replace '^.*\\','')
            if ($GPO.Owner -and $GPO.Owner -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM') {
                if (-not ($DomainAdmins -contains $ownerSam) -and -not $PrivGroupMembership.ContainsKey($ownerSam)) {
                    $OwnerRisk = "HIGH"
                }
            }

            # --- 4.1 GPO Content Analysis ---
            $WDigestEnabled   = "No"
            $DefenderDisabled = "No"
            $AutoRunEnabled   = "No"
            $UNCScriptRisk    = "No"
            $GpoContentRisk   = "No"
            try {
                # Registry Preferences XML (Machine + User)
                foreach ($regXmlPath in @("$GPOPath\Machine\Preferences\Registry\Registry.xml",
                                          "$GPOPath\User\Preferences\Registry\Registry.xml")) {
                    if (Test-Path $regXmlPath -ErrorAction SilentlyContinue) {
                        [xml]$regXml = Get-Content $regXmlPath -Raw -ErrorAction Stop
                        $items = $regXml.RegistrySettings.Registry
                        if ($null -eq $items) { $items = $regXml.RegistrySettings.Collection.Registry }
                        foreach ($item in @($items)) {
                            if ($null -eq $item) { continue }
                            $rKey  = $item.Properties.key
                            $rName = $item.Properties.name
                            $rVal  = $item.Properties.value
                            if ($rKey -match 'WDigest' -and $rName -eq 'UseLogonCredential' -and $rVal -eq '1') {
                                $WDigestEnabled = "CRITICAL"
                            }
                            if ($rKey -match 'Windows.Defender' -and
                                $rName -match 'DisableAntiSpyware|DisableRealtimeMonitoring' -and $rVal -eq '1') {
                                $DefenderDisabled = "HIGH"
                            }
                            if ($rKey -match 'Explorer' -and $rName -eq 'NoDriveTypeAutoRun' -and $rVal -eq '0') {
                                $AutoRunEnabled = "HIGH"
                            }
                        }
                    }
                }
                # Scripts.ini (Machine + User) - flag UNC logon script paths
                foreach ($scriptIni in @("$GPOPath\Machine\Scripts\scripts.ini",
                                         "$GPOPath\User\Scripts\scripts.ini")) {
                    if (Test-Path $scriptIni -ErrorAction SilentlyContinue) {
                        $iniContent = Get-Content $scriptIni -Raw -ErrorAction Stop
                        if ($iniContent -match '\\\\[^\s]+\\') { $UNCScriptRisk = "HIGH" }
                    }
                }
                # GptTmpl.inf - WDigest and Defender policy keys
                $gptTmpl = "$GPOPath\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                if (Test-Path $gptTmpl -ErrorAction SilentlyContinue) {
                    $tmplRaw = Get-Content $gptTmpl -Raw -ErrorAction Stop
                    if ($tmplRaw -match 'EnableWDigest\s*=\s*1')        { $WDigestEnabled   = "CRITICAL" }
                    if ($tmplRaw -match 'DisableAntiSpyware\s*=\s*1')   { $DefenderDisabled = "HIGH" }
                }
            } catch {}
            # Overall content risk
            if (@($WDigestEnabled,$DefenderDisabled,$AutoRunEnabled,$UNCScriptRisk) -contains "CRITICAL") { $GpoContentRisk = "CRITICAL" }
            elseif (@($WDigestEnabled,$DefenderDisabled,$AutoRunEnabled,$UNCScriptRisk) -contains "HIGH") { $GpoContentRisk = "HIGH" }

            [PSCustomObject]@{
                DisplayName       = $GPO.DisplayName
                Created           = if ($GPO.CreationTime)    {$GPO.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")} else {""}
                LastModified      = if ($GPO.ModificationTime){$GPO.ModificationTime.ToString("yyyy-MM-dd HH:mm:ss")} else {""}
                GpoStatus         = $GPO.GpoStatus.ToString()
                Owner             = $GPO.Owner
                WmiFilter         = $wmiFilter
                LinkedTo          = $linkedTo
                Path              = $GPOPath
                DistinguishedName = $GPODN
                LinkedCount       = $LinkedCount
                OrphanRisk        = $OrphanRisk
                OwnerRisk         = $OwnerRisk
                WDigestEnabled    = $WDigestEnabled
                DefenderDisabled  = $DefenderDisabled
                AutoRunEnabled    = $AutoRunEnabled
                UNCScriptRisk     = $UNCScriptRisk
                GpoContentRisk    = $GpoContentRisk
            }
        }

        Export-CsvNoBom ($GpoReport | Sort-Object DisplayName) $GpoCsvPath
        Write-Success "Exported GPO: $(@($GpoReport).Count) records -> gpo.csv"
    } catch {
        Write-Warn "GroupPolicy module not available: $_"
    }
} else {
    Write-Warn "Skipping GPO collection (-SkipGPO)"
    if (Test-Path $GpoCsvPath) { $GpoReport = Import-Csv $GpoCsvPath; Write-Info "Loaded existing gpo.csv" }
}

# =============================================================================
# 6. AUDIT POLICY  ->  auditpolicy.csv
# =============================================================================
Write-Host ""; Write-Info "Collecting audit policy..."
$AuditCsvPath = Join-Path $OutputPath "auditpolicy.csv"
try {
    # NB: auditpol needs an ELEVATED local-admin token. Being Domain Admin is NOT
    # enough: if the script is not run "as Administrator" auditpol fails (0x522)
    # and returns nothing -> previously the file was silently skipped.
    if (-not $script:IsElevated) {
        Write-Warn "Not elevated - skipping auditpol (see the pre-flight warning above)."
        $auditRaw = $null; $auditExit = 1314   # ERROR_PRIVILEGE_NOT_HELD
    } else {
        $auditRaw  = auditpol /get /category:* /r 2>$null
        $auditExit = $LASTEXITCODE
    }
    if (-not $auditRaw -or $auditExit -ne 0) {
        Write-Warn "auditpol failed (exit $auditExit). Run the script from an ELEVATED PowerShell (Run as Administrator). auditpolicy.csv NOT generated."
    } else {
        # Critical subcategories keyed by locale-independent GUID (first 8 hex of
        # the subcategory GUID). English-name matching kept as a fallback so the
        # risk classification also works when the OS UI language is not English.
        $critGuids = @{
            '0cce9210'=$true; '0cce9211'=$true; '0cce9215'=$true; '0cce9216'=$true
            '0cce9217'=$true; '0cce9228'=$true; '0cce922b'=$true; '0cce922f'=$true
            '0cce923b'=$true; '0cce923c'=$true; '0cce923f'=$true; '0cce9240'=$true
            '0cce9242'=$true
        }
        $critSubs = @('Logon','Logoff','Account Lockout','Kerberos Authentication Service',
                      'Kerberos Service Ticket Operations','Credential Validation',
                      'Directory Service Access','Directory Service Changes',
                      'Sensitive Privilege Use','Audit Policy Change',
                      'Security System Extension','Security State Change','Process Creation')
        # Parse positionally so localized column headers do not break access.
        # /r columns: MachineName,PolicyTarget,Subcategory,SubcategoryGUID,Inclusion,Exclusion
        $rows = $auditRaw |
                ConvertFrom-Csv -Header 'MachineName','PolicyTarget','Subcategory','SubGuid','Setting','Exclusion' |
                Where-Object { $_.SubGuid -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}' }   # keep real subcategory rows only
        $report = foreach ($r in $rows) {
            $sub = $r.Subcategory; if (-not $sub -or $sub -eq 'N/A') { continue }
            $g8  = (($r.SubGuid -replace '[{}]','').ToLower() + '        ').Substring(0,8)
            $set = $r.Setting
            $isCrit  = $critGuids.ContainsKey($g8) -or ($critSubs -contains $sub)
            # Locale-tolerant setting classification (EN + IT + empty).
            $noAudit  = [string]::IsNullOrWhiteSpace($set) -or ($set -match '^(No Auditing|Nessun controllo)')
            $onlySucc = $set -match '^(Success|Riuscito)$'
            $risk = if ($isCrit -and $noAudit) {'CRITICAL'} elseif ($isCrit -and $onlySucc) {'Partial'} else {'OK'}
            [PSCustomObject]@{Subcategory=$sub;Setting=$set;IsCritical=if($isCrit){"Yes"}else{"No"};Risk=$risk}
        }
        if ($report) {
            Export-CsvNoBom $report $AuditCsvPath
            Write-Success "Audit policy exported ($(@($report).Count) subcategories) -> auditpolicy.csv"
        } else {
            Write-Warn "auditpol returned no parseable rows - auditpolicy.csv NOT generated."
        }
    }
} catch { Write-Warn "Audit policy collection failed: $_" }

# =============================================================================
# 7.x IR SIGNALS
# =============================================================================
Write-Host ""; Write-Info "Running IR signal checks..."

# 7.6 RODC Password Replication Policy
$RODCs = Get-ADDomainController -Filter { IsReadOnly -eq $true } -ErrorAction SilentlyContinue
foreach ($rodc in $RODCs) {
    try {
        $rodcObj = Get-ADComputer -Identity $rodc.ComputerObjectDN -Properties 'msDS-RevealOnDemandGroup' -ErrorAction Stop
        foreach ($allowedDN in $rodcObj.'msDS-RevealOnDemandGroup') {
            $groupSam = ($allowedDN -split ',')[0] -replace '^CN=',''
            if ($PrivGroupNames -contains $groupSam) {
                Write-Warn "RODC $($rodc.HostName): PRIVILEGED GROUP '$groupSam' in PRP allowed list - CRITICAL"
            }
        }
    } catch {}
}

# 7.7 AdminSDHolder backdoor (already computed above)
if ($AdminSDHolderBackdoor) {
    Write-Warn "AdminSDHolder backdoor ACEs: $($AdminSDHolderBackdoor.Count)"
    $AdminSDHolderBackdoor | ForEach-Object { Write-Warn "  -> $_" }
} else { Write-Success "AdminSDHolder: clean" }

# 7.8 DCShadow rights correlation
if ($AclReport.Count -gt 0) {
    $dsInstall = $AclReport | Where-Object { $_.AttackPath -match 'Replica install' }
    foreach ($r in $dsInstall) {
        $princ = ($r.SourcePrincipal -replace '\s*\(.*\)$','')
        $hasCC = $AclReport | Where-Object {
            $_.TargetDN -like "*$ConfigDN" -and $_.Permission -match 'CreateChild' -and $_.SourcePrincipal -like "*$princ*"
        }
        if ($hasCC) { Write-Warn "DCShadow rights combo detected for: $($r.SourcePrincipal)" }
    }
}

# =============================================================================
# SUMMARY STATS
# =============================================================================
Write-Host ""
Write-Host "  +-----------------------------------------+" -ForegroundColor DarkGreen
Write-Host "  |           AUDIT COMPLETED               |" -ForegroundColor DarkGreen
Write-Host "  +-----------------------------------------+" -ForegroundColor DarkGreen
Write-Host ""
Write-Host "  Output: $OutputPath" -ForegroundColor White
Write-Host ""

$stat_DomAdmins    = @($UsersReport | Where-Object { $_.IsDomainAdmin           -eq "Yes" }).Count
$stat_Kerb         = @($UsersReport | Where-Object { $_.Kerberoastable           -eq "Yes" }).Count
$stat_ASREP        = @($UsersReport | Where-Object { $_.ASREPRoastable           -eq "Yes" }).Count
$stat_PwdNoExp     = @($UsersReport | Where-Object { $_.PasswordNeverExpire      -eq "Yes" -and $_.AccountDisabled -eq "No" }).Count
$stat_OldPwd       = @($UsersReport | Where-Object { $_.OldPassword              -eq "Yes" }).Count
$stat_AdminCount   = @($UsersReport | Where-Object { $_.AdminCount               -eq "Yes" -and $_.SamAccountName -ne "krbtgt" }).Count
$stat_PwdNR        = @($UsersReport | Where-Object { $_.PasswordNotRequired      -eq "Yes" -and $_.SamAccountName -notmatch '\$$' }).Count
$stat_DCSync       = @($UsersReport | Where-Object { $_.HasDCSync                -eq "Yes" }).Count
$stat_Delegation   = @($UsersReport | Where-Object { $_.UserDelegation           -ne "No"  }).Count
$stat_Disabled     = @($UsersReport | Where-Object { $_.AccountDisabled          -eq "Yes" }).Count
$stat_SIDHistory   = @($UsersReport | Where-Object { $_.SIDHistoryCritical       -ne "No"  }).Count
$stat_RevEnc       = @($UsersReport | Where-Object { $_.ReversibleEncryption     -eq "CRITICAL" }).Count
$stat_AdminOrphans = @($UsersReport | Where-Object { $_.AdminCountOrphan         -eq "Yes" }).Count
$stat_WeakKerb     = @($UsersReport | Where-Object { $_.WeakKerberos             -eq "CRITICAL" }).Count

$stat_StaleComp    = @($ComputersReport | Where-Object { $_.StaleComputer        -in @("Yes","Never") -and $_.Enabled -eq $true }).Count
$stat_NoLAPS       = @($ComputersReport | Where-Object { $_.LAPSStatus           -eq "Not Deployed" -and $_.Enabled -eq $true -and $_.IsDC -ne "True" }).Count
$stat_EOL          = @($ComputersReport | Where-Object { $_.OSIsEOL              -eq "Yes" }).Count
$stat_NonDCUnconstr= @($ComputersReport | Where-Object { $_.NonDCUnconstrained   -eq "CRITICAL" }).Count
$stat_RBCD         = @($ComputersReport | Where-Object { $_.RBCD_AllowedActOnBehalf -ne "No" }).Count

$stat_ACL_Critical = ($AclReport | Where-Object { $_.Risk -eq 'CRITICAL' }).Count
$stat_ACL_High     = ($AclReport | Where-Object { $_.Risk -eq 'HIGH'     }).Count
$stat_ACL_Medium   = ($AclReport | Where-Object { $_.Risk -eq 'MEDIUM'   }).Count
$stat_ACL_Low      = ($AclReport | Where-Object { $_.Risk -eq 'LOW'      }).Count
$AclTotalGroups    = if ($AclReport.Count -gt 0) { ($AclReport | Select-Object -ExpandProperty GroupId -Unique).Count } else { 0 }

$stat_GPO          = @($GpoReport).Count

Write-Host "  Quick Security Stats:" -ForegroundColor Cyan
Write-Host "    Domain Admins:             $stat_DomAdmins"    -ForegroundColor $(if($stat_DomAdmins   -gt 5){"Red"}else{"Green"})
Write-Host "    Kerberoastable:            $stat_Kerb"          -ForegroundColor $(if($stat_Kerb        -gt 0){"Red"}else{"Green"})
Write-Host "    AS-REP Roastable:          $stat_ASREP"         -ForegroundColor $(if($stat_ASREP       -gt 0){"Red"}else{"Green"})
Write-Host "    Weak Kerberos + Kerbst:    $stat_WeakKerb"      -ForegroundColor $(if($stat_WeakKerb    -gt 0){"Red"}else{"Green"})
Write-Host "    SID History (any):         $stat_SIDHistory"    -ForegroundColor $(if($stat_SIDHistory  -gt 0){"Red"}else{"Green"})
Write-Host "    Reversible Encryption:     $stat_RevEnc"        -ForegroundColor $(if($stat_RevEnc      -gt 0){"Red"}else{"Green"})
Write-Host "    PASSWD_NOTREQD (0x20):     $stat_PwdNR"         -ForegroundColor $(if($stat_PwdNR       -gt 0){"Red"}else{"Green"})
Write-Host "    Password Never Expires:    $stat_PwdNoExp"      -ForegroundColor $(if($stat_PwdNoExp    -gt 5){"Yellow"}else{"Green"})
Write-Host "    Old Password (>365 days):  $stat_OldPwd"        -ForegroundColor $(if($stat_OldPwd      -gt 0){"Yellow"}else{"Green"})
Write-Host "    AdminCount=1 Orphans:      $stat_AdminOrphans"  -ForegroundColor $(if($stat_AdminOrphans-gt 0){"Yellow"}else{"Green"})
Write-Host "    DCSync Rights:             $stat_DCSync"        -ForegroundColor $(if($stat_DCSync       -gt 0){"Red"}else{"Green"})
Write-Host "    User Delegation:           $stat_Delegation"    -ForegroundColor $(if($stat_Delegation   -gt 0){"Yellow"}else{"Green"})
Write-Host "    Disabled Accounts:         $stat_Disabled"      -ForegroundColor Gray
Write-Host "    Stale Computers (>90d):    $stat_StaleComp"     -ForegroundColor $(if($stat_StaleComp   -gt 0){"Yellow"}else{"Green"})
Write-Host "    Computers Without LAPS:    $stat_NoLAPS"        -ForegroundColor $(if($stat_NoLAPS      -gt 0){"Yellow"}else{"Green"})
Write-Host "    EOL Operating Systems:     $stat_EOL"           -ForegroundColor $(if($stat_EOL         -gt 0){"Red"}else{"Green"})
Write-Host "    Non-DC Unconstrained Del:  $stat_NonDCUnconstr" -ForegroundColor $(if($stat_NonDCUnconstr-gt 0){"Red"}else{"Green"})
Write-Host "    RBCD configured (PC):      $stat_RBCD"          -ForegroundColor $(if($stat_RBCD        -gt 0){"Yellow"}else{"Green"})
Write-Host "    Machine Account Quota:     $MAQ"                -ForegroundColor $(if($MAQ -gt 0){"Red"}else{"Green"})
Write-Host "    Pre-W2K Access Group:      $PreW2kStatus"       -ForegroundColor $(if($PreW2kStatus -eq 'CRITICAL'){"Red"}elseif($PreW2kStatus -ne 'Empty (OK)'){"Yellow"}else{"Green"})
Write-Host "    AdminSDHolder Backdoor:    $($AdminSDHolderBackdoor.Count)" -ForegroundColor $(if($AdminSDHolderBackdoor){"Red"}else{"Green"})
Write-Host "    ACL - CRITICAL:            $stat_ACL_Critical"  -ForegroundColor $(if($stat_ACL_Critical -gt 0){"Red"}else{"Green"})
Write-Host "    ACL - HIGH:                $stat_ACL_High"      -ForegroundColor $(if($stat_ACL_High     -gt 0){"Red"}else{"Green"})
Write-Host "    ACL - MEDIUM:              $stat_ACL_Medium"    -ForegroundColor $(if($stat_ACL_Medium   -gt 0){"Yellow"}else{"Green"})
Write-Host "    ACL - LOW:                 $stat_ACL_Low"       -ForegroundColor Gray
Write-Host "    ACL Distinct Patterns:     $AclTotalGroups"     -ForegroundColor Gray
Write-Host "    Total GPO:                 $stat_GPO"           -ForegroundColor Gray
Write-Host ""

# =============================================================================
# AUTO-INJECT INTO DASHBOARD HTML
# =============================================================================
Write-Info "Finding HTML dashboard template..."
$TemplatePath = $null
$candidates = @(
    (Join-Path $PSScriptRoot "AD-Security-Dashboard.html"),
    (Join-Path $PSScriptRoot "..\AD-Security-Dashboard.html"),
    (Join-Path (Get-Location) "AD-Security-Dashboard.html")
)
foreach ($c in $candidates) { if (Test-Path $c) { $TemplatePath = (Resolve-Path $c).Path; break } }

if (-not $TemplatePath) {
    Write-Warn "Dashboard template not found. Upload CSVs manually."
} else {
    Write-Info "Template: $TemplatePath"
    try {
        $html       = [System.IO.File]::ReadAllText($TemplatePath, [System.Text.Encoding]::UTF8)
        $startMarker = '// %%AUTO_DATA_START%%'
        $endMarker   = '// %%AUTO_DATA_END%%'
        $startIdx    = $html.IndexOf($startMarker)
        $endIdx      = $html.IndexOf($endMarker)

        if ($startIdx -lt 0 -or $endIdx -le $startIdx) {
            Write-Warn "Auto-inject markers not found."
        } else {
            $csvMap = [ordered]@{
                users       = $UsersCsvPath
                computers   = $ComputersCsvPath
                domain      = $DomainCsvPath
                acl         = $AclCsvPath
                gpo         = $GpoCsvPath
                policy      = $PolicyCsvPath
            }
            if (Test-Path $AuditCsvPath) { $csvMap['auditpolicy'] = $AuditCsvPath }

            $propLines = [System.Collections.Generic.List[string]]::new()
            foreach ($key in $csvMap.Keys) {
                $path = $csvMap[$key]
                if (Test-Path $path) {
                    $content = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
                    $jsonStr = $content | ConvertTo-Json
                    $propLines.Add("  ${key}: $jsonStr")
                } else {
                    $propLines.Add("  ${key}: null")
                }
            }
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $propLines.Add("  injectedAt: ""Audit executed at $timestamp""")

            $block = @"
// %%AUTO_DATA_START%%
const _AUTO_DATA = {
$($propLines -join ",`n")
};
// %%AUTO_DATA_END%%
"@
            $before  = $html.Substring(0, $startIdx)
            $after   = $html.Substring($endIdx + $endMarker.Length)
            $newHtml = $before + $block + $after
            $newHtml = $newHtml -replace 'var DASH_AUTO_LAUNCH = false', 'var DASH_AUTO_LAUNCH = true'

            $OutputDashboard = Join-Path $OutputPath "AD-Security-Dashboard.html"
            [System.IO.File]::WriteAllText($OutputDashboard, $newHtml, (New-Object System.Text.UTF8Encoding $false))

            Write-Host ""
            Write-Host "  +-----------------------------------------+" -ForegroundColor Green
            Write-Host "  |         DASHBOARD READY                 |" -ForegroundColor Green
            Write-Host "  +-----------------------------------------+" -ForegroundColor Green
            Write-Host "  Open: $OutputDashboard" -ForegroundColor Cyan
            Write-Host ""
        }
    } catch { Write-Warn "Dashboard generation failed: $_" }
}

# =============================================================================
# ZIP OUTPUT
# =============================================================================
Write-Host ""; Write-Info "Compressing output..."
$ZipPath = "$OutputPath.zip"
try {
    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
    Compress-Archive -Path "$OutputPath\*" -DestinationPath $ZipPath -CompressionLevel Optimal
    Remove-Item -Path $OutputPath -Recurse -Force -Confirm:$false
    Write-Host ""
    Write-Host "  +-----------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |           OUTPUT READY                  |" -ForegroundColor DarkCyan
    Write-Host "  +-----------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  ZIP: $ZipPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Success "Extract the ZIP and open AD-Security-Dashboard.html to start the analysis."
} catch {
    Write-Warn "Could not create ZIP: $_"
    Write-Warn "Output preserved at: $OutputPath"
}
