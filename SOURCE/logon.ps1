<#
.SYNOPSIS
    Consolidated EAMC logon script
.NOTES
    Name: logon.ps1
    Author: Nick Gibson
    Version: 3.4.0
    DateCreated: 19 Oct 2022
    Specifies a SQLConnection
.PARAMETER Location
    Allows alternate drive mapping
.PARAMETER UseSQL
    Allows specification at invocation if SQL logging is enabled
.INPUTS
    None. You cannot pipe objects to this script
.OUTPUTS
    None.
.CHANGELOG
    19 Oct 2022: Initial creation based on various scripts called by eamclogonLCI.bat - v1.0
    19 Oct 2022: Bugfix: Account for multiple sticks of RAM
    20 Oct 2022: Added SQL functionality - v2.0
    25 Oct 2022: Added CallAlert function
    25 Oct 2022: Added HideWindow function
    25 Oct 2022: Modified PrinterLogging and ApplicationLogging to use used-defined table types to prevent dozens of INSERT queries per logon event
    26 Oct 2022: Removed all hardcoded paths and location references, moved to defined variables
    26 Oct 2022: Added switch paramters to all functions to allow turning on and off file and/or SQL logging script-wide
    26 Oct 2022: Added comments and documentation
    26 Oct 2022: Converted all database operations to parameterized stored procedures to increase security
    27 Oct 2022: Added command line switch for SQL operations
    27 Oct 2022: Added option to disable terminal server logging
    27 Oct 2022: Added location parameter for alternate drive mappings
    27 Oct 2022: Modified MapDrive and UnMapDrive to use NET USE, as PowerShell cmdlets map invisible drives
    07 Nov 2022: Added debug switch along with debugging log code.  Added UPN collection to Logging function
    08 Nov 2022: Created variables for drive mapping data structure.  Added MapAllDrives function to handle bulk drive mapping based on location parameter
    09 Nov 2022: Added CheckForAlert function to handle periodic alerts.  Commented ProfileRedirection, as those functions have been moved to the calling batch
    10 Nov 2022: Moved all variable values to prefs.json - v3.0
    15 Nov 2022: Removed as many uses of Get-CimInstance as possible.  It is slow, especially during login events.  Switched to registry reads where possible, or direct calls to the kernel otherwise.
    16 Nov 2022: Added version number in debug logging; rearranged location of SQLConnection.Open to just prior to use to prevent timeout
    16 Nov 2022: Added FastLog
    13 Dec 2022: Added additional logging to HardwareInventory.  Switched hard drive data from PowerShell cmdlet to C# class
    04 Dec 2023: Added OSInstallDate capture to HardwareInventory
    07 Feb 2023: Added LastBoot Timestamp to HardwareInventory
    08 May 2023: Added code to wait for domain network
    24 Jul 2023: Added DOC copy code
    25 Jul 2023: Added RunPeriodic function and Write-Log function.  Changed all calls to $Global:DebugWriter to Write-Log.
    02 Nov 2023: Added support for invocation of scheduled task list
    12 Dec 2023: Added function for updating wwwHomePage attribute per DHA standards 
    12 Dec 2023: Added support for self-deleting tasks
    18 Dec 2023: Added support for Image-Based TipoftheDay popups
    20 Dec 2023: Added support for DB-Based TipoftheDay popups
    27 Dec 2023: Added support for Xaml within prefs.json
    28 Dec 2023: Added support for printer removal
    02 Apr 2024: Added support for Safety popup using DB-Based TipoftheDay function
    14 Mar 2025: Changed timestamp in Write-Log
    14 Mar 2025: Revamped Write-Log into Logging class. Replaced all references to Logging.Append
#>
using namespace System.Collections.Generic
using namespace System.Text
param (
    [string]$Location,
    [switch]$UseSQL,
    [switch]$debug
)
$Error.Clear()

#######################################################################################
#                             DEBUG LOGGING CLASS                                     #
#######################################################################################

class Logging {
	#Fields
	hidden [StringBuilder] $logs

	#Properties
	[string]               $LogFile

	#ctr
	Logging() {
		$this.logs = New-Object StringBuilder(5000)
	}
	Logging([string] $logFile) {
		$this.logs = New-Object StringBuilder(5000)
		$this.LogFile = $logFile
	}

    #Methods
	[void] Append([string] $LogString) {
        $this.Append($LogString, $true)
    }
    [void] Append([string[]] $LogStrings) {
        $this.Append($LogStrings, $true)
    }
    [void] Append([string] $LogString, [boolean] $IncludeDate) {
        [string]$timestamp = Get-Date -Format "MM/dd/yyyy HH:mm:ss.fffff"
        $LogString = $LogString.TrimEnd().Replace(([char]13), " ").Replace(([char]10), " ")
        if ($LogString -eq "") {
            if ($IncludeDate) {
                [void]$this.logs.AppendLine($timestamp)
            }
            return
        }
        if ($IncludeDate) {
            $this.logs.AppendLine("$timestamp : $LogString")
            return
        }
        $this.logs.AppendLine("$LogString")
    }
    [void] Append([string[]] $LogStrings, [boolean] $IncludeDate) {
        foreach($line in $LogStrings) {
            $this.Append($line, $IncludeDate)
        }
    }

    [string] GetLogs() {
        return $this.logs.ToString()
    }

    [boolean] WriteLogFile() {
        if ($LogFile -eq "") {
            return $false;
        }
        if (-not [File]::Exists($LogFile))
            return $false
        try {
            Set-Content -Path $destination -Value $($this.logs.ToString()) -Force
            return $true
        } catch {
            return $false
        }
    }
}


#######################################################################################
#                            INITIALIZE DEBUG LOGS                                    #
#######################################################################################


Set-Location C:
$Global:Logger = [Logging]::new()
$Global:DoDebug = [boolean]$debug
$Global:OneDriveEnabled = $false
$Global:Logger.Append($env:USERNAME, $false)
$Global:Logger.Append($env:COMPUTERNAME, $false)
$Global:Logger.Append('Script Start - v3.4.0')

$Global:LogonTimestamp = Get-Date
$Global:Exception = ""

#######################################################################################
#                    VARIABLE CUSTOMIZATION BEGINS HERE                               #
#######################################################################################

if ($psISE) {
    $script = $psise.CurrentFile.DisplayName
} else {
    $script = Split-Path -Leaf $MyInvocation.MyCommand.Definition
}
$Global:Logger.Append("ScriptCheck: $script")
if ($script -eq 'logon_test.ps1') {
    $preferenceFileLocation              = "\\NETWORK\PATH\TO\PREFS\prefs_test.json"
} else {
    $preferenceFileLocation              = "\\NETWORK\PATH\TO\PREFS\Userdata\scripts\logon\prefs.json"
}
$connectionCheckServer               = 'HARDCODED SQL SERVER NAME'

#######################################################################################
#                      VARIABLE CUSTOMIZATION ENDS HERE                               #
#######################################################################################

$Global:Logger.Append('Environment: Creating custom namespace')

Add-Type -TypeDefinition @"
    using System;
    using System.Runtime;
    using System.Runtime.InteropServices;
    namespace Gibson{
        public class HardwareStats{
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
            public class MEMORYSTATUSEX
            {
                public uint dwLength;
                public uint dwMemoryLoad;
                public ulong ullTotalPhys;
                public ulong ullAvailPhys;
                public ulong ullTotalPageFile;
                public ulong ullAvailPageFile;
                public ulong ullTotalVirtual;
                public ulong ullAvailVirtual;
                public ulong ullAvailExtendedVirtual;
                public MEMORYSTATUSEX()
                {
                this.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
                }
            }

            [return: MarshalAs(UnmanagedType.Bool)]
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool GlobalMemoryStatusEx(
                [In, Out] MEMORYSTATUSEX lpBuffer
            );

            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern bool GetLogicalProcessorInformation(
                IntPtr Buffer,
                ref uint ReturnLength
            );

            [StructLayout(LayoutKind.Sequential)]
            public struct CACHE_DESCRIPTOR {
                public byte Level;
                public byte Associativity;
                public ushort LineSize;
                public uint Size;
                public PROCESSOR_CACHE_TYPE Type;
            }

            public enum PROCESSOR_CACHE_TYPE {
                Unified = 0,
                Instruction = 1,
                Data = 2,
                Trace = 3,
            }
         
            [StructLayout(LayoutKind.Sequential)]
            public struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
                public UIntPtr ProcessorMask;
                public LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
                public ProcessorRelationUnion RelationUnion;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct ProcessorRelationUnion {
                [FieldOffset(0)] public CACHE_DESCRIPTOR Cache;
                [FieldOffset(0)] public uint NumaNodeNumber;
                [FieldOffset(0)] public byte ProcessorCoreFlags;
                [FieldOffset(0)] private UInt64 Reserved1;
                [FieldOffset(8)] private UInt64 Reserved2;
            }

            public enum LOGICAL_PROCESSOR_RELATIONSHIP : uint {
                RelationProcessorCore    = 0,
                RelationNumaNode         = 1,
                RelationCache            = 2,
                RelationProcessorPackage = 3,
                RelationGroup            = 4,
                RelationAll              = 0xffff
            }
         
            private const int ERROR_INSUFFICIENT_BUFFER = 122;
         
            public static SYSTEM_LOGICAL_PROCESSOR_INFORMATION[] GetLogicalProcessorInformation() {
                uint ReturnLength = 0;
                GetLogicalProcessorInformation(IntPtr.Zero, ref ReturnLength);
                if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER) {
                    IntPtr Ptr = Marshal.AllocHGlobal((int)ReturnLength);
                    try {
                        if (GetLogicalProcessorInformation(Ptr, ref ReturnLength)) {
                            int size = Marshal.SizeOf(typeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
                            int len = (int)ReturnLength / size;
                            SYSTEM_LOGICAL_PROCESSOR_INFORMATION[] Buffer = new SYSTEM_LOGICAL_PROCESSOR_INFORMATION[len];
                            IntPtr Item = Ptr;
                            for (int i = 0; i < len; i++) {
                                Buffer[i] = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION)Marshal.PtrToStructure(Item, typeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
                                Item = (IntPtr)(Item.ToInt64() + (long)size);
                            }
                            return Buffer;
                        }
                    } finally {
                        Marshal.FreeHGlobal(Ptr);
                    }
                }
                return null;
            }
         
            public static uint GetNumberOfSetBits(ulong value) {
                uint num = 0;
                while (value > 0) {
                    if ((value & 1) == 1)
                        num++;
                    value >>= 1;
                }
                return num;
            }

            public static ulong GetTotalMem() {
                var memoryStatus = new MEMORYSTATUSEX();
                if (GlobalMemoryStatusEx(memoryStatus)) {
                    return memoryStatus.ullTotalPhys;
                } else {
                    return 0;
                }
            }

            [DllImport("kernel32")]
            extern static UInt64 GetTickCount64();

            public static TimeSpan GetUpTime() {
                return TimeSpan.FromMilliseconds(GetTickCount64());
            }
        }
    }
"@

$Global:Logger.Append('Environment: Implementing functions')
Function GenerateSQLConnection {
<#
.SYNOPSIS
    A pretty wrapper for the System.Data.SqlClient.SQLConnection constructor
.PARAMETER ServerName
    Required. Specifies the name of the SQL Server.  It should not be formatted as a UNC path, but may be an FQDN
.PARAMETER DBName
    Required. Specifies the name of a database on the provided server.
.PARAMETER Username
    Optional. Only used if Kerberos integrated security is not used. If used, a password must be provided
.PARAMETER Password
    Optional. Only used if Kerberos integrated security is not used. If used, a username must be provided
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    System.Data.SQLClient.SQLConnection  A connection object to the specified server and database. Returns null if ServerName is not a valid hostname
#>
    [OutputType([System.Data.SqlClient.SQLConnection])]
    param (
        [Parameter(Mandatory=$true)][string]$ServerName,
        [Parameter(Mandatory=$true)][string]$DBName,
        [string]$Username,
        [string]$Password
    )
    $Global:Logger.Append('GenerateSQLConnection: Begin')
    if ($ServerName -match '(?=^\\\\)?(?<server>[a-z0-9-]*)$') {
        $connectionString = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
        $connectionString["Server"] = $Matches.server
        $connectionString["Initial Catalog"] = $DBName
        if ($Username -and $Password) {
            $connectionString["Persist Security Info"] = $false
            $connectionString["User ID"] = $Username
            $connectionString["Password"] = $Password.ToString()
        } else {
            $connectionString["Integrated Security"] = $true
        }
        try {
            $c = New-Object System.Data.SqlClient.SQLConnection($connectionString.ToString())
            $Global:Logger.Append('GenerateSQLConnection: Sucessfully instantiated SQLConnection object')
            return $c
        } catch {
            $Global:Logger.Append('GenerateSQLConnection: Failed to instantiate SQLConnection object')
            return $null
        }
    } else {
            $Global:Logger.Append('GenerateSQLConnection: Invalid server name')
        return $null
    }
}

Function CloseSQLConnection {
<#
.SYNOPSIS
    Closes and disposes of a specified SQLConnection
.PARAMETER Connection
    Required. Specifies a SQLConnection
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    No explicit outputs, however the SQLConnection is passed by referenced, and modified by this function
#>
    param (
        [Parameter(Mandatory=$true)][System.Data.SqlClient.SQLConnection]$Connection
    )
    $Connection.Close()
    $Connection.Dispose()
    $Global:Logger.Append('CloseSQLConnection: Closed connection and disposed of SQLConnection object')
}

Function CleanCerts {
<#
.SYNOPSIS
    Removes unneeded certificates from Personal certificate store
.PARAMETER userEDIPI
    Required. Specifies the current user's EDIPI for pattern matching
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None.
#>
    param (
        [string]$userEDIPI
    )
    try {
        Push-Location Cert:\CurrentUser\My
        $PersonalStore = Get-ChildItem | Sort-Object -Property Subject
        $CurrentExp = New-Object System.Collections.Generic.List[datetime]
        $CodeSigningType = [Microsoft.PowerShell.Commands.EnhancedKeyUsageRepresentation]::new("Code Signing","1.3.6.1.5.5.7.3.3")
        foreach ($Cert in $PersonalStore) {
            if ($Cert.FriendlyName.Contains('CN=') -and 
            $Cert.Subject.Contains($userEDIPI)) { 
                $Global:Logger.Append('CleanCerts: ARA Cert retained')
                continue
            }
            if ($Cert.FriendlyName.StartsWith('Signature') -and $Cert.EnhancedKeyUsageList -contains $CodeSigningType) {
                $Global:Logger.Append('CleanCerts: Code Signing Cert Retained')
                continue
            }
            if ($Cert.FriendlyName.StartsWith('Encryption') -or 
            $Cert.FriendlyName.StartsWith('Signature') -or 
            $Cert.FriendlyName.StartsWith('Authentication')) {
                if (-not $Cert.Subject.Contains($userEDIPI)) {
                    $Global:Logger.Append('CleanCerts: Foreign Cert Removed')
                    $CertPath = (Get-ChildItem | Where-Object {$_.Thumbprint -eq $Cert.Thumbprint} | Select-Object -Property PSPath).PSPath
                    Remove-Item $CertPath
                    continue
                }
                if ([datetime]$Cert.GetExpirationDateString() -lt [datetime]::Now) {
                    $Global:Logger.Append('CleanCerts: Expired Cert Removed')
                    $CertPath = (Get-ChildItem | Where-Object {$_.Thumbprint -eq $Cert.Thumbprint} | Select-Object -Property PSPath).PSPath
                    Remove-Item $CertPath
                    continue
                }
                if ($Cert.FriendlyName.StartsWith('Authentication')) {
                    $CurrentExp.Add([datetime]$Cert.GetExpirationDateString())
                }
                $Global:Logger.Append('CleanCerts: Core certs retained')
                continue
            }
            if ($Cert.Subject.Contains('Adobe')) {
                $Global:Logger.Append('CleanCerts: Adobe Certs Removed')
                $CertPath = (Get-ChildItem | Where-Object {$_.Thumbprint -eq $Cert.Thumbprint} | Select-Object -Property PSPath).PSPath
                Remove-Item $CertPath
                continue
            }
            if ($Cert.Subject.Contains('SERIALNUMBER=')) {
                if ($CurrentExp.Contains([datetime]$Cert.GetExpirationDateString())) {
                    $Global:Logger.Append('CleanCerts: Component cert retained')
                    continue
                } else {
                    $Global:Logger.Append('CleanCerts: Component cert removed for exp mismatch')
                    $CertPath = (Get-ChildItem | Where-Object {$_.Thumbprint -eq $Cert.Thumbprint} | Select-Object -Property PSPath).PSPath
                    Remove-Item $CertPath
                    continue
                }
            }
        }
    } catch {
        $Global:Logger.Append('CleanCerts: Error Generated')
    } finally {
        Pop-Location
    }
}

Function WebAttributeCheck {
<#
.SYNOPSIS
    Reads and updates wwwHomePage value from AD according to DHA standards
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    Boolean.  If user has OneDrive configured, returns true. Else returns false
#>
    param (
        [boolean]$Clean = $false
    )
    $GetDetailsOf_AVAILABILITY_STATUS = 303
    try {    
        $Global:Logger.Append('PIV Check: Starting check')
        Import-Module pki
        Push-Location Cert:\CurrentUser\My

        $OneDriveEpoch = [System.DateTime]::ParseExact('10-18-23','MM-dd-yy',$null)

        $UserDataDefinition = @("UPN","HOST","EMAIL","CERTEXP","CA","ODStatus","UPDATE")

        $Searcher = New-Object DirectoryServices.DirectorySearcher 
        $Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(samAccountName=$($env:USERNAME)))"
        $Searcher.SearchRoot = "LDAP://DC=med,DC=ds,DC=osd,DC=mil"
        $null = $Searcher.PropertiesToLoad.Add("wwwhomepage")
        $null = $Searcher.PropertiesToLoad.Add("userprincipalname")
        $null = $Searcher.PropertiesToLoad.Add("CN")
        $null = $Searcher.PropertiesToLoad.Add("mail")
        $User = $Searcher.FindOne()
        $UserDataStore = New-Object System.Collections.Generic.Dictionary"[String,String]"
        if ($User.Properties.mail[0] -match 'navy\.mil' -or $User.Properties.userprincipalname[0].Substring(11,4) -eq '1700') {
            $Global:Exception = "Navy"
        } elseif (($User.Properties.mail[0] -match 'af\.mil' -or $User.Properties.userprincipalname[0].Substring(11,4) -eq '5700')) {
            $Global:Exception = "Air Force"
        } elseif ($User.Properties.cn[0] -match 'MHIC') {
            $Global:Exception = "MHIC"
        }
        if ([string]::IsNullOrWhiteSpace($User.Properties.wwwhomepage[0])) {
            for ($i = 0; $i -lt $UserDataDefinition.Count; $i ++) {
                $thisdef = $UserDataDefinition[$i]
                $UserDataStore.Add($thisdef, "")
            }    
        } else {
            $DataArray = $User.Properties.wwwhomepage[0].Split('|')
            for ($i = 0; $i -lt $DataArray.Count; $i ++) {
                if ($i -ge $UserDataDefinition.Count) {
                    $thisdef = "Misc$($i)"
                } else {
                    $thisdef = $UserDataDefinition[$i]
                }
                $UserDataStore.Add($thisdef, $DataArray[$i])
            }
        }
        $userEDIPI = $User.Properties.userprincipalname[0].Substring(0,10)
        if ($Clean) {
            CleanCerts -userEDIPI $userEDIPI
        }
        $UserDataStore["UPDATE"] = (Get-Date).ToString('MM-dd-yy')
        foreach ($cert in (Get-ChildItem)) {
            $Global:Logger.Append("PIV Check: Cert: $($cert.Thumbprint) :: $($cert.Subject)")
            $Global:Logger.Append("    PIV Check: Cert PN: $($cert.Extensions.Format(1) -match 'Principal name=')")
            $Global:Logger.Append("    PIV Check: Cert PI: $($cert.Extensions.Format(1) -match 'Policy Identifier=2.16.840.1.101.')")
            $Global:Logger.Append("    PIV Check: Cert Issuer: $($cert.Issuer)")
            $Global:Logger.Append("    PIV Check: Cert Exp: $([datetime]$cert.GetExpirationDateString())")
        }
        $certAuth = Get-ChildItem | 
            Where-Object {
                $_.Extensions.Oid.FriendlyName.Contains("Subject Alternative Name") -and 
                    ($_.Extensions.Format(1) -match 'Principal name=') -and 
                    ($_.Extensions.Format(1) -match 'Policy Identifier=2.16.840.1.101.3.2.1.3.13') -and 
                    ((New-TimeSpan -Start $(Get-Date) -End $([datetime]$_.GetExpirationDateString())).Days -ge 0) -and 
                    $_.Issuer.Contains("U.S. Government")
            } | 
            Sort-Object -Property NotAfter -Descending | 
            Select-Object -First 1

        $certEnc = Get-ChildItem | 
            Where-Object {
                $_.Extensions.Oid.FriendlyName.Contains("Subject Alternative Name") -and 
                $_.Extensions.Format(1)[6] -match 'RFC822 Name' -and 
                $_.Extensions.Format(1)[3] -match "Policy Identifier=2.16.840.1.101.2.1.11.39" -and 
                ((New-TimeSpan -Start $(Get-Date) -End $([datetime]$_.GetExpirationDateString())).Days -ge 0) -and 
                $_.Issuer.Contains("DOD EMAIL") -and 
                $_.Subject.Contains($userEDIPI)
            } | 
            Sort-Object -Property NotAfter -Descending | 
            Select-Object -First 1

        if($certAuth){
	        $UserDataStore["UPN"] = [regex]::Match($certAuth.Extensions.Format(1)[6], "(?<piv>\d{16}@mil)").Value
	        $UserDataStore["CERTEXP"] = $certAuth.NotAfter.ToString('MM-dd-yy')
	        $UserDataStore["CA"] = [regex]::Match($certAuth.Issuer, '(?:^CN=DOD ID )(?<ca>CA-\d*)').Groups['ca'].Value
        }else{
	        $UserDataStore["UPN"] = "NOPIV"
	        $UserDataStore["CERTEXP"] = ""
	        $UserDataStore["CA"] = ""
        }
        $Global:Logger.Append("PIV Check: UPN: $($UserDataStore["UPN"])")
        $Global:Logger.Append("PIV Check: CERTEXP: $($UserDataStore["CERTEXP"])")
        $Global:Logger.Append("PIV Check: CA: $($UserDataStore["CA"])")
        if($certEnc){
	        $UserDataStore["EMAIL"] = [regex]::Match($certEnc.extensions.format(1)[6], '(?:RFC822 Name=)(?<email>.*\.mil)').Groups['email'].Value
        }else{
	        $UserDataStore["EMAIL"] = "NoEmailCert"
        }
        $Global:Logger.Append("PIV Check: EMAIL: $($UserDataStore["EMAIL"])")
        $UserDataStore["HOST"] = $env:computername
        $Global:Logger.Append("PIV Check: HOST: $($UserDataStore["HOST"])")
        $date = New-Object DateTime
        if (
            [DateTime]::TryParseExact($UserDataStore["UPDATE"], 'MM-dd-yy', $null, [System.Globalization.DateTimeStyles]::None, [ref] $date) -and 
            $date -gt $OneDriveEpoch -and
            $UserDataStore["ODStatus"] -eq "OneTrue"
        ) {
            $UserDataStore["ODStatus"] = "OneTrue"
            $OneDriveEnabled = $true
            $Global:Logger.Append("PIV Check: ODStatus: OneTrue selected based on previous state")
        } else {
            try {
	            $OneDriveDocs = "$env:OneDrive\Documents"
	            $Shell = (New-Object -ComObject Shell.Application).NameSpace((Split-Path $OneDriveDocs))
	            $DocsStatus = $Shell.getDetailsOf(($Shell.ParseName((Split-Path $OneDriveDocs -Leaf))),$GetDetailsOf_AVAILABILITY_STATUS)
	            $OneDriveDesk = "$env:OneDrive\Desktop"
	            $Shell = (New-Object -ComObject Shell.Application).NameSpace((Split-Path $OneDriveDesk))
	            $DeskStatus = $Shell.getDetailsOf(($Shell.ParseName((Split-Path $OneDriveDesk -Leaf))),$GetDetailsOf_AVAILABILITY_STATUS)
	            $OneDrivePics = "$env:OneDrive\Pictures"
	            $Shell = (New-Object -ComObject Shell.Application).NameSpace((Split-Path $OneDrivePics))
	            $PicsStatus = $Shell.getDetailsOf(($Shell.ParseName((Split-Path $OneDrivePics -Leaf))),$GetDetailsOf_AVAILABILITY_STATUS)
	            $OneDrivePics2 = "$env:OneDrive\My Pictures"
	            $Shell = (New-Object -ComObject Shell.Application).NameSpace((Split-Path $OneDrivePics2))
	            $PicsStatus2 = $Shell.getDetailsOf(($Shell.ParseName((Split-Path $OneDrivePics2 -Leaf))),$GetDetailsOf_AVAILABILITY_STATUS)
	            if (($DocsStatus -match "Available") -or 
                    ($DeskStatus -match "Available") -or 
                    ($PicsStatus -match "Available") -or 
                    ($PicsStatus2 -match "Available") -or
                    ($DocsStatus -match "Sync") -or 
                    ($DeskStatus -match "Sync") -or 
                    ($PicsStatus -match "Sync") -or 
                    ($PicsStatus2 -match "Sync")
                ){
		            $UserDataStore["ODStatus"] = "OneTrue"
                    $OneDriveEnabled = $true
                    $Global:Logger.Append("PIV Check: ODStatus: OneTrue selected based  on folder state")
	            } else {
		            $UserDataStore["ODStatus"] = "OneFalse"
                    $OneDriveEnabled = $false
                    $Global:Logger.Append("PIV Check: ODStatus: OneFalse selected based on folder state")
	            }
                $Global:Logger.Append("    PIV Check: ODStatus: Documents exist: $([System.IO.Directory]::Exists("$env:OneDrive\Documents"))")
                $Global:Logger.Append("    PIV Check: ODStatus: Desktop exist: $([System.IO.Directory]::Exists("$env:OneDrive\Desktop"))")
                $Global:Logger.Append("    PIV Check: ODStatus: Pictures exist: $([System.IO.Directory]::Exists("$env:OneDrive\Pictures"))")
                $Global:Logger.Append("    PIV Check: ODStatus: My Pictures exist: $([System.IO.Directory]::Exists("$env:OneDrive\My Pictures"))")
                $Global:Logger.Append("    PIV Check: ODStatus: Documents state: $DocsStatus")
                $Global:Logger.Append("    PIV Check: ODStatus: Desktop state: $DeskStatus")
                $Global:Logger.Append("    PIV Check: ODStatus: Pictures state: $PicsStatus")
                $Global:Logger.Append("    PIV Check: ODStatus: My Pictures state: $PicsStatus2")
            } catch {
                $UserDataStore["ODStatus"] = "OneFalse"
                $OneDriveEnabled = $false
                $Global:Logger.Append("PIV Check: ODStatus: OneFalse selected based on error state")
                $Global:Logger.Append("PIV Check: ODStatus: $($error[0].ErrorDetails.Message)")
            }
        } 
        $Global:Logger.Append("PIV Check: ODStatus: $($UserDataStore["ODStatus"])")
        $sb = New-Object System.Text.StringBuilder
        $isFirst = $true
        foreach ($item in $UserDataStore.Values) {
            if ($isFirst) {
                [void]$sb.Append($item)
                $isFirst = $false
            } else {
                [void]$sb.Append("|$($item)")
            }
        }

        $UserDE = [ADSI]($User.Path)
        $UserDE.Put("wwwhomepage",$sb.ToString())
        $UserDE.SetInfo()
        $Global:Logger.Append('PIV Check: Check complete')
    } catch {
        $Global:Logger.Append('PIV Check: Check failed')
    } finally {
        Pop-Location
    }
    return $OneDriveEnabled
}

Function RunPeriodic {
<#
.SYNOPSIS
    Checks if current day matches input
.PARAMETER Day
    Required. Specifies the day of week to be checked against
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    Boolean.  If input matches, returns true. Else returns false
#>
    param (
        [Parameter(Mandatory=$true)][string]$Day
    )
    return ($Day -eq (Get-Date).DayOfWeek)
}

Function MapDrive {
<#
.SYNOPSIS
    Creates smb drive mappings using net use
.PARAMETER Letter
    Required. Specifies the drive letter to be mapped
.PARAMETER UNC
    Required. Specifies the UNC path to be mapped
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    Boolean.  On failure will return $false, otherwise will return $null
#>
    param (
        [Parameter(Mandatory=$true)][string]$Letter,
        [Parameter(Mandatory=$true)][string]$UNC
    )
    $Global:Logger.Append("MapDrive: Begin attempt to map $UNC")
    try {
        $null = ([System.IO.DirectoryInfo]::new($UNC)).GetDirectories()
    } catch {
        $Global:Logger.Append("MapDrive: Function exited.  User does not have rights to $UNC")
        return $null
    }
    if ($Letter -match '(?<letter>[A-Za-z])') {
        $Letter = -join($Matches.letter, ':')
    } else {
        $Global:Logger.Append("MapDrive: Invalid drive letter '$letter'")
        return $null
    }
    if ($Letter.Substring(0,1) -in (Get-PSDrive | Select-Object Name).Name) {
        $Global:Logger.Append("MapDrive: Skipped already mapped '$letter'")
        return $null
    }
    try {
        net use $letter $unc /PERSISTENT:YES
        $Global:Logger.Append("MapDrive: Sucessfully mapped drive $letter.")
    } catch {
        $Global:Logger.Append("MapDrive: Net use command failed with letter $letter and path $unc")
        return $false
    }
    trap [System.UnauthorizedAccessException] {
        $Global:Logger.Append("MapDrive: Function exited.  User does not have rights to $UNC")
    }
}

Function MapAllDrives {
<#
.SYNOPSIS
    Bulk drive mapping based on specific List and Hashtable data structures
.PARAMETER Location
    Required. Specifies the Location parameter provided to the script
.PARAMETER LocationList
    Required. A String-based Generic List of all locations
.PARAMETER MappingList
    Required. A Hashtable array-based Generic List of mappings that correspond in order to locations in LocationList
.Parameter GlobalMaps
    Optional. A Hashtable-based Generic List of maps that apply to all users
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param(
        [string]$Location,
        [List[String]]$LocationList,
        [List[Hashtable[]]]$MappingList,
        [List[Hashtable]]$GlobalMaps
    )
    $Global:Logger.Append('MapAllDrives: Begin')
    if ($GlobalMaps) {
        $Global:Logger.Append('MapAllDrives: GlobalMaps')
        foreach ($Mapping in $GlobalMaps) {
            $null = MapDrive -Letter $Mapping.Letter -UNC $Mapping.UNC
        }
    }
    if (($Location -eq $LocationList[$LocationList.Count-1]) -or ($null -eq $Location) -or ($Location.Length -eq 0)) {
        $Global:Logger.Append('MapAllDrives: DefaultMaps')
        foreach ($Mapping in $MappingList[$LocationList.Count-1]) {
            $null = MapDrive -Letter $Mapping.Letter -UNC $Mapping.UNC
        }
        return
    }
    for($i=0;$i -lt $LocationList.Count-1;$i++) {
        if ($Location -eq $LocationList[$i]) {
            $Global:Logger.Append('MapAllDrives: LocationMaps')
            foreach ($Mapping in $MappingList[$i]) {
                $null = MapDrive -Letter $Mapping.Letter -UNC $Mapping.UNC
            }
            break
        }
    }
}

Function Map-SpecialtyDrives {
<#
.SYNOPSIS
    Bulk drive mapping based on specific List and Hashtable data structures
.PARAMETER Location
    Required. Specifies the Location parameter provided to the script
.PARAMETER LocationList
    Required. A String-based Generic List of all locations
.PARAMETER MappingList
    Required. A Hashtable array-based Generic List of mappings that correspond in order to locations in LocationList
.Parameter GlobalMaps
    Optional. A Hashtable-based Generic List of maps that apply to all users
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param(
        [string[]]$UserGroups,
        [List[SpecialtyMap]]$SpecialtyList
    )
    $Global:Logger.Append('Map-SpecialtyDrives: Begin')
    foreach ($SpecialtyMap in $SpecialtyList) {
        if ($UserGroups -contains $SpecialtyMap.Group) {
            $null = MapDrive -Letter $SpecialtyMap.Letter -UNC $SpecialtyMap.UNC
        }
    }
}

Function UnmapDrive {
<#
.SYNOPSIS
    Unmaps one or more drives as a wrapper for net use
.PARAMETER Letters
    Required. Specifies an array of strings that represent drive letters.  If multi-character strings are passed, only the first character in each string will be processed
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [Parameter(Mandatory=$true)][string[]]$Letters
    )
    foreach ($Letter in $Letters) {
        if ($Letter -match '(?<letter>[A-Za-z])') {
            $Letter = -join($Matches.letter, ':')
            try {
                net use $Letter /DELETE /Y
                $Global:Logger.Append("MapDrive: Sucessfully unmapped drive $letter.")
            } catch {
                $Global:Logger.Append("UnmapDrive: failed to unmap drive $letter.  Not unexpected")
            }
        } else {
            $Global:Logger.Append("UnmapDrive: Invalid drive letter '$letter'")
            continue
        }
    }
}

Function GetTimeZoneCode {
<#
.SYNOPSIS
    Returns either the time zone abbreviation for CONUS time zones, or the UTC offset for OCONUS
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    System.String.  Time zone data.  Three letter abbreviations may be globally ambiguous and should be understood to reference CONUS time zones.
#>
    if ($Global:LogonTimestamp.IsDaylightSavingTime()) {
        $middle = 'D'
    } else {
        $middle = 'S'
    }
    $null = (Get-TimeZone).DisplayName -match '\((?<offset>UTC[+|-]\d{2}:\d{2})\).*'
    $offset = $Matches
    switch ((((Get-TimeZone).Id -split ' ')[0])) {
        'Eastern' {$name = -join('E', $middle, 'T'); break}
        'Central' {$name = -join('C', $middle, 'T'); break}
        'Mountain' {$name = -join('M', $middle, 'T'); break}
        'Pacific' {$name = -join('P', $middle, 'T'); break}
        Default {$name = $offset}
    }
    return $name
}

Function Get-UserDN {
<#
.SYNOPSIS
    Returns the Distinguished Name of the current user
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    System.String. The distinguished name from LDAP of the current user.
#>
    $SysInfo = New-Object -ComObject "ADSystemInfo"
    try {
        $dn = $SysInfo.GetType().InvokeMember("UserName", "GetProperty", $Null, $SysInfo, $Null)
        $Global:Logger.Append('Get-UserDN: Retreived DN for user')
        return $dn
    } catch {
        $Global:Logger.Append('Get-UserDN: Failed to retreive DN for user')
        return $null
    }
}

Function Get-UserGroups {
<#
.SYNOPSIS
    Returns a string[] of the user's direct group memberships (no recursion)
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    System.String[]. The group names from user's memberOf property
#>
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(samAccountName=$($env:USERNAME)))"
    $Searcher.SearchRoot = "LDAP://DC=med,DC=ds,DC=osd,DC=mil"
    $null = $Searcher.PropertiesToLoad.Add("memberOf")
    $User = $Searcher.FindOne()
    return (($User.Properties.memberof | Select-String -Pattern 'CN=(?<group>[^,]*)' -AllMatches).Matches.Groups | ? {$_.Name -eq 'group'} | select Value).Value
}

Function Logging {
<#
.SYNOPSIS
    Generates multiple logon event logs and saves it to various files and/or database
.PARAMETER MachineLogs
    Specifies the path to be written to. If the target file already exists, it will be appended to.
.PARAMETER MachineStats
    Specifies the path to be written to. If the target file already exists, it will be appended to.
.PARAMETER UserLogon
    Specifies the path to be written to. If the target file already exists, it will be appended to.
.PARAMETER ComputerLogon
    Specifies the path to be written to. If the target file already exists, it will be appended to.
.PARAMETER connection
    Specifies an already configured SqlConnection obejct.  This connection may be provided open, but will be returned closed.
.PARAMETER LogToFile
    A switch if a logfile should be written.  If this switch is set and one or more of the target path parameters are not provided, no exception will be generated
.PARAMETER LogToDB
    A switch if a row should be MERGEd into a database.  If this switch is set and no connection is provided, no exception will be generated
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    System.String. If LogToDB is set, will return the active IP address. Otherwise returns $null
#>
    [OutputType([string])]
    param (
        [string]$MachineLogs,
        [string]$MachineStats,
        [string]$UserLogon,
        [string]$ComputerLogon,
        [System.Data.SqlClient.SqlConnection]$connection,
        [switch]$LogToFile,
        [switch]$LogToDB,
        [switch]$LogToTS,
        [boolean]$ODStatus = $null
    )
    $pattern = -join('^', $Global:SiteCode, 'TS.*$')
    if (-not $LogToTS -and ($env:computername -match $pattern)) {
        $Global:Logger.Append('Logging: Logging skipped due to Terminal Server rule')
        return $null
    }

    $LogToFile = [boolean](($MachineLogs -and $LogToFile) -or ($MachineStats -and $LogToFile) -or ($UserLogon -and $LogToFile) -or ($ComputerLogon -and $LogToFile))
    $LogToDb = [boolean]($connection -and $LogToDB)

    if (-not $LogToDB -and -not $LogToFile) {
        $Global:Logger.Append('Logging: Logging skipped because LogToDB and LogToFile are both off')
        return $null
    }

    $Global:Logger.Append('Logging: Logging not skipped by TS or logging options')

    $userDN = Get-UserDN
    if ($null -ne $env:LOGONSERVER) {
        try {
            $logonServerFQDN = [string]([System.Net.Dns]::GetHostByName($($env:LOGONSERVER.Replace('\\',''))).hostname)
        } catch {
            $Global:Logger.Append("Logging: Failed to get FQDN for logonserver. $($_)")
            $logonServerFQDN = $null
        }
    } else {
        $logonServerFQDN = $null
    }

    if ($LogToFile) {
        $LogTime1 = (Get-Date).ToString('ddd MMM dd HH:mm:ss yyyy')
        if ((Get-Date).IsDaylightSavingTime()) {
            $LogTime2 = (Get-Date).ToString("ddd MMM dd HH:mm:ss $(GetTimeZoneCode) yyyy")
        } else {
            $LogTime2 = (Get-Date).ToString("ddd MMM dd HH:mm:ss $(GetTimeZoneCode) yyyy")
        }
        $username = $env:USERNAME
        $LogEntry1 = -join($LogTime1, ' -- ', $username, "`r`n")
        $LogEntry2 = [System.Text.StringBuilder]::new()
        [void]$LogEntry2.AppendLine($username)
        foreach ($e in (Get-ChildItem env:)) {
            [void]$LogEntry2.AppendLine("$($e.name)=$($e.value)")
        }
        $(ipconfig /all) -split "`r`n" | ForEach-Object {[void]$LogEntry2.AppendLine($_)}
        $LogEntry3 = ($username, $logonServerFQDN, $env:COMPUTERNAME, $LogTime2, $userDN) -join '|'
        $LogEntry3 = -join($LogEntry3, "`r`n")
        $Destination1 = -join ($MachineLogs, $env:COMPUTERNAME, '.log')
        $Destination2 = -join ($MachineStats, $env:COMPUTERNAME, '.LOG')
        $Destination3 = -join ($UserLogon, $username, '.log')
        $Destination4 = -join ($ComputerLogon, $env:COMPUTERNAME, '.log')
        if (Test-Path $MachineLogs) {
            Add-Content -Value $LogEntry1 -LiteralPath $Destination1
        }
        if (Test-Path $MachineStats) {
            Add-Content -Value $LogEntry2.ToString() -LiteralPath $Destination2
        }
        if (Test-Path $UserLogon) {
            Add-Content -Value $LogEntry3 -LiteralPath $Destination3
        }
        if (Test-Path $ComputerLogon) {
            Add-Content -Value $LogEntry3 -LiteralPath $Destination4
        }
    }

    if ($LogToDB) {
        $Global:Logger.Append('Logging: Collecting adapter data')
        $data = (ipconfig /all)
        $adapters = New-Object System.Collections.Generic.List[PSObject]
        $adapter = $null
        foreach ($line in $data) {
            if ($line -match '10\.249\.\d\.\d{1,3}') {
                $adapter = $null
                continue
            }
            if ($line -match '10\.249\.[0-7]\d{1,2}\.\d{1,3}') {
                $adapter = $null
                continue
            }
            if ($line -match '10\.249\.8[1-9]\.\d{1,3}') {
                $adapter = $null
                continue
            }
            if ($line -match '10\.249\.9\d\.\d{1,3}') {
                $adapter = $null
                continue
            }
            if ($line -match '169\.254\.\d{1,3}\.\d{1,3}') {
                $adapter = $null
                continue
            }
            if ($line -match '^(?!Windows)[^\s]') {
                #This is the beginning of a new adapter
                if ($null -ne $adapter) {
                    #gotta save the last adapter info before nuking
                    $adapters.Add($adapter)
                }
                if ($line -match '\*') {
                    #This is a virtual adapter, skip
                    $adapter = $null
                    continue
                }
                $adapter = New-Object System.Management.Automation.PSObject | select desc, state, ip, mac
            } elseif ($null -eq $adapter) {
                #This is not data we want to capture
                continue
            } elseif ($line -match '\s+Description(?:\s?(?:\.\s)+):\s(?<desc>(?:\S+\s?)+)') {
                $adapter.desc = $Matches.desc
            } elseif ($line -match '\s+IPv4\sAddress(?:\s?(?:\.\s)+):\s(?<ip>(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))') {
                $adapter.ip = $Matches.ip
                $adapter.state = 'Up'
                if (($Matches.ip -notlike "10.0*") -and ($Matches.ip -notlike "192.168.*")) {
                    $IPAddress = $Matches.ip.Trim()
                }
                $Global:Logger.Append("General: Workstation IP: $IPAddress")
                $MACAddress = $adapter.mac
            } elseif ($line -match '\s+Physical\sAddress(?:\s?(?:\.\s)+):\s(?<mac>([0-9A-F]{2}-){5}[0-9A-F]{2})') {
                $adapter.mac = $Matches.mac
            } elseif ($line -match '\s+Media\sState(?:\s?(?:\.\s)+):\sMedia\sdisconnected') {
                $adapter.state = 'Down'
            }
        }
        if ($adapter -notin $adapters -and $adapter.desc -ne $null) {
            $adapters.Add($adapter)
        }
        try {
            $Global:Logger.Append('Logging: Generating LoginDataInsert object')
            $cmd = New-Object System.Data.SqlClient.SqlCommand
            $cmd.Connection = $connection
            $cmd.CommandType = [System.Data.CommandType]::StoredProcedure
            $cmd.CommandText = "dbo.LoginDataInsert"

            [void]$cmd.Parameters.Add("@UserDN", [System.Data.SqlDbType]::NVarChar)
            $cmd.Parameters["@UserDN"].Value = [string]($userDN)

            [void]$cmd.Parameters.Add("@UPN", [System.Data.SqlDbType]::Char)
            $cmd.Parameters["@UPN"].Value = [string](whoami /upn)

            [void]$cmd.Parameters.Add("@IP", [System.Data.SqlDbType]::VarChar)
            $cmd.Parameters["@IP"].Value = [string]($IPAddress)

            [void]$cmd.Parameters.Add("@MAC", [System.Data.SqlDbType]::Char)
            $cmd.Parameters["@MAC"].Value = [string]($MACAddress)

            [void]$cmd.Parameters.Add("@DC", [System.Data.SqlDbType]::VarChar)
            if ($logonServerFQDN) {
                $cmd.Parameters["@DC"].Value = [string]($logonServerFQDN)
            } else {
                $cmd.Parameters["@DC"].Value = [System.DBNull]::Value
            }

            [void]$cmd.Parameters.Add("@ODStatus", [System.Data.SqlDbType]::Bit)
            [void]$cmd.Parameters.Add("@ODCount", [System.Data.SqlDbType]::Int)
            if ($ODStatus) {
                $cmd.Parameters["@ODCount"].Value = [System.DBNull]::Value
                $cmd.Parameters["@ODStatus"].Value = 1
                try {
                    if ($env:USERNAME -ne 'nicholas.j.gibson10') {
                        $cmd.Parameters["@ODCount"].Value = @([System.IO.Directory]::EnumerateFiles($env:OneDriveCommercial, '*', 'AllDirectories')).Count
                    }
                } catch {
                    $cmd.Parameters["@ODCount"].Value = [System.DBNull]::Value
                }
            } else {
                $cmd.Parameters["@ODCount"].Value = [System.DBNull]::Value
                $cmd.Parameters["@ODStatus"].Value = 0
            }
            [void]$cmd.Parameters.Add("@Exception", [System.Data.SqlDbType]::VarChar)
            if ([string]::IsNullOrWhiteSpace($Global:Exception)) {
                $cmd.Parameters["@Exception"].Value = [System.DBNull]::Value
            } else {
                $cmd.Parameters["@Exception"].Value = $Global:Exception
            }
            [void]$cmd.Parameters.Add("@SAAccount", [System.Data.SqlDbType]::Bit)
            if ($UserDN -match 'DN FOR NPE ACCOUNTS') {
                $cmd.Parameters["@SAAccount"].Value = 1
            } else {
                $cmd.Parameters["@SAAccount"].Value = 0
            }
        } catch {
            $Global:Logger.Append("Logging: Failed to assign parameter for LoginDataInsert. $_")
        }
        if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
            try {
                $connection.Open()
            } catch {
                $Global:Logger.Append("Logging: Failed to open connection. $($_.Exception)")
            }
        }
        try {
            [void]$cmd.ExecuteNonQuery()
            $Global:Logger.Append('Logging: Execution of LogonDataInsert succeeded.')
        } catch {
            $Global:Logger.Append("Logging: Failed to execute stored procedure LogonDataInsert. $($_.Exception)")
        }
        $Global:Logger.Append("Logging: Adapter count: $($Adapters.Count)")
        foreach ($Adapter in $Adapters) {
            if ($null -eq $Adapter.desc) {continue}
            $Global:Logger.Append('Logging: Generating AdapterInsertObject')
            $cmd = New-Object System.Data.SqlClient.SqlCommand
            $cmd.Connection = $connection
            $cmd.CommandType = [System.Data.CommandType]::StoredProcedure
            $cmd.CommandText = "dbo.AdapterInsert"

            try {
                [void]$cmd.Parameters.Add("@AdapterState", [System.Data.SqlDbType]::VarChar)
                $cmd.Parameters["@AdapterState"].Value = [string]($adapter.state)

                [void]$cmd.Parameters.Add("@AdapterDesc", [System.Data.SqlDbType]::VarChar)
                $cmd.Parameters["@AdapterDesc"].Value = [string]($Adapter.desc)

                [void]$cmd.Parameters.Add("@IPv4", [System.Data.SqlDbType]::VarChar)
                if ($adapter.IP) {
                    $cmd.Parameters["@IPv4"].Value = [string]($adapter.ip)
                } else {
                    $cmd.Parameters["@IPv4"].Value = [System.DBNull]::Value
                }

                [void]$cmd.Parameters.Add("@MAC", [System.Data.SqlDbType]::Char)
                $cmd.Parameters["@MAC"].Value = [string]($adapter.mac)
            } catch {
                $Global:Logger.Append("Logging: Failed to assign parameter for AdapterInsert. $_")
            }
            if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
                try {
                    $connection.Open()
                } catch {
                    $Global:Logger.Append("Logging: Failed to open connection. $($_.Exception)")
                }
            }
            try {
                [void]$cmd.ExecuteNonQuery()
                $Global:Logger.Append("Logging: Execution of AdapterInsert succeeded. $($_.Exception)")
            } catch {
                $Global:Logger.Append("Logging: Failed to execute stored procedure AdapterInsert. $($_.Exception)")
            }
        }
        $connection.Close()
    }

    if (Test-Path Variable:\IPAddress) {
        return $IPAddress
    } else {
        return $null
    }

    trap {
        $Global:Logger.Append("Logging: General uncaught error. $($_)")
        continue
    }
}

Function PrinterLogging {
<#
.SYNOPSIS
    Generates a printer inventory and saves it to a file and/or database
.PARAMETER TargetPath
    Specifies the path to be written to. If the target file already exists, it will be overwritten
.PARAMETER PrinterToAdd
    Specifies a network printer to be added to all clients that don't already have it
.PARAMETER connection
    Specifies an already configured SqlConnection obejct.  This connection may be provided open, but will be returned closed.
.PARAMETER LogToFile
    A switch if a logfile should be written.  If this switch is set and no TargetPath is provided, no exception will be generated
.PARAMETER LogToDB
    A switch if the dataset should be written to a database.  If this switch is set and no connection is provided, no exception will be generated
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [string]$TargetPath,
        [string]$PrinterToAdd,
        [System.Data.SqlClient.SqlConnection]$connection,
        [switch]$LogToFile,
        [switch]$LogToDB,
        [switch]$LogToTS
    )

    $pattern = -join('^', $Global:SiteCode, 'TS.*$')
    if (-not $LogToTS -and ($env:computername -match $pattern)) {
        return $null
    }

    $osCaption = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
    If ($osCaption -like '*server*') {
        return $null
    }

    $LogToFile = [boolean]($TargetPath -and $LogToFile)
    $LogToDb = [boolean]($LogToDB)
    if (-not $LogToDB -and -not $LogToFile) {
        return $null
    }

    $Printers = Get-CimInstance -ClassName Win32_Printer -Property *
    $Printers | Add-Member -MemberType NoteProperty -Name Computer -Value $env:COMPUTERNAME
    $Printers | Add-Member -MemberType NoteProperty -Name User -Value $env:USERNAME
    $Printers = $Printers | Select-Object Computer, User, @{label='PORT';expression={$_.Portname}}, Network, Name, Location, Servername, ShareName, @{label='INAD';expression={$_.Published}}, DriverName, Local_TCPIPPort

    foreach ($printer in $Printers) {
        foreach ($port in (Get-CimInstance -ClassName Win32_TCPIPPrinterPort)) {
            if ($port.Name -eq $printer.PORT) {
                $printer.Local_TCPIPPort = $port.HostAddress
            }
        }
        if (-not $printer.Network -and $printer.PORT -match '^WSD-') {
            try {
                $printerInstance = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\$($Printer.Name)\PnPData" -Name DeviceInstanceId
                $port = (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$($printerInstance)" -Name LocationInformation).Trim().Replace('http://','').Replace('https://','')
                if ($port -match '^[^:]*') {
                    $printer.Local_TCPIPPort = $Matches.0
                } else {
                    $printer.Local_TCPIPPort = $port
                }
            } catch {
                $printer.Local_TCPIPPort = $null
            } finally {
                $printerInstance = $null
                $port = $null
            }
        }
    }

    $Printers = $Printers | Where-Object {$_.PORT -notmatch '^TS' -and $_.Name -notmatch '\(redirected' -and $_.DriverName -notmatch 'Remote Desktop Easy Print'}

    if ($LogToFile -and $TargetPath) {
        $Destination = -join ($TargetPath, $env:COMPUTERNAME, '-', $env:USERNAME, '-Printers.csv')
        $Printers | Export-Csv -LiteralPath $Destination -NoTypeInformation -Force
    }

    if ($LogToDB) {
        $cmd = New-Object System.Data.SqlClient.SqlCommand
        $cmd.Connection = $connection
        [Microsoft.SqlServer.Server.SqlMetaData[]]$printer_tbltype = @(
            [Microsoft.SqlServer.Server.SqlMetaData]::new("printername", [System.Data.SqlDbType]::VarChar, 50),
            [Microsoft.SqlServer.Server.SqlMetaData]::new("port", [System.Data.SqlDbType]::VarChar, 75),
            [Microsoft.SqlServer.Server.SqlMetaData]::new("network", [System.Data.SqlDbType]::Bit),
            [Microsoft.SqlServer.Server.SqlMetaData]::new("location", [System.Data.SqlDbType]::VarChar, 100),
            [Microsoft.SqlServer.Server.SqlMetaData]::new("servername", [System.Data.SqlDbType]::VarChar, 25),
            [Microsoft.SqlServer.Server.SqlMetaData]::new("sharename", [System.Data.SqlDbType]::VarChar, 50),
            [Microsoft.SqlServer.Server.SqlMetaData]::new("InAD", [System.Data.SqlDbType]::Bit),
            [Microsoft.SqlServer.Server.SqlMetaData]::new("drivername", [System.Data.SqlDbType]::VarChar, 100),
            [Microsoft.SqlServer.Server.SqlMetaData]::new("Local_TCPIPPort", [System.Data.SqlDbType]::VarChar, 50)
        )

        $printerlist = New-Object 'System.Collections.Generic.List[Microsoft.SqlServer.Server.SqlDataRecord]'

        foreach ($printer in $Printers) {
            [Microsoft.SqlServer.Server.SqlDataRecord]$printer_rec = [Microsoft.SqlServer.Server.SqlDataRecord]::new($printer_tbltype)
            $printer_rec.SetString($printer_rec.GetOrdinal("printername"), $printer.Name)

            if ($null -eq $printer.PORT) {
                $printer_rec.SetString($printer_rec.GetOrdinal("port"), [System.DBNull]::Value)
            } else {
                $printer_rec.SetString($printer_rec.GetOrdinal("port"), $printer.PORT)
            }

            $printer_rec.SetBoolean($printer_rec.GetOrdinal("network"), $printer.Network)

            if ($null -eq $printer.Location) {
                $printer_rec.SetString($printer_rec.GetOrdinal("location"), [System.DBNull]::Value)
            } else {
                $printer_rec.SetString($printer_rec.GetOrdinal("location"), $printer.Location)
            }

            if ($null -eq $printer.Servername) {
                $printer_rec.SetString($printer_rec.GetOrdinal("servername"), [System.DBNull]::Value)
            } else {
                $printer_rec.SetString($printer_rec.GetOrdinal("servername"), $printer.Servername)
            }

            if ($null -eq $printer.ShareName) {
                $printer_rec.SetString($printer_rec.GetOrdinal("sharename"), [System.DBNull]::Value)
            } else {
                $printer_rec.SetString($printer_rec.GetOrdinal("sharename"), $printer.ShareName)
            }

            $printer_rec.SetBoolean($printer_rec.GetOrdinal("InAD"), $printer.INAD)

            if ($null -eq $printer.DriverName) {
                $printer_rec.SetString($printer_rec.GetOrdinal("drivername"), [System.DBNull]::Value)
            } else {
                $printer_rec.SetString($printer_rec.GetOrdinal("drivername"), $printer.DriverName)
            }

            if ($null -eq $printer.Local_TCPIPPort) {
                $printer_rec.SetString($printer_rec.GetOrdinal("Local_TCPIPPort"), [System.DBNull]::Value)
            } else {
                $printer_rec.SetString($printer_rec.GetOrdinal("Local_TCPIPPort"), $printer.Local_TCPIPPort)
            }

            $printerlist.Add($printer_rec)
        }
        $cmd.CommandType = [System.Data.CommandType]::StoredProcedure
        $cmd.CommandText = "dbo.PrinterInsert"
        [void]$cmd.Parameters.Add("@PrinterList", [System.Data.SqlDbType]::Structured)
        $cmd.Parameters["@PrinterList"].Direction = [System.Data.ParameterDirection]::Input
        $cmd.Parameters["@PrinterList"].TypeName = "dbo.PrinterList"
        $cmd.Parameters["@PrinterList"].Value = $printerlist
        if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
            try {
                $connection.Open()
            } catch {
                $Global:Logger.Append("PrinterLogging: Failed to open connection. $($_.Exception)")
            }
        }
        try {
            [void]$cmd.ExecuteNonQuery()
            $Global:Logger.Append("PrinterLogging: Execution of PrinterInsert succeeded. $($_.Exception)")
        } catch {
            $Global:Logger.Append("PrinterLogging: Failed to execute stored procedure PrinterInsert. $($_.Exception)")
        }
        trap {
            $Global:Logger.Append("PrinterLogging: General uncaught error. $($_)")
            continue
        }
        $connection.Close()
    }

    if (($null -ne $PrinterToAdd) -and -not ($Printers | Where-Object {$_.Name -eq $PrinterToAdd})) {
        Start-Process -FilePath rundll32 -ArgumentList "printui.dll,PrintUIEntry /in /n $($PrinterToAdd) /q"
    }
}

Function AppLogging {
<#
.SYNOPSIS
    Generates an application inventory and saves it to a file and/or database
.PARAMETER TargetPath
    Specifies the path to be written to. If the target file already exists, it will be overwritten
.PARAMETER connection
    Specifies an already configured SqlConnection obejct.  This connection may be provided open, but will be returned closed.
.PARAMETER LogToFile
    A switch if a logfile should be written.  If this switch is set and no TargetPath is provided, no exception will be generated
.PARAMETER LogToDB
    A switch if the dataset should be written to a database.  If this switch is set and no connection is provided, no exception will be generated
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [string]$TargetPath,
        [System.Data.SqlClient.SqlConnection]$connection,
        [switch]$LogToFile,
        [switch]$LogToDB,
        [switch]$LogToTS
    )

    $pattern = -join('^', $Global:SiteCode, 'TS.*$')
    if (-not $LogToTS -and ($env:computername -match $pattern)) {
        return $null
    }

    $LogToFile = [boolean]($TargetPath -and $LogToFile)
    if (-not $LogToFile -and -not $LogToDb) {
        return $null
    }

    $list = New-Object System.Collections.Generic.List[PSObject]
    $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'=$((Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName)})
    foreach ($key in (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\)) {
        if ($null -eq $key.GetValue('QuietDisplayName') -and $null -ne $key.GetValue('DisplayName')) {
            $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'=$($key.GetValue('DisplayName'))})
        } elseif ($null -ne $key.GetValue('QuietDisplayName') -and $null -eq $key.GetValue('DisplayName')) {
            $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'=$($key.GetValue('QuietDisplayName'))})
        } elseif ($null -ne $key.GetValue('QuietDisplayName') -and $null -ne $key.GetValue('DisplayName')) {
            $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'="$($key.GetValue('DisplayName'))/$($key.GetValue('QuietDisplayName'))"})
        }
    }

    foreach ($key in (Get-ChildItem HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\)) {
        if ($null -eq $key.GetValue('QuietDisplayName') -and $null -ne $key.GetValue('DisplayName')) {
            $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'=$($key.GetValue('DisplayName'))})
        } elseif ($null -ne $key.GetValue('QuietDisplayName') -and $null -eq $key.GetValue('DisplayName')) {
            $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'=$($key.GetValue('QuietDisplayName'))})
        } elseif ($null -ne $key.GetValue('QuietDisplayName') -and $null -ne $key.GetValue('DisplayName')) {
            $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'="$($key.GetValue('DisplayName'))/$($key.GetValue('QuietDisplayName'))"})
        }
    }

    if ($LogToFile) {
        $Destination = -join($TargetPath, $env:COMPUTERNAME, '.Applications.csv')
        $list | Export-Csv -LiteralPath $Destination -NoTypeInformation -Force
    }

    if ($LogToDB) {
        $cmd = New-Object System.Data.SqlClient.SqlCommand
        $cmd.Connection = $connection
        $strippedAppList = New-Object System.Collections.Generic.List[string]
        foreach ($app in $list) {
            $strippedAppList.Add($app.APPLICATION.Trim())
        }
        $strippedAppList = $strippedAppList | Sort-Object | Get-Unique
        [Microsoft.SqlServer.Server.SqlMetaData[]]$app_tbltype = @(
            [Microsoft.SqlServer.Server.SqlMetaData]::new("applicationname", [System.Data.SqlDbType]::VarChar, -1)
        )
        $applist = New-Object 'System.Collections.Generic.List[Microsoft.SqlServer.Server.SqlDataRecord]'
        foreach ($app in $strippedAppList) {
            [Microsoft.SqlServer.Server.SqlDataRecord]$app_rec = [Microsoft.SqlServer.Server.SqlDataRecord]::new($app_tbltype)
            $app_rec.SetString($app_rec.GetOrdinal("applicationname"), [string]($app))
            $applist.Add($app_rec)
        }
        $cmd.CommandType = [System.Data.CommandType]::StoredProcedure
        $cmd.CommandText = "dbo.ApplicationInsert"
        [void]$cmd.Parameters.Add("@ApplicationList", [System.Data.SqlDbType]::Structured)
        $cmd.Parameters["@ApplicationList"].Direction = [System.Data.ParameterDirection]::Input
        $cmd.Parameters["@ApplicationList"].TypeName = "dbo.ApplicationList"
        $cmd.Parameters["@ApplicationList"].Value = $applist
        if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
            try {
                $connection.Open()
            } catch {
                $Global:Logger.Append("AppLogging: Failed to open connection. $($_.Exception)")
            }
        }
        try {
            [void]$cmd.ExecuteNonQuery()
            $Global:Logger.Append('AppLogging: Execution of ApplicationInsert succeeded.')
        } catch {
            $Global:Logger.Append("AppLogging: Failed to execute stored procedure ApplicationInsert. $($_.Exception)")
        }
        trap {
            $Global:Logger.Append("AppLogging: General uncaught error. $($_)")
            continue
        }
        $connection.Close()
    }
}

Function ProfileRedirection {
<#
.SYNOPSIS
    Redirects user profile folders to network HomeShare locations
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    try {
        $OneDrive = "$($env:USERPROFILE)\OneDrive - militaryhealth"
        $shellFolders = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        $userShellFolders = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        $destinations = $shellFolders, $userShellFolders
        $Global:Logger.Append("ProfileRedirection: OneDrivePath $OneDrive")
        if ([System.IO.Directory]::Exists($OneDrive)) {
            $Global:Logger.Append("ProfileRedirection: OneDrivePath Detected")
            foreach ($destination in $destinations) {
                $Global:Logger.Append("ProfileRedirection: Setting Keys At $destination")
                Set-ItemProperty -Path $destination -Name 'Personal' -Value "$($OneDrive)\Documents"
                Set-ItemProperty -Path $destination -Name 'My Music' -Value "$($OneDrive)\My Music"
                Set-ItemProperty -Path $destination -Name 'My Pictures' -Value "$($OneDrive)\My Pictures"
                Set-ItemProperty -Path $destination -Name 'My Video' -Value "$($OneDrive)\My Video"
            }
        } else {
            $Global:Logger.Append("ProfileRedirection: OneDrivePath Not Detected")
            foreach ($destination in $destinations) {
                $Global:Logger.Append("ProfileRedirection: Setting Keys At $destination")
                Set-ItemProperty -Path $destination -Name 'Personal' -Value "$($env:USERPROFILE)\Documents"
                Set-ItemProperty -Path $destination -Name 'My Music' -Value "$($env:USERPROFILE)\My Music"
                Set-ItemProperty -Path $destination -Name 'My Pictures' -Value "$($env:USERPROFILE)\My Pictures"
                Set-ItemProperty -Path $destination -Name 'My Video' -Value "$($env:USERPROFILE)\My Video"
            }
        }
        $Global:Logger.Append('ProfileRediction: Modified user shell folders')
    } catch {
        $Global:Logger.Append('ProfileRediction: Failed to modify user shell folders')
    }
}

Function IndividualFileManagement {
<#
.SYNOPSIS
    General maintenance actions requested by IA/Cyber
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    Remove-Item -Recurse -Force -Path "$($env:LOCALAPPDATA)\OneLaunch" -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Force -Path C:\Windows\SysWOW64\msxml4.dll -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Force -Path C:\Windows\SysWOW64\msxml4r.dll -Confirm:$false -ErrorAction SilentlyContinue

    #$OneDrive = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    #if (-not [System.IO.Directory]::Exists($OneDrive)) {
    #    New-Item -Path $($env:USERPROFILE) -Name "OneDrive - militaryhealth" -ItemType Directory
    #    New-Item -Path $OneDrive -Name "Documents" -ItemType Directory
    #    New-Item -Path $OneDrive -Name "Desktop" -ItemType Directory
    #    New-Item -Path $OneDrive -Name "Downloads" -ItemType Directory
    #}
}

Function LocalFileCopy {
<#
.SYNOPSIS
    File copy for DOC/Critical Events
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    $PSPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $OldCodeGreen1 = 'C:\AdminTools\CriticalEvent\CodeGreenClient'
    $OldCodeGreen2 = 'C:\AdminTools\CriticalEvent\CodeGreenConsole'
    $OldBat = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\CriticalEvents.bat'

    if ([System.IO.File]::Exists($OldBat)) {
        Remove-Item $OldBat -Confirm:$false
    }
    if ([System.IO.Directory]::Exists($OldCodeGreen1)) {
        Remove-Item $OldCodeGreen1 -Recurse -Confirm:$false
    }
    if ([System.IO.Directory]::Exists($OldCodeGreen2)) {
        Remove-Item $OldCodeGreen2 -Recurse -Confirm:$false
    }
    Start-Process -FilePath $PSPath -ArgumentList @(
        '-NoExit',
        '-File "C:\AdminTools\CriticalEvent\CriticalEvent.ps1"',
        '-ExecutionPolicy Bypass'
    ) -WindowStyle Hidden
    Start-Process -FilePath $PSPath -ArgumentList @(
        '-File "C:\AdminTools\CriticalEvent\DOCConsole.ps1"',
        '-ExecutionPolicy Bypass'
    ) -WindowStyle Hidden
    Start-Process -FilePath $PSPath -ArgumentList @(
        '-NoExit',
        '-MTA',
        '-File "C:\AdminTools\CriticalEvent\RegisterConsoleEvent.ps1"',
        '-ExecutionPolicy Bypass'
    ) -WindowStyle Hidden
}

Function HardwareInventory {
<#
.SYNOPSIS
    Generates a hardware inventory and saves it to a file and/or database
.PARAMETER TargetPath
    Specifies the path to be written to. If the target file already exists, it will be overwritten. Required if LogToFile is set.
.PARAMETER connection
    Specifies an already configured SqlConnection obejct.  This connection may be provided open, but will be returned closed. Required if LogToDB is set/
.PARAMETER IP
    Optionally provides the IP address, as Get-NetIPAddress is computationally expensive
.PARAMETER LogToFile
    A switch if a logfile should be written.  If this switch is set and no TargetPath is provided, no exception will be generated
.PARAMETER LogToDB
    A switch if a row should be MERGEd into a database.  If this switch is set and no connection is provided, no exception will be generated
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [string]$TargetPath,
        [System.Data.SqlClient.SqlConnection]$connection,
        [string]$IP,
        [switch]$LogToFile,
        [switch]$LogToDB,
        [switch]$LogToTS
    )

    $pattern = -join('^', $Global:SiteCode, 'TS.*$')
    if (-not $LogToTS -and ($env:computername -match $pattern)) {
        $Global:Logger.Append('HardwareInventory: Logging skipped due to Terminal Server rule')
        return $null
    }

    $LogToFile = [boolean]($TargetPath -and $LogToFile)
    if (-not $LogToFile -and -not $LogToDb) {
        $Global:Logger.Append('HardwareInventory: Logging skipped because LogToDB and LogToFile are both off')
        return $null
    }
    $Global:Logger.Append('HardwareInventory: Collecting hardware data')
    $HardwareDataPath = "HKCU:\System\CurrentControlSet\Control\$Global:SiteCode"
    if (-not (Test-Path $HardwareDataPath)) {
        $Global:Logger.Append('HardwareInventory: BIOS Data not cached. Generating registry cache.')
        $null = New-Item -Path "HKCU:\System\CurrentControlSet\Control" -Name $Global:SiteCode
        $bios = Get-CimInstance -ClassName Win32_Bios
        $null = New-ItemProperty -Path $HardwareDataPath -Name SN -Value $bios.SerialNumber
    } else {
        $Global:Logger.Append("HardwareInventory: BIOS data cached in registry. Skipping Win32_Bios")
    }
    $data = Get-ItemProperty -Path $HardwareDataPath
    $Global:Logger.Append('HardwareInventory: Fetching CPU Count from Windows API')
    $CoreCount = ([Gibson.HardwareStats]::GetLogicalProcessorInformation() | ? {$_.Relationship -eq 'RelationProcessorCore'}).Count
    $Global:Logger.Append('HardwareInventory: Fetching CPU data from Registry')
    $CPUName = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name ProcessorNameString).ProcessorNameString
    $arch = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment\" -Name PROCESSOR_ARCHITECTURE).PROCESSOR_ARCHITECTURE
    $Manufacturer = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS" -Name SystemManufacturer).SystemManufacturer
    $Model = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS" -Name SystemProductName).SystemProductName
    $SN = $data.SN

    $Global:Logger.Append('HardwareInventory: Parsing ipconfig')
    if ($null -eq $IP) {
        $IP = foreach ($line in $(ipconfig)) {if ($line -match 'IPv4\sAddress(?:\.\s)+:\s(?<ip>(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))') {$Matches.ip}}
    }

    $ver = [System.Environment]::OSVersion.Version.ToString()
    $Global:Logger.Append('HardwareInventory: Fetching RAM from Windows API')
    $mem = [math]::Ceiling(([Gibson.HardwareStats]::GetTotalMem())/1GB)
    $Global:Logger.Append('HardwareInventory: Fetching HDD data from Windows API')
    foreach ($drive in $([System.IO.DriveInfo]::GetDrives())) {if ($drive.Name -eq 'C:\') {$hdd = [int]($drive.TotalSize/1GB)}}

    try {
        $regInstallDate =  Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' | select -ExpandProperty InstallDate
        $convertedInstallDate = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromSeconds($regInstallDate))
    } catch {
        $convertedInstallDate = (Get-CimInstance -ClassName Win32_OperatingSystem | Select InstallDate).InstallDate
    }

    $uptime = New-Object System.Diagnostics.PerformanceCounter("System", "System Up Time")
    $null = $uptime.NextValue()
    $lastboot = [DateTime]::Now.Subtract(([TimeSpan]::FromSeconds($uptime.NextValue())))

    $btstate = $true

    $null = Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $null = [Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime]
    $null = [Windows.Devices.Radios.RadioAccessStatus,Windows.System.Devices,ContentType=WindowsRuntime]
    $null = [Windows.Devices.Radios.RadioState,Windows.System.Devices,ContentType=WindowsRuntime]
    $asTaskGeneric = (
        [System.WindowsRuntimeSystemExtensions].GetMethods() | 
        Where-Object { 
            ($_.Name -eq 'AsTask') -and 
            ($_.GetParameters().Count -eq 1) -and 
            ($_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1') 
        }
    )[0]
    Function Await($WinRtTask, $ResultType) {
        $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $netTask.Wait(-1) | Out-Null
        $netTask.Result
    }
    try {
        $Global:Logger.Append('HardwareInventory: Requesting access to radio status')
        $null = Await ([Windows.Devices.Radios.Radio]::RequestAccessAsync()) ([Windows.Devices.Radios.RadioAccessStatus])
        $Global:Logger.Append('HardwareInventory: Fetching radio status')
        $radios = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
        $bluetooth = $radios | Where-Object { $_.Kind -eq 'Bluetooth' }
        if (($bluetooth | Where-Object {$_.State -eq "On"}).Count -gt 0) {
            $btstate = $true
            $Global:Logger.Append('HardwareInventory: Active BT Radio')
        } else {
            $Global:Logger.Append('HardwareInventory: No active BT radios')
            $btstate = $false
        }
    } catch {
        $Global:Logger.Append('HardwareInventory: Radio status indeterminate')
    }


    if ($LogToFile) {
        $inv = [System.Text.StringBuilder]::new()
        [void]$inv.AppendLine($((Get-Date).ToString('ddd MM/dd/yyy')))
        [void]$inv.AppendLine("Computer Name: $($env:COMPUTERNAME)")
        [void]$inv.AppendLine("Manufacturer: $($cs.Manufacturer)")
        [void]$inv.AppendLine("Model: $($cs.Model)")
        [void]$inv.AppendLine("IPAddress: $IP")
        [void]$inv.AppendLine("Operating System: $ver")
        [void]$inv.AppendLine("Total Memory: $mem")
        [void]$inv.AppendLine("OS Install Date: $convertedInstallDate")
        $inv.ToString() | Out-File -FilePath "$($TargetPath)$($env:COMPUTERNAME).txt" -Force
    }

    if ($LogToDB) {
        $Global:Logger.Append('HardwareInventory: Generating StatInsert object')
        $cmd = New-Object System.Data.SqlClient.SqlCommand
        $cmd.Connection = $connection
        $cmd.CommandType = [System.Data.CommandType]::StoredProcedure
        $cmd.CommandText = "dbo.StatInsert"

        [void]$cmd.Parameters.Add("@Cores", [System.Data.SqlDbType]::SmallInt)
        $cmd.Parameters["@Cores"].Value = [convert]::ToInt16($CoreCount)

        [void]$cmd.Parameters.Add("@Arch", [System.Data.SqlDbType]::VarChar)
        $cmd.Parameters["@Arch"].Value = $arch

        [void]$cmd.Parameters.Add("@Id", [System.Data.SqlDbType]::VarChar)
        $cmd.Parameters["@Id"].Value = $CPUName

        [void]$cmd.Parameters.Add("@Manuf", [System.Data.SqlDbType]::VarChar)
        $cmd.Parameters["@Manuf"].Value = $Manufacturer

        [void]$cmd.Parameters.Add("@Model", [System.Data.SqlDbType]::VarChar)
        $cmd.Parameters["@Model"].Value = $Model

        [void]$cmd.Parameters.Add("@SN", [System.Data.SqlDbType]::VarChar)
        $cmd.Parameters["@SN"].Value = $SN

        [void]$cmd.Parameters.Add("@OSVer", [System.Data.SqlDbType]::VarChar)
        $cmd.Parameters["@OSVer"].Value = $ver

        [void]$cmd.Parameters.Add("@Mem", [System.Data.SqlDbType]::Int)
        $cmd.Parameters["@Mem"].Value = [convert]::ToInt32($mem)

        [void]$cmd.Parameters.Add("@HDD", [System.Data.SqlDbType]::Int)
        $cmd.Parameters["@HDD"].Value = [convert]::ToInt32($hdd)

        [void]$cmd.Parameters.Add("@InstallDate", [System.Data.SqlDbType]::DateTime2)
        $cmd.Parameters["@InstallDate"].Value = $convertedInstallDate

        [void]$cmd.Parameters.Add("@LastBoot", [System.Data.SqlDbType]::DateTime2)
        $cmd.Parameters["@LastBoot"].Value = $lastboot

        [void]$cmd.Parameters.Add("@BTState", [System.Data.SqlDbType]::Bit)
        $cmd.Parameters["@BTState"].Value = $btstate

        [void]$cmd.Parameters.Add("@TPMVersion", [System.Data.SqlDbType]::VarChar)
        $TPMDeviceName = (Get-WmiObject Win32_PNPEntity | Where {$_.Name -match "Trusted Platform Module"}).Name
        $Global:Logger.Append("HardwareInventory: TPM Detected: $TPMDeviceName")
        if ((Get-WmiObject Win32_PNPEntity | Where {$_.Name -match "Trusted Platform Module"}).Name -match '(?:Trusted Platform Module )(\d\.\d)') {
            $cmd.Parameters["@TPMVersion"].Value = $Matches[1]
        } else {
            $cmd.Parameters["@TPMVersion"].Value = 'Unk'
        }
        $Global:Logger.Append("HardwareInventory: TPM Version Detected As: $($cmd.Parameters["@TPMVersion"].Value)")
        if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
            try {
                $connection.Open()
            } catch {
                $Global:Logger.Append("HardwareInventory: Failed to open connection. $($_.Exception)")
            }
        }
        try {
            [void]$cmd.ExecuteNonQuery()
            $Global:Logger.Append('HardwareInventory: Execution of StatInsert succeeded.')
        } catch {
            $Global:Logger.Append("HardwareInventory: Failed to execute stored procedure StatInsert. $($_.Exception)")
        }
        $connection.Close()
    }
}

Function CheckForAlert {
<#
.SYNOPSIS
    Decides whether to call CallAlert based on if CallAlert is only desired periodically, and if it is within the desired window
.PARAMETER baseDate
    Required if doPeriodic is True. The base date off which periodicy is calculated
.PARAMETER Interval
    Required if doPeriodic is True. The periodicy interval.
.PARAMETER missedAlertWindow
    Required if doPeriodic is True. The number of days after the interval window a missed alert will still fire.
.PARAMETER doPeriodic
    If false, this function is a wrapped for CallAlert.
.PARAMETER AlertFile
    Required. Specifies the file to be launched.  Generally expected to be an HTA file
.PARAMETER RunOnServer
    Optional. Specifies whether execution should terminate on server OSes.  Defaults to $false
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param(
        [datetime]$baseDate,
        [int]$Interval,
        [int]$missedAlertWindow,
        [switch]$doPeriodic,
        [Parameter(Mandatory=$true)][string]$AlertFile,
        [switch]$RunOnServer = $false
    )


    #Base dir
    if (Test-Path "$($env:USERPROFILE)\OneDrive - militaryhealth") {
        $basedir = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    } else {
        $basedir = $env:USERPROFILE
    }

    if (Test-Path "$basedir\noalert.txt") {
        $Global:Logger.Append('CheckForAlert: Exempt')
        return $null
    }

    if ((whoami /upn) -match '\.ad(s|w)@mil$') {
        $Global:Logger.Append('CheckForAlert: Exempt')
        return $null
    }

    #If we aren't doing periodic alerts, just forward to CallAlert and move on
    if (-not $doPeriodic) {
        $Global:Logger.Append('CheckForAlert: Non-periodic CallAlert')
        return CallAlert -AlertFile $AlertFile -RunOnServer:$RunOnServer
    }

    #How long has it been since the last intended alert day?
    $alertSpan = (New-TimeSpan -Start $baseDate -End $(Get-Date)).Days % $Interval

    #How long has it been since the last actual alert?
    if (-not (Test-Path "$basedir\alert.txt")) {
        $fileSpan = 30
    } else {
        $fileSpan = (New-TimeSpan -Start $((Get-ChildItem "$basedir\alert.txt").LastWriteTime) -End $(Get-Date)).Days
    }

    $todayIsInAlertWindow = ($alertSpan -le $missedAlertWindow)
    $fileDateIsWithinAlertWindow = ($fileSpan -le $missedAlertWindow)

    if ($todayIsInAlertWindow -and -not $fileDateIsWithinAlertWindow) {
        $Global:Logger.Append('CheckForAlert: Periodic CallAlert')
        return CallAlert -AlertFile $AlertFile -RunOnServer:$RunOnServer
    } else {
        $Global:Logger.Append('CheckForAlert: Out of phase for periodic CallAlert')
        return $null
    }
}

Function CallAlert {
<#
.SYNOPSIS
    Uses invoke item to launch a file, optionally skipping execution on server OSes.
    This function will write a 0-byte file to the user's homeshare to log the last time the user saw the alert.
.PARAMETER AlertFile
    Required. Specifies the file to be launched.  Generally expected to be an HTA file
.PARAMETER RunOnServer
    Optional. Specifies whether execution should terminate on server OSes.  Defaults to $false
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [Parameter(Mandatory=$true)][string]$AlertFile,
        [switch]$RunOnServer = $false
    )
    $osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption | Select-Object Caption).caption

    If (($osCaption -like '*server*') -and ($RunOnServer -eq $false)) {
        return $null
    }

    #Base dir
    if (Test-Path "$($env:USERPROFILE)\OneDrive - militaryhealth") {
        $basedir = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    } else {
        $basedir = $env:USERPROFILE
    }

    if (Test-Path $AlertFile) {
        $Global:Logger.Append('CallAlert: Alert file exists.')
        Invoke-Item $AlertFile
        Set-Content -Path "$basedir\alert.txt" -Value $null
        $(Get-Item "$basedir\alert.txt").lastwritetime=$(Get-Date)
    } else {
        return $null
    }
}

Function Display-Totd {
<#
.SYNOPSIS
    Displays an image from the appropriate day folder of the supplied base path.
.PARAMETER BasePath
    Required. Specifies the base path that contains the day folders.
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [Parameter(Mandatory=$true)][string]$BasePath
    )
    $Global:Logger.Append('Display-Totd: Invoked')

    if (Test-Path "$($env:USERPROFILE)\OneDrive - militaryhealth") {
        $profDir = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    } else {
        $profDir = $env:USERPROFILE
    }

    if (Test-Path "$profDir\nototd.txt") {
        $Global:Logger.Append('Display-Totd: Exempt')
        return
    }

    if ((whoami /upn) -match '\.ad(s|w)\@mil') {return}
    $TodaysPath = "$BasePath\$((Get-Date).DayOfWeek)"
    if (-not (Test-Path $TodaysPath)) {return}
    $Global:Logger.Append('Display-Totd: TodayPath Exists')
    $image = Get-ChildItem -path $TodaysPath -Recurse -Include  *.png,*.jpg,*.jpeg,*.bmp -Name | Sort-Object -Property LastWriteTime | Select-Object -last 1
    if ($null -eq $image) {return}
    $Global:Logger.Append('Display-Totd: Image in TodayPath Exists')
    $imagePath = "$($TodaysPath)\$($image)"
    $file = Get-Item ($imagePath)
    $Global:Logger.Append("Display-Totd: TargetImage: $file")
    [void][reflection.assembly]::LoadWithPartialName("System.Drawing")
    $img = [System.Drawing.Image]::FromFile($file)
    [void][reflection.assembly]::LoadWithPartialName("System.Windows.Forms")
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $form = New-Object Windows.Forms.Form
    $form.Text = "Image Viewer"
    $form.Width = $img.Size.Width
    $form.Height = $img.Size.Height
    $pictureBox = New-Object Windows.Forms.PictureBox
    $pictureBox.Width = $img.Size.Width
    $pictureBox.Height = $img.Size.Height
    $pictureBox.Image = $img
    $form.Controls.Add($pictureBox)
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.Add_Shown( { $form.Activate() } )
    $Global:Logger.Append('Display-Totd: Image Displayed')
    $form.ShowDialog()
}

Function Display-NewTotd {
<#
.SYNOPSIS
    Displays a Tip of the Day from a supplied Database.
.PARAMETER ServerName
    Required. Specifies the name of the SQL Server.  It should not be formatted as a UNC path, but may be an FQDN
.PARAMETER DBName
    Required. Specifies the name of a database on the provided server.
.PARAMETER ImagePath
    Required. Specifies the full path of an image referenced by the XAML
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [Parameter(Mandatory=$true)][string]$ServerName,
        [Parameter(Mandatory=$true)][string]$DBName,
        [Parameter(Mandatory=$true)][string]$ImagePath,
        [Parameter(Mandatory=$true)][xml]$Xaml
    )
    $Global:Logger.Append('Display-NewTotd: Invoked')

    if (Test-Path "$($env:USERPROFILE)\OneDrive - militaryhealth") {
        $profDir = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    } else {
        $profDir = $env:USERPROFILE
    }

    if ((Test-Path "$profDir\nototd.txt") -or ((whoami /upn) -match '\.ad(s|w)\@mil')) {
        $Global:Logger.Append('Display-NewTotd: Exempt')
        return
    }

    $connection = GenerateSQLConnection -ServerName $ServerName -DBName $DBName

    $Global:Logger.Append('Display-NewTotd: Retrieving Tip')
    $cmd = New-Object System.Data.SqlClient.SqlCommand -Property @{
        Connection = $connection
        CommandType = [System.Data.CommandType]::StoredProcedure
        CommandText = "dbo.sp_GetTip"
    }

    [void]$cmd.Parameters.Add("@UserID", [System.Data.SqlDbType]::VarChar)
    $cmd.Parameters["@UserID"].Value = $env:USERNAME   

    $dt = New-Object System.Data.DataTable
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
    $returned = $adapter.Fill($dt)

    $connection.Close()
    if ($returned -eq 0 -or $null -eq $dt.TipID_PK -or $dt.TipID_PK -is [System.DBNull]) {
        $Global:Logger.Append('Display-NewTotd: No Tip Found')
        return
    }

    $TipID = $dt.TipID_PK
    $Title = $dt.Title
    $TipText = $dt.Tip
    $DisplayDate = $dt.DisplayDate

    $dt.Dispose()
    $Global:Logger.Append('Display-NewTotd: Tip Found, Constructing Display')

    [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')    | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')   | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')          | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName('WindowsFormsIntegration') | Out-Null

    $TipReader = New-Object System.Xml.XmlNodeReader($Xaml)
    $TipWindow = [System.Windows.Markup.XamlReader]::Load($TipReader)

    $Tip_imgBulb = $TipWindow.FindName("imgBulb")
        $Tip_imgBulb.Source = New-Object System.Windows.Media.Imaging.BitmapImage($ImagePath)
    $Tip_lblDate = $TipWindow.FindName("lblDate")
        $Tip_lblDate.Content = $DisplayDate
    $Tip_lblTitle = $TipWindow.FindName("lblTitle")
        $Tip_lblTitle.Content = $Title
    $Tip_txbTip = $TipWindow.FindName("txbTip")
        $Tip_txbTip.Text = $TipText
    $Tip_bntOK = $TipWindow.FindName("bntOK")
        $Tip_bntOK.Add_Click({ $TipWindow.Close() })

    $null = $TipWindow.ShowDialog()
    $Global:Logger.Append('Display-NewTotd: Display Closed by User')
}

Function RemovePrinters {
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [object[]]$ServerList,

        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [object[]]$PrinterList
    )
    $Global:Logger.Append('RemovePrinters: Begin')
    $RemovalList = Get-Printer | Where-Object {$_.ComputerName -in $InvalidPrintServers -or $_.Name -in $InvalidPrinterNames}
    if ($RemovalList -is [ciminstance]) {
        $Global:Logger.Append("RemovePrinters: Removing $($RemovalList.Name)")
        $RemovalList | Remove-Printer
    } elseif ($RemovalList -is [object[]]) {
        foreach ($Printer in $RemovalList) {
            $Global:Logger.Append("RemovePrinters: Removing $($Printer.Name)")
        }
        $RemovalList | Remove-Printer
    } else {
        $Global:Logger.Append('RemovePrinters: No matching printers to remove')
    }
}

Function HideWindow {
<#
.SYNOPSIS
    Implements the Winuser.h ShowWindow function from the Win32 API.  This will hide the window belonging to the current process.
    Note, this action cannot be undone.  The window will remain hidden until the process terminates.
.INPUTS
    None. You cannot pipe objects to HideWindow
.OUTPUTS
    None
.LINK
    https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
#>
    $Global:Logger.Append('HideWindow: Begin')
    if (-not (Test-Path variable:global:psISE)) {
        Add-Type -Name win -Member '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);' -Namespace native
        [native.win]::ShowWindow([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle, 0)
        $Global:Logger.Append('HideWindow: Hidden.')
    } else {
        $Global:Logger.Append('HideWindow: Not hidden.')
    }
}

Function InvokeScheduledTasks {
<#
.SYNOPSIS
    Invokes pre-installed scheduled tasks by name
.PARAMETER TaskList
    Required. String[] of scheduled tasks to be launched
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None.
#>
    param (
        [Parameter(Mandatory=$true)][string[]]$TaskList
    )
    foreach ($TaskName in $TaskList) {
        try {
            Start-ScheduledTask -TaskName $TaskName
            $Global:Logger.Append("InvokeScheduledTasks: Scheduled task created - $TaskName.")
        } catch {
            $Global:Logger.Append('InvokeScheduledTasks: Scheduled task creation failed.')
        }
    }
}

#######################################################################################
#                        PREFERENCE LOAD AND PARSE                                    #
#######################################################################################

$Global:Logger.Append('Environment: Preference structure')
$prefs                               = Get-Content $preferenceFileLocation | ConvertFrom-Json
$Global:Logger.Append('Environment: Loaded preference file to memory')

class SpecialtyMap {
    [ValidateNotNullOrEmpty()][string]$Group
    [ValidateNotNullOrEmpty()][string]$Letter
    [ValidateNotNullOrEmpty()][string]$UNC
}

$Global:SiteCode                     = $prefs.GlobalVariables.SiteCode
$MachineLogsLoc                      = $prefs.FileVariables.MachineLogsLoc
$MachineStatsLoc                     = $prefs.FileVariables.MachineStatsLoc
$UserLogonLoc                        = $prefs.FileVariables.UserLogonLoc
$ComputerLogonLoc                    = $prefs.FileVariables.ComputerLogonLoc
$PrinterLogsLoc                      = $prefs.FileVariables.PrinterLogsLoc
$ApplicationLogsLoc                  = $prefs.FileVariables.ApplicationLogsLoc
$HardwareInvLoc                      = $prefs.FileVariables.HardwareInvLoc
$FastLogLoc                          = $prefs.FileVariables.FastLogLoc
$AlertFile                           = $prefs.FunctionVariables.AlertFile
$GlobalPrinter                       = $prefs.FunctionVariables.GlobalPrinter
$TotdBasePath                        = $prefs.FunctionVariables.TotdBasePath
$TotdImage                           = $prefs.FunctionVariables.NewTotdImage
$TotdXaml                            = $prefs.FunctionVariables.NewTotdXaml
$SafetyXaml                          = $prefs.FunctionVariables.SafetyXaml
$InvalidPrintServers                 = $prefs.FunctionVariables.InvalidPrintServers
$InvalidPrinterNames                 = $prefs.FunctionVariables.InvalidPrinterNames
$DatabaseServer                      = $prefs.DatabaseVariables.DatabaseServer
$Database                            = $prefs.DatabaseVariables.DatabaseName
$TotdDatabase                        = $prefs.DatabaseVariables.TotdDatabase
$SafetyDatabase                      = $prefs.DatabaseVariables.SafetyDatabase
$LogToFiles                          = $prefs.LoggingOverrides.LogToFiles
$ScheduledTaskList                   = $prefs.ScheduledTaskList
if ($prefs.LoggingOverrides.LogToDB) {
    $LogToDatabase = $true
} else {
    $LogToDatabase = $UseSQL
}
$LogToDatabase                       = $prefs.LoggingOverrides.LogToDB
$DrivesToUnMap                       = $prefs.MappingVariables.DrivesToUnmap
$LogTSData                           = $prefs.LoggingOverrides.LogTSData
$StartDate                           = [convert]::ToDateTime($prefs.CheckForAlertVariables.StartDate)
$Span                                = $prefs.CheckForAlertVariables.Span
$DaysAfterAlertDateToShowMissedAlert = $prefs.CheckForAlertVariables.AlertWindow
$DoPeriodic                          = $prefs.CheckForAlertVariables.DoPeriodic

$Global:Logger.Append('Environment: Generated simple variables from preferences')
if ($prefs.FunctionExecution.HideWindow) {
    $null = HideWindow
}
if (-not (Test-Path variable:global:psISE)) {
    Start-Sleep -Seconds 30
}
$LocationList                        = [List[String]]::new()
$MappingList                         = [List[Hashtable[]]]::new()
$GlobalMaps                          = [List[Hashtable]]::new()
$SpecialtyMaps                       = [List[SpecialtyMap]]::new()
$SpecialtyGroups                     = [List[String]]::new()
$UserGroups                          = Get-UserGroups
foreach ($map in $prefs.MappingVariables.GlobalMaps) {
    $GlobalMaps.Add(@{Letter=$map.Letter;UNC=$map.UNC})
}
foreach ($locationmap in $prefs.MappingVariables.LocationMaps) {
    $LocationList.Add($locationmap.Name)
    $temp = [List[Hashtable]]::new()
    foreach ($mapping in $locationmap.Mappings) {
        $temp.Add(@{Letter=$mapping.Letter;UNC=$mapping.UNC})
    }
    $MappingList.Add($temp)
}
$defaultmaps = [List[Hashtable]]::new()
foreach ($map in $prefs.MappingVariables.DefaultMaps.Mappings) {
    $defaultmaps.Add(@{Letter=$map.Letter;UNC=$map.UNC})
}
foreach ($default in $prefs.MappingVariables.DefaultMaps.PermittedNames) {
    $LocationList.Add($default)
    $MappingList.Add($defaultmaps)
}
foreach ($specialty in $prefs.MappingVariables.SpecialtyMaps) {
    $temp = [SpecialtyMap]@{
        Group = $specialty.Group
        Letter = $specialty.Letter
        UNC = $specialty.UNC
    }
    $SpecialtyMaps.Add($temp)
    $SpecialtyGroups.Add($specialty.Group)
}

$Global:Logger.Append('Environment: Generated data structures from preferences')

if ($LogToDatabase) {
    $connection = GenerateSQLConnection -ServerName $DatabaseServer -DBName $Database
    $Global:Logger.Append('Environment: Testing SQLConnection object')
    try {
        $connection.Open()
        $connection.Close()
        $Global:Logger.Append('Environment: SQLConnection object valid')
    } catch {
        $Global:Logger.Append('Environment: Failed to open SQL connection.  Falling back to file logging')
		$Global:Logger.Append("Environment: $($Error[0].Exception.GetType().FullName) : $($Error[0])")
        $LogToDatabase = $false
        $LogToFiles = $true
    }
} else {
    $connection = $null
}
# A Note About Function Order
# HideWindow is first because we want to vanish as quickly as possible - in fact, it has been moved inside Preference parsing
# CheckForAlert is second because we want loading the alert to mask further processing
# Logging is third because it returns a value useful in HardwareInventory. Get-NetIPAddress costs 3.1s, so if we can only do it once, all the better
# PrinterLogging, AppLogging, and HardwareInventory are interchangable
# Next, drive mappings are established, and general misc work is done
# At this time, I believe the items in IndividualFileManagement are no longer required, however the function remains as a placeholder for future IA requests

if ($prefs.FunctionExecution.CheckForAlert) {
    CheckForAlert -baseDate $StartDate -Interval $Span -missedAlertWindow $DaysAfterAlertDateToShowMissedAlert -doPeriodic:$DoPeriodic -AlertFile $AlertFile
}
$ODStatus = $null
if ($prefs.FunctionExecution.WebAttributeCheck) {
    $ODStatus = (WebAttributeCheck -Clean $($prefs.FunctionExecution.CleanCerts)).Where({$null -ne $_})[0]
}
if ($prefs.FunctionExecution.Logging) {
    $IP = Logging -MachineLogs $MachineLogsLoc -MachineStats $MachineStatsLoc -UserLogon $UserLogonLoc -ComputerLogon $ComputerLogonLoc -connection $connection -LogToFile:$LogToFiles -LogToDB:$LogToDatabase -LogToTS:$LogTSData -ODStatus $ODStatus
}
if ($prefs.FunctionExecution.HardwareInventory) {
    HardwareInventory -TargetPath $HardwareInvLoc -IP $IP -connection $connection -LogToFile:$LogToFiles -LogToDB:$LogToDatabase -LogToTS:$LogTSData
}
if ($prefs.FunctionExecution.PrinterLogging) {
    PrinterLogging -TargetPath $PrinterLogsLoc -PrinterToAdd $GlobalPrinter -connection $connection -LogToFile:$LogToFiles -LogToDB:$LogToDatabase -LogToTS:$LogTSData
}
if ($prefs.FunctionExecution.AppLogging) {
    AppLogging -TargetPath $ApplicationLogsLoc -connection $connection -LogToFile:$LogToFiles -LogToDB:$LogToDatabase -LogToTS:$LogTSData
}
if ($prefs.FunctionExecution.Unmap) {
    $null = UnmapDrive -Letters $DrivesToUnMap
}
if ($prefs.FunctionExecution.Map) {
    MapAllDrives -Location $Location -LocationList $LocationList -MappingList $MappingList -GlobalMaps $GlobalMaps
}
if ($prefs.FunctionExecution.SpecialtyMap) {
    if ($UserGroups | ?{$SpecialtyGroups.ToArray() -contains $_}) {
        Map-SpecialtyDrives -UserGroups $UserGroups -SpecialtyList $SpecialtyMaps
    }
}
if ($prefs.FunctionExecution.ProfileRedirection) {
    ProfileRedirection
}
if ($prefs.FunctionExecution.IARemoval) {
    IndividualFileManagement
}
if ($prefs.FunctionExecution.FastLog) {
    $Global:Logger.Append('Environment: Writing fastlog')
    $filename = "$($env:COMPUTERNAME)-$($env:USERNAME).txt"
    $null = New-Item -Path $FastLogLoc -Name $filename -ItemType File -Force
    $(Get-Item "$($FastLogLoc)$($filename)").lastwritetime=$(Get-Date)
}
if ($prefs.FunctionExecution.LocalFileCopy) {
    LocalFileCopy
}
if ($prefs.FunctionExecution.GlobalPrinterAdd) {
    Start-Process -FilePath rundll32 -ArgumentList "printui.dll,PrintUIEntry /in /n $($GlobalPrinter) /q"
}
if ($prefs.FunctionExecution.ScheduledTaskLaunch) {
    InvokeScheduledTasks -TaskList $ScheduledTaskList
}
if ($prefs.FunctionExecution.PrinterRemoval) {
    RemovePrinters -ServerList $(,$InvalidPrintServers) -PrinterList $(,$InvalidPrinterNames)
}
# Each function that uses the connection should open and close the connection independently, but this is good housekeeping
# To ensure dangling connections aren't left
if ($connection) {
    CloseSQLConnection -Connection $connection
}
foreach ($task in $prefs.OneTimeTasks) {
    $Now = [DateTime]::Now
    $RunTime = $Now.AddMinutes($task.Delay)
    $ExpTime = $RunTime.AddMinutes($task.Expiry)
    $TaskTrigger = New-ScheduledTaskTrigger -Once -At $RunTime
    $TaskTrigger.EndBoundary = $ExpTime.ToString("yyyy-MM-dd'T'HH:mm:ss")
    $TaskSettings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 00:00:01 -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -Hidden
    $TaskAction = New-ScheduledTaskAction -Execute $task.TaskPath
    try {
        $null = Register-ScheduledTask -TaskName $task.TaskName -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -ErrorAction SilentlyContinue
        $Global:Logger.Append("OneTimeTasks: Task registration complete - $($task.TaskName)")
    } catch {
        $Global:Logger.Append('OneTimeTasks: Task registration failed.')
    }
}

if ($prefs.FunctionExecution.TipOfTheDay -and -not $prefs.FunctionExecution.NewTotd) {
    Display-Totd -BasePath $TotdBasePath
} elseif ($prefs.FunctionExecution.NewTotd) {
    Display-NewTotd -ServerName $DatabaseServer -DBName $TotdDatabase -ImagePath $TotdImage -Xaml $TotdXaml
}
if ($prefs.FunctionExecution.SafetyTip) {
    Display-NewTotd -ServerName $DatabaseServer -DBName $SafetyDatabase -ImagePath $TotdImage -Xaml $SafetyXaml
}
if ($prefs.LoggingOverrides.LogDebugData -or $debug) {
    $fileName = "$($env:USERNAME).txt"
    $Global:Logger.LogFile = [System.IO.Path]::Combine($prefs.FileVariables.DebugLogLoc, $filename)
    $Global:Logger.Append("")
    $Global:Logger.WriteLogFile()
}

exit

# General exception trap to close the $connection if it exists
trap {
    $Global:Logger.Append("Global: General uncaught error. $($_)")
    if ($connection -and ($connection.State -ne [System.Data.ConnectionState]::Closed)) {
        $connection.Close()
    }
    continue
}
