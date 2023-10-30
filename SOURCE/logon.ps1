<#
.SYNOPSIS
    Consolidated logon script
.NOTES
    Name: logon.ps1
    Author: Nick Gibson
    Version: 3.1.5
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
#>
param (
    [string]$Location,
    [switch]$UseSQL,
    [switch]$debug
)

#######################################################################################
#                            INITIALIZE DEBUG LOGS                                    #
#######################################################################################
Function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true
        )]
        [AllowEmptyString()]
        [string]$LogString,
		[boolean]$IncludeDate = $true
    )
    Process {
        foreach ($Line in $LogString) {
            if ($Line -eq "") {
                if ($IncludeDate) {
                    [void]$Global:DebugWriter.AppendLine("$(Get-Date -Format "MM/dd/yyyy HH:mm:ss.fffff")")
                } else {
                    continue
                }
            } else {
	            if ($IncludeDate) {
		            [void]$Global:DebugWriter.AppendLine("$(Get-Date -Format "MM/dd/yyyy HH:mm:ss.fffff"): $Line")
	            } else {
		            [void]$Global:DebugWriter.AppendLine("$Line")
	            }
            }
        }
    }
}
$Global:DebugWriter = New-Object System.Text.StringBuilder(5000)
$Global:DoDebug = [boolean]$debug
Write-Log -LogString $env:USERNAME -IncludeDate:$false
Write-Log -LogString $env:COMPUTERNAME -IncludeDate:$false
Write-Log -LogString 'Script Start - v3.2.0'
$Global:LogonTimestamp = Get-Date

#######################################################################################
#                    VARIABLE CUSTOMIZATION BEGINS HERE                               #
#######################################################################################

#NOTE: YOU MUST SET THIS TO A GLOBALLY ACCESSIBLE PATH WHERE YOUR prefs.json WILL BE STORED
$preferenceFileLocation              = "prefs.json"

#######################################################################################
#                      VARIABLE CUSTOMIZATION ENDS HERE                               #
#######################################################################################

Write-Log -LogString 'Environment: Creating custom namespace'

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

Write-Log -LogString 'Environment: Implementing functions'
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
    Write-Log -LogString 'GenerateSQLConnection: Begin'
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
            Write-Log -LogString 'GenerateSQLConnection: Sucessfully instantiated SQLConnection object'
            return $c
        } catch {
            Write-Log -LogString 'GenerateSQLConnection: Failed to instantiate SQLConnection object'
            return $null
        }
    } else {
            Write-Log -LogString 'GenerateSQLConnection: Invalid server name'
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
    Write-Log -LogString 'CloseSQLConnection: Closed connection and disposed of SQLConnection object'
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
    Write-Log -LogString "MapDrive: Begin attempt to map $UNC"
    try {
        $null = ([System.IO.DirectoryInfo]::new($UNC)).GetDirectories()
    } catch {
        Write-Log -LogString "MapDrive: Function exited.  User does not have rights to $UNC"
        return $null
    }
    if ($Letter -match '(?<letter>[A-Za-z])') {
        $Letter = -join($Matches.letter, ':')
    } else {
        Write-Log -LogString "MapDrive: Invalid drive letter '$letter'"
        return $null
    }
    if ($Letter.Substring(0,1) -in (Get-PSDrive | Select-Object Name).Name) {
        Write-Log -LogString "MapDrive: Skipped already mapped '$letter'"
        return $null
    }
    try {
        net use $letter $unc /PERSISTENT:YES
        Write-Log -LogString "MapDrive: Sucessfully mapped drive $letter."
    } catch {
        Write-Log -LogString "MapDrive: Net use command failed with letter $letter and path $unc"
        return $false
    }
    trap [System.UnauthorizedAccessException] {
        Write-Log -LogString "MapDrive: Function exited.  User does not have rights to $UNC"
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
        [System.Collections.Generic.List[String]]$LocationList,
        [System.Collections.Generic.List[Hashtable[]]]$MappingList,
        [System.Collections.Generic.List[Hashtable]]$GlobalMaps
    )
    Write-Log -LogString 'MapAllDrives: Begin'
    if ($GlobalMaps) {
        Write-Log -LogString 'MapAllDrives: GlobalMaps'
        foreach ($Mapping in $GlobalMaps) {
            $null = MapDrive -Letter $Mapping.Letter -UNC $Mapping.UNC
        }
    }
    if (($Location -eq $LocationList[$LocationList.Count-1]) -or ($null -eq $Location) -or ($Location.Length -eq 0)) {
        Write-Log -LogString 'MapAllDrives: DefaultMaps'
        foreach ($Mapping in $MappingList[$LocationList.Count-1]) {
            $null = MapDrive -Letter $Mapping.Letter -UNC $Mapping.UNC
        }
        return
    }
    for($i=0;$i -lt $LocationList.Count-1;$i++) {
        if ($Location -eq $LocationList[$i]) {
            Write-Log -LogString 'MapAllDrives: LocationMaps'
            foreach ($Mapping in $MappingList[$i]) {
                $null = MapDrive -Letter $Mapping.Letter -UNC $Mapping.UNC
            }
            break
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
                Write-Log -LogString "MapDrive: Sucessfully unmapped drive $letter."
            } catch {
                Write-Log -LogString "UnmapDrive: failed to unmap drive $letter.  Not unexpected"
            }
        } else {
            Write-Log -LogString "UnmapDrive: Invalid drive letter '$letter'"
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
        Write-Log -LogString 'Get-UserDN: Retreived DN for user'
        return $dn
    } catch {
        Write-Log -LogString 'Get-UserDN: Failed to retreive DN for user'
        return $null
    }
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
        [switch]$LogToTS
    )
    $pattern = -join('^', $Global:SiteCode, 'TS.*$')
    if (-not $LogToTS -and ($env:computername -match $pattern)) {
        Write-Log -LogString 'Logging: Logging skipped due to Terminal Server rule'
        return $null
    }

    $LogToFile = [boolean](($MachineLogs -and $LogToFile) -or ($MachineStats -and $LogToFile) -or ($UserLogon -and $LogToFile) -or ($ComputerLogon -and $LogToFile))
    $LogToDb = [boolean]($connection -and $LogToDB)

    if (-not $LogToDB -and -not $LogToFile) {
        Write-Log -LogString 'Logging: Logging skipped because LogToDB and LogToFile are both off'
        return $null
    }

    Write-Log -LogString 'Logging: Logging not skipped by TS or logging options'

    $userDN = Get-UserDN
    if ($null -ne $env:LOGONSERVER) {
        try {
            $logonServerFQDN = [string]([System.Net.Dns]::GetHostByName($($env:LOGONSERVER.Replace('\\',''))).hostname)
        } catch {
            Write-Log -LogString "Logging: Failed to get FQDN for logonserver. $($_)"
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
        if ($MachineLogs) {
            Add-Content -Value $LogEntry1 -LiteralPath $Destination1
        }
        if ($MachineStats) {
            Add-Content -Value $LogEntry2.ToString() -LiteralPath $Destination2
        }
        if ($UserLogon) {
            Add-Content -Value $LogEntry3 -LiteralPath $Destination3
        }
        if ($ComputerLogon) {
            Add-Content -Value $LogEntry3 -LiteralPath $Destination4
        }
    }

    if ($LogToDB) {
        Write-Log -LogString 'Logging: Collecting adapter data'
        $data = (ipconfig /all)
        $adapters = New-Object System.Collections.Generic.List[PSObject]
        $adapter = $null
        foreach ($line in $data) {
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
                    $IPAddress = $Matches.ip
                }
                Write-Log -LogString "General: Workstation IP: $IPAddress"
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
            Write-Log -LogString 'Logging: Generating LoginDataInsert object'
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
        } catch {
            Write-Log -LogString "Logging: Failed to assign parameter for LoginDataInsert. $_"
        }
        if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
            try {
                $connection.Open()
            } catch {
                Write-Log -LogString "Logging: Failed to open connection. $($_.Exception)"
            }
        }
        try {
            [void]$cmd.ExecuteNonQuery()
            Write-Log -LogString 'Logging: Execution of LogonDataInsert succeeded.'
        } catch {
            Write-Log -LogString "Logging: Failed to execute stored procedure LogonDataInsert. $($_.Exception)"
        }
        Write-Log -LogString "Logging: Adapter count: $($Adapters.Count)"
        foreach ($Adapter in $Adapters) {
            if ($null -eq $Adapter.desc) {continue}
            Write-Log -LogString 'Logging: Generating AdapterInsertObject'
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
                Write-Log -LogString "Logging: Failed to assign parameter for AdapterInsert. $_"
            }
            if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
                try {
                    $connection.Open()
                } catch {
                    Write-Log -LogString "Logging: Failed to open connection. $($_.Exception)"
                }
            }
            try {
                [void]$cmd.ExecuteNonQuery()
                Write-Log -LogString "Logging: Execution of AdapterInsert succeeded. $($_.Exception)"
            } catch {
                Write-Log -LogString "Logging: Failed to execute stored procedure AdapterInsert. $($_.Exception)"
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
        Write-Log -LogString "Logging: General uncaught error. $($_)"
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
                Write-Log -LogString "PrinterLogging: Failed to open connection. $($_.Exception)"
            }
        }
        try {
            [void]$cmd.ExecuteNonQuery()
            Write-Log -LogString "PrinterLogging: Execution of PrinterInsert succeeded. $($_.Exception)"
        } catch {
            Write-Log -LogString "PrinterLogging: Failed to execute stored procedure PrinterInsert. $($_.Exception)"
        }
        trap {
            Write-Log -LogString "PrinterLogging: General uncaught error. $($_)"
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
        [Microsoft.SqlServer.Server.SqlMetaData[]]$app_tbltype = @(
            [Microsoft.SqlServer.Server.SqlMetaData]::new("applicationname", [System.Data.SqlDbType]::VarChar, -1)
        )
        $applist = New-Object 'System.Collections.Generic.List[Microsoft.SqlServer.Server.SqlDataRecord]'
        foreach ($app in $list) {
            [Microsoft.SqlServer.Server.SqlDataRecord]$app_rec = [Microsoft.SqlServer.Server.SqlDataRecord]::new($app_tbltype)
            $app_rec.SetString($app_rec.GetOrdinal("applicationname"), [string]($app.APPLICATION))
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
                Write-Log -LogString "AppLogging: Failed to open connection. $($_.Exception)"
            }
        }
        try {
            [void]$cmd.ExecuteNonQuery()
            Write-Log -LogString 'AppLogging: Execution of ApplicationInsert succeeded.'
        } catch {
            Write-Log -LogString "AppLogging: Failed to execute stored procedure ApplicationInsert. $($_.Exception)"
        }
        trap {
            Write-Log -LogString "AppLogging: General uncaught error. $($_)"
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
        if ([System.IO.Directory]::Exists($OneDrive)) {
            foreach ($destination in $destinations) {
                Set-ItemProperty -Path $destination -Name 'Personal' -Value "$($OneDrive)\Documents"
                Set-ItemProperty -Path $destination -Name 'My Music' -Value "$($OneDrive)\My Music"
                Set-ItemProperty -Path $destination -Name 'My Pictures' -Value "$($OneDrive)\My Pictures"
                Set-ItemProperty -Path $destination -Name 'My Video' -Value "$($OneDrive)\My Video"
            }
        } else {
            foreach ($destination in $destinations) {
                Set-ItemProperty -Path $destination -Name 'Personal' -Value "$($env:USERPROFILE)\Documents"
                Set-ItemProperty -Path $destination -Name 'My Music' -Value "$($env:USERPROFILE)\My Music"
                Set-ItemProperty -Path $destination -Name 'My Pictures' -Value "$($env:USERPROFILE)\My Pictures"
                Set-ItemProperty -Path $destination -Name 'My Video' -Value "$($env:USERPROFILE)\My Video"
            }
        }
        Write-Log -LogString 'ProfileRediction: Modified user shell folders'
    } catch {
        Write-Log -LogString 'ProfileRediction: Failed to modify user shell folders'
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

Function IAItemRemoval {
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
        Write-Log -LogString 'HardwareInventory: Logging skipped due to Terminal Server rule'
        return $null
    }

    $LogToFile = [boolean]($TargetPath -and $LogToFile)
    if (-not $LogToFile -and -not $LogToDb) {
        Write-Log -LogString 'HardwareInventory: Logging skipped because LogToDB and LogToFile are both off'
        return $null
    }
    Write-Log -LogString 'HardwareInventory: Collecting hardware data'
    $HardwareDataPath = "HKCU:\System\CurrentControlSet\Control\$Global:SiteCode"
    if (-not (Test-Path $HardwareDataPath)) {
        Write-Log -LogString 'HardwareInventory: BIOS Data not cached. Generating registry cache.'
        $null = New-Item -Path "HKCU:\System\CurrentControlSet\Control" -Name $Global:SiteCode
        $bios = Get-CimInstance -ClassName Win32_Bios
        $null = New-ItemProperty -Path $HardwareDataPath -Name SN -Value $bios.SerialNumber
    } else {
        Write-Log -LogString "HardwareInventory: BIOS data cached in registry. Skipping Win32_Bios"
    }
    $data = Get-ItemProperty -Path $HardwareDataPath
    Write-Log -LogString 'HardwareInventory: Fetching CPU Count from Windows API'
    $CoreCount = ([Gibson.HardwareStats]::GetLogicalProcessorInformation() | ? {$_.Relationship -eq 'RelationProcessorCore'}).Count
    Write-Log -LogString 'HardwareInventory: Fetching CPU data from Registry'
    $CPUName = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name ProcessorNameString).ProcessorNameString
    $arch = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment\" -Name PROCESSOR_ARCHITECTURE).PROCESSOR_ARCHITECTURE
    $Manufacturer = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS" -Name SystemManufacturer).SystemManufacturer
    $Model = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS" -Name SystemProductName).SystemProductName
    $SN = $data.SN

    Write-Log -LogString 'HardwareInventory: Parsing ipconfig'
    if ($null -eq $IP) {
        $IP = foreach ($line in $(ipconfig)) {if ($line -match 'IPv4\sAddress(?:\.\s)+:\s(?<ip>(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))') {$Matches.ip}}
    }

    $ver = [System.Environment]::OSVersion.Version.ToString()
    Write-Log -LogString 'HardwareInventory: Fetching RAM from Windows API'
    $mem = [math]::Ceiling(([Gibson.HardwareStats]::GetTotalMem())/1GB)
    Write-Log -LogString 'HardwareInventory: Fetching HDD data from Windows API'
    foreach ($drive in $([System.IO.DriveInfo]::GetDrives())) {if ($drive.Name -eq 'C:\') {$hdd = [int]($drive.TotalSize/1GB)}}

    $regInstallDate =  Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' | select -ExpandProperty InstallDate
    $convertedInstallDate = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromSeconds($regInstallDate))

    $uptime = New-Object System.Diagnostics.PerformanceCounter("System", "System Up Time")
    $uptime.NextValue()
    $lastboot = [DateTime]::Now.Subtract(([TimeSpan]::FromSeconds($uptime.NextValue())))

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
        Write-Log -LogString 'HardwareInventory: Generating StatInsert object'
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

        if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
            try {
                $connection.Open()
            } catch {
                Write-Log -LogString "HardwareInventory: Failed to open connection. $($_.Exception)"
            }
        }
        try {
            [void]$cmd.ExecuteNonQuery()
            Write-Log -LogString 'HardwareInventory: Execution of StatInsert succeeded.'
        } catch {
            Write-Log -LogString "HardwareInventory: Failed to execute stored procedure StatInsert. $($_.Exception)"
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
    if (Test-Path $env:HOMESHARE) {
        $basedir = $env:HOMESHARE
    } elseif (Test-Path "$($env:USERPROFILE)\OneDrive - militaryhealth") {
        $basedir = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    } else {
        $basedir = $env:USERPROFILE
    }

    if (Test-Path "$basedir\noalert.txt") {
        Write-Log -LogString 'CheckForAlert: Exempt'
        return $null
    }

    #If we aren't doing periodic alerts, just forward to CallAlert and move on
    if (-not $doPeriodic) {
        Write-Log -LogString 'CheckForAlert: Non-periodic CallAlert'
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
        Write-Log -LogString 'CheckForAlert: Periodic CallAlert'
        return CallAlert -AlertFile $AlertFile -RunOnServer:$RunOnServer
    } else {
        Write-Log -LogString 'CheckForAlert: Out of phase for periodic CallAlert'
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
    if (Test-Path $env:HOMESHARE) {
        $basedir = $env:HOMESHARE
    } elseif (Test-Path "$($env:USERPROFILE)\OneDrive - militaryhealth") {
        $basedir = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    } else {
        $basedir = $env:USERPROFILE
    }

    if (Test-Path $AlertFile) {
        Write-Log -LogString 'CallAlert: Alert file exists.'
        Invoke-Item $AlertFile
        Set-Content -Path "$basedir\alert.txt" -Value $null
        $(Get-Item "$basedir\alert.txt").lastwritetime=$(Get-Date)
    } else {
        return $null
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
    Write-Log -LogString 'HideWindow: Begin'
    if (-not (Test-Path variable:global:psISE)) {
        Add-Type -Name win -Member '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);' -Namespace native
        [native.win]::ShowWindow([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle, 0)
        Write-Log -LogString 'HideWindow: Hidden.'
    } else {
        Write-Log -LogString 'HideWindow: Not hidden.'
    }
}

#######################################################################################
#                        PREFERENCE LOAD AND PARSE                                    #
#######################################################################################

Write-Log -LogString 'Environment: Preference structure'
$prefs                               = Get-Content $preferenceFileLocation | ConvertFrom-Json
Write-Log -LogString 'Environment: Loaded preference file to memory'

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
$DatabaseServer                      = $prefs.DatabaseVariables.DatabaseServer
$Database                            = $prefs.DatabaseVariables.DatabaseName
$LogToFiles                          = $prefs.LoggingOverrides.LogToFiles
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

Write-Log -LogString 'Environment: Generated simple variables from preferences'
if ($prefs.FunctionExecution.HideWindow) {
    $null = HideWindow
}

$LocationList                        = New-Object System.Collections.Generic.List[String]
$MappingList                         = New-Object System.Collections.Generic.List[Hashtable[]]
$GlobalMaps                          = New-Object System.Collections.Generic.List[Hashtable]
foreach ($map in $prefs.MappingVariables.GlobalMaps) {
    $GlobalMaps.Add(@{Letter=$map.Letter;UNC=$map.UNC})
}
foreach ($locationmap in $prefs.MappingVariables.LocationMaps) {
    $LocationList.Add($locationmap.Name)
    $temp = New-Object System.Collections.Generic.List[Hashtable]
    foreach ($mapping in $locationmap.Mappings) {
        $temp.Add(@{Letter=$mapping.Letter;UNC=$mapping.UNC})
    }
    $MappingList.Add($temp)
}
$defaultmaps = New-Object System.Collections.Generic.List[Hashtable]
foreach ($map in $prefs.MappingVariables.DefaultMaps.Mappings) {
    $defaultmaps.Add(@{Letter=$map.Letter;UNC=$map.UNC})
}
foreach ($default in $prefs.MappingVariables.DefaultMaps.PermittedNames) {
    $LocationList.Add($default)
    $MappingList.Add($defaultmaps)
}

Write-Log -LogString 'Environment: Generated data structures from preferences'

if ($LogToDatabase) {
    $connection = GenerateSQLConnection -ServerName $DatabaseServer -DBName $Database
    Write-Log -LogString 'Environment: Testing SQLConnection object'
    try {
        $connection.Open()
        $connection.Close()
        Write-Log -LogString 'Environment: SQLConnection object valid'
    } catch {
        Write-Log -LogString 'Environment: Failed to open SQL connection.  Falling back to file logging'
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
if ($prefs.FunctionExecution.Logging) {
    $IP = Logging -MachineLogs $MachineLogsLoc -MachineStats $MachineStatsLoc -UserLogon $UserLogonLoc -ComputerLogon $ComputerLogonLoc -connection $connection -LogToFile:$LogToFiles -LogToDB:$LogToDatabase -LogToTS:$LogTSData
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
if ($prefs.FunctionExecution.ProfileRedirection) {
    ProfileRedirection
}
if ($prefs.FunctionExecution.IARemoval) {
    IndividualFileManagement
}
if ($prefs.FunctionExecution.FastLog) {
    Write-Log -LogString 'Environment: Writing fastlog'
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
# Each function that uses the connection should open and close the connection independently, but this is good housekeeping
# To ensure dangling connections aren't left
if ($connection) {
    CloseSQLConnection -Connection $connection
}
if ($prefs.LoggingOverrides.LogDebugData) {
    $fileName = "$($env:USERNAME).txt"
    $destination = -join($prefs.FileVariables.DebugLogLoc, $fileName)
    Write-Log -LogString ""
    $Global:DebugWriter.ToString() | Set-Content -Path $destination -Force
}
exit

# General exception trap to close the $connection if it exists
trap {
    Write-Log -LogString "Global: General uncaught error. $($_)"
    if ($connection -and ($connection.State -ne [System.Data.ConnectionState]::Closed)) {
        $connection.Close()
    }
    continue
}
