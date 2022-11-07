<#
.SYNOPSIS
    Consolidated logon script
.NOTES
    Name: logonLCI.ps1
    Author: Nick Gibson
    Version: 2.3
    DateCreated: 19 Oct 2022
    Variables that must be set
.PARAMETER Location
    Allows alternate drive mapping
.PARAMETER UseSQL
    Allows specification at invocation if SQL logging is enabled
.INPUTS
    None. You cannot pipe objects to this script
.OUTPUTS
    None.
.CHANGELOG
    19 Oct 2022: Initial creation
    19 Oct 2022: Bugfix: Account for multiple sticks of RAM
    20 Oct 2022: Added SQL functionality
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
#>
param (
    [string]$Location,
    [switch]$UseSQL,
    [switch]$debug
)

$Global:DebugWriter = New-Object System.Text.StringBuilder
$Global:DoDebug = [boolean]$debug
$Global:DebugWriter.AppendLine($env:USERNAME) | Out-Null
$Global:DebugWriter.AppendLine($env:COMPUTERNAME) | Out-Null
$Global:DebugWriter.AppendLine($(Get-Date)) | Out-Null

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
    if ($ServerName -match '(?=^\\\\)?(?<server>[a-z0-9-]*)$') {
        $connectionString = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
        $connectionString["Server"] = $Matches.server
        $connectionString["Initial Catalog"] = $Database
        if ($Username -and $Password) {
            $connectionString["Persist Security Info"] = $false
            $connectionString["User ID"] = $Username
            $connectionString["Password"] = $Password.ToString()
        } else {
            $connectionString["Integrated Security"] = $true            
        }
        try {
            $c = New-Object System.Data.SqlClient.SQLConnection($connectionString.ToString())
            $Global:DebugWriter.AppendLine("$(Get-Date): GenerateSQLConnection: Sucessfully instantiated SQLConnection object") | Out-Null
            return $c
        } catch {
            $Global:DebugWriter.AppendLine("$(Get-Date): GenerateSQLConnection: Failed to instantiate SQLConnection object") | Out-Null
            return $null
        }
    } else {
        $Global:DebugWriter.AppendLine("$(Get-Date): GenerateSQLConnection: Invalid server name") | Out-Null
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
    $Global:DebugWriter.AppendLine("$(Get-Date): CloseSQLConnection: Closed connection and disposed of SQLConnection object") | Out-Null
}

Function MapDrive {
<#
.SYNOPSIS
    Creates smb drive mappings using New-PSDrive
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
    Get-Acl $UNC | Out-Null
    if ($Letter -match '(?<letter>[A-Za-z])') {
        $Letter = -join($Matches.letter, ':')
    } else {
        $Global:DebugWriter.AppendLine("$(Get-Date): MapDrive: Invalid drive letter '$letter'") | Out-Null
        return $null
    }
    try {
        net use $letter $unc /PERSISTENT:YES
        $Global:DebugWriter.AppendLine("$(Get-Date): MapDrive: Sucessfully mapped drive $letter.") | Out-Null
    } catch {
        $Global:DebugWriter.AppendLine("$(Get-Date): MapDrive: Net use command failed with letter $letter and path $unc") | Out-Null
        return $false
    }
    trap [System.UnauthorizedAccessException] {
        $Global:DebugWriter.AppendLine("$(Get-Date): MapDrive: Function exited.  User does not have rights to $UNC") | Out-Null
    }
}

Function UnmapDrive {
<#
.SYNOPSIS
    Unmaps one or more drives as a wrapper for Remove-PSDrive and Remove-SmbMapping
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
                $Global:DebugWriter.AppendLine("$(Get-Date): MapDrive: Sucessfully unmapped drive $letter.") | Out-Null
            } catch {
                $Global:DebugWriter.AppendLine("$(Get-Date): UnmapDrive: failed to unmap drive $letter.  Not unexpected") | Out-Null
            }
        } else {
            $Global:DebugWriter.AppendLine("$(Get-Date): UnmapDrive: Invalid drive letter '$letter'") | Out-Null
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
    if ((Get-Date).IsDaylightSavingTime()) {
        $middle = 'D'
    } else {
        $middle = 'S'
    }
    (Get-TimeZone).DisplayName -match '\((?<offset>UTC[+|-]\d{2}:\d{2})\).*' | Out-Null
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
        $Global:DebugWriter.AppendLine("$(Get-Date): Get-UserDN: Retreived DN for user") | Out-Null
        return $dn
    } catch {
        $Global:DebugWriter.AppendLine("$(Get-Date): Get-UserDN: Failed to retreive DN for user") | Out-Null
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
        $Global:DebugWriter.AppendLine("$(Get-Date): Logging: Logging skipped due to Terminal Server rule") | Out-Null
        return $null
    } 

    $LogToFile = [boolean](($MachineLogs -and $LogToFile) -or ($MachineStats -and $LogToFile) -or ($UserLogon -and $LogToFile) -or ($ComputerLogon -and $LogToFile))
    $LogToDb = [boolean]($connection -and $LogToDB)

    if (-not $LogToDB -and -not $LogToFile) {
        $Global:DebugWriter.AppendLine("$(Get-Date): Logging: Logging skipped because LogToDB and LogToFile are both off") | Out-Null
        return $null
    }

    $userDN = Get-UserDN
    if ($null -ne $env:LOGONSERVER) {
        try {
            $logonServerFQDN = [string]([System.Net.Dns]::GetHostByName($($env:LOGONSERVER.Replace('\\',''))).hostname)
        } catch {
            $Global:DebugWriter.AppendLine("$(Get-Date): Logging: Failed to get FQDN for logonserver. $($_)") | Out-Null
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
        foreach ($e in (gci env:)) {
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
    if ($LogToDB -and $connection) {
        if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
            try {
                $connection.Open()
            } catch {
                $Global:DebugWriter.AppendLine("$(Get-Date): Logging: Failed to open connection. $($_.FullyQualifiedErrorId)") | Out-Null
            }
        }
        $Adapters = Get-NetAdapter | Select Name, status, InterfaceDescription, IP, MacAddress, ifIndex, InterfaceType, DriverFileName
        foreach ($adapter in $Adapters) {
            $IP = [string]((Get-NetIPAddress | Where-Object {$_.InterfaceIndex -eq $adapter.ifIndex} | Select-Object -Property IPAddress).IPAddress)
            $adapter.IP=$IP
        }
        $Adapter = $Adapters | 
            Where-Object {$_.Status -eq 'Up' -and $_.DriverFileName -ne "vmnetadapter.sys" -and -not [string]::IsNullOrEmpty($_.IP)} | 
            Select-Object -First 1
        try {
            $MACAddress = [string]($Adapter.MacAddress)
            if ($Adapter.IP -match '(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])') {
                $IPAddress = $Matches[0]
            } else {
                $IPAddress = [string]($Adapter.IP)
            }

            $cmd = New-Object System.Data.SqlClient.SqlCommand
            $cmd.Connection = $connection

            $cmd.CommandType = [System.Data.CommandType]::StoredProcedure
            $cmd.CommandText = "dbo.LoginDataInsert"

            $cmd.Parameters.Add("@UserDN", [System.Data.SqlDbType]::NVarChar) | Out-Null
            $cmd.Parameters["@UserDN"].Value = [string]($userDN)

            $cmd.Parameters.Add("@UPN", [System.Data.SqlDbType]::Char) | Out-Null
            $cmd.Parameters["@UPN"].Value = [string](whoami /upn)

            $cmd.Parameters.Add("@IP", [System.Data.SqlDbType]::VarChar) | Out-Null
            $cmd.Parameters["@IP"].Value = [string]($IPAddress)

            $cmd.Parameters.Add("@MAC", [System.Data.SqlDbType]::Char) | Out-Null
            $cmd.Parameters["@MAC"].Value = [string]($MACAddress)

            $cmd.Parameters.Add("@DC", [System.Data.SqlDbType]::VarChar) | Out-Null

            if ($logonServerFQDN) {
                $cmd.Parameters["@DC"].Value = [string]($logonServerFQDN)
            } else {
                $cmd.Parameters["@DC"].Value = [System.DBNull]::Value
            }
        } catch {
            $Global:DebugWriter.AppendLine("$(Get-Date): Logging: Failed to assign parameter for LoginDataInsert. $_") | Out-Null
        }

        try {
            $cmd.ExecuteNonQuery() | Out-Null
            $Global:DebugWriter.AppendLine("$(Get-Date): Logging: Execution of LogonDataInsert succeeded.") | Out-Null
        } catch {
            $Global:DebugWriter.AppendLine("$(Get-Date): Logging: Failed to execute stored procedure LogonDataInsert. $($_.Exception)") | Out-Null
        }

        foreach ($Adapter in $Adapters) {
            $cmd = New-Object System.Data.SqlClient.SqlCommand
            $cmd.Connection = $connection
            $cmd.CommandType = [System.Data.CommandType]::StoredProcedure
            $cmd.CommandText = "dbo.AdapterInsert"

            try {
                $cmd.Parameters.Add("@AdapterName", [System.Data.SqlDbType]::VarChar) | Out-Null
                $cmd.Parameters["@AdapterName"].Value = [string]($adapter.Name)

                $cmd.Parameters.Add("@AdapterState", [System.Data.SqlDbType]::VarChar) | Out-Null
                $cmd.Parameters["@AdapterState"].Value = [string]($adapter.Status)

                $cmd.Parameters.Add("@AdapterDesc", [System.Data.SqlDbType]::VarChar) | Out-Null
                $cmd.Parameters["@AdapterDesc"].Value = [string]($Adapter.InterfaceDescription)

                $cmd.Parameters.Add("@IP", [System.Data.SqlDbType]::VarChar) | Out-Null
                if ($adapter.IP) {
                    $cmd.Parameters["@IP"].Value = [string]($adapter.IP)
                } else {
                    $cmd.Parameters["@IP"].Value = [System.DBNull]::Value
                }
                $cmd.Parameters.Add("@MAC", [System.Data.SqlDbType]::Char) | Out-Null
                $cmd.Parameters["@MAC"].Value = [string]($adapter.MacAddress)
            } catch {
                $Global:DebugWriter.AppendLine("$(Get-Date): Logging: Failed to assign parameter for AdapterInsert. $_") | Out-Null
            }

            try {
                $cmd.ExecuteNonQuery() | Out-Null
                $Global:DebugWriter.AppendLine("$(Get-Date): Logging: Execution of AdapterInsert succeeded. $($_.Exception)") | Out-Null
            } catch {
                $Global:DebugWriter.AppendLine("$(Get-Date): Logging: Failed to execute stored procedure AdapterInsert. $($_.Exception)") | Out-Null
            }
        }
        $connection.Close()
    }
    if (Test-Path Variable:\IP) {
        return $IP
    } else {
        return $null
    }
    trap {
        $Global:DebugWriter.AppendLine("$(Get-Date): Logging: General uncaught error. $($_)") | Out-Null
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

    $osCaption = (Get-WmiObject -Class Win32_OperatingSystem -Property Caption | Select Caption).caption
    If ($osCaption -like '*server*') {
        return $null
    }

    $LogToFile = [boolean]($TargetPath -and $LogToFile)
    $LogToDb = [boolean]($connection -and $LogToDB)

    if (-not $LogToDB -and -not $LogToFile) {
        return $null
    }

    $Printers = Get-WmiObject -Class Win32_Printer -Property *
    $Printers | Add-Member -MemberType NoteProperty -Name Computer -Value $env:COMPUTERNAME
    $Printers | Add-Member -MemberType NoteProperty -Name User -Value $env:USERNAME
    $Printers = $Printers | Select-Object Computer, User, @{label='PORT';expression={$_.Portname}}, Network, Name, Location, Servername, ShareName, @{label='INAD';expression={$_.Published}}, DriverName, Local_TCPIPPort
    foreach ($printer in $Printers) {
        foreach ($port in (Get-WmiObject -Class Win32_TCPIPPrinterPort)) {
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
        if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
            $connection.Open()
        }
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

        $cmd.Parameters.Add("@PrinterList", [System.Data.SqlDbType]::Structured) | Out-Null
        $cmd.Parameters["@PrinterList"].Direction = [System.Data.ParameterDirection]::Input
        $cmd.Parameters["@PrinterList"].TypeName = "dbo.PrinterList"
        $cmd.Parameters["@PrinterList"].Value = $printerlist

        try {
            $cmd.ExecuteNonQuery() | Out-Null
            $Global:DebugWriter.AppendLine("$(Get-Date): PrinterLogging: Execution of PrinterInsert succeeded. $($_.Exception)") | Out-Null
        } catch {
            $Global:DebugWriter.AppendLine("$(Get-Date): PrinterLogging: Failed to execute stored procedure PrinterInsert. $($_.Exception)") | Out-Null
        }
        trap {
            $Global:DebugWriter.AppendLine("$(Get-Date): PrinterLogging: General uncaught error. $($_)") | Out-Null
            continue
        }
        $connection.Close()
    }

    if (($null -ne $PrinterToAdd) -and -not ($Printers | ? {$_.Name -eq $PrinterToAdd})) {
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
    if (-not $LogToTS -and ($env:computername -match $pattern)) {{
        return $null
    } 

    $LogToFile = [boolean]($TargetPath -and $LogToFile)
    $LogToDb = [boolean]($connection -and $LogToDB)

    if (-not $LogToFile -and -not $LogToDb) {
        return $null
    }

    $list = New-Object System.Collections.Generic.List[PSObject]
    $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'=$((Get-WmiObject -Class Win32_OperatingSystem -Property Caption | Select Caption).caption)})
    foreach ($key in (gci HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\)) {
        if ($null -eq $key.GetValue('QuietDisplayName') -and $null -ne $key.GetValue('DisplayName')) {
            $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'=$($key.GetValue('DisplayName'))})
        } elseif ($null -ne $key.GetValue('QuietDisplayName') -and $null -eq $key.GetValue('DisplayName')) {
            $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'=$($key.GetValue('QuietDisplayName'))})
        } elseif ($null -ne $key.GetValue('QuietDisplayName') -and $null -ne $key.GetValue('DisplayName')) {
            $list.add([PSCustomObject]@{'COMPUTERNAME'=$env:COMPUTERNAME;'USERNAME'=$env:USERNAME;'APPLICATION'="$($key.GetValue('DisplayName'))/$($key.GetValue('QuietDisplayName'))"})
        }
    }
    foreach ($key in (gci HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\)) {
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
        if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
            $connection.Open()
        }
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

        $cmd.Parameters.Add("@ApplicationList", [System.Data.SqlDbType]::Structured) | Out-Null
        $cmd.Parameters["@ApplicationList"].Direction = [System.Data.ParameterDirection]::Input
        $cmd.Parameters["@ApplicationList"].TypeName = "dbo.ApplicationList"
        $cmd.Parameters["@ApplicationList"].Value = $applist

        try {
            $cmd.ExecuteNonQuery() | Out-Null
            $Global:DebugWriter.AppendLine("$(Get-Date): AppLogging: Execution of ApplicationInsert succeeded.") | Out-Null
        } catch {
            $Global:DebugWriter.AppendLine("$(Get-Date): AppLogging: Failed to execute stored procedure ApplicationInsert. $($_.Exception)") | Out-Null
        }
        trap {
            $Global:DebugWriter.AppendLine("$(Get-Date): AppLogging: General uncaught error. $($_)") | Out-Null
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
        $shellFolders = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        $userShellFolders = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        $destinations = $shellFolders, $userShellFolders
        foreach ($destination in $destinations) {
            Set-ItemProperty -Path $destination -Name 'Personal' -Value "$($env:HOMESHARE)"
            Set-ItemProperty -Path $destination -Name 'My Music' -Value "$($env:HOMESHARE)\My Music"
            Set-ItemProperty -Path $destination -Name 'My Pictures' -Value "$($env:HOMESHARE)\My Pictures"
            Set-ItemProperty -Path $destination -Name 'My Video' -Value "$($env:HOMESHARE)\My Video"
        }
        $Global:DebugWriter.AppendLine("$(Get-Date): ProfileRediction: Modified user shell folders") | Out-Null
    } catch {
        $Global:DebugWriter.AppendLine("$(Get-Date): ProfileRediction: Failed to modify user shell folders") | Out-Null
    }
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
        $Global:DebugWriter.AppendLine("$(Get-Date): HardwareInventory: Logging skipped due to Terminal Server rule") | Out-Null
        return $null
    } 

    $LogToFile = [boolean]($TargetPath -and $LogToFile)
    $LogToDb = [boolean]($connection -and $LogToDB)

    if (-not $LogToFile -and -not $LogToDb) {
        $Global:DebugWriter.AppendLine("$(Get-Date): HardwareInventory: Logging skipped because LogToDB and LogToFile are both off") | Out-Null
        return $null
    }


    $cs = Get-WmiObject -Class Win32_ComputerSystem
    $bios = Get-WmiObject -Class Win32_Bios
    $cpu = Get-WmiObject -Class Win32_Processor
    if ($null -eq $IP) {
        $IP = [string]((Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1'}).IPAddress)
    }
    $ver = [System.Environment]::OSVersion.Version.ToString()
    $mem = (Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum/1MB
    $hdd = [int]((Get-Disk -Number 0 | Select size).size/1GB)

    if ($LogToFile) {
        $inv = [System.Text.StringBuilder]::new()
        [void]$inv.AppendLine($((Get-Date).ToString('ddd MM/dd/yyy')))
        [void]$inv.AppendLine("Computer Name: $($env:COMPUTERNAME)")
        [void]$inv.AppendLine("Manufacturer: $($cs.Manufacturer)")
        [void]$inv.AppendLine("Model: $($cs.Model)")
        [void]$inv.AppendLine("IPAddress: $IP")
        [void]$inv.AppendLine("Operating System: $ver")
        [void]$inv.AppendLine("Total Memory: $mem")
        $inv.ToString() | Out-File -FilePath "$($TargetPath)$($env:COMPUTERNAME).txt" -Force
    }
    if ($LogToDB) {
        if ($connection.State -eq [System.Data.ConnectionState]::Closed) {
            try {
                $connection.Open()
            } catch {
                $Global:DebugWriter.AppendLine("$(Get-Date): HardwareInventory: Failed to open connection. $($_.FullyQualifiedErrorId)") | Out-Null
            }
        }
        $cmd = New-Object System.Data.SqlClient.SqlCommand
        $cmd.Connection = $connection

        $cmd.CommandType = [System.Data.CommandType]::StoredProcedure
        $cmd.CommandText = "dbo.StatInsert"

        $cmd.Parameters.Add("@Cores", [System.Data.SqlDbType]::SmallInt) | Out-Null
        $cmd.Parameters["@Cores"].Value = [convert]::ToInt16($cpu.NumberofCores)

        $cmd.Parameters.Add("@Arch", [System.Data.SqlDbType]::VarChar) | Out-Null
        $cmd.Parameters["@Arch"].Value = $env:PROCESSOR_ARCHITECTURE

        $cmd.Parameters.Add("@Id", [System.Data.SqlDbType]::VarChar) | Out-Null
        $cmd.Parameters["@Id"].Value = $cpu.Name

        $cmd.Parameters.Add("@Manuf", [System.Data.SqlDbType]::VarChar) | Out-Null
        $cmd.Parameters["@Manuf"].Value = $cs.Manufacturer

        $cmd.Parameters.Add("@Model", [System.Data.SqlDbType]::VarChar) | Out-Null
        $cmd.Parameters["@Model"].Value = $cs.Model

        $cmd.Parameters.Add("@SN", [System.Data.SqlDbType]::VarChar) | Out-Null
        $cmd.Parameters["@SN"].Value = $bios.SerialNumber

        $cmd.Parameters.Add("@OSVer", [System.Data.SqlDbType]::VarChar) | Out-Null
        $cmd.Parameters["@OSVer"].Value = $ver

        $cmd.Parameters.Add("@Mem", [System.Data.SqlDbType]::SmallInt) | Out-Null
        $cmd.Parameters["@Mem"].Value = [convert]::ToInt16($mem)

        $cmd.Parameters.Add("@HDD", [System.Data.SqlDbType]::SmallInt) | Out-Null
        $cmd.Parameters["@HDD"].Value = [convert]::ToInt16($hdd)

        try {
            $cmd.ExecuteNonQuery() | Out-Null
            $Global:DebugWriter.AppendLine("$(Get-Date): HardwareInventory: Execution of StatInsert succeeded.") | Out-Null
        } catch {
            $Global:DebugWriter.AppendLine("$(Get-Date): HardwareInventory: Failed to execute stored procedure StatInsert. $($_.Exception)") | Out-Null
        }
        $connection.Close()
    }
}

Function CallAlert {
<#
.SYNOPSIS
    Uses invoke item to launch a file, optionally skipping execution on server OSes.
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
    $osCaption = (Get-WmiObject -Class Win32_OperatingSystem -Property Caption | Select Caption).caption
    If (($osCaption -like '*server*') -and ($RunOnServer -eq $false)) {
        return $null
    }
    if (Test-Path $AlertFile) {
        $Global:DebugWriter.AppendLine("$(Get-Date): CallAlert: Alert file exists.") | Out-Null
        Invoke-Item $AlertFile
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
    if (-not (Test-Path variable:global:psISE)) {
        $Global:DebugWriter.AppendLine("$(Get-Date): HideWindow: Hidden.") | Out-Null
        Add-Type -Name win -Member '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);' -Namespace native
        [native.win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)
    } else {
        $Global:DebugWriter.AppendLine("$(Get-Date): HideWindow: Not hidden.") | Out-Null
    }
}

# The following variables document the various locations that log files are written to.
# The value of these variables is only important if $LogToFiles is set to $true

$MachineLogsLoc         = ''
$MachineStatsLoc        = ''
$UserLogonLoc           = ''
$ComputerLogonLoc       = ''
$PrinterLogsLoc         = ''
$ApplicationLogsLoc     = ''
$HardwareInvLoc         = ''

# $AlertFile is the location of the item that is invoked for the on-logon alert.  This could be an HTA file,
# or an executable.  If the on-logon alert is changed to another powershell script, the CallAlert function
# should be modified to use a dot-source reference instead of Invoke-Item

$AlertFile              = ''

# $GlobalPrinter is used within the PrinterLogging function to add a single specified printer to all users
# If this is no longer desireable, $GlobalPrinter can be set to $null

$GlobalPrinter          = ''

# These variables are for writing logging data to a SQL Server database.
# The value of these variables is only important if $LogToDatabase is set to $true

$DatabaseServer         = ''
$Database               = ''

# The following specifies in all child functions if logging data should be written to files, a database, or both

$LogToFiles             = $false
$LogToDatabase          = $true

# Various localization

$Global:SiteCode              = ''
$DrivesToUnMap                = @('')
$LocationList                 = New-Object System.Collections.Generic.List[String]
$OUList                       = New-Object System.Collections.Generic.List[String]
$MappingList                  = New-Object System.Collections.Generic.List[Hashtable[]]
#Items must be added to LocationList, OUList, and MappingList as matched triplets
#Additionally, items added to MappingList must be an array of Hashtables with keys Letter and UNC
#Example:
#$LocationList.Add('Location1')
#$OUList.Add('OU1')
#$MappingList.Add((@{Letter='Y';UNC='\\server1\path1'},@{Letter='Z';UNC='\\server1\path2'}))
#The last item added will be treated as default

# Uncomment below section if using command-line switch to set UseSQL
#if ($UseSQL) {
#    $LogToDatabase      = $true
#} else {
#    $LogToDatabase      = $false 
#}

# The following specifies if certain logging functions should be disabled on terminal servers
$LogTSData              = $false

# Note: All functions either are set to a variable or piped to Out-Null.  This is to supress an error messages, and
# make explicit when and if functions should be returning or displaying data

if ($LogToDatabase) {
    $connection = GenerateSQLConnection -ServerName $DatabaseServer -DBName $Database
} else {
    $connection = $null
}

# A Note About Function Order
# HideWindow is first because we want to vanish as quickly as possible
# CallAlert is second because we want loading the alert to mask further processing
# Logging is third because it returns a value useful in HardwareInventory. Get-NetIPAddress costs 3.1s, so if we can only do it once, all the better
# PrinterLogging, AppLogging, and HardwareInventory are interchangable
# Next, drive mappings are cleared, re-established, and general misc work is done
# At this time, I believe the items in IAItemRemoval are no longer required, however the function remains as a placeholder for future IA requests

HideWindow | Out-Null
CallAlert -AlertFile $AlertFile  | Out-Null

#LOGGING
$IP = Logging -MachineLogs $MachineLogsLoc -MachineStats $MachineStatsLoc -UserLogon $UserLogonLoc -ComputerLogon $ComputerLogonLoc -connection $connection -LogToFile:$LogToFiles -LogToDB:$LogToDatabase -LogToTS:$LogTSData
HardwareInventory -TargetPath $HardwareInvLoc -IP $IP -connection $connection -LogToFile:$LogToFiles -LogToDB:$LogToDatabase -LogToTS:$LogTSData  | Out-Null
PrinterLogging -TargetPath $PrinterLogsLoc -PrinterToAdd $GlobalPrinter -connection $connection -LogToFile:$LogToFiles -LogToDB:$LogToDatabase -LogToTS:$LogTSData  | Out-Null
AppLogging -TargetPath $ApplicationLogsLoc -connection $connection -LogToFile:$LogToFiles -LogToDB:$LogToDatabase -LogToTS:$LogTSData  | Out-Null

#DRIVE MAINTENANCE
UnmapDrive -Letters $DrivesToUnMap | Out-Null
$UserDN = Get-UserDN
$UserDN -match '(?:CN=[^=]*,OU=)(?<topOU>[^,]*)' | Out-Null
$TopOU = $Matches.topOU

for($i=0;$i -lt $LocationList.Count-1;$i++) {
    if (($Location -eq $LocationList[$i]) -or ($TopOU -eq $OUList[$i])) {
        foreach ($Mapping in $MappingList[$i]) {
            MapDrive -Letter $Mapping.Letter -UNC $Mapping.UNC | Out-Null
        }
        break
    }
}
if (($Location -eq $LocationList[$LocationList.Count-1]) -or ($TopOU -eq $OUList[$LocationList.Count-1]) -or ($null -eq $Location) -or ($Location.Length -eq 0)) {
    foreach ($Mapping in $MappingList[$LocationList.Count-1]) {
        MapDrive -Letter $Mapping.Letter -UNC $Mapping.UNC | Out-Null
    }
}


#GENERAL MAINTENANCE
ProfileRedirection | Out-Null
IAItemRemoval | Out-Null

# Each function that uses the connection should open and close the connection independently, but this is good housekeeping
# To ensure dangling connections aren't left
if ($connection) {
    CloseSQLConnection -Connection $connection | Out-Null
}
if ($Global:DoDebug) {
    $fileName = "$($env:USERNAME).txt"
    $destination = -join($HardwareInvLoc, $fileName)
    $Global:DebugWriter.ToString() | Set-Content -Path $destination -Force
}
exit
# General exception trap to close the $connection if it exists
trap {
    $Global:DebugWriter.AppendLine("$(Get-Date): Global: General uncaught error. $($_)") | Out-Null
    if ($connection -and ($connection.State -ne [System.Data.ConnectionState]::Closed)) {
        $connection.Close()
    }
    continue
}
