/****** LINES 10 and 12 may have to be altered to meet the specifics of your SQL Server installation *****/
/****** Requires SQL Server 2016 / Compatibility Level 130 *****/

USE [master]
GO
/****** Object:  Database [EUDLogging]    Script Date: 9/21/2023 11:33:57 AM ******/
CREATE DATABASE [EUDLogging]
GO
ALTER DATABASE [EUDLogging] MODIFY FILE
( NAME = N'EUDLogging', SIZE = 3022848KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
GO
ALTER DATABASE [EUDLogging] MODIFY FILE
( NAME = N'EUDLogging_log', SIZE = 1843200KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
GO
ALTER DATABASE [EUDLogging] SET COMPATIBILITY_LEVEL = 130
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [EUDLogging].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [EUDLogging] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [EUDLogging] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [EUDLogging] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [EUDLogging] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [EUDLogging] SET ARITHABORT OFF 
GO
ALTER DATABASE [EUDLogging] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [EUDLogging] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [EUDLogging] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [EUDLogging] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [EUDLogging] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [EUDLogging] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [EUDLogging] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [EUDLogging] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [EUDLogging] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [EUDLogging] SET  DISABLE_BROKER 
GO
ALTER DATABASE [EUDLogging] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [EUDLogging] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [EUDLogging] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [EUDLogging] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [EUDLogging] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [EUDLogging] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [EUDLogging] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [EUDLogging] SET RECOVERY FULL 
GO
ALTER DATABASE [EUDLogging] SET  MULTI_USER 
GO
ALTER DATABASE [EUDLogging] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [EUDLogging] SET DB_CHAINING ON 
GO
ALTER DATABASE [EUDLogging] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [EUDLogging] SET TARGET_RECOVERY_TIME = 60 SECONDS 
GO
ALTER DATABASE [EUDLogging] SET DELAYED_DURABILITY = DISABLED 
GO
ALTER DATABASE [EUDLogging] SET ACCELERATED_DATABASE_RECOVERY = OFF  
GO
ALTER DATABASE [EUDLogging] SET QUERY_STORE = OFF
GO
USE [EUDLogging]
GO
/****** Object:  DatabaseRole [db_updater]    Script Date: 11/3/2023 7:48:34 AM ******/
CREATE ROLE [db_updater]
GO
/****** Object:  DatabaseRole [db_powersusers]    Script Date: 11/3/2023 7:48:34 AM ******/
CREATE ROLE [db_powersusers]
GO
/****** Object:  UserDefinedTableType [dbo].[ApplicationList]    Script Date: 9/21/2023 11:33:57 AM ******/
CREATE TYPE [dbo].[ApplicationList] AS TABLE(
	[applicationname] [varchar](max) NULL
)
GO
CREATE TABLE [dbo].[DMLSS](
	[Ecn5] [nvarchar](255) NULL,
	[Ecn] [nvarchar](255) NULL,
	[MfrSerialNo] [nvarchar](255) NULL,
	[AcqDate] [date] NULL,
	[Nomenclature] [nvarchar](255) NULL,
	[LifeExp] [nvarchar](255) NULL,
	[Manufacturer] [nvarchar](255) NULL,
	[CommonModel] [nvarchar](255) NULL,
	[EquipmentLocation] [nvarchar](255) NULL,
	[Ownership] [nvarchar](255) NULL,
	[CustomerName] [nvarchar](255) NULL,
	[CustodianViewCustdnPocSer] [nvarchar](255) NULL,
	[CustodianName] [nvarchar](255) NULL,
	[AcqCostLow] [money] NULL,
	[AcqCostHigh] [money] NULL,
	[RunDate] [datetime] NULL
) 
GO
/****** Object:  UserDefinedTableType [dbo].[PrinterList]    Script Date: 9/21/2023 11:33:57 AM ******/
CREATE TYPE [dbo].[PrinterList] AS TABLE(
	[printername] [varchar](50) NOT NULL,
	[port] [varchar](75) NULL,
	[network] [bit] NOT NULL,
	[location] [varchar](100) NULL,
	[servername] [varchar](25) NULL,
	[sharename] [varchar](50) NULL,
	[InAD] [bit] NOT NULL,
	[drivername] [varchar](100) NULL,
	[Local_TCPIPPort] [varchar](50) NULL
)
GO
/****** Object:  UserDefinedFunction [dbo].[ESTToUTC]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date, ,>
-- Description:	<Description, ,>
-- =============================================
CREATE FUNCTION [dbo].[ESTToUTC] 
(
	@InputDate sql_variant
)
RETURNS DateTime2
AS
BEGIN
	-- Declare the return variable here
	DECLARE @InputDate2 As DateTime2
	IF (TRY_CONVERT(Datetime2,@InputDate) IS NULL)
		RETURN NULL;
	SET @InputDate2 = TRY_CONVERT(Datetime2,@InputDate);
	RETURN (@InputDate2 AT TIME ZONE 'UTC');


END
GO
/****** Object:  UserDefinedFunction [dbo].[GetUserLoginData]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE FUNCTION [dbo].[GetUserLoginData] 
(
	@user varchar(20)
)
RETURNS 
@T TABLE 
(
	computername varchar(15),
	loggedOnUserSAM varchar(20),
	loggedOnUserUPN char(20),
	[timestamp] datetime2,
	[IP] varchar(15),
	MAC char(17),
	logonDC varchar(100)
)
AS
BEGIN
	DECLARE @LastTenDays int
	SELECT @LastTenDays = COUNT(DISTINCT logontimestamp) FROM EUDLoginData WHERE loggedOnUserSAM=@user AND logonTimestamp >= DATEADD(day,-10, GETDATE())
	IF (@LastTenDays >= 10)
		INSERT INTO @T 
			SELECT computername, loggedOnUserSAM, loggedOnUserUPN, dbo.UTCToEST(logontimestamp) AS [timestamp], IP, MAC, logonDC
				FROM EUDLoginData WHERE loggedOnUserSAM=@user AND logonTimestamp >= DATEADD(day,-10, GETDATE())
	ELSE
		INSERT INTO @T 
			SELECT TOP(10) computername, loggedOnUserSAM, loggedOnUserUPN, dbo.UTCToEST(logontimestamp) AS [timestamp], IP, MAC, logonDC
	            FROM EUDLoginData WHERE loggedOnUserSAM=@user
				ORDER BY logonTimestamp DESC
	RETURN
END
GO
/****** Object:  UserDefinedFunction [dbo].[GetUserLoginDataByDoDID]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE FUNCTION [dbo].[GetUserLoginDataByDoDID] 
(
	@dodid varchar(10)
)
RETURNS 
@T TABLE 
(
	computername varchar(15),
	loggedOnUserSAM varchar(20),
	loggedOnUserUPN char(20),
	[timestamp] datetime2,
	[IP] varchar(15),
	MAC char(17),
	logonDC varchar(100)
)
AS
BEGIN
	DECLARE @LastTenDays int
	SELECT @LastTenDays = COUNT(DISTINCT logontimestamp) FROM EUDLoginData WHERE edipi=@dodid AND logonTimestamp >= DATEADD(day,-10, GETDATE())
	IF (@LastTenDays >= 10)
		INSERT INTO @T 
			SELECT computername, loggedOnUserSAM, loggedOnUserUPN, dbo.UTCToEST(logontimestamp) AS [timestamp], IP, MAC, logonDC
				FROM EUDLoginData WHERE edipi=@dodid AND logonTimestamp >= DATEADD(day,-10, GETDATE())
	ELSE
		INSERT INTO @T 
			SELECT TOP(10) computername, loggedOnUserSAM, loggedOnUserUPN, dbo.UTCToEST(logontimestamp) AS [timestamp], IP, MAC, logonDC
	            FROM EUDLoginData WHERE edipi=@dodid
				ORDER BY logonTimestamp DESC
	RETURN
END
GO
/****** Object:  UserDefinedFunction [dbo].[GetVLANData]    Script Date: 11/3/2023 7:48:34 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date, ,>
-- Description:	<Description, ,>
-- =============================================
CREATE FUNCTION [dbo].[GetVLANData]
(
	@IP varchar(15),
	@Name bit
)
RETURNS varchar(100)
AS
BEGIN
	-- Declare the return variable here
	DECLARE @Result varchar(100)
	IF (CHARINDEX(' ', @IP)>0)
		SET @IP = SUBSTRING(@IP, 0, CHARINDEX(' ', @IP))
	IF (@Name=1) 
		SELECT 
			@Result = VLAN 
		FROM VLANs 
		WHERE dbo.IPAddressIsInRange(@IP, [VLAN_CIDR]) = 1
	ELSE
		SELECT 
			@Result = VLAN_Desc 
		FROM VLANs 
		WHERE dbo.IPAddressIsInRange(@IP, [VLAN_CIDR]) = 1
	-- Return the result of the function
	RETURN @Result
END
GO
	
/****** Object:  UserDefinedFunction [dbo].[InventoryData]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE FUNCTION [dbo].[InventoryData] 
(
	@List varchar(MAX)
)
RETURNS 
@Output TABLE 
(
	Ecn char(6),
	SerialNumber varchar(50),
	computername varchar(15),
	loggedOnUserSAM varchar(20),
	VLAN varchar(50),
	VLAN_DESC varchar(100),
	lastLogon datetime2
)
AS
BEGIN
INSERT INTO @Output SELECT d.Ecn, d.SerialNumber, d.computername, u.loggedOnUserSAM, n.VLAN, n.VLAN_Desc, COALESCE(IIF(n.[timestamp]>u.logonTimestamp,n.[timestamp],u.logonTimestamp), d.LastBoot) lastLogon FROM
(SELECT s.computername, s.SerialNumber, d.Ecn, s.LastBoot FROM EUDStatData s
LEFT JOIN DMLSS d ON s.SerialNumber=d.MfrSerialNo
) d
LEFT JOIN
(SELECT computername, 
        lastMediaState, 
        AdapterDesc, 
        IPv4,(
            SELECT VLAN FROM VLANs WHERE dbo.IPAddressIsInRange([IPv4], [VLAN_CIDR])=1
        ) VLAN, (
            SELECT VLAN_Desc FROM VLANs WHERE dbo.IPAddressIsInRange([IPv4], [VLAN_CIDR]) = 1
        ) VLAN_Desc, 
        MAC, 
        MAX(dbo.UTCToEST(data_timestamp)) AS[timestamp]
    FROM EUDNetData
	WHERE lastMediaState = 'Up' AND AdapterDesc NOT LIKE 'vmx%'
	GROUP BY computername, lastMediaState, AdapterDesc, IPv4, MAC) n
INNER JOIN
(SELECT l1.computername, l2.loggedOnUserSAM, l1.logonTimestamp FROM
(SELECT computername, MAX(logonTimestamp) logonTimestamp FROM EUDLoginData GROUP BY computername) l1
LEFT JOIN
(SELECT loggedOnUserSAM, logonTimestamp FROM EUDLoginData) l2
ON l1.logonTimestamp=l2.logonTimestamp) u
ON n.computername=u.computername
ON n.computername=d.computername
WHERE d.SerialNumber IN (SELECT * FROM dbo.SplitString(@List, ','))
	
	RETURN 
END
GO
/****** Object:  UserDefinedFunction [dbo].[InventoryDataByECN]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE FUNCTION [dbo].[InventoryDataByECN] (
	@List varchar(MAX)
)
RETURNS @Output TABLE (
	Ecn char(6),
	SerialNumber varchar(50),
	computername varchar(15),
	loggedOnUserSAM varchar(20),
	VLAN varchar(50),
	VLAN_DESC varchar(100),
	lastLogon datetime2
) AS BEGIN
	INSERT INTO @Output 
		SELECT	d.Ecn, 
				d.SerialNumber, 
				n.computername, 
				u.loggedOnUserSAM, 
				n.VLAN, 
				n.VLAN_Desc, 
				IIF(n.[timestamp]>u.logonTimestamp,n.[timestamp],u.logonTimestamp) lastLogon 
		FROM (
			SELECT	computername, 
					lastMediaState, 
					AdapterDesc, 
					IPv4,
					(SELECT VLAN FROM VLANs WHERE dbo.IPAddressIsInRange([IPv4], [VLAN_CIDR])=1) VLAN, 
					(SELECT VLAN_Desc FROM VLANs WHERE dbo.IPAddressIsInRange([IPv4], [VLAN_CIDR]) = 1) VLAN_Desc, 
					MAC, 
					MAX(dbo.UTCToEST(data_timestamp)) AS[timestamp]
			FROM EUDNetData
			WHERE lastMediaState = 'Up' AND AdapterDesc NOT LIKE 'vmx%'
			GROUP BY computername, lastMediaState, AdapterDesc, IPv4, MAC
		) n
		INNER JOIN (
			SELECT	l1.computername, 
					l2.loggedOnUserSAM, 
					l1.logonTimestamp 
			FROM (
				SELECT	computername, 
						MAX(logonTimestamp) logonTimestamp 
				FROM EUDLoginData 
				GROUP BY computername
			) l1
			LEFT JOIN (
				SELECT	loggedOnUserSAM, 
						logonTimestamp 
				FROM EUDLoginData
			) l2
			ON l1.logonTimestamp=l2.logonTimestamp
		) u
		ON n.computername=u.computername
		LEFT JOIN (
			SELECT	s.computername, 
					s.SerialNumber, 
					d.Ecn 
			FROM EUDStatData s
			LEFT JOIN 
				DMLSS d 
			ON s.SerialNumber=d.MfrSerialNo
		) d
		ON n.computername=d.computername
		WHERE d.Ecn IN (SELECT * FROM dbo.SplitString(@List, ',')
	)
	RETURN 
END
GO
/****** Object:  UserDefinedFunction [dbo].[IPAddressIsInRange]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date, ,>
-- Description:	<Description, ,>
-- =============================================
CREATE FUNCTION [dbo].[IPAddressIsInRange]
(
	@ip varchar(45),
	@range as varchar(18)
)
RETURNS bit
AS
BEGIN
	declare @prefix varchar(15),
		@cidr varchar(2),
		@mask bigint,
		@ipv6check int

	set @ipv6check = COALESCE(CHARINDEX(':',@ip,0), 0)
	if (@ipv6check>0) return 0

	set @prefix = left(@range, charindex('/', @range) - 1)
	set @cidr = right(@range, len(@range) - charindex('/', @range))
	-- Converts to a bit mask, e.g. /24 = 255.255.255.0
	set @mask = 4294967295 - power(2, 32 - @cidr) + 1

	if (dbo.IPAddressToInteger(@ip) & @mask) = dbo.IPAddressToInteger(@prefix)
		return 1
	return 0

END
GO
/****** Object:  UserDefinedFunction [dbo].[IPAddressToInteger]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date, ,>
-- Description:	<Description, ,>
-- =============================================
CREATE FUNCTION [dbo].[IPAddressToInteger]
(
	-- Add the parameters for the function here
	@ip varchar(15)
)
RETURNS bigint
AS
BEGIN
    return (
      convert(bigint, parsename(@ip, 1)) +
      convert(bigint, parsename(@ip, 2)) * 256 +
      convert(bigint, parsename(@ip, 3)) * 65536 +
      convert(bigint, parsename(@ip, 4)) * 16777216
    )
END
GO
/****** Object:  UserDefinedFunction [dbo].[SAMUser]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE FUNCTION [dbo].[SAMUser] 
(

)
RETURNS varchar(25)
AS
BEGIN
	-- Declare the return variable here


	-- Return the result of the function
	RETURN SUBSTRING(SYSTEM_USER,CHARINDEX('\',SYSTEM_USER)+1,LEN(SYSTEM_USER)-4)

END
GO
/****** Object:  UserDefinedFunction [dbo].[SNfromECN]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date, ,>
-- Description:	<Description, ,>
-- =============================================
CREATE FUNCTION [dbo].[SNfromECN]
(
	@ecn varchar(6)
)
RETURNS varchar(50)
AS
BEGIN
	DECLARE @DMLSS_SN varchar(255)
	DECLARE @EUD_SN varchar(50)
	DECLARE @MAX_LEN int
	DECLARE @hostname varchar(15)

	IF LEN(@ecn)=5 BEGIN 
		SET @ecn = '0' + @ecn 
	END
	SELECT @DMLSS_SN = MfrSerialNo FROM [DMLSS] WHERE Ecn=@ecn
	IF @DMLSS_SN IS NULL RETURN 'DMLSS error'
	IF (LEN(@DMLSS_SN)>50) BEGIN
		SET @MAX_LEN = 50
	END ELSE BEGIN
		SET @MAX_LEN = LEN(@DMLSS_SN)
	END
	SET @EUD_SN = LEFT(@DMLSS_SN, @MAX_LEN)

	SELECT @hostname = computername FROM dbo.EUDStatData WHERE SerialNumber LIKE @EUD_SN+'%'
	IF @hostname IS NULL RETURN 'log error'

	-- Return the result of the function
	RETURN @hostname

END
GO
/****** Object:  UserDefinedFunction [dbo].[SplitString]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [dbo].[SplitString]
(    
      @Input NVARCHAR(MAX),
      @Character CHAR(1)
)
RETURNS @Output TABLE (
      Item NVARCHAR(1000)
)
AS
BEGIN
      DECLARE @StartIndex INT, @EndIndex INT
 
      SET @StartIndex = 1
      IF SUBSTRING(@Input, LEN(@Input) - 1, LEN(@Input)) <> @Character
      BEGIN
            SET @Input = @Input + @Character
      END
 
      WHILE CHARINDEX(@Character, @Input) > 0
      BEGIN
            SET @EndIndex = CHARINDEX(@Character, @Input)
           
            INSERT INTO @Output(Item)
            SELECT SUBSTRING(@Input, @StartIndex, @EndIndex - 1)
           
            SET @Input = SUBSTRING(@Input, @EndIndex + 1, LEN(@Input))
      END
 
      RETURN
END
GO
/****** Object:  UserDefinedFunction [dbo].[TODAY_UTC]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date, ,>
-- Description:	<Description, ,>
-- =============================================
CREATE FUNCTION [dbo].[TODAY_UTC] ()
RETURNS Date
AS
BEGIN
	RETURN CAST(dbo.ESTToUTC(GETDATE()) AS Date)
END
GO
/****** Object:  UserDefinedFunction [dbo].[UTCToEST]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date, ,>
-- Description:	<Description, ,>
-- =============================================
CREATE FUNCTION [dbo].[UTCToEST] 
(
	@InputDate sql_variant
)
RETURNS DateTime2
AS
BEGIN
	-- Declare the return variable here
	DECLARE @InputDate2 As DateTime2
	IF (TRY_CONVERT(Datetime2,@InputDate) IS NULL)
		RETURN NULL;
	SET @InputDate2 = TRY_CONVERT(Datetime2,@InputDate);
	RETURN (@InputDate2 AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time');


END
GO
/****** Object:  Table [dbo].[Applications]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Applications](
	[computername] [varchar](15) NOT NULL,
	[username] [varchar](20) NOT NULL,
	[applicationname] [varchar](max) NOT NULL,
	[data_timestamp] [datetime2](7) NOT NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[EUDLoginData]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EUDLoginData](
	[computername] [varchar](15) NOT NULL,
	[loggedOnUserSAM] [varchar](20) NOT NULL,
	[loggedOnUserUPN] [char](20) NULL,
	[loggedOnUserDN] [nvarchar](200) NULL,
	[logonTimestamp] [datetime2](7) NOT NULL,
	[IP] [varchar](15) NOT NULL,
	[MAC] [char](17) NOT NULL,
	[logonDC] [varchar](100) NULL,
	[edipi]  AS (case when len([loggedOnUserUPN])=(20) AND isnumeric(substring([loggedOnUserUPN],(1),(10)))=(1) then substring([loggedOnUserUPN],(1),(10))  end) PERSISTED,
 CONSTRAINT [PK_EUDLoginData] PRIMARY KEY CLUSTERED 
(
	[computername] ASC,
	[loggedOnUserSAM] ASC,
	[logonTimestamp] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vwLatestLogin]    Script Date: 11/3/2023 7:48:34 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vwLatestLogin]
AS
WITH max_time AS (SELECT        computername, MAX(logonTimestamp) AS logonTimeStamp
                                            FROM            dbo.EUDLoginData
                                            GROUP BY computername)
    SELECT        d.computername, d.logonTimestamp, d.IP
     FROM            dbo.EUDLoginData AS d INNER JOIN
                              max_time AS m ON d.computername = m.computername AND d.logonTimestamp = m.logonTimeStamp
GO
/****** Object:  Table [dbo].[DMLSS]    Script Date: 11/3/2023 7:48:34 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[DMLSS](
	[Ecn5] [nvarchar](255) NULL,
	[Ecn] [nvarchar](255) NULL,
	[MfrSerialNo] [nvarchar](255) NULL,
	[AcqDate] [date] NULL,
	[Nomenclature] [nvarchar](255) NULL,
	[LifeExp] [nvarchar](255) NULL,
	[Manufacturer] [nvarchar](255) NULL,
	[CommonModel] [nvarchar](255) NULL,
	[EquipmentLocation] [nvarchar](255) NULL,
	[Ownership] [nvarchar](255) NULL,
	[CustomerName] [nvarchar](255) NULL,
	[CustodianViewCustdnPocSer] [nvarchar](255) NULL,
	[CustodianName] [nvarchar](255) NULL,
	[AcqCostLow] [money] NULL,
	[AcqCostHigh] [money] NULL,
	[RunDate] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[HWList]    Script Date: 11/3/2023 7:48:34 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[HWList]
AS
SELECT l.computername AS [Asset Name]
	,'' AS Nickname
	,l.[IP] AS [Asset IP Address]
	,'' AS [Public Facing]
	,'' AS [Public Facing FQDN]
	,'' AS [Public Facing IP Address]
	,'' AS [Public Facing URL(s)]
	,IIF(d.Ecn = NULL OR s.SerialNumber LIKE 'VMWare%', 'Yes', 'No') AS [Virtual Asset]
	,s.Manufacturer
	,s.Model AS [Model Number]
	,IIF(d.Ecn = NULL OR s.SerialNumber LIKE 'VMWare%','',s.SerialNumber) AS [Serial Number]
	,s.OSVersion AS [OS/iOS/FW Version]
	,s.PhysicalMemoryGB AS [Memory Size]
	,dbo.GetVLANData(l.[IP], 0) AS [Location (P/C/S & Building)]
	,l.logonTimestamp
FROM dbo.EUDStatData s
INNER JOIN dbo.vwLatestLogin l
	ON s.computername = l.computername 
LEFT JOIN dbo.DMLSS d
	ON s.SerialNumber = CAST(d.MfrSerialNo AS varchar(50))
WHERE l.logonTimestamp >= DATEADD(day,-60,GETDATE())
GO	
/****** Object:  Table [dbo].[EUDNetData]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EUDNetData](
	[computername] [varchar](15) NOT NULL,
	[lastMediaState] [varchar](50) NULL,
	[AdapterDesc] [varchar](100) NOT NULL,
	[IPv4] [varchar](45) NULL,
	[MAC] [char](17) NOT NULL,
	[data_timestamp] [datetime2](7) NULL,
 CONSTRAINT [PK_EUDNetData] PRIMARY KEY CLUSTERED 
(
	[computername] ASC,
	[AdapterDesc] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[EUDStatData]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EUDStatData](
	[computername] [varchar](15) NOT NULL,
	[CPUCount] [smallint] NULL,
	[CPU_Arch] [varchar](50) NULL,
	[CPU_Id] [varchar](100) NULL,
	[Manufacturer] [varchar](100) NULL,
	[Model] [varchar](50) NULL,
	[SerialNumber] [varchar](50) NULL,
	[OSVersion] [varchar](15) NULL,
	[PhysicalMemoryGB] [int] NULL,
	[HDD0_SizeGB] [smallint] NULL,
	[data_timestamp] [datetime2](7) NULL,
	[OSInstallDate] [datetime2](7) NULL,
	[LastBoot] [datetime2](7) NULL,
	[Kiosk] [bit] NULL,
	[Server_os] [bit] NOT NULL,
 CONSTRAINT [PK_EUDStatData] PRIMARY KEY CLUSTERED 
(
	[computername] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  UserDefinedFunction [dbo].[FullHardwareData]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE FUNCTION [dbo].[FullHardwareData]
(	
	@hostname varchar(25)
)
RETURNS TABLE 
AS
RETURN 
(
	SELECT s.computername, d.ECN, d.CustomerName as Dept, d.CustodianName as hrh, d.AcqDate, d.RunDate, s.CPUCount, s.CPU_Arch, s.CPU_Id, s.Manufacturer, s.Model, s.SerialNumber, s.OSVersion, s.PhysicalMemoryGB, s.HDD0_SizeGB, s.data_timestamp, s.OSInstallDate, s.LastBoot
        FROM EUDLogging.dbo.EUDStatData s LEFT JOIN DMLSS d ON s.SerialNumber=d.MfrSerialNo WHERE computername=@hostname
)
GO
/****** Object:  View [dbo].[vwLogging]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vwLogging]
AS
SELECT        TOP (100) PERCENT computername, loggedOnUserSAM, loggedOnUserUPN, dbo.UTCToEST(logonTimestamp) AS timestamp, IP, MAC, logonDC
FROM            dbo.EUDLoginData
GO
/****** Object:  View [dbo].[vwHardwareList]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vwHardwareList]
AS
SELECT        TOP (100) PERCENT s.computername AS [Machine Name (Required)], '' AS Nickname, i.IP AS [IP Address], CASE WHEN s.SerialNumber LIKE 'VMware%' OR
                         s.Manufacturer LIKE 'VMware%' THEN 'Yes' WHEN s.SerialNumber IS NULL THEN '' ELSE 'No' END AS [Virtual Asset?], s.Manufacturer, s.Model AS [Model Number], s.SerialNumber AS [Serial Number], 
                         s.OSVersion AS [OS/iOS/FW Version], s.PhysicalMemoryGB AS [Memory Size / Type], s.OSInstallDate, d.Ecn, s.LastBoot, s.Kiosk, s.Server_os
FROM            dbo.EUDStatData AS s LEFT OUTER JOIN
                         DMLSS AS d ON s.SerialNumber = d.MfrSerialNo AND s.SerialNumber <> '' LEFT OUTER JOIN
                             (SELECT        l.computername, l.IP, l.logonTimestamp
                               FROM            dbo.EUDLoginData AS l INNER JOIN
                                                             (SELECT        computername, MAX(logonTimestamp) AS LastLogin
                                                               FROM            dbo.EUDLoginData
                                                               GROUP BY computername) AS tm ON tm.computername = l.computername AND l.logonTimestamp = tm.LastLogin) AS i ON i.computername = s.computername
GO
/****** Object:  Table [dbo].[Custody]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Custody](
	[CustodyID] [int] IDENTITY(1,1) NOT NULL,
	[SerialNumber] [varchar](50) NOT NULL,
	[DoDID] [varchar](10) NOT NULL,
	[Received] [datetime2](7) NOT NULL,
	[Returned] [datetime2](7) NULL,
	[ReceivedBy] [varchar](25) NOT NULL,
	[ReturnedBy] [varchar](25) NULL,
	[FullScan] [varchar](255) NULL,
	[PickupDoDID] [varchar](10) NULL,
	[PickupFullScan] [varchar](255) NULL,
 CONSTRAINT [PK_Custody_1] PRIMARY KEY CLUSTERED 
(
	[CustodyID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[DMLSSTemp]    Script Date: 11/3/2023 7:48:34 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[DMLSSTemp](
	[Ecn5] [nvarchar](255) NULL,
	[Ecn] [nvarchar](255) NULL,
	[MfrSerialNo] [nvarchar](255) NULL,
	[AcqDate] [varchar](255) NULL,
	[Nomenclature] [nvarchar](255) NULL,
	[LifeExp] [nvarchar](255) NULL,
	[Manufacturer] [nvarchar](255) NULL,
	[CommonModel] [nvarchar](255) NULL,
	[EquipmentLocation] [nvarchar](255) NULL,
	[Ownership] [nvarchar](255) NULL,
	[CustomerName] [nvarchar](255) NULL,
	[CustodianViewCustdnPocSer] [nvarchar](255) NULL,
	[CustodianName] [nvarchar](255) NULL,
	[AcqCostLow] [varchar](255) NOT NULL,
	[AcqCostHigh] [varchar](255) NOT NULL,
	[RunDate] [datetime] NOT NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[EUDTest]    Script Date: 11/3/2023 7:48:34 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EUDTest](
	[computername] [varchar](15) NOT NULL,
	[loggedOnUserSAM] [varchar](20) NOT NULL,
	[loggedOnUserUPN] [char](20) NULL,
	[loggedOnUserDN] [nvarchar](200) NULL,
	[logonTimestamp] [datetime2](7) NOT NULL,
	[IP] [varchar](15) NOT NULL,
	[MAC] [char](17) NOT NULL,
	[logonDC] [varchar](100) NULL,
	[edipi]  AS (case when len([loggedOnUserUPN])=(20) AND isnumeric(substring([loggedOnUserUPN],(1),(10)))=(1) then substring([loggedOnUserUPN],(1),(10))  end) PERSISTED
) ON [PRIMARY]
GO	
/****** Object:  Table [dbo].[iaccess_badges]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[iaccess_badges](
	[badge_id] [int] IDENTITY(1,1) NOT NULL,
	[badge_serial] [int] NOT NULL,
	[badge_status] [int] NOT NULL,
 CONSTRAINT [PK_iaccess_badges] PRIMARY KEY CLUSTERED 
(
	[badge_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[iaccess_log]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[iaccess_log](
	[issuance_id] [int] IDENTITY(1,1) NOT NULL,
	[badge_id] [int] NOT NULL,
	[issued_to] [char](10) NOT NULL,
	[issue_date] [datetime2](7) NOT NULL,
	[return_date] [datetime2](7) NULL,
 CONSTRAINT [PK_iaccess] PRIMARY KEY CLUSTERED 
(
	[issuance_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[iaccess_status]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[iaccess_status](
	[iaccess_status_id] [int] IDENTITY(1,1) NOT NULL,
	[iaccess_status_desc] [varchar](50) NOT NULL,
 CONSTRAINT [PK_iaccess_status] PRIMARY KEY CLUSTERED 
(
	[iaccess_status_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Printers]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Printers](
	[computername] [varchar](15) NOT NULL,
	[username] [varchar](25) NOT NULL,
	[printername] [varchar](50) NOT NULL,
	[port] [varchar](75) NULL,
	[network] [bit] NOT NULL,
	[location] [varchar](100) NULL,
	[servername] [varchar](25) NULL,
	[sharename] [varchar](50) NULL,
	[InAD] [bit] NOT NULL,
	[drivername] [varchar](100) NULL,
	[Local_TCPIPPort] [varchar](50) NULL,
	[data_timestamp] [datetime2](7) NULL,
 CONSTRAINT [PK_Printers] PRIMARY KEY CLUSTERED 
(
	[computername] ASC,
	[username] ASC,
	[printername] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PrintJobs]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PrintJobs](
	[PrinterName] [varchar](25) NOT NULL,
	[LastJob] [datetime2](7) NOT NULL,
 CONSTRAINT [PK_PrintJobs] PRIMARY KEY CLUSTERED 
(
	[PrinterName] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[VLANs]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VLANs](
	[VLAN] [varchar](50) NOT NULL,
	[VLAN_Desc] [varchar](100) NOT NULL,
	[VLAN_CIDR] [varchar](18) NOT NULL,
 CONSTRAINT [PK_VLANs] PRIMARY KEY CLUSTERED 
(
	[VLAN_CIDR] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
/****** Object:  Index [NonClusteredIndex-20221213-080331]    Script Date: 9/21/2023 11:33:57 AM ******/
CREATE NONCLUSTERED INDEX [NonClusteredIndex-20221213-080331] ON [dbo].[Applications]
(
	[computername] ASC,
	[username] ASC,
	[data_timestamp] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
/****** Object:  Index [UQ_Custody_OneActive]    Script Date: 9/21/2023 11:33:57 AM ******/
CREATE UNIQUE NONCLUSTERED INDEX [UQ_Custody_OneActive] ON [dbo].[Custody]
(
	[SerialNumber] ASC
)
WHERE ([Returned] IS NULL)
WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
/****** Object:  Index [UQ_Custody_PreventDupe]    Script Date: 9/21/2023 11:33:57 AM ******/
CREATE UNIQUE NONCLUSTERED INDEX [UQ_Custody_PreventDupe] ON [dbo].[Custody]
(
	[SerialNumber] ASC,
	[Received] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
SET ARITHABORT ON
SET CONCAT_NULL_YIELDS_NULL ON
SET QUOTED_IDENTIFIER ON
SET ANSI_NULLS ON
SET ANSI_PADDING ON
SET ANSI_WARNINGS ON
SET NUMERIC_ROUNDABORT OFF
GO
/****** Object:  Index [edipi_login]    Script Date: 9/21/2023 11:33:57 AM ******/
CREATE NONCLUSTERED INDEX [edipi_login] ON [dbo].[EUDLoginData]
(
	[edipi] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
/****** Object:  Index [NonClusteredIndex-20221213-080423]    Script Date: 9/21/2023 11:33:57 AM ******/
CREATE NONCLUSTERED INDEX [NonClusteredIndex-20221213-080423] ON [dbo].[EUDLoginData]
(
	[computername] ASC,
	[loggedOnUserSAM] ASC,
	[logonTimestamp] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
/****** Object:  Index [NonClusteredIndex-20221213-080548]    Script Date: 9/21/2023 11:33:57 AM ******/
CREATE NONCLUSTERED INDEX [NonClusteredIndex-20221213-080548] ON [dbo].[EUDNetData]
(
	[computername] ASC,
	[IPv4] ASC,
	[MAC] ASC,
	[data_timestamp] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
/****** Object:  Index [NonClusteredIndex-20221213-080626]    Script Date: 9/21/2023 11:33:57 AM ******/
CREATE NONCLUSTERED INDEX [NonClusteredIndex-20221213-080626] ON [dbo].[EUDStatData]
(
	[computername] ASC,
	[SerialNumber] ASC,
	[data_timestamp] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
ALTER TABLE [dbo].[Applications] ADD  DEFAULT (host_name()) FOR [computername]
GO
ALTER TABLE [dbo].[Applications] ADD  DEFAULT ([dbo].[SAMUser]()) FOR [username]
GO
ALTER TABLE [dbo].[Applications] ADD  CONSTRAINT [DF_Applications_data_timestamp]  DEFAULT (sysdatetime()) FOR [data_timestamp]
GO
ALTER TABLE [dbo].[EUDLoginData] ADD  DEFAULT (host_name()) FOR [computername]
GO
ALTER TABLE [dbo].[EUDLoginData] ADD  DEFAULT ([dbo].[SAMUser]()) FOR [loggedOnUserSAM]
GO
ALTER TABLE [dbo].[EUDLoginData] ADD  CONSTRAINT [DF__EUDLoginD__logon__4316F928]  DEFAULT (sysdatetime()) FOR [logonTimestamp]
GO
ALTER TABLE [dbo].[EUDNetData] ADD  DEFAULT (host_name()) FOR [computername]
GO
ALTER TABLE [dbo].[EUDNetData] ADD  CONSTRAINT [DF_EUDNetData_data_timestamp]  DEFAULT (sysdatetime()) FOR [data_timestamp]
GO
ALTER TABLE [dbo].[EUDStatData] ADD  DEFAULT (host_name()) FOR [computername]
GO
ALTER TABLE [dbo].[EUDStatData] ADD  CONSTRAINT [DF_EUDStatData_data_timestamp]  DEFAULT (sysdatetime()) FOR [data_timestamp]
GO
ALTER TABLE [dbo].[EUDStatData] ADD  DEFAULT ((0)) FOR [Kiosk]
GO
ALTER TABLE [dbo].[EUDStatData] ADD  CONSTRAINT [EUDStat_Server_Default]  DEFAULT ((0)) FOR [Server_os]
GO
ALTER TABLE [dbo].[Printers] ADD  CONSTRAINT [DF_Printers_computername]  DEFAULT (host_name()) FOR [computername]
GO
ALTER TABLE [dbo].[Printers] ADD  DEFAULT ([dbo].[SAMUser]()) FOR [username]
GO
ALTER TABLE [dbo].[Printers] ADD  CONSTRAINT [DF_Printers_data_timestamp]  DEFAULT (sysdatetime()) FOR [data_timestamp]
GO
ALTER TABLE [dbo].[iaccess_badges]  WITH CHECK ADD  CONSTRAINT [FK_iaccess_badges_iaccess_status] FOREIGN KEY([badge_status])
REFERENCES [dbo].[iaccess_status] ([iaccess_status_id])
GO
ALTER TABLE [dbo].[iaccess_badges] CHECK CONSTRAINT [FK_iaccess_badges_iaccess_status]
GO
ALTER TABLE [dbo].[iaccess_log]  WITH CHECK ADD  CONSTRAINT [FK_iaccess_iaccess_badges] FOREIGN KEY([badge_id])
REFERENCES [dbo].[iaccess_badges] ([badge_id])
GO
ALTER TABLE [dbo].[iaccess_log] CHECK CONSTRAINT [FK_iaccess_iaccess_badges]
GO
/****** Object:  StoredProcedure [dbo].[AdapterInsert]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[AdapterInsert]
	@AdapterName varchar(50) = NULL,
	@AdapterState varchar(50),
	@AdapterDesc varchar(100),
	@IP varchar(45) = NULL,
	@IPv4 varchar(45) = NULL,
	@IPv6 varchar(45) = NULL,
	@MAC char(17)
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	MERGE dbo.EUDNetData t 
	USING ( 
		SELECT 
			HOST_NAME() AS computername, 
			@AdapterState AS lastMediaState, 
			@AdapterDesc AS AdapterDesc, 
			COALESCE(@IPv4, @IP, NULL) AS IPv4, 
			@MAC AS MAC 
	) s 
    ON (
		s.computername = t.computername 
		AND s.AdapterDesc = t.AdapterDesc
	) 
	WHEN MATCHED THEN 
    UPDATE SET 
		t.lastMediaState=s.lastMediaState, 
		t.IPv4=s.IPv4, 
		t.MAC=s.MAC,
		t.data_timestamp = SYSUTCDATETIME()
    WHEN NOT MATCHED BY TARGET THEN 
	INSERT (
		computername, 
		lastMediaState, 
		AdapterDesc, 
		IPv4, 
		MAC,
		data_timestamp
	) VALUES (
		DEFAULT, 
		@AdapterState, 
		@AdapterDesc, 
		@IPv4, 
		@MAC,
		SYSUTCDATETIME()
	);
END

GO
/****** Object:  StoredProcedure [dbo].[AddiAccessBatch]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[AddiAccessBatch]
	@startnum int,
	@endnum int
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;
	WITH i (i) AS (
		SELECT @startnum i
		UNION ALL
		SELECT i+1 FROM i
		WHERE i < @endnum
	)
	INSERT INTO iaccess_badges (badge_serial, badge_status)
		SELECT i, 1 AS [status] FROM i OPTION(MAXRECURSION 0)
END
GO
/****** Object:  StoredProcedure [dbo].[ApplicationInsert]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[ApplicationInsert] 
	-- Add the parameters for the stored procedure here
	@ApplicationList ApplicationList READONLY 
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	DELETE FROM dbo.Applications WHERE computername=HOST_NAME() AND username=dbo.SAMUser()
	INSERT INTO dbo.Applications
		SELECT 
			HOST_NAME() AS computername, 
			dbo.SAMUser() AS username,
			a.applicationname,
			SYSUTCDATETIME() AS data_timestamp
		FROM
			@ApplicationList a
END
GO
/****** Object:  StoredProcedure [dbo].[iAccessIssuance]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[iAccessIssuance]
	@serial varchar(10),
	@issued_to char(10)
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;
	DECLARE @is_out int;
	DECLARE @badge_id int;
	DECLARE @status int;
	DECLARE @sn int = CAST(@serial AS int)
	SELECT @badge_id=badge_id, @status=badge_status FROM iaccess_badges WHERE badge_serial=@sn;
	SELECT @is_out=COUNT(issuance_id) FROM iaccess_log WHERE badge_id=@badge_id AND return_date IS NULL;
	IF @is_out>0
	BEGIN
		UPDATE iaccess_log SET return_date=SYSDATETIME() WHERE badge_id=@badge_id AND return_date IS NULL;
	END
	SET NOCOUNT OFF;
	BEGIN TRY
		BEGIN TRANSACTION
			INSERT INTO iaccess_log(badge_id, issued_to, issue_date) VALUES (@badge_id,@issued_to,SYSDATETIME());
			SET NOCOUNT ON;
			UPDATE iaccess_badges SET badge_status=2 WHERE badge_id=@badge_id;
		COMMIT
	END TRY
	BEGIN CATCH
		IF @@TRANCOUNT > 0
			ROLLBACK TRAN
		DECLARE @ErrorMessage NVARCHAR(4000);  
		DECLARE @ErrorSeverity INT;  
		DECLARE @ErrorState INT;  

		SELECT   
		   @ErrorMessage = ERROR_MESSAGE(),  
		   @ErrorSeverity = ERROR_SEVERITY(),  
		   @ErrorState = ERROR_STATE();  

		RAISERROR (@ErrorMessage, @ErrorSeverity, @ErrorState);
	END CATCH
END
GO
/****** Object:  StoredProcedure [dbo].[iAccessReturn]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[iAccessReturn]
	@issuance_id int
AS
BEGIN
	SET NOCOUNT OFF;
	DECLARE @badge_id int 
	SELECT @badge_id=badge_id FROM iaccess_log WHERE issuance_id=@issuance_id;
	UPDATE iaccess_log SET return_date=SYSDATETIME() WHERE issuance_id=@issuance_id;
	SET NOCOUNT ON;
	UPDATE iaccess_badges SET badge_status = 1 WHERE badge_id=@badge_id;
END
GO
/****** Object:  StoredProcedure [dbo].[LoginDataInsert]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[LoginDataInsert] 
	@UserDN nvarchar(200),
	@UPN char(20),
	@IP varchar(15), 
	@MAC char(17), 
	@DC varchar(100)
	--@Uptime int = null
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	INSERT INTO dbo.EUDLoginData (computername, loggedOnUserSAM, loggedOnUserUPN, loggedOnUserDN, logonTimestamp, IP, MAC, logonDC) VALUES (DEFAULT, DEFAULT, @UPN, @UserDN, SYSUTCDATETIME(), @IP, @MAC, @DC);
END
GO
/****** Object:  StoredProcedure [dbo].[PrinterInsert]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[PrinterInsert] 
	-- Add the parameters for the stored procedure here
	@PrinterList PrinterList READONLY 
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	DELETE FROM dbo.Printers WHERE computername=HOST_NAME() AND username=dbo.SAMUser()
	INSERT INTO dbo.Printers
		SELECT 
			HOST_NAME() AS computername, 
			dbo.SAMUser() AS username,
			p.printername,
			p.[port],
			p.network,
			p.[location],
			p.servername,
			p.sharename,
			p.InAD,
			p.drivername,
			p.Local_TCPIPPort,
			SYSUTCDATETIME() AS data_timestamp
		FROM
			@PrinterList p
END
GO
/****** Object:  StoredProcedure [dbo].[PrintJob]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[PrintJob]
	@PrinterName varchar(20)
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	MERGE PrintJobs AS TARGET
	USING (SELECT @PrinterName AS PrinterName, SYSDATETIME() AS LastJob) AS SOURCE
	ON TARGET.PrinterName=SOURCE.PrinterName
	WHEN MATCHED THEN UPDATE SET TARGET.LastJob=SOURCE.LastJob
	WHEN NOT MATCHED BY TARGET
	THEN INSERT (PrinterName, LastJob) VALUES (SOURCE.PrinterName, SOURCE.LastJob);
END
GO
/****** Object:  StoredProcedure [dbo].[StatInsert]    Script Date: 9/21/2023 11:33:57 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[StatInsert] 
	@Cores smallint,
	@Arch varchar(50),
	@Id varchar(100),
	@Manuf varchar(100),
	@Model varchar(50),
	@SN varchar(50),
	@OSVer varchar(15),
	@Mem int,
	@HDD int,
	@InstallDate datetime2,
	@LastBoot datetime2 = null,
	@Kiosk bit = null,
	@Server bit = null,
	@BTState bit
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	SET @Kiosk = COALESCE(@Kiosk, 0)
	SET @Server = COALESCE(@Server, 0)

    -- Insert statements for procedure here
	MERGE dbo.EUDStatData t
        USING ( SELECT HOST_NAME() AS computername, 
                    @Cores AS CPUCount, 
                    @Arch AS CPU_Arch, 
                    @Id AS CPU_Id, 
                    @Manuf AS Manufacturer, 
                    @Model AS Model, 
                    @SN AS SerialNumber, 
                    @OSVer AS OSVersion, 
                    @Mem AS PhysicalMemoryGB, 
                    @HDD AS HDD0_SizeGB,
		    @InstallDate AS OSInstallDate,
		    @LastBoot AS LastBoot,
		    @Kiosk as Kiosk,
		    @Server as Server_OS,
		    @BTState as BTState
                ) s
                ON (s.computername = t.computername) 
                WHEN MATCHED THEN 
                UPDATE SET t.CPUCount=s.CPUCount, t.CPU_Arch=s.CPU_Arch, t.CPU_ID=s.CPU_Id, t.Manufacturer=s.Manufacturer, t.Model=s.Model, 
					t.SerialNumber=s.SerialNumber, t.PhysicalMemoryGB=s.PhysicalMemoryGB, t.HDD0_SizeGB=s.HDD0_SizeGB, t.data_timestamp=SYSUTCDATETIME(), 
					t.OSInstalLDate=s.OSInstallDate, t.LastBoot=s.LastBoot, t.Kiosk=s.Kiosk, t.Server_OS=s.Server_OS, t.BTState=s.BTState
                WHEN NOT MATCHED BY TARGET THEN
                INSERT (computername, CPUCount, CPU_Arch, CPU_Id, Manufacturer, Model, SerialNumber, OSVersion, PhysicalMemoryGB, HDD0_SizeGB, data_timestamp, OSInstallDate, LastBoot, Kiosk, Server_OS, BTState)
                VALUES (HOST_NAME(), @Cores, @arch, @Id, @manuf, @model, @SN, @OSVer, @mem, @HDD, SYSUTCDATETIME(), @InstallDate, @LastBoot, @Kiosk, @Server, @BTState);
END
GO
USE [master]
GO
ALTER DATABASE [EUDLogging] SET  READ_WRITE 
GO
