USE [EUDLogging]
GO
/****** Object:  UserDefinedTableType [dbo].[ApplicationList]    Script Date: 11/10/2022 2:18:38 PM ******/
CREATE TYPE [dbo].[ApplicationList] AS TABLE(
	[applicationname] [varchar](max) NULL
)
GO
/****** Object:  UserDefinedTableType [dbo].[PrinterList]    Script Date: 11/10/2022 2:18:38 PM ******/
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
/****** Object:  UserDefinedFunction [dbo].[SAMUser]    Script Date: 11/10/2022 2:18:38 PM ******/
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
/****** Object:  Table [dbo].[Applications]    Script Date: 11/10/2022 2:18:38 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Applications](
	[computername] [varchar](15) NOT NULL,
	[username] [varchar](20) NOT NULL,
	[applicationname] [varchar](max) NOT NULL,
	[data_timestamp] [datetime2](7) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[EUDLoginData]    Script Date: 11/10/2022 2:18:38 PM ******/
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
 CONSTRAINT [PK_EUDLoginData] PRIMARY KEY CLUSTERED 
(
	[computername] ASC,
	[loggedOnUserSAM] ASC,
	[logonTimestamp] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[EUDNetData]    Script Date: 11/10/2022 2:18:38 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EUDNetData](
	[computername] [varchar](15) NOT NULL,
	[AdapterName] [varchar](50) NOT NULL,
	[lastMediaState] [varchar](50) NULL,
	[AdapterDesc] [varchar](100) NULL,
	[IP] [varchar](45) NULL,
	[MAC] [char](17) NOT NULL,
	[data_timestamp] [datetime2](7) NULL,
 CONSTRAINT [PK_EUDNetData] PRIMARY KEY CLUSTERED 
(
	[computername] ASC,
	[AdapterName] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[EUDStatData]    Script Date: 11/10/2022 2:18:38 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EUDStatData](
	[computername] [varchar](15) NOT NULL,
	[ECN] [char](6) NULL,
	[CPUCount] [smallint] NULL,
	[CPU_Arch] [varchar](50) NULL,
	[CPU_Id] [varchar](100) NULL,
	[Manufacturer] [varchar](100) NULL,
	[Model] [varchar](50) NULL,
	[SerialNumber] [varchar](50) NULL,
	[OSVersion] [varchar](15) NULL,
	[PhysicalMemoryMB] [int] NULL,
	[HDD0_SizeGB] [smallint] NULL,
	[data_timestamp] [datetime2](7) NULL,
 CONSTRAINT [PK_EUDStatData] PRIMARY KEY CLUSTERED 
(
	[computername] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Printers]    Script Date: 11/10/2022 2:18:38 PM ******/
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
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  UserDefinedFunction [dbo].[DailyTest]    Script Date: 11/10/2022 2:18:38 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE FUNCTION [dbo].[DailyTest] ()
RETURNS TABLE 
AS
RETURN 
(
	-- Add the SELECT statement with parameter references here
	SELECT (
	SELECT COUNT(ua.username) uaCount FROM (
		SELECT DISTINCT username FROM Applications WHERE data_timestamp > CAST(GETDATE() AS Date)) ua
	) uaCount, (
	SELECT COUNT(cua.computername) cuaCount FROM (
		SELECT DISTINCT computername, username FROM Applications WHERE data_timestamp > CAST(GETDATE() AS Date)) cua
	) cuaCount, (
	SELECT COUNT(ca.computername) caCount FROM (
		SELECT DISTINCT computername FROM Applications WHERE data_timestamp > CAST(GETDATE() AS Date)) ca
	) caCount, (
	SELECT COUNT(ul.loggedOnUserSAM) ulCount FROM (
		SELECT DISTINCT loggedOnUserSAM FROM EUDLoginData WHERE logontimestamp > CAST(GETDATE() AS Date)) ul
	) ulCount, (
	SELECT COUNT(cul.computername) culCount FROM (
		SELECT DISTINCT computername, loggedOnUserSAM FROM EUDLoginData WHERE logontimestamp > CAST(GETDATE() AS Date)) cul
	) culCount, (
	SELECT COUNT(cl.computername) clCount FROM (
		SELECT DISTINCT computername FROM EUDLoginData WHERE logontimestamp > CAST(GETDATE() AS Date)) cl
	) clCount, (
	SELECT COUNT(up.username) upCount FROM (
		SELECT DISTINCT username FROM Printers WHERE data_timestamp > CAST(GETDATE() AS Date)) up
	) upCount, (
	SELECT COUNT(cup.computername) cupCount FROM (
		SELECT DISTINCT computername, username FROM Printers WHERE data_timestamp > CAST(GETDATE() AS Date)) cup
	) cupCount, (
	SELECT COUNT(cp.computername) cpCount FROM (
		SELECT DISTINCT computername FROM Printers WHERE data_timestamp > CAST(GETDATE() AS Date)) cp
	) cpCount, (
	SELECT COUNT(cn.computername) cnCount FROM (
		SELECT DISTINCT computername FROM EUDNetData WHERE data_timestamp > CAST(GETDATE() AS Date)) cn
	) cnCount, (
	SELECT COUNT(cs.computername) csCount FROM (
		SELECT DISTINCT computername FROM EUDStatData WHERE data_timestamp > CAST(GETDATE() AS Date)) cs
	) csCount
)
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
ALTER TABLE [dbo].[Printers] ADD  CONSTRAINT [DF_Printers_computername]  DEFAULT (host_name()) FOR [computername]
GO
ALTER TABLE [dbo].[Printers] ADD  DEFAULT ([dbo].[SAMUser]()) FOR [username]
GO
ALTER TABLE [dbo].[Printers] ADD  CONSTRAINT [DF_Printers_data_timestamp]  DEFAULT (sysdatetime()) FOR [data_timestamp]
GO
/****** Object:  StoredProcedure [dbo].[AdapterInsert]    Script Date: 11/10/2022 2:18:38 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[AdapterInsert]
	@AdapterName varchar(50),
	@AdapterState varchar(50),
	@AdapterDesc varchar(100),
	@IP varchar(45),
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
			@AdapterName AS AdapterName, 
			@AdapterState AS lastMediaState, 
			@AdapterDesc AS AdapterDesc, 
			@IP AS [IP], 
			@MAC AS MAC 
	) s 
    ON (
		s.computername = t.computername 
		AND s.AdapterName = t.AdapterName
	) 
	WHEN MATCHED THEN 
    UPDATE SET 
		t.lastMediaState=s.lastMediaState, 
		t.AdapterDesc=s.AdapterDesc, 
		t.[IP]=s.[IP], 
		t.MAC=s.MAC,
		t.data_timestamp = SYSDATETIME()
    WHEN NOT MATCHED BY TARGET THEN 
	INSERT (
		computername, 
		AdapterName, 
		lastMediaState, 
		AdapterDesc, 
		[IP], 
		MAC,
		data_timestamp
	) VALUES (
		DEFAULT, 
		@AdapterName, 
		@AdapterState, 
		@AdapterDesc, 
		@IP, 
		@MAC,
		GETDATE()
	);
END
GO
/****** Object:  StoredProcedure [dbo].[ApplicationInsert]    Script Date: 11/10/2022 2:18:38 PM ******/
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
			SYSDATETIME() AS data_timestamp
		FROM
			@ApplicationList a
END
GO
/****** Object:  StoredProcedure [dbo].[LoginDataInsert]    Script Date: 11/10/2022 2:18:38 PM ******/
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
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	INSERT INTO dbo.EUDLoginData (computername, loggedOnUserSAM, loggedOnUserUPN, loggedOnUserDN, IP, MAC, logonDC) VALUES (DEFAULT, DEFAULT, @UPN, @UserDN, @IP, @MAC, @DC);
END
GO
/****** Object:  StoredProcedure [dbo].[PrinterInsert]    Script Date: 11/10/2022 2:18:38 PM ******/
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
			SYSDATETIME() AS data_timestamp
		FROM
			@PrinterList p
END
GO
/****** Object:  StoredProcedure [dbo].[StatInsert]    Script Date: 11/10/2022 2:18:38 PM ******/
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
	@Mem smallint,
	@HDD smallint
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

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
                    @Mem AS PhysicalMemoryMB, 
                    @HDD AS HDD0_SizeGB
                ) s
                ON (s.computername = t.computername) 
                WHEN MATCHED THEN 
                UPDATE SET t.PhysicalMemoryMB=s.PhysicalMemoryMB, t.HDD0_SizeGB=s.HDD0_SizeGB, t.data_timestamp=SYSDATETIME()
                WHEN NOT MATCHED BY TARGET THEN
                INSERT (computername, CPUCount, CPU_Arch, CPU_Id, Manufacturer, Model, SerialNumber, OSVersion, PhysicalMemoryMB, HDD0_SizeGB, data_timestamp)
                VALUES (HOST_NAME(), @Cores, @arch, @Id, @manuf, @model, @SN, @OSVer, @mem, @HDD, DEFAULT);
END
GO
