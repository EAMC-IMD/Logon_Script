# logon.ps1

[logon.ps1](SOURCE/logon.ps1) - designed to be invoked from a login batch file as defined in a user's AD properties - is part of a larger IT intelligence framework.  
See [LogLookupTool](https://github.com/EAMC-IMD/LogLookupTool) for the front-end application that exposes the data collected by this script.
The script collects copious data about the End User Device (EUD) and the user and preferentially writes that data to a database (see [db_structure.sql](SOURCE/db_structure.sql) for database initialization).

logon.ps1 is extensively documented, and designed so that it should not require modification - either for deployment at a site, or to customize functions. 
All that is handled either through command line parameters, or through [prefs.json](SOURCE/prefs.json)

# prefs.json

logon.ps1 offloads all customization into prefs.json.  Nearly any function can be turned on or off using the FunctionExecution object's properties.

Other objects should be self explanatory by cross-examining references in logon.ps1
