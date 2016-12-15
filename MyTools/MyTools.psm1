Import-Module PSWorkflowUtility
Import-Module CimCmdlets
$MyToolsDriveTypePreference = 'Local'
$MyToolsErrorLogFile = 'C:\errors.txt'
$MyToolsLogFile = 'C:\log.txt'
$DefaultSQLServer = "629145-SYSADMIN.rslc.local"
Function Update-IISLogs{
<#
.Synopsis
   Function used to insert/update the servers event IIS logs from a domain to a MSSQL database
.DESCRIPTION
   Update-IISLogs
.EXAMPLE
   Update-IISLogs
#>
	[cmdletbinding()]
	Param
	(
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[array]$ComputerName,
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$DestServer = "629145-SYSADMIN.rslc.local",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$DestDB = "Tools",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$Website,
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[int]$Tail = 50,
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$TableName = "IISLogs"
	)
	BEGIN
	{
		[array]$error_log = $null
		[array]$Sql = $null
		[array]$FailedSql = $null
		[array]$results = $null
		[array]$websites = $null
		[array]$jobs = $null
		[array]$ObjectArray = $null
		$date = Get-Date
		[array]$activeservers = $null
		Get-Job | Remove-Job
		$connection = new-object -typename system.data.sqlclient.sqlconnection
		$connection.connectionstring = "Server=$DestServer;Database=$DestDB;Trusted_Connection=True;Connection Timeout=600;"
		$connection.open() | out-null
	}
	PROCESS
	{
		$command = new-object -typename system.data.sqlclient.sqlcommand
		$command.connection = $connection
		if ($ComputerName.count -gt 0)
		{
			$servers = $ComputerName
		}
		else
		{
			$servers = (Get-ADComputer -Filter * -Properties * | where { $_.lastlogondate -gt ((get-date).AddDays(-30)) }).name
		}
		foreach ($server in $servers)
		{
			if (Test-Connection $server -Count 1)
			{
				Invoke-Command -ComputerName $server -ScriptBlock { get-website | select id, @{ name = "LogPath"; Expression = { $_.logfile.directory } }, name } -AsJob -JobName $server
				$activeservers += $server
			}
			else
			{
				Write-Host -Object "Server $server not responding! `n"
			}
		}
		while ((Get-Job -State Running).count -gt 0)
		{
			Start-Sleep -Milliseconds 500
		}
		foreach ($server in $activeservers)
		{
			$websites += Receive-Job -Name $server -AutoRemoveJob -Wait
		}
		$i = 0
		while ($i -lt $websites.count)
		{
			Invoke-Command -ComputerName $websites[$i].pscomputername -ArgumentList $websites[$i].logpath, $websites[$i].id, $Tail -ScriptBlock { param ($LogPath,
					$WebsiteId,
					$Tail) Get-ChildItem -Path "$LogPath\W3SVC$WebsiteId\*.log" -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime -Descending -ErrorAction SilentlyContinue | Select-Object -First 1 -ErrorAction SilentlyContinue | Get-Content -Tail $Tail -ErrorAction SilentlyContinue } -AsJob -JobName "$($websites[$i].pscomputername):$($websites[$i].id):$($websites[$i].name)"
			$jobs += "$($websites[$i].pscomputername):$($websites[$i].id):$($websites[$i].name)"
			$i++
		}
		while ((Get-Job -State Running).count -gt 0)
		{
			Start-Sleep -Milliseconds 500
		}
		foreach ($job in $jobs)
		{
			$results = Receive-Job -Name $job -AutoRemoveJob -Wait
			foreach ($result in $results)
			{
				[array]$fields = $result -split " "
				$object = New-Object -TypeName PSCustomObject
				Add-Member -InputObject $object -MemberType NoteProperty -Name "ComputerName" -Value $($job -split ":")[0]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "WebsiteName" -Value $($job -split ":")[2]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "WebsiteId" -Value $($job -split ":")[1]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "Date" -Value $fields[0]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "Time" -Value $fields[1]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "s-ip" -Value $fields[2]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "cs-method" -Value $fields[3]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "cs-uri-stem" -Value $fields[4]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "cs-uri-query" -Value $fields[5]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "s-port" -Value $fields[6]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "cs-username" -Value $fields[7]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "c-ip" -Value $fields[8]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "cs(User-Agent)" -Value $fields[9]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "cs(Referer)" -Value $fields[10]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "sc-status" -Value $fields[11]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "sc-substatus" -Value $fields[12]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "sc-win32-status" -Value $fields[13]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "time-taken" -Value $fields[14]
				Add-Member -InputObject $object -MemberType NoteProperty -Name "X-Forwarded-For" -Value $fields[15]
				$ObjectArray += $object
			}
		}
		foreach ($object in $ObjectArray)
		{
			$sql += "MERGE $DestDB.dbo.$TableName AS Target `
	                    USING (VALUES(`'$($object.'ComputerName' -replace "`'", "`'`'")`',`'$($object.'WebsiteName' -replace "`'", "`'`'")`',`'$($object.'WebsiteId' -replace "`'", "`'`'")`',`'$($object.'date' -replace "`'", "`'`'")`',
	                            `'$($object.'time' -replace "`'", "`'`'")`',`'$($object.'s-ip' -replace "`'", "`'`'")`',`'$($object.'cs-method' -replace "`'", "`'`'")`',`'$($object.'cs-uri-stem' -replace "`'", "`'`'")`',
	                            `'$($object.'cs-uri-query' -replace "`'", "`'`'")`',`'$($object.'s-port' -replace "`'", "`'`'")`',`'$($object.'cs-username' -replace "`'", "`'`'")`',`'$($object.'c-ip' -replace "`'", "`'`'")`',
	                            `'$($object.'cs(user-Agent)' -replace "`'", "`'`'")`',`'$($object.'cs(Referer)' -replace "`'", "`'`'")`',`'$($object.'sc-status' -replace "`'", "`'`'")`',`'$($object.'sc-substatus' -replace "`'", "`'`'")`',
	                            `'$($object.'sc-win32-status' -replace "`'", "`'`'")`',`'$($object.'time-taken' -replace "`'", "`'`'")`',`'$($object.'X-Forwarded-For' -replace "`'", "`'`'")`')) 
	                    AS source (ComputerName,WebsiteName,WebsiteId,date,time,[s-ip],[cs-method],[cs-uri-stem],[cs-uri-query],[s-port],[cs-username],[c-ip],[cs(User-Agent)],[cs(Referer)],[sc-status],[sc-substatus],[sc-win32-status],[time-taken],[X-Forwarded-For])
	                    ON (Target.ComputerName = Source.ComputerName and Target.WebsiteName = Source.WebsiteName and Target.date = Source.date and Target.time = SOURCE.time)
	                    WHEN NOT MATCHED BY TARGET THEN
	                        INSERT (ComputerName,WebsiteName,WebsiteId, date,time,[s-ip],[cs-method],[cs-uri-stem],[cs-uri-query],[s-port],[cs-username],[c-ip],[cs(User-Agent)],[cs(Referer)],[sc-status],[sc-substatus],[sc-win32-status],[time-taken],[X-Forwarded-For]) 
	                        VALUES (source.ComputerName,source.WebsiteName,source.WebsiteId,source.date,source.time,source.[s-ip],source.[cs-method],source.[cs-uri-stem],source.[cs-uri-query],source.[s-port],source.[cs-username],source.[c-ip],source.[cs(User-Agent)],source.[cs(Referer)],source.[sc-status],source.[sc-substatus],source.[sc-win32-status],source.[time-taken],source.[X-Forwarded-For]);"
		}
		foreach ($query in $sql)
		{
			try
			{
				$command.Commandtext = $query
				$command.executenonquery() | Out-Null
			}
			catch [System.Data.SqlClient.SqlException]
			{
				$FailedSql += $query
			}
		}
	}
	END
	{
		if ($Sql.count -gt 0)
		{
			Out-File -FilePath c:\sql.txt -InputObject "`n################################################################################################"
			Out-File -FilePath c:\sql.txt -InputObject "Start of the sql queries for IIS logs captured on $date"
			Out-File -FilePath c:\sql.txt -InputObject $sql
			Out-File -FilePath c:\sql.txt -InputObject "`n################################################################################################`n"
		}
		if ($FailedSql.count -gt 0)
		{
			Out-File -FilePath c:\failedsql.txt -InputObject "`n################################################################################################" -Append
			Out-File -FilePath c:\failedsql.txt -InputObject "Start of the failed sql queries for IIS logs captured on $date logs" -Append
			Out-File -FilePath c:\failedsql.txt -InputObject $FailedSql -Append
			Out-File -FilePath c:\failedsql.txt -InputObject "`n################################################################################################`n" -Append
			
		}
		if ($MyToolsErrorLogFile)
		{
			Out-File -Append -FilePath $MyToolsErrorLogFile -InputObject $error_log -ErrorAction SilentlyContinue
		}
		$connection.close()
	}
}
Function Get-LocalConnections{
<#
.Synopsis
   Get Local connections
.DESCRIPTION
   This commandlet gets the number of local connections for the provided list of computers
.EXAMPLE
   Get-LocalConnections -ComputerName "computer1.lab.pri" -Port "80"
#>
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [String[]]$ComputerName,
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [int]$Port,
        [switch]$Continuous
    )

    Begin
    {
    }
    Process
    {
        if ($Continuous)
        {
            while ($true)
            {
                [array]$objects = $null
                foreach ($computer in $ComputerName)
                {
                    $object = New-Object -TypeName psobject
                    $object | Add-Member –Type NoteProperty –Name "Server" -Value $computer
                    $result = Invoke-Command -ComputerName $computer -ScriptBlock {netstat -ant} | Select-String -Pattern ":$Port"
                    if ($result.count -gt 0)
                    {
                        $object | Add-Member –Type NoteProperty –Name "Total Conn" -Value $result.count
                        $object | Add-Member –Type NoteProperty –Name "CLOSE_WAIT" -Value $($result | Select-String -SimpleMatch "CLOSE_WAIT").count
                        $object | Add-Member –Type NoteProperty –Name "ESTABLISHED" -Value $($result | Select-String -SimpleMatch "ESTABLISHED").count
                        $object | Add-Member –Type NoteProperty –Name "TIME_WAIT" -Value $($result | Select-String -SimpleMatch "TIME_WAIT").count
                        $object | Add-Member –Type NoteProperty –Name "Date" -Value (get-date)
                    }
                    $objects += $object
                }
                Clear-Host
                $objects | ft -AutoSize
            }
        }
        else
        {
            [array]$objects = $null
            foreach ($computer in $ComputerName)
            {
                $object = New-Object -TypeName psobject
                $object | Add-Member –Type NoteProperty –Name "Server" -Value $computer
                $result = Invoke-Command -ComputerName $computer -ScriptBlock {netstat -ant} | Select-String -Pattern ":$Port"
                if ($result.count -gt 0)
                {
                    $object | Add-Member –Type NoteProperty –Name "Total Conn" -Value $result.count
                    $object | Add-Member –Type NoteProperty –Name "CLOSE_WAIT" -Value $($result | Select-String -SimpleMatch "CLOSE_WAIT").count
                    $object | Add-Member –Type NoteProperty –Name "ESTABLISHED" -Value $($result | Select-String -SimpleMatch "ESTABLISHED").count
                    $object | Add-Member –Type NoteProperty –Name "TIME_WAIT" -Value $($result | Select-String -SimpleMatch "TIME_WAIT").count
                    $object | Add-Member –Type NoteProperty –Name "Date" -Value (get-date)
                }
                $objects += $object
            }
            $objects | ft -AutoSize
        }
        
    }
    End
    {
    }
}
Function Update-EventViwerLogs{
<#
.Synopsis
   Function used to insert/update the servers event viewer logs from a domain to a MSSQL database
.DESCRIPTION
   Update-EventViwerLogs
.EXAMPLE
   Update-EventViwerLogs
#>
	[cmdletbinding()]
	Param
	(
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[array]$ComputerName,
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$DestServer = "629145-SYSADMIN.rslc.local",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$DestDB = "Tools",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$LogPath = "c:\update_servers_log",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateSet("System", "Application", "Security")]
		[string]$LogName = "System",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$TableName = "EventViewerLogs",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[datetime]$After = (Get-Date).AddHours(-6)
	)
	BEGIN
	{
		[array]$error_log = $null
		[array]$Sql = $null
		[array]$FailedSql = $null
		[array]$results = $null
		[array]$activeservers = $null
		$connection = new-object -typename system.data.sqlclient.sqlconnection
		$connection.connectionstring = "Server=$DestServer;Database=$DestDB;Trusted_Connection=True;Connection Timeout=60;"
		$connection.open() | out-null
		$date = Get-Date
		Get-Job | Remove-Job
	}
	PROCESS
	{
		$command = new-object -typename system.data.sqlclient.sqlcommand
		$command.connection = $connection
		if ($ComputerName.count -gt 0)
		{
			$servers = $ComputerName
		}
		else
		{
			$servers = (Get-ADComputer -Filter * -Properties * | where { $_.lastlogondate -gt ((get-date).AddDays(-30)) }).name
		}
		foreach ($server in $servers)
		{
			if (Test-Connection $server -Count 1 -ErrorAction SilentlyContinue)
			{
				try
				{
					Invoke-Command -ComputerName $server -ArgumentList $LogName, $After -ScriptBlock { param ($LogName,
							$After) Get-EventLog -LogName $LogName -After $After -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue -AsJob -JobName $server
					$activeservers += $server
				}
				catch [ExpandPropertyNotFound, Microsoft.PowerShell.Commands.SelectObjectCommand]
				{
					
				}
			}
			else
			{
				$error_log += "Server $server not responding! `n"
			}
		}
		while ((Get-Job -State Running).count -gt 0)
		{
			Start-Sleep -Milliseconds 500
		}
		foreach ($server in $activeservers)
		{
			$results += Receive-Job -Name $server
		}
		foreach ($result in $results)
		{
			$SQL += "MERGE $DestDB.dbo.$TableName AS Target
                    USING (VALUES(`'$($($result.category -replace "_", "`'_") -replace "`'", "`'`'")`', `'$($($result.categorynumber -replace "_", "`'_") -replace "`'", "`'`'")`',`'$($($result.Container -replace "_", "`'_") -replace "`'", "`'`'")`',`'$($($result.Data -replace "_", "`'_") -replace "`'", "`'`'")`' ,`'$($($result.EntryType -replace "_", "`'_") -replace "`'", "`'`'")`' ,`'$($($result.Index -replace "_", "`'_") -replace "`'", "`'`'")`' ,`'$($($result.InstanceId -replace "_", "`'_") -replace "`'", "`'`'")`' ,`'$($($result.MachineName -replace "_", "`'_") -replace "`'", "`'`'")`' ,
                                    `'$($($result.Message -replace "_", "`'_") -replace "`'", "`'`'")`' ,`'$($($result.ReplacementStrings -replace "_", "`'_") -replace "`'", "`'`'")`' ,`'$($($result.Site -replace "_", "`'_") -replace "`'", "`'`'")`' ,`'$($($result.Source -replace "_", "`'_") -replace "`'", "`'`'")`' , `'$($($result.TimeGenerated -replace "_", "`'_") -replace "`'", "`'`'")`' ,`'$($($result.TimeWritten -replace "_", "`'_") -replace "`'", "`'`'")`',`'$($($result.UserName -replace "_", "`'_") -replace "`'", "`'`'")`',`'$($($result.EventID -replace "_", "`'_") -replace "`'", "`'`'")`', `'$LogName`')) 
                                    AS source (category, categorynumber, container, [Data],entrytype,[Index], instanceid, machinename, [Message], replacementstrings,[site],[source],timegenerated, timewritten, username, eventid,LogName)
                    ON (Target.TimeGenerated = Source.TimeGenerated and Target.MachineName = Source.MachineName and Target.LogName = Source.LogName and Target.Message = SOURCE.Message)
                    WHEN NOT MATCHED BY TARGET THEN
                        INSERT ( category, categorynumber, container, [Data],entrytype,[Index], instanceid, machinename, [Message], replacementstrings,[site],[source],timegenerated, timewritten, username, eventid,LogName) 
                        VALUES ( source.category, source.categorynumber, source.container, source.data, source.entrytype, source.[INDEX], source.instanceid, source.machinename, source.message, source.replacementstrings, source.site, 
                                    source.source, source.timegenerated, source.timewritten, source.username, source.eventid, source.LogName );"
		}
		foreach ($query in $sql)
		{
			try
			{
				$command.Commandtext = $query
				$command.executenonquery() | Out-Null
			}
			catch [System.Data.SqlClient.SqlException]
			{
				$FailedSql += $query
			}
		}
	}
	END
	{
		if ($Sql.count -gt 0)
		{
			Out-File -FilePath c:\sql.txt -InputObject "`n################################################################################################"
			Out-File -FilePath c:\sql.txt -InputObject "Start of the sql queries for EventViewer logs captured on $date logs"
			Out-File -FilePath c:\sql.txt -InputObject $sql
			Out-File -FilePath c:\sql.txt -InputObject "`n################################################################################################`n"
		}
		if ($FailedSql.count -gt 0)
		{
			Out-File -FilePath c:\failedsql.txt -InputObject "`n################################################################################################" -Append
			Out-File -FilePath c:\failedsql.txt -InputObject "Start of the failed sql queries for EventViewer logs captured on $date logs" -Append
			Out-File -FilePath c:\failedsql.txt -InputObject $FailedSql -Append
			Out-File -FilePath c:\failedsql.txt -InputObject "`n################################################################################################`n" -Append
		}
		if ($MyToolsErrorLogFile)
		{
			Out-File -Append -FilePath $MyToolsErrorLogFile -InputObject $error_log -ErrorAction SilentlyContinue
		}
		$connection.close()
	}
}
Function Watch-Command{
	##############################################################################
	##
	## Watch-Command
	##
	## From Windows PowerShell Cookbook (O'Reilly)
	## by Lee Holmes (http://www.leeholmes.com/guide)
	##
	##############################################################################
	<# .SYNOPSIS
	Watches the result of a command invocation, alerting you when the output
	either matches a specified string, lacks a specified string, or has simply
	changed.
	.EXAMPLE
	PS > Watch-Command { Get-Process -Name Notepad | Measure } -UntilChanged
	Monitors Notepad processes until you start or stop one.
	.EXAMPLE
	PS > Watch-Command { Get-Process -Name Notepad | Measure } -Until "Count
	Monitors Notepad processes until there is exactly one open.
	.EXAMPLE
	PS > Watch-Command {
	     Get-Process -Name Notepad | Measure } -While 'Count    : \d\s*\n'
	Monitors Notepad processes while there are between 0 and 9 open
	(once number after the colon).
	#>
	[CmdletBinding(DefaultParameterSetName = "Forever")]
	param(
	    ## The script block to invoke while monitoring
	    [Parameter(Mandatory = $true, Position = 0)]
	    [ScriptBlock] $ScriptBlock,
	    ## The delay, in seconds, between monitoring attempts
	    [Parameter()]
	    [Double] $DelaySeconds = 1,
	    ## Specifies that the alert sound should not be played
	    [Parameter()]
	    [Switch] $Quiet,
	    ## Monitoring continues only while the output of the
	    ## command remains the same.
	    [Parameter(ParameterSetName = "UntilChanged", Mandatory = $false)]
	    [Switch] $UntilChanged,
	    ## The regular expression to search for. Monitoring continues
	    ## until this expression is found.
	    [Parameter(ParameterSetName = "Until", Mandatory = $false)]
	    [String] $Until,
	    ## The regular expression to search for. Monitoring continues
	    ## until this expression is not found.
	    [Parameter(ParameterSetName = "While", Mandatory = $false)]
	    [String] $While
	)
	Set-StrictMode -Version 3
	$initialOutput = ""
	## Start a continuous loop
	while($true)
	{
	    ## Run the provided script block
	    $r = & $ScriptBlock
	    ## Clear the screen and display the results
	    Clear-Host
	    $ScriptBlock.ToString().Trim()
	    ""
	    $textOutput = $r | Out-String
	    $textOutput
	    ## Remember the initial output, if we haven't
	    ## stored it yet
		if (-not $initialOutput)
		{
			$initialOutput = $textOutput
		}
		## If we are just looking for any change,
	    ## see if the text has changed.
	    if($UntilChanged)
	    {
	        if($initialOutput -ne $textOutput)
	        {
	break }
	}
	    ## If we need to ensure some text is found,
	    ## break if we didn't find it.
	    if($While)
	    {
	        if($textOutput -notmatch $While)
	        {
	break }
	}
	    ## If we need to wait for some text to be found,
	    ## break if we find it.
	    if($Until)
	    {
	        if($textOutput -match $Until)
	        {
	break }
	}
	## Delay
	    Start-Sleep -Seconds $DelaySeconds
	}
	## Notify the user
	if(-not $Quiet)
	{
	    [Console]::Beep(1000, 1000)
	}
}
Function Copy-ItemWithProgress{
<#
.SYNOPSIS
RoboCopy with PowerShell progress.

.DESCRIPTION
Performs file copy with RoboCopy. Output from RoboCopy is captured,
parsed, and returned as Powershell native status and progress.

.PARAMETER RobocopyArgs
List of arguments passed directly to Robocopy.
Must not conflict with defaults: /ndl /TEE /Bytes /NC /nfl /Log

.OUTPUTS
Returns an object with the status of final copy.
REMINDER: Any error level below 8 can be considered a success by RoboCopy.

.EXAMPLE
C:\PS> .\Copy-ItemWithProgress c:\Src d:\Dest

Copy the contents of the c:\Src directory to a directory d:\Dest
Without the /e or /mir switch, only files from the root of c:\src are copied.

.EXAMPLE
C:\PS> .\Copy-ItemWithProgress '"c:\Src Files"' d:\Dest /mir /xf *.log -Verbose

Copy the contents of the 'c:\Name with Space' directory to a directory d:\Dest
/mir and /XF parameters are passed to robocopy, and script is run verbose

.LINK
https://keithga.wordpress.com/2014/06/23/copy-itemwithprogress

.NOTES
By Keith S. Garner (KeithGa@KeithGa.com) - 6/23/2014
With inspiration by Trevor Sullivan @pcgeek86

#>
	
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
		[string[]]$RobocopyArgs
	)
	
	$ScanLog = [IO.Path]::GetTempFileName()
	$RoboLog = [IO.Path]::GetTempFileName()
	$ScanArgs = $RobocopyArgs + "/ndl /TEE /bytes /Log:$ScanLog /nfl /L".Split(" ")
	$RoboArgs = $RobocopyArgs + "/ndl /TEE /bytes /Log:$RoboLog /NC".Split(" ")
	
	# Launch Robocopy Processes
	write-verbose ("Robocopy Scan:`n" + ($ScanArgs -join " "))
	write-verbose ("Robocopy Full:`n" + ($RoboArgs -join " "))
	$ScanRun = start-process robocopy -PassThru -WindowStyle Hidden -ArgumentList $ScanArgs
	$RoboRun = start-process robocopy -PassThru -WindowStyle Hidden -ArgumentList $RoboArgs
	
	# Parse Robocopy "Scan" pass
	$ScanRun.WaitForExit()
	$LogData = get-content $ScanLog
	if ($ScanRun.ExitCode -ge 8)
	{
		$LogData | out-string | Write-Error
		throw "Robocopy $($ScanRun.ExitCode)"
	}
	$FileSize = [regex]::Match($LogData[-4], ".+:\s+(\d+)\s+(\d+)").Groups[2].Value
	write-verbose ("Robocopy Bytes: $FileSize `n" + ($LogData -join "`n"))
	
	# Monitor Full RoboCopy
	while (!$RoboRun.HasExited)
	{
		$LogData = get-content $RoboLog
		$Files = $LogData -match "^\s*(\d+)\s+(\S+)"
		if ($Files -ne $Null)
		{
			$copied = ($Files[0..($Files.Length - 2)] | %{ $_.Split("`t")[-2] } | Measure -sum).Sum
			if ($LogData[-1] -match "(100|\d?\d\.\d)\%")
			{
				write-progress Copy -ParentID $RoboRun.ID -percentComplete $LogData[-1].Trim ("% `t") $LogData[-1]
				$Copied += $Files[-1].Split("`t")[-2] /100 * ($LogData[-1].Trim("% `t"))
			}
			else
			{
				write-progress Copy -ParentID $RoboRun.ID -Complete
			}
			write-progress ROBOCOPY -ID $RoboRun.ID -PercentComplete ($Copied/$FileSize * 100) $Files[-1].Split ("`t")[-1]
		}
	}
	
	# Parse full RoboCopy pass results, and cleanup
	(get-content $RoboLog)[-11.. -2] | out-string | Write-Verbose
	[PSCustomObject]@{ ExitCode = $RoboRun.ExitCode }
	remove-item $RoboLog, $ScanLog
}
Function Get-ComputerCounter{
	[cmdletbinding()]
	Param (
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string[]]$ServerNames,
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$DestServer = "629145-SYSADMIN.rslc.local",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$DestDB = "Tools",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$LogPath = "c:\Get_ComputerCounter_log.txt",
		[int]$Samples=60,
		[int]$interval=2
	)
	BEGIN
	{
		Import-Module -Name sqlps -DisableNameChecking
		$SMO = "Microsoft.SqlServer.Management.Smo"
		$dbint = [Microsoft.SqlServer.Management.Smo.Datatype]::Int
		$dbdatetime = [Microsoft.SqlServer.Management.Smo.Datatype]::DateTime
		[array]$error_log = $null
		[array]$sql = $null
		$SchemaName = "dbo"
		$connection = New-Object ('Microsoft.SqlServer.Management.SMO.Server') "$DestServer"
		$db = $connection.databases[$DestDB]
		foreach ($Server in $ServerNames)
		{
			$tablename = "$($Server)_counters"
			$CounterTable = $connection.databases[$tablename]
			if (!($db.tables[$CounterTable]))
			{
				Write-Host "Table $tablename does not exist!"
				Write-Host "Creating Table: [$SchemaName].[$tablename]"
				$table = New-Object ("$SMO.table") ($db, $tablename, $SchemaName)
				
				$column = New-Object ("$SMO.column") ($table, "ID", $dbint)
				$column.identity = $true
				$column.identityseed = 1
				$column.identityincrement = 1
				$table.columns.add($column)
				
				$column = New-Object ("$SMO.column") ($table, "Timestamp", $dbdatetime)
				$column.Nullable = $false
				$table.columns.add($column)
				
				$column = New-Object ("$SMO.column") ($table, "DiskQue", $dbint)
				$column.Nullable = $false
				$table.columns.add($column)
				
				$column = New-Object ("$SMO.column") ($table, "ProcessorTime", $dbint)
				$column.Nullable = $false
				$table.columns.add($column)
				
				$column = New-Object ("$SMO.column") ($table, "Memory", $dbint)
				$column.Nullable = $false
				$table.columns.add($column)
				
				# Create the table
				$Table.Create()
			}
		}
	}
	PROCESS
	{
		Import-Module -Name sqlps -DisableNameChecking
		$counters = @(
		"\PhysicalDisk(_total)\Disk Bytes/sec",
		"\PhysicalDisk(_total)\Current Disk Queue Length",
		"\processor(_total)\% processor time",
		"\Memory\Available MBytes"
		)
		<#,
		"\logicalDisk(c:)\% free space",
		"\logicalDisk(d:)\% free space",
		"\logicalDisk(e:)\% free space",
		"\logicalDisk(f:)\% free space",
		"\logicalDisk(l:)\% free space",
		"\logicalDisk(p:)\% free space",
		"\logicalDisk(q:)\% free space",
		"\logicalDisk(r:)\% free space",
		"\logicalDisk(s:)\% free space",
		"\logicalDisk(t:)\% free space",
		"\logicalDisk(x:)\% free space",
		"\logicalDisk(z:)\% free space"
		#>
		$data = Get-Counter -ComputerName $servers -Counter $counters -MaxSamples $Samples -SampleInterval $interval -ErrorAction SilentlyContinue -ErrorVariable DataError
	}
	END
	{
	}
}
Function Update-Servers{
<#
.Synopsis
   Function used to insert/update the servers from a domain to a MSSQL database
.DESCRIPTION
   Function used to insert/update the servers from a domain to a MSSQL database
.EXAMPLE
   Update-Servers
#>
	[cmdletbinding()]
	Param
	(
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$DestServer = "733476-SQLLOG01",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$DestDB = "Tools",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$LogPath = "c:\update_servers_log"
	)
	BEGIN
	{
		[array]$error_log = $null
		[array]$sql = $null
		$connection = new-object -typename system.data.sqlclient.sqlconnection
		$connection.connectionstring = "Server=$DestServer;Database=$DestDB;Trusted_Connection=True;"
		$connection.open() | out-null
		$date = Get-Date
	}
	PROCESS
	{
		$clear_table = "TRUNCATE table $DestDB.dbo.SERVERS"
		$command = new-object -typename system.data.sqlclient.sqlcommand
		$command.connection = $connection
		#$servers = Get-Content -Path C:\servers.txt
		$servers = (Get-ADComputer -Filter * -Properties * | where { $_.lastlogondate -gt ((get-date).AddDays(-30)) }).name
		foreach ($server in $servers)
		{
			if (Test-Connection -ComputerName "$server" -Count 2 -Quiet -ErrorVariable CmdErrors)
			{
				$server
				$ErrorActionPreference = 'Stop'
				try
				{
					[string]$server_OS = (Get-CimInstance -ClassName CIM_OperatingSystem -ComputerName "$server" -ErrorVariable CmdErrors).caption
					[int]$server_RAM = (((Get-CimInstance -ClassName CIM_ComputerSystem -ComputerName "$server" -ErrorVariable CmdErrors).totalphysicalmemory)/1gb)
					[string]$server_CPU_MODEL = ((Get-CimInstance -ClassName CIM_Processor -ComputerName "$server" -ErrorVariable CmdErrors)[0]).name
					[int]$server_CPU_cores = (Get-CimInstance -ClassName CIM_computerSystem -ComputerName "$server" -ErrorVariable CmdErrors).NumberOfLogicalProcessors
					$server_drives_number = (Get-CimInstance -ClassName CIM_LogicalDisk -ComputerName "$server" -ErrorVariable CmdErrors | where { $_.drivetype -eq "3" }).count
					$server_drives = (Get-CimInstance -ClassName CIM_LogicalDisk -ComputerName "$server" -ErrorVariable CmdErrors | where { $_.drivetype -eq "3" }).deviceid
					foreach ($drive in $server_drives)
					{
						New-Variable -Force -Name ($drive[0] + "_Drive_Size") -Value ([math]::Round((Get-CimInstance -ClassName CIM_LogicalDisk -ComputerName "$server" -ErrorVariable CmdErrors| where { $_.drivetype -eq "3" } | where { $_.deviceid -eq "$drive" }).Size/1gb))
						New-Variable -Force -Name ($drive[0] + "_Drive_Free") -Value ([math]::Round((Get-CimInstance -ClassName CIM_LogicalDisk -ComputerName "$server" -ErrorVariable CmdErrors| where { $_.drivetype -eq "3" } | where { $_.deviceid -eq "$drive" }).FreeSpace/1gb))
					}
					$server_drives_size = (Get-CimInstance -ClassName CIM_LogicalDisk -ComputerName "$server" -ErrorVariable CmdErrors | where { $_.drivetype -eq "3" }).size
					$size_sum = 0
					$server_drives_size | Foreach { $size_sum += [math]::Round($_/1gb) }
					$server_drives_free = (Get-CimInstance -ClassName CIM_LogicalDisk -ComputerName "$server" -ErrorVariable CmdErrors| where { $_.drivetype -eq "3" }).FreeSpace
					$Free_sum = 0
					$server_drives_Free | Foreach { $Free_sum += [math]::Round($_/1gb) }
					[string]$server_BIOS_NAME = (Get-CimInstance CIM_BIOSElement -ComputerName "$server" -ErrorVariable CmdErrors).Name
					[string]$server_BIOS_Serial = (Get-CimInstance CIM_BIOSElement -ComputerName "$server" -ErrorVariable CmdErrors).SerialNumber
					[datetime]$server_LAST_BOOT_TIME = (Get-CimInstance -ClassName CIM_OperatingSystem -ComputerName "$server" -ErrorVariable CmdErrors).LastBootUpTime
					$SQL += "INSERT INTO $DestDB.dbo.SERVERS ( `
						    SERVER_NAME,OS,RAM,CPU_MODEL,CPU_CORES,BIOS_NAME,BIOS_SERIAL,LAST_BOOT_TIME,FREE_SPACE,TOTAL_SIZE,`
						    C_Drive_Size,C_Drive_FREE,D_Drive_Size,D_Drive_FREE,E_Drive_Size,E_Drive_FREE,F_Drive_Size,F_Drive_FREE,L_Drive_Size,L_Drive_FREE,P_Drive_Size,P_Drive_FREE,`
						    Q_Drive_Size,Q_Drive_FREE,R_Drive_Size,R_Drive_FREE,S_Drive_Size,S_Drive_FREE,T_Drive_Size,T_Drive_FREE,X_Drive_Size,X_Drive_FREE,Z_Drive_Size,Z_Drive_FREE) `
	                        VALUES (`
	                                '$($server)','$($server_OS)',`
	                                '$($server_RAM)','$($server_CPU_MODEL)',`
								    '$($server_CPU_cores)','$($server_BIOS_NAME)',`
	                                '$($server_BIOS_Serial)','$($server_LAST_BOOT_TIME)',`
	                                '$($Free_sum)','$($size_sum)',`
	                                '$($C_Drive_Size)','$($C_Drive_Free)',`
								    '$($D_Drive_Size)','$($D_Drive_Free)',`
								    '$($E_Drive_Size)','$($E_Drive_Free)',`
								    '$($F_Drive_Size)','$($F_Drive_Free)',`
								    '$($L_Drive_Size)','$($L_Drive_Free)',`
								    '$($P_Drive_Size)','$($P_Drive_Free)',`
								    '$($Q_Drive_Size)','$($Q_Drive_Free)',`
								    '$($R_Drive_Size)','$($R_Drive_Free)',`
								    '$($S_Drive_Size)','$($S_Drive_Free)',`
								    '$($T_Drive_Size)','$($T_Drive_Free)',`
								    '$($X_Drive_Size)','$($X_Drive_Free)',`
								    '$($Z_Drive_Size)','$($Z_Drive_Free)'`
	                                );"
				}
				catch [Microsoft.Management.Infrastructure.CimException]
				{
					#cim exception
					$error_log += "Unhandled exception [Microsoft.Management.Infrastructure.CimException]"
					$error_log += "`n $server `n"
					$error_log += $CmdErrors | select -Property *
				}			
				catch [System.Management.Automation.RuntimeException]
				{
					#null array
					$error_log += "Unhandled exception [System.Management.Automation.RuntimeException]"
					$error_log += "`n $server `n"
					$error_log += $CmdErrors | select -Property *
				}				
				catch
				{
					$error_log += "Unhandled exception ################################################"
					$error_log += "`n $server `n"
					$error_log += $CmdErrors | select -Property *
				}
				$ErrorActionPreference = 'Continue'
			}
			else
			{
				$error_log += "Server $server not responding! `n"
			}
		}
		$command.CommandText = $clear_table
		$command.executenonquery() | Out-Null
		$command.Commandtext = $sql
		$command.executenonquery() | Out-Null
	}
	END
	{
        Out-File -Append -FilePath $MyToolsErrorLogFile -InputObject $error_log
		$connection.close()
	}
}
Function Update-ActiveComputers{
<#
.Synopsis
   Function used to update the Active servers list to a MSSQL database
.DESCRIPTION
   Update-ActiveComputers
.EXAMPLE
   Update-ActiveComputers
#>
	[cmdletbinding()]
	Param
	(
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$DestServer = "629145-SYSADMIN.rslc.local",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$Domain = "rslc.local",
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$LogPath = "c:\update_ActiveServers_log",
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$TableName = "ActiveServers",
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [datetime]$After=(Get-Date).AddDays(-30),
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]$DestDB = "Tools"
	)
	BEGIN
	{
		$connection = new-object -typename system.data.sqlclient.sqlconnection
		$connection.connectionstring = "Server=$DestServer;Database=$DestDB;Trusted_Connection=True;Connection Timeout=60;"
		$connection.open() | out-null
        $command = new-object -typename system.data.sqlclient.sqlcommand
		$command.connection = $connection
		$date = Get-Date
        Get-Job | Remove-Job
        [array]$ComputerNames = $null
        [array]$ActiveComputerNames = $null
	}
	PROCESS
	{
        $clear_table = "TRUNCATE table $DestDB.dbo.$TableName"
		$ComputerNames = (Get-ADComputer -Filter * -Properties * | where { $_.lastlogondate -gt ((get-date).AddDays(-30)) }).DNSHostName | Sort-Object -Unique
		foreach ($server in $ComputerNames)
        {
            if (Test-Connection -ComputerName $server -Count 1 -ErrorAction SilentlyContinue)
            {
                $ActiveComputerNames += $server
            }
            else
            {
                Write-Host -ForegroundColor Cyan -Object "$(get-date) : $server is not responding !"
            }
        }
        foreach ($server in $ActiveComputerNames)
        {
            $SQL +="INSERT INTO $DestDB.dbo.$TableName (ComputerName) 
                    Values
                    (`'$($($server -replace "_","`'_") -replace "`'","`'`'")`');"
		}
        Write-Host -ForegroundColor Cyan -Object "$(Get-Date) : Executing sql queries."
        $command.CommandText = $clear_table
		$command.executenonquery() | Out-Null
		foreach ($query in $sql)
		{
			try
			{
				Invoke-Sqlcmd -ServerInstance $DestServer -Query $query -Database $DestDB -QueryTimeout 600
				<#$command.Commandtext = $query
				$command.executenonquery() | Out-Null#>
			}
			catch [System.Data.SqlClient.SqlException]
			{
				$FailedSql += $query
			}
		}
        Write-Host -ForegroundColor Cyan -Object "$(Get-Date) : Finished executing sql queries."
	}
	END
	{
		if ($Sql.count -gt 0)
		{
			if (Test-Path -Path "c:\sql.txt" -ErrorAction SilentlyContinue)
			{
				Remove-Item -Path "c:\sql.txt" -Force
			}
			Out-File -FilePath c:\sql.txt -InputObject "`n################################################################################################"
			Out-File -FilePath c:\sql.txt -InputObject "Start of the sql queries for Update Active Servers captured on $date logs" -Append
			Out-File -FilePath c:\sql.txt -InputObject $sql -Append
			Out-File -FilePath c:\sql.txt -InputObject "`n################################################################################################`n" -Append
		}
		if ($FailedSql.count -gt 0)
		{
			Out-File -FilePath c:\failedsql.txt -InputObject "`n################################################################################################" -Append
			Out-File -FilePath c:\failedsql.txt -InputObject "Start of the sql queries for Update Active Servers captured on $date logs" -Append
			Out-File -FilePath c:\failedsql.txt -InputObject $FailedSql -Append
			Out-File -FilePath c:\failedsql.txt -InputObject "`n################################################################################################`n" -Append
		}
		if ($MyToolsErrorLogFile)
		{
			Out-File -Append -FilePath $MyToolsErrorLogFile -InputObject $error_log -ErrorAction SilentlyContinue
		}
		$connection.close()
	}
}
function Set-ServicePassword {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ServiceName,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$NewPassword,

        [switch]$LogErrors,

        [ValidateScript({-not (Test-Path $_)})]
        [string]$ErrorLogFile=$ErrorLogFilePreference
    )
    Process {
        foreach ($computer in $ComputerName) {
            $service = Get-WmiObject -ComputerName $computer `
                                     -Class Win32_Service `
                                     -Filter "Name='$servicename'"
            if ($PSCmdlet.ShouldProcess("for service $servicename on $computer")) {
                $service.change($null,$null,$null,$null,$null,$null,$null,$NewPassword)
            }

        } #foreach computer
    } #process
}
function Remove-LogFile {
    [CmdletBinding()]
    param([string]$LogFilePath)
    try {
        Remove-Item -Path $LogFilePath -ErrorAction Stop
        Write-Output $True
        Write-Verbose "Deleted $LogFilePath"
    } catch [System.Management.Automation.ItemNotFoundException] {
        # not found
        Write-Verbose "$LogFilePath did not exist, nothing to delete"
        Write-Output $True
    } catch [System.IO.IOException] {
        # read only or access denied
        Write-Error "$LogFilePath denied or read only, not deleted!!!"
        Write-Output $false
    } catch {
        # other
        Write-Warning "Unknown error deleting $LogFilePath"
		Write-Output $false
    }
}
function Get-SystemInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string[]]$ComputerName,

        [switch]$LogErrors,

        [string]$ErrorLogFile=$ErrorLogFilePreference
    )
    Begin {
        if( -not (Remove-LogFile $ErrorLogFile)) { break } 
    }
    Process {
        foreach ($computer in $ComputerName) {
            try {
                $os = Get-WmiObject -ErrorAction Stop -ComputerName $computer -Class Win32_OperatingSystem
                $cs = Get-WmiObject -ComputerName $computer -Class Win32_ComputerSystem
                $bios = Get-WmiObject -ComputerName $computer -Class Win32_BIOS
                $proc = Get-WmiObject -ComputerName $computer -Class Win32_Processor | Select -first 1

                $properties = @{'ComputerName'=$os.csname;
                                'OSVersion'=$os.version;
                                'OSBuild'=$os.buildnumber;
                                'SPVersion'=$os.servicepackmajorversion;
                                'OSArchitecture'=$os.osarchitecture;
                                'Mfgr'=$cs.manufacturer;
                                'Model'=$cs.model;
                                'BIOSSerial'=$bios.serialnumber;
                                'DateChecked'=(get-date);
                                'ProcArchitecture'="$($proc.addresswidth)-bit"}

                $obj = New-Object -TypeName PSObject -Property $properties
                $obj.psobject.typenames.insert(0,'Report.SystemInfo')
                Write-Output $obj
            } catch {
                if ($LogErrors) {
                    $computer | out-file $ErrorLogFile -Append
                }
            } 
        } #foreach computer
    } #process
}
function Get-NetAdaptIPAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)]
        [string[]]$ComputerName
    )
    PROCESS {
        foreach ($computer in $ComputerName) {
            $session = New-CimSession -ComputerName $computer

            $adapters = Get-NetAdapter -CimSession $session
            foreach ($adapter in $adapters) {

                $addresses = Get-NetIPAddress -CimSession $session |
                             Where-Object { $_.ifIndex -eq $adapter.ifIndex }
                foreach ($address in $addresses) {

                    $properties = @{'ComputerName'=$computer;
                                    'AdaptName'=$adapter.name;
                                    'IPAddress'=$address.ipaddress;
                                    'Family'=$address.addressfamily}
                    $obj = New-Object -TypeName PSObject -Property $properties
                    Write-Output $obj

                } #foreach address
            } #foreach adapter

            Remove-CimSession -CimSession $session
        } #foreach computer
    } #process
}
function Get-ServerEventLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,
                   ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        [string[]]$ComputerName,
        [int]$EventNumber=10,
        [System.Management.Automation.CredentialAttribute()]$credential,
        [int]$DayNumber=1

    )
    BEGIN {}
    PROCESS{
          Invoke-Command -ScriptBlock { Get-EventLog Application -Newest $EventNumber -EntryType Error,Warning} -Credential $credential -ComputerName $ComputerName | where -FilterScript {$_.timegenerated -gt (Get-Date).AddDays($DayNumber)} | Format-Table -Property @{name = 'Time' ; expression = {$_.timegenerated.toshortdatestring()}},@{name = 'Name'; expression = {$_.pscomputername}},source,message -AutoSize
    }
    END {}
}
function Get-DiskSpaceInfo {
<# 
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage='Computer name to query',
                   ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        [string[]]$ComputerName,
        [Parameter(Position=2,
                   ValueFromPipelineByPropertyName=$True)]
        [Validateset('Floppy','Local','Optical')]
        [string]$Drivetype = 'Local',
        [string]$ErrorLogFile = $MyToolsErrorLogFile
    )
    BEGIN {
        Remove-Item -Path $ErrorLogFile -ErrorAction SilentlyContinue
    }
    PROCESS {
        foreach ($computer in $computername) {
            $params = @{'ComputerName'=$ComputerName
                        'Class'='Win32_LogicalDisk'}
            switch ($Drivetype) {
                'Local' { $params.add('Filter','DriveType=3'); break }
                'Flopy' { $params.add('Filter','DriveType=2'); break }
                'Optical' { $params.add('Filter','DriveType=5'); break }
            }
            try {
                Get-WmiObject @params -ErrorAction Stop -ErrorVariable myerr |
                Select-Object @{n='Drive';e={$_.DeviceID}},
                                @{n='Size';e={[math]::Round(($_.Size / 1GB),2)}},
                                @{n='FreeSpace';e={[math]::Round(($_.FreeSpace / 1GB),2)}},
                                @{n='FreePercent';e={[math]::Round(($_.FreeSpace / $_.Size * 100),2)}},
                                PSComputerName
            } catch {
                $computer | Out-File $ErrorLogFile -Append
                Write-Verbose "Failed to connect to $computer ; Error is $myerr"
            }
        }
    }
    END {}
}
function Get-ComputerDetails {
    param(
        [string[]]$ComputerName
    )
    foreach ($comp in $ComputerName) {
        $os = Get-WmiObject -Class Win32_operatingsystem -ComputerName $comp
        $cs = Get-WmiObject -Class Win32_computersystem -ComputerName $comp
        $bios = Get-WmiObject -Class Win32_BIOS -ComputerName $comp

        $props = [ordered]@{'ComputerName'=$comp;
                   'OSVersion'=$os.version;
                   'SPVersion'=$os.servicepackmajorversion;
                   'Mfgr'=$cs.manufacturer;
                   'RAM'=$cs.totalphysicalmemory;
                   'BIOSSerial'=$bios.serialnumber
                  }
        $obj = New-Object -TypeName PSObject -Property $props
        Write-Output $obj
    }
}
function Set-ComputerState {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,
               ValueFromPipeline=$True,
               ValueFromPipelineByPropertyName=$True)]
    [string[]]$ComputerName,
    [switch]$force,
    [Parameter(ParameterSetName='Logoff')]
    [switch]$LogOff,
    [Parameter(ParameterSetName='Restart')]
    [Switch]$Restart,
    [Parameter(ParameterSetName='Shutdown')]
    [Switch]$Shutdown,
    [Parameter(ParameterSetName='PowerOff')]
    [Switch]$PowerOff
    )
    PROCESS {
        foreach($computer in $ComputerName) {
            if (Check-Computer $computer) {
                if ($works) {
                    $os = Get-WmiObject -ComputerName $computer -Class Win32_OperatingSystem
                    if ($LogOff) { $arg = 0 }
                    if ($Restart) { $arg = 2 }
                    if ($Shutdown) { $arg = 1 }
                    if ($PowerOff) { $arg = 8 }
                    if ($Force) { $arg += 4 }
                    try {
                        $ErrorActionPreference = 'Stop'
                        $os.Win32Shutdown($arg)
                        $ErrorActionPreference = 'Continue'
                    } catch {
                        #whatever
                    }
                }
            }
        }
    }
}
function Test-Computer {
    param(
        [string[]]$Computer )
    $works = $true
    if (Test-Connection $computer -Count 1 -Quiet) {
        try {
            Get-WmiObject win32_bios -ComputerName $computer -ErrorAction Stop | Out-Null
        } catch {
            $works = $false
        }
    } else {
        $works = $false
    }
    return $works
}
function Get-Computernamesfordiskdetailsfromdatabase{
	[Cmdletbindings()]
	param()
	BEGIN 
	{
		$connection = new-object -typename system.data.sqlclient.sqlconnection
		$connection.connectionstring="Server=app01\sqlexpr;Database=myDataBase;Trusted_Connection=True;"
		$connection.open() | out-null
	}
	PROCESS
	{
		$command = new-object -typename system.data.sqlclient.sqlcommand
		$command.connection = $connection

		$SQL="Select Computername FROM DiskData"		
		Write-Debug "Executing $sql"
		$command.Commandtext = $sql

		$reader = $command.executereader()

		While ($reader.read()){
			$reader.getsqlstring(0).value
			#$computername = $reader.getsqlstring(0)
			#Write-Output $computername
		}
    }
	END
	{
		$connection.close()
	}
}
function Backup-Database {
    Backup - Full Database Backup
    #============================================================
    # Backup a Database using PowerShell and SQL Server SMO
    # Script below creates a full backup
    #============================================================
 
    #specify database to backup
    #ideally this will be an argument you pass in when you run
    #this script, but let's simplify for now
    $dbToBackup = "test"
 
    #clear screen
    cls
 
    #load assemblies
    #note need to load SqlServer.SmoExtended to use SMO backup in SQL Server 2008
    #otherwise may get this error
    #Cannot find type [Microsoft.SqlServer.Management.Smo.Backup]: make sure
    #the assembly containing this type is loaded.
 
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null
 
    #create a new server object
    $server = New-Object ("Microsoft.SqlServer.Management.Smo.Server") "(local)"
    $backupDirectory = $server.Settings.BackupDirectory
 
    #display default backup directory
    "Default Backup Directory: " + $backupDirectory
 
    $db = $server.Databases[$dbToBackup]
    $dbName = $db.Name
 
    $timestamp = Get-Date -format yyyyMMddHHmmss
    $smoBackup = New-Object ("Microsoft.SqlServer.Management.Smo.Backup")
 
    #BackupActionType specifies the type of backup.
    #Options are Database, Files, Log
    #This belongs in Microsoft.SqlServer.SmoExtended assembly
 
    $smoBackup.Action = "Database"
    $smoBackup.BackupSetDescription = "Full Backup of " + $dbName
    $smoBackup.BackupSetName = $dbName + " Backup"
    $smoBackup.Database = $dbName
    $smoBackup.MediaDescription = "Disk"
    $smoBackup.Devices.AddDevice($backupDirectory + "\" + $dbName + "_" + $timestamp + ".bak", "File")
    $smoBackup.SqlBackup($server)
 
    #let's confirm, let's list list all backup files
    $directory = Get-ChildItem $backupDirectory
 
    #list only files that end in .bak, assuming this is your convention for all backup files
    $backupFilesList = $directory | where {$_.extension -eq ".bak"}
    $backupFilesList | Format-Table Name, LastWriteTime
 }
function Restore-Database {
    Restore - Database Restore Overwriting Original Database
    #============================================================
    # Restore a Database using PowerShell and SQL Server SMO
    # Restore to the same database, overwrite existing db
    #============================================================
 
    #clear screen
    cls
 
    #load assemblies
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null

    #Need SmoExtended for backup
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
    [Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
    [Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null
 
    #get backup file
    #you can also use PowerShell to query the last backup file based on the timestamp
    #I'll save that enhancement for later
    $backupFile = "C:\Program Files\Microsoft SQL Server\MSSQL10.MSSQLSERVER\MSSQL\Backup\test_db_20090531153233.bak"
 
    #we will query the db name from the backup file later
 
    $server = New-Object ("Microsoft.SqlServer.Management.Smo.Server") "(local)"
    $backupDevice = New-Object ("Microsoft.SqlServer.Management.Smo.BackupDeviceItem") ($backupFile, "File")
    $smoRestore = new-object("Microsoft.SqlServer.Management.Smo.Restore")
 
    #settings for restore
    $smoRestore.NoRecovery = $false;
    $smoRestore.ReplaceDatabase = $true;
    $smoRestore.Action = "Database"
 
    #show every 10% progress
    $smoRestore.PercentCompleteNotification = 10;
 
    $smoRestore.Devices.Add($backupDevice)
 
    #read db name from the backup file's backup header
    $smoRestoreDetails = $smoRestore.ReadBackupHeader($server)
 
    #display database name
    "Database Name from Backup Header : " + $smoRestoreDetails.Rows[0]["DatabaseName"]
 
    $smoRestore.Database = $smoRestoreDetails.Rows[0]["DatabaseName"]
 
    #restore
    $smoRestore.SqlRestore($server)
 
    "Done"

 
    Restore - Database Restore On a New Database Name
    #============================================================
    # Restore a Database using PowerShell and SQL Server SMO
    # Restore to the a new database name, specifying new mdf and ldf
    #============================================================
 
    #clear screen
    cls
 
    #load assemblies
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null

    #Need SmoExtended for backup
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
    [Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
    [Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null
 
    $backupFile = 'C:\Program Files\Microsoft SQL Server\MSSQL10.MSSQLSERVER\MSSQL\Backup\test_db_20090531153233.bak'
 
    #we will query the database name from the backup header later
    $server = New-Object ("Microsoft.SqlServer.Management.Smo.Server") "(local)"
    $backupDevice = New-Object("Microsoft.SqlServer.Management.Smo.BackupDeviceItem") ($backupFile, "File")
    $smoRestore = new-object("Microsoft.SqlServer.Management.Smo.Restore")
 
    #restore settings
    $smoRestore.NoRecovery = $false;
    $smoRestore.ReplaceDatabase = $true;
    $smoRestore.Action = "Database"
    $smoRestorePercentCompleteNotification = 10;
    $smoRestore.Devices.Add($backupDevice)
 
    #get database name from backup file
    $smoRestoreDetails = $smoRestore.ReadBackupHeader($server)
 
    #display database name
    "Database Name from Backup Header : " +$smoRestoreDetails.Rows[0]["DatabaseName"]
 
    #give a new database name
    $smoRestore.Database =$smoRestoreDetails.Rows[0]["DatabaseName"] + "_Copy"
 
    #specify new data and log files (mdf and ldf)
    $smoRestoreFile = New-Object("Microsoft.SqlServer.Management.Smo.RelocateFile")
    $smoRestoreLog = New-Object("Microsoft.SqlServer.Management.Smo.RelocateFile")
 
    #the logical file names should be the logical filename stored in the backup media
    $smoRestoreFile.LogicalFileName = $smoRestoreDetails.Rows[0]["DatabaseName"]
    $smoRestoreFile.PhysicalFileName = $server.Information.MasterDBPath + "\" + $smoRestore.Database + "_Data.mdf"
    $smoRestoreLog.LogicalFileName = $smoRestoreDetails.Rows[0]["DatabaseName"] + "_Log"
    $smoRestoreLog.PhysicalFileName = $server.Information.MasterDBLogPath + "\" + $smoRestore.Database + "_Log.ldf"
    $smoRestore.RelocateFiles.Add($smoRestoreFile)
    $smoRestore.RelocateFiles.Add($smoRestoreLog)
 
    #restore database
    $smoRestore.SqlRestore($server)
}
function ConvertTo-EnhancedHTML {
<#
.SYNOPSIS
Provides an enhanced version of the ConvertTo-HTML command that includes
inserting an embedded CSS style sheet, JQuery, and JQuery Data Tables for
interactivity. Intended to be used with HTML fragments that are produced
by ConvertTo-EnhancedHTMLFragment. This command does not accept pipeline
input.


.PARAMETER jQueryURI
A Uniform Resource Indicator (URI) pointing to the location of the 
jQuery script file. You can download jQuery from www.jquery.com; you should
host the script file on a local intranet Web server and provide a URI
that starts with http:// or https://. Alternately, you can also provide
a file system path to the script file, although this may create security
issues for the Web browser in some configurations.


Tested with v1.8.2.


Defaults to http://ajax.aspnetcdn.com/ajax/jQuery/jquery-1.8.2.min.js, which
will pull the file from Microsoft's ASP.NET Content Delivery Network.


.PARAMETER jQueryDataTableURI
A Uniform Resource Indicator (URI) pointing to the location of the 
jQuery Data Table script file. You can download this from www.datatables.net;
you should host the script file on a local intranet Web server and provide a URI
that starts with http:// or https://. Alternately, you can also provide
a file system path to the script file, although this may create security
issues for the Web browser in some configurations.


Tested with jQuery DataTable v1.9.4


Defaults to http://ajax.aspnetcdn.com/ajax/jquery.dataTables/1.9.3/jquery.dataTables.min.js,
which will pull the file from Microsoft's ASP.NET Content Delivery Network.


.PARAMETER CssStyleSheet
The CSS style sheet content - not a file name. If you have a CSS file,
you can load it into this parameter as follows:


    -CSSStyleSheet (Get-Content MyCSSFile.css)


Alternately, you may link to a Web server-hosted CSS file by using the
-CssUri parameter.


.PARAMETER CssUri
A Uniform Resource Indicator (URI) to a Web server-hosted CSS file.
Must start with either http:// or https://. If you omit this, you
can still provide an embedded style sheet, which makes the resulting
HTML page more standalone. To provide an embedded style sheet, use
the -CSSStyleSheet parameter.


.PARAMETER Title
A plain-text title that will be displayed in the Web browser's window
title bar. Note that not all browsers will display this.


.PARAMETER PreContent
Raw HTML to insert before all HTML fragments. Use this to specify a main
title for the report:


    -PreContent "<H1>My HTML Report</H1>"


.PARAMETER PostContent
Raw HTML to insert after all HTML fragments. Use this to specify a 
report footer:


    -PostContent "Created on $(Get-Date)"


.PARAMETER HTMLFragments
One or more HTML fragments, as produced by ConvertTo-EnhancedHTMLFragment.


    -HTMLFragments $part1,$part2,$part3
.EXAMPLE
The following is a complete example script showing how to use
ConvertTo-EnhancedHTMLFragment and ConvertTo-EnhancedHTML. The
example queries 6 pieces of information from the local computer
and produces a report in C:\. This example uses most of the
avaiable options. It relies on Internet connectivity to retrieve
JavaScript from Microsoft's Content Delivery Network. This 
example uses an embedded stylesheet, which is defined as a here-string
at the top of the script.


$computername = 'localhost'
$path = 'c:\'
$style = @"
<style>
body {
    color:#333333;
    font-family:Calibri,Tahoma;
    font-size: 10pt;
}
h1 {
    text-align:center;
}
h2 {
    border-top:1px solid #666666;
}


th {
    font-weight:bold;
    color:#eeeeee;
    background-color:#333333;
    cursor:pointer;
}
.odd  { background-color:#ffffff; }
.even { background-color:#dddddd; }
.paginate_enabled_next, .paginate_enabled_previous {
    cursor:pointer; 
    border:1px solid #222222; 
    background-color:#dddddd; 
    padding:2px; 
    margin:4px;
    border-radius:2px;
}
.paginate_disabled_previous, .paginate_disabled_next {
    color:#666666; 
    cursor:pointer;
    background-color:#dddddd; 
    padding:2px; 
    margin:4px;
    border-radius:2px;
}
.dataTables_info { margin-bottom:4px; }
.sectionheader { cursor:pointer; }
.sectionheader:hover { color:red; }
.grid { width:100% }
.red {
    color:red;
    font-weight:bold;
} 
</style>
"@


function Get-InfoOS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$ComputerName
    )
    $os = Get-WmiObject -class Win32_OperatingSystem -ComputerName $ComputerName
    $props = @{'OSVersion'=$os.version;
               'SPVersion'=$os.servicepackmajorversion;
               'OSBuild'=$os.buildnumber}
    New-Object -TypeName PSObject -Property $props
}


function Get-InfoCompSystem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$ComputerName
    )
    $cs = Get-WmiObject -class Win32_ComputerSystem -ComputerName $ComputerName
    $props = @{'Model'=$cs.model;
               'Manufacturer'=$cs.manufacturer;
               'RAM (GB)'="{0:N2}" -f ($cs.totalphysicalmemory / 1GB);
               'Sockets'=$cs.numberofprocessors;
               'Cores'=$cs.numberoflogicalprocessors}
    New-Object -TypeName PSObject -Property $props
}


function Get-InfoBadService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$ComputerName
    )
    $svcs = Get-WmiObject -class Win32_Service -ComputerName $ComputerName `
           -Filter "StartMode='Auto' AND State<>'Running'"
    foreach ($svc in $svcs) {
        $props = @{'ServiceName'=$svc.name;
                   'LogonAccount'=$svc.startname;
                   'DisplayName'=$svc.displayname}
        New-Object -TypeName PSObject -Property $props
    }
}


function Get-InfoProc {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$ComputerName
    )
    $procs = Get-WmiObject -class Win32_Process -ComputerName $ComputerName
    foreach ($proc in $procs) { 
        $props = @{'ProcName'=$proc.name;
                   'Executable'=$proc.ExecutablePath}
        New-Object -TypeName PSObject -Property $props
    }
}


function Get-InfoNIC {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$ComputerName
    )
    $nics = Get-WmiObject -class Win32_NetworkAdapter -ComputerName $ComputerName `
           -Filter "PhysicalAdapter=True"
    foreach ($nic in $nics) {      
        $props = @{'NICName'=$nic.servicename;
                   'Speed'=$nic.speed / 1MB -as [int];
                   'Manufacturer'=$nic.manufacturer;
                   'MACAddress'=$nic.macaddress}
        New-Object -TypeName PSObject -Property $props
    }
}


function Get-InfoDisk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$ComputerName
    )
    $drives = Get-WmiObject -class Win32_LogicalDisk -ComputerName $ComputerName `
           -Filter "DriveType=3"
    foreach ($drive in $drives) {      
        $props = @{'Drive'=$drive.DeviceID;
                   'Size'=$drive.size / 1GB -as [int];
                   'Free'="{0:N2}" -f ($drive.freespace / 1GB);
                   'FreePct'=$drive.freespace / $drive.size * 100 -as [int]}
        New-Object -TypeName PSObject -Property $props 
    }
}


foreach ($computer in $computername) {
    try {
        $everything_ok = $true
        Write-Verbose "Checking connectivity to $computer"
        Get-WmiObject -class Win32_BIOS -ComputerName $Computer -EA Stop | Out-Null
    } catch {
        Write-Warning "$computer failed"
        $everything_ok = $false
    }


    if ($everything_ok) {
        $filepath = Join-Path -Path $Path -ChildPath "$computer.html"


        $params = @{'As'='List';
                    'PreContent'='<h2>OS</h2>'}
        $html_os = Get-InfoOS -ComputerName $computer |
                   ConvertTo-EnhancedHTMLFragment @params 


        $params = @{'As'='List';
                    'PreContent'='<h2>Computer System</h2>'}
        $html_cs = Get-InfoCompSystem -ComputerName $computer |
                   ConvertTo-EnhancedHTMLFragment @params 


        $params = @{'As'='Table';
                    'PreContent'='<h2>&diams; Local Disks</h2>';
                    'EvenRowCssClass'='even';
                    'OddRowCssClass'='odd';
                    'MakeTableDynamic'=$true;
                    'TableCssClass'='grid';
                    'Properties'='Drive',
                                 @{n='Size(GB)';e={$_.Size}},
                                 @{n='Free(GB)';e={$_.Free};css={if ($_.FreePct -lt 80) { 'red' }}},
                                 @{n='Free(%)';e={$_.FreePct};css={if ($_.FreeePct -lt 80) { 'red' }}}}
        $html_dr = Get-InfoDisk -ComputerName $computer |
                   ConvertTo-EnhancedHTMLFragment @params




        $params = @{'As'='Table';
                    'PreContent'='<h2>&diams; Processes</h2>';
                    'MakeTableDynamic'=$true;
                    'TableCssClass'='grid'}
        $html_pr = Get-InfoProc -ComputerName $computer |
                   ConvertTo-EnhancedHTMLFragment @params 




        $params = @{'As'='Table';
                    'PreContent'='<h2>&diams; Services to Check</h2>';
                    'EvenRowCssClass'='even';
                    'OddRowCssClass'='odd';
                    'MakeHiddenSection'=$true;
                    'TableCssClass'='grid'}
        $html_sv = Get-InfoBadService -ComputerName $computer |
                   ConvertTo-EnhancedHTMLFragment @params 


        $params = @{'As'='Table';
                    'PreContent'='<h2>&diams; NICs</h2>';
                    'EvenRowCssClass'='even';
                    'OddRowCssClass'='odd';
                    'MakeHiddenSection'=$true;
                    'TableCssClass'='grid'}
        $html_na = Get-InfoNIC -ComputerName $Computer |
                   ConvertTo-EnhancedHTMLFragment @params




        $params = @{'CssStyleSheet'=$style;
                    'Title'="System Report for $computer";
                    'PreContent'="<h1>System Report for $computer</h1>";
                    'HTMLFragments'=@($html_os,$html_cs,$html_dr,$html_pr,$html_sv,$html_na)}
        ConvertTo-EnhancedHTML @params |
        Out-File -FilePath $filepath


    }
}






#>
    [CmdletBinding()]
    param(
        [string]$jQueryURI = 'http://ajax.aspnetcdn.com/ajax/jQuery/jquery-1.8.2.min.js',
        [string]$jQueryDataTableURI = 'http://ajax.aspnetcdn.com/ajax/jquery.dataTables/1.9.3/jquery.dataTables.min.js',
        [Parameter(ParameterSetName='CSSContent')][string[]]$CssStyleSheet,
        [Parameter(ParameterSetName='CSSURI')][string[]]$CssUri,
        [string]$Title = 'Report',
        [string]$PreContent,
        [string]$PostContent,
        [Parameter(Mandatory=$True)][string[]]$HTMLFragments
    )


    <#
        Add CSS style sheet. If provided in -CssUri, add a <link> element.
        If provided in -CssStyleSheet, embed in the <head> section.
        Note that BOTH may be supplied - this is legitimate in HTML.
    #>
    Write-Verbose "Making CSS style sheet"
    $stylesheet = ""
    if ($PSBoundParameters.ContainsKey('CssUri')) {
        $stylesheet = "<link rel=`"stylesheet`" href=`"$CssUri`" type=`"text/css`" />"
    }
    if ($PSBoundParameters.ContainsKey('CssStyleSheet')) {
        $stylesheet = "<style>$CssStyleSheet</style>" | Out-String
    }


    <#
        Create the HTML tags for the page title, and for
        our main javascripts.
    #>
    Write-Verbose "Creating <TITLE> and <SCRIPT> tags"
    $titletag = ""
    if ($PSBoundParameters.ContainsKey('title')) {
        $titletag = "<title>$title</title>"
    }
    $script += "<script type=`"text/javascript`" src=`"$jQueryURI`"></script>`n<script type=`"text/javascript`" src=`"$jQueryDataTableURI`"></script>"


    <#
        Render supplied HTML fragments as one giant string
    #>
    Write-Verbose "Combining HTML fragments"
    $body = $HTMLFragments | Out-String


    <#
        If supplied, add pre- and post-content strings
    #>
    Write-Verbose "Adding Pre and Post content"
    if ($PSBoundParameters.ContainsKey('precontent')) {
        $body = "$PreContent`n$body"
    }
    if ($PSBoundParameters.ContainsKey('postcontent')) {
        $body = "$body`n$PostContent"
    }


    <#
        Add a final script that calls the datatable code
        We dynamic-ize all tables with the .enhancedhtml-dynamic-table
        class, which is added by ConvertTo-EnhancedHTMLFragment.
    #>
    Write-Verbose "Adding interactivity calls"
    $datatable = ""
    $datatable = "<script type=`"text/javascript`">"
    $datatable += '$(document).ready(function () {'
    $datatable += "`$('.enhancedhtml-dynamic-table').dataTable();"
    $datatable += '} );'
    $datatable += "</script>"


    <#
        Datatables expect a <thead> section containing the
        table header row; ConvertTo-HTML doesn't produce that
        so we have to fix it.
    #>
    Write-Verbose "Fixing table HTML"
    $body = $body -replace '<tr><th>','<thead><tr><th>'
    $body = $body -replace '</th></tr>','</th></tr></thead>'


    <#
        Produce the final HTML. We've more or less hand-made
        the <head> amd <body> sections, but we let ConvertTo-HTML
        produce the other bits of the page.
    #>
    Write-Verbose "Producing final HTML"
    ConvertTo-HTML -Head "$stylesheet`n$titletag`n$script`n$datatable" -Body $body  
    Write-Debug "Finished producing final HTML"


}
function ConvertTo-EnhancedHTMLFragment {
<#
.SYNOPSIS
Creates an HTML fragment (much like ConvertTo-HTML with the -Fragment switch
that includes CSS class names for table rows, CSS class and ID names for the
table, and wraps the table in a <DIV> tag that has a CSS class and ID name.


.PARAMETER InputObject
The object to be converted to HTML. You cannot select properties using this
command; precede this command with Select-Object if you need a subset of
the objects' properties.


.PARAMETER EvenRowCssClass
The CSS class name applied to even-numbered <TR> tags. Optional, but if you
use it you must also include -OddRowCssClass.


.PARAMETER OddRowCssClass
The CSS class name applied to odd-numbered <TR> tags. Optional, but if you 
use it you must also include -EvenRowCssClass.


.PARAMETER TableCssID
Optional. The CSS ID name applied to the <TABLE> tag.


.PARAMETER DivCssID
Optional. The CSS ID name applied to the <DIV> tag which is wrapped around the table.


.PARAMETER TableCssClass
Optional. The CSS class name to apply to the <TABLE> tag.


.PARAMETER DivCssClass
Optional. The CSS class name to apply to the wrapping <DIV> tag.


.PARAMETER As
Must be 'List' or 'Table.' Defaults to Table. Actually produces an HTML
table either way; with Table the output is a grid-like display. With
List the output is a two-column table with properties in the left column
and values in the right column.


.PARAMETER Properties
A comma-separated list of properties to include in the HTML fragment.
This can be * (which is the default) to include all properties of the
piped-in object(s). In addition to property names, you can also use a
hashtable similar to that used with Select-Object. For example:


 Get-Process | ConvertTo-EnhancedHTMLFragment -As Table `
               -Properties Name,ID,@{n='VM';
                                     e={$_.VM};
                                     css={if ($_.VM -gt 100) { 'red' }
                                          else { 'green' }}}


This will create table cell rows with the calculated CSS class names.
E.g., for a process with a VM greater than 100, you'd get:


  <TD class="red">475858</TD>
  
You can use this feature to specify a CSS class for each table cell
based upon the contents of that cell. Valid keys in the hashtable are:


  n, name, l, or label: The table column header
  e or expression: The table cell contents
  css or csslcass: The CSS class name to apply to the <TD> tag 
  
Another example:


  @{n='Free(MB)';
    e={$_.FreeSpace / 1MB -as [int]};
    css={ if ($_.FreeSpace -lt 100) { 'red' } else { 'blue' }}
    
This example creates a column titled "Free(MB)". It will contain
the input object's FreeSpace property, divided by 1MB and cast
as a whole number (integer). If the value is less than 100, the
table cell will be given the CSS class "red." If not, the table
cell will be given the CSS class "blue." The supplied cascading
style sheet must define ".red" and ".blue" for those to have any
effect.  


.PARAMETER PreContent
Raw HTML content to be placed before the wrapping <DIV> tag. 
For example:


    -PreContent "<h2>Section A</h2>"


.PARAMETER PostContent
Raw HTML content to be placed after the wrapping <DIV> tag.
For example:


    -PostContent "<hr />"


.PARAMETER MakeHiddenSection
Used in conjunction with -PreContent. Adding this switch, which
needs no value, turns your -PreContent into  clickable report
section header. The section will be hidden by default, and clicking
the header will toggle its visibility.


When using this parameter, consider adding a symbol to your -PreContent
that helps indicate this is an expandable section. For example:


    -PreContent '<h2>&diams; My Section</h2>'


If you use -MakeHiddenSection, you MUST provide -PreContent also, or
the hidden section will not have a section header and will not be
visible.


.PARAMETER MakeTableDynamic
When using "-As Table", makes the table dynamic. Will be ignored
if you use "-As List". Dynamic tables are sortable, searchable, and
are paginated.


You should not use even/odd styling with tables that are made
dynamic. Dynamic tables automatically have their own even/odd
styling. You can apply CSS classes named ".odd" and ".even" in 
your CSS to style the even/odd in a dynamic table.


.EXAMPLE
 $fragment = Get-WmiObject -Class Win32_LogicalDisk |
             Select-Object -Property PSComputerName,DeviceID,FreeSpace,Size |
             ConvertTo-HTMLFragment -EvenRowClass 'even' `
                                    -OddRowClass 'odd' `
                                    -PreContent '<h2>Disk Report</h2>' `
                                    -MakeHiddenSection `
                                    -MakeTableDynamic


 You will usually save fragments to a variable, so that multiple fragments
 (each in its own variable) can be passed to ConvertTo-EnhancedHTML.
.NOTES
Consider adding the following to your CSS when using dynamic tables:


    .paginate_enabled_next, .paginate_enabled_previous {
        cursor:pointer; 
        border:1px solid #222222; 
        background-color:#dddddd; 
        padding:2px; 
        margin:4px;
        border-radius:2px;
    }
    .paginate_disabled_previous, .paginate_disabled_next {
        color:#666666; 
        cursor:pointer;
        background-color:#dddddd; 
        padding:2px; 
        margin:4px;
        border-radius:2px;
    }
    .dataTables_info { margin-bottom:4px; }


This applies appropriate coloring to the next/previous buttons,
and applies a small amount of space after the dynamic table.


If you choose to make sections hidden (meaning they can be shown
and hidden by clicking on the section header), consider adding
the following to your CSS:


    .sectionheader { cursor:pointer; }
    .sectionheader:hover { color:red; }


This will apply a hover-over color, and change the cursor icon,
to help visually indicate that the section can be toggled.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [object[]]$InputObject,


        [string]$EvenRowCssClass,
        [string]$OddRowCssClass,
        [string]$TableCssID,
        [string]$DivCssID,
        [string]$DivCssClass,
        [string]$TableCssClass,


        [ValidateSet('List','Table')]
        [string]$As = 'Table',


        [object[]]$Properties = '*',


        [string]$PreContent,


        [switch]$MakeHiddenSection,


        [switch]$MakeTableDynamic,


        [string]$PostContent
    )
    BEGIN {
        <#
            Accumulate output in a variable so that we don't
            produce an array of strings to the pipeline, but
            instead produce a single string.
        #>
        $out = ''


        <#
            Add the section header (pre-content). If asked to
            make this section of the report hidden, set the
            appropriate code on the section header to toggle
            the underlying table. Note that we generate a GUID
            to use as an additional ID on the <div>, so that
            we can uniquely refer to it without relying on the
            user supplying us with a unique ID.
        #>
        Write-Verbose "Precontent"
        if ($PSBoundParameters.ContainsKey('PreContent')) {
            if ($PSBoundParameters.ContainsKey('MakeHiddenSection')) {
               [string]$tempid = [System.Guid]::NewGuid()
               $out += "<span class=`"sectionheader`" onclick=`"`$('#$tempid').toggle(500);`">$PreContent</span>`n"
            } else {
                $out += $PreContent
                $tempid = ''
            }
        }


        <#
            The table will be wrapped in a <div> tag for styling
            purposes. Note that THIS, not the table per se, is what
            we hide for -MakeHiddenSection. So we will hide the section
            if asked to do so.
        #>
        Write-Verbose "DIV"
        if ($PSBoundParameters.ContainsKey('DivCSSClass')) {
            $temp = " class=`"$DivCSSClass`""
        } else {
            $temp = ""
        }
        if ($PSBoundParameters.ContainsKey('MakeHiddenSection')) {
            $temp += " id=`"$tempid`" style=`"display:none;`""
        } else {
            $tempid = ''
        }
        if ($PSBoundParameters.ContainsKey('DivCSSID')) {
            $temp += " id=`"$DivCSSID`""
        }
        $out += "<div $temp>"


        <#
            Create the table header. If asked to make the table dynamic,
            we add the CSS style that ConvertTo-EnhancedHTML will look for
            to dynamic-ize tables.
        #>
        Write-Verbose "TABLE"
        $_TableCssClass = ''
        if ($PSBoundParameters.ContainsKey('MakeTableDynamic') -and $As -eq 'Table') {
            $_TableCssClass += 'enhancedhtml-dynamic-table '
        }
        if ($PSBoundParameters.ContainsKey('TableCssClass')) {
            $_TableCssClass += $TableCssClass
        }
        if ($_TableCssClass -ne '') {
            $css = "class=`"$_TableCSSClass`""
        } else {
            $css = ""
        }
        if ($PSBoundParameters.ContainsKey('TableCSSID')) {
            $css += "id=`"$TableCSSID`""
        } else {
            if ($tempid -ne '') {
                $css += "id=`"$tempid`""
            }
        }
        $out += "<table $css>"


        <#
            We're now setting up to run through our input objects
            and create the table rows
        #>
        $fragment = ''
        $wrote_first_line = $false
        $even_row = $false


        if ($properties -eq '*') {
            $all_properties = $true
        } else {
            $all_properties = $false
        }


    }
    PROCESS {


        foreach ($object in $inputobject) {
            Write-Verbose "Processing object"
            $datarow = ''
            $headerrow = ''


            <#
                Apply even/odd row class. Note that this will mess up the output
                if the table is made dynamic. That's noted in the help.
            #>
            if ($PSBoundParameters.ContainsKey('EvenRowCSSClass') -and $PSBoundParameters.ContainsKey('OddRowCssClass')) {
                if ($even_row) {
                    $row_css = $OddRowCSSClass
                    $even_row = $false
                    Write-Verbose "Even row"
                } else {
                    $row_css = $EvenRowCSSClass
                    $even_row = $true
                    Write-Verbose "Odd row"
                }
            } else {
                $row_css = ''
                Write-Verbose "No row CSS class"
            }


            <#
                If asked to include all object properties, get them.
            #>
            if ($all_properties) {
                $properties = $object | Get-Member -MemberType Properties | Select -ExpandProperty Name
            }


            <#
                We either have a list of all properties, or a hashtable of
                properties to play with. Process the list.
            #>
            foreach ($prop in $properties) {
                Write-Verbose "Processing property"
                $name = $null
                $value = $null
                $cell_css = ''


                <#
                    $prop is a simple string if we are doing "all properties,"
                    otherwise it is a hashtable. If it's a string, then we
                    can easily get the name (it's the string) and the value.
                #>
                if ($prop -is [string]) {
                    Write-Verbose "Property $prop"
                    $name = $Prop
                    $value = $object.($prop)
                } elseif ($prop -is [hashtable]) {
                    Write-Verbose "Property hashtable"
                    <#
                        For key "css" or "cssclass," execute the supplied script block.
                        It's expected to output a class name; we embed that in the "class"
                        attribute later.
                    #>
                    if ($prop.ContainsKey('cssclass')) { $cell_css = $Object | ForEach $prop['cssclass'] }
                    if ($prop.ContainsKey('css')) { $cell_css = $Object | ForEach $prop['css'] }


                    <#
                        Get the current property name.
                    #>
                    if ($prop.ContainsKey('n')) { $name = $prop['n'] }
                    if ($prop.ContainsKey('name')) { $name = $prop['name'] }
                    if ($prop.ContainsKey('label')) { $name = $prop['label'] }
                    if ($prop.ContainsKey('l')) { $name = $prop['l'] }


                    <#
                        Execute the "expression" or "e" key to get the value of the property.
                    #>
                    if ($prop.ContainsKey('e')) { $value = $Object | ForEach $prop['e'] }
                    if ($prop.ContainsKey('expression')) { $value = $tObject | ForEach $prop['expression'] }


                    <#
                        Make sure we have a name and a value at this point.
                    #>
                    if ($name -eq $null -or $value -eq $null) {
                        Write-Error "Hashtable missing Name and/or Expression key"
                    }
                } else {
                    <#
                        We got a property list that wasn't strings and
                        wasn't hashtables. Bad input.
                    #>
                    Write-Warning "Unhandled property $prop"
                }


                <#
                    When constructing a table, we have to remember the
                    property names so that we can build the table header.
                    In a list, it's easier - we output the property name
                    and the value at the same time, since they both live
                    on the same row of the output.
                #>
                if ($As -eq 'table') {
                    Write-Verbose "Adding $name to header and $value to row"
                    $headerrow += "<th>$name</th>"
                    $datarow += "<td$(if ($cell_css -ne '') { ' class="'+$cell_css+'"' })>$value</td>"
                } else {
                    $wrote_first_line = $true
                    $headerrow = ""
                    $datarow = "<td$(if ($cell_css -ne '') { ' class="'+$cell_css+'"' })>$name :</td><td$(if ($cell_css -ne '') { ' class="'+$cell_css+'"' })>$value</td>"
                    $out += "<tr$(if ($row_css -ne '') { ' class="'+$row_css+'"' })>$datarow</tr>"
                }
            }


            <#
                Write the table header, if we're doing a table.
            #>
            if (-not $wrote_first_line -and $as -eq 'Table') {
                Write-Verbose "Writing header row"
                $out += "<tr>$headerrow</tr><tbody>"
                $wrote_first_line = $true
            }


            <#
                In table mode, write the data row.
            #>
            if ($as -eq 'table') {
                Write-Verbose "Writing data row"
                $out += "<tr$(if ($row_css -ne '') { ' class="'+$row_css+'"' })>$datarow</tr>"
            }
        }
    }
    END {
        <#
            Finally, post-content code, the end of the table,
            the end of the <div>, and write the final string.
        #>
        Write-Verbose "PostContent"
        if ($PSBoundParameters.ContainsKey('PostContent')) {
            $out += "`n$PostContent"
        }
        Write-Verbose "Done"
        $out += "</tbody></table></div>"
        Write-Output $out
    }
}
Function Get-LocalGroupMembership {
    <#
        .SYNOPSIS
            Recursively list all members of a specified Local group.

        .DESCRIPTION
            Recursively list all members of a specified Local group. This can be run against a local or
            remote system or systems. Recursion is unlimited unless specified by the -Depth parameter.

            Alias: glgm

        .PARAMETER Computername
            Local or remote computer/s to perform the query against.
            
            Default value is the local system.

        .PARAMETER Group
            Name of the group to query on a system for all members.
            
            Default value is 'Administrators'

        .PARAMETER Depth
            Limit the recursive depth of a query. 
            
            Default value is 2147483647.

        .PARAMETER Throttle
            Number of concurrently running jobs to run at a time

            Default value is 10

        .NOTES
            Author: Boe Prox
            Created: 8 AUG 2013
            Version 1.0 (8 AUG 2013):
                -Initial creation

        .EXAMPLE
            Get-LocalGroupMembership

            Name              ParentGroup       isGroup Type   Computername Depth
            ----              -----------       ------- ----   ------------ -----
            Administrator     Administrators      False Domain DC1              1
            boe               Administrators      False Domain DC1              1
            testuser          Administrators      False Domain DC1              1
            bob               Administrators      False Domain DC1              1
            proxb             Administrators      False Domain DC1              1
            Enterprise Admins Administrators       True Domain DC1              1
            Sysops Admins     Enterprise Admins    True Domain DC1              2
            Domain Admins     Enterprise Admins    True Domain DC1              2
            Administrator     Enterprise Admins   False Domain DC1              2
            Domain Admins     Administrators       True Domain DC1              1
            proxb             Domain Admins       False Domain DC1              2
            Administrator     Domain Admins       False Domain DC1              2
            Sysops Admins     Administrators       True Domain DC1              1
            Org Admins        Sysops Admins        True Domain DC1              2
            Enterprise Admins Sysops Admins        True Domain DC1              2       
            
            Description
            -----------
            Gets all of the members of the 'Administrators' group on the local system.        
            
        .EXAMPLE
            Get-LocalGroupMembership -Group 'Administrators' -Depth 1
            
            Name              ParentGroup    isGroup Type   Computername Depth
            ----              -----------    ------- ----   ------------ -----
            Administrator     Administrators   False Domain DC1              1
            boe               Administrators   False Domain DC1              1
            testuser          Administrators   False Domain DC1              1
            bob               Administrators   False Domain DC1              1
            proxb             Administrators   False Domain DC1              1
            Enterprise Admins Administrators    True Domain DC1              1
            Domain Admins     Administrators    True Domain DC1              1
            Sysops Admins     Administrators    True Domain DC1              1   
            
            Description
            -----------
            Gets the members of 'Administrators' with only 1 level of recursion.         
            
    #>
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('CN','__Server','Computer','IPAddress')]
        [string[]]$Computername = $env:COMPUTERNAME,
        [parameter()]
        [string]$Group = "Administrators",
        [parameter()]
        [int]$Depth = ([int]::MaxValue),
        [parameter()]
        [Alias("MaxJobs")]
        [int]$Throttle = 10
    )
    Begin {
        $PSBoundParameters.GetEnumerator() | ForEach {
            Write-Verbose $_
        }
        #region Extra Configurations
        Write-Verbose ("Depth: {0}" -f $Depth)
        #endregion Extra Configurations
        #Define hash table for Get-RunspaceData function
        $runspacehash = @{}
        #Function to perform runspace job cleanup
        Function Get-RunspaceData {
            [cmdletbinding()]
            param(
                [switch]$Wait
            )
            Do {
                $more = $false         
                Foreach($runspace in $runspaces) {
                    If ($runspace.Runspace.isCompleted) {
                        $runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null                 
                    } ElseIf ($runspace.Runspace -ne $null) {
                        $more = $true
                    }
                }
                If ($more -AND $PSBoundParameters['Wait']) {
                    Start-Sleep -Milliseconds 100
                }   
                #Clean out unused runspace jobs
                $temphash = $runspaces.clone()
                $temphash | Where {
                    $_.runspace -eq $Null
                } | ForEach {
                    Write-Verbose ("Removing {0}" -f $_.computer)
                    $Runspaces.remove($_)
                }             
            } while ($more -AND $PSBoundParameters['Wait'])
        }

        #region ScriptBlock
            $scriptBlock = {
            Param ($Computer,$Group,$Depth,$NetBIOSDomain,$ObjNT,$Translate)            
            $Script:Depth = $Depth
            $Script:ObjNT = $ObjNT
            $Script:Translate = $Translate
            $Script:NetBIOSDomain = $NetBIOSDomain
            Function Get-LocalGroupMember {
                [cmdletbinding()]
                Param (
                    [parameter()]
                    [System.DirectoryServices.DirectoryEntry]$LocalGroup
                )
                # Invoke the Members method and convert to an array of member objects.
                $Members= @($LocalGroup.psbase.Invoke("Members"))
                $Counter++
                ForEach ($Member In $Members) {                
                    Try {
                        $Name = $Member.GetType().InvokeMember("Name", 'GetProperty', $Null, $Member, $Null)
                        $Path = $Member.GetType().InvokeMember("ADsPath", 'GetProperty', $Null, $Member, $Null)
                        # Check if this member is a group.
                        $isGroup = ($Member.GetType().InvokeMember("Class", 'GetProperty', $Null, $Member, $Null) -eq "group")
                        If (($Path -like "*/$Computer/*")) {
                            $Type = 'Local'
                        } Else {$Type = 'Domain'}
                        New-Object PSObject -Property @{
                            Computername = $Computer
                            Name = $Name
                            Type = $Type
                            ParentGroup = $LocalGroup.Name[0]
                            isGroup = $isGroup
                            Depth = $Counter
                        }
                        If ($isGroup) {
                            # Check if this group is local or domain.
                            #$host.ui.WriteVerboseLine("(RS)Checking if Counter: {0} is less than Depth: {1}" -f $Counter, $Depth)
                            If ($Counter -lt $Depth) {
                                If ($Type -eq 'Local') {
                                    If ($Groups[$Name] -notcontains 'Local') {
                                        $host.ui.WriteVerboseLine(("{0}: Getting local group members" -f $Name))
                                        $Groups[$Name] += ,'Local'
                                        # Enumerate members of local group.
                                        Get-LocalGroupMember $Member
                                    }
                                } Else {
                                    If ($Groups[$Name] -notcontains 'Domain') {
                                        $host.ui.WriteVerboseLine(("{0}: Getting domain group members" -f $Name))
                                        $Groups[$Name] += ,'Domain'
                                        # Enumerate members of domain group.
                                        Get-DomainGroupMember $Member $Name $True
                                    }
                                }
                            }
                        }
                    } Catch {
                        $host.ui.WriteWarningLine(("GLGM{0}" -f $_.Exception.Message))
                    }
                }
            }

            Function Get-DomainGroupMember {
                [cmdletbinding()]
                Param (
                    [parameter()]
                    $DomainGroup, 
                    [parameter()]
                    [string]$NTName, 
                    [parameter()]
                    [string]$blnNT
                )
                Try {
                    If ($blnNT -eq $True) {
                        # Convert NetBIOS domain name of group to Distinguished Name.
                        $objNT.InvokeMember("Set", "InvokeMethod", $Null, $Translate, (3, ("{0}{1}" -f $NetBIOSDomain.Trim(),$NTName)))
                        $DN = $objNT.InvokeMember("Get", "InvokeMethod", $Null, $Translate, 1)
                        $ADGroup = [ADSI]"LDAP://$DN"
                    } Else {
                        $DN = $DomainGroup.distinguishedName
                        $ADGroup = $DomainGroup
                    }         
                    $Counter++   
                    ForEach ($MemberDN In $ADGroup.Member) {
                        $MemberGroup = [ADSI]("LDAP://{0}" -f ($MemberDN -replace '/','\/'))
                        New-Object PSObject -Property @{
                            Computername = $Computer
                            Name = $MemberGroup.name[0]
                            Type = 'Domain'
                            ParentGroup = $NTName
                            isGroup = ($MemberGroup.Class -eq "group")
                            Depth = $Counter
                        }
                        # Check if this member is a group.
                        If ($MemberGroup.Class -eq "group") {              
                            If ($Counter -lt $Depth) {
                                If ($Groups[$MemberGroup.name[0]] -notcontains 'Domain') {
                                    Write-Verbose ("{0}: Getting domain group members" -f $MemberGroup.name[0])
                                    $Groups[$MemberGroup.name[0]] += ,'Domain'
                                    # Enumerate members of domain group.
                                    Get-DomainGroupMember $MemberGroup $MemberGroup.Name[0] $False
                                }                                                
                            }
                        }
                    }
                } Catch {
                    $host.ui.WriteWarningLine(("GDGM{0}" -f $_.Exception.Message))
                }
            }
            #region Get Local Group Members
            $Script:Groups = @{}
            $Script:Counter=0
            # Bind to the group object with the WinNT provider.
            $ADSIGroup = [ADSI]"WinNT://$Computer/$Group,group"
            Write-Verbose ("Checking {0} membership for {1}" -f $Group,$Computer)
            $Groups[$Group] += ,'Local'
            Get-LocalGroupMember -LocalGroup $ADSIGroup
            #endregion Get Local Group Members
        }
        #endregion ScriptBlock
        Write-Verbose ("Checking to see if connected to a domain")
        Try {
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $Root = $Domain.GetDirectoryEntry()
            $Base = ($Root.distinguishedName)

            # Use the NameTranslate object.
            $Script:Translate = New-Object -comObject "NameTranslate"
            $Script:objNT = $Translate.GetType()

            # Initialize NameTranslate by locating the Global Catalog.
            $objNT.InvokeMember("Init", "InvokeMethod", $Null, $Translate, (3, $Null))

            # Retrieve NetBIOS name of the current domain.
            $objNT.InvokeMember("Set", "InvokeMethod", $Null, $Translate, (1, "$Base"))
            [string]$Script:NetBIOSDomain =$objNT.InvokeMember("Get", "InvokeMethod", $Null, $Translate, 3)  
        } Catch {Write-Warning ("{0}" -f $_.Exception.Message)}         
        
        #region Runspace Creation
        Write-Verbose ("Creating runspace pool and session states")
        $sessionstate = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
        $runspacepool.Open()  
        
        Write-Verbose ("Creating empty collection to hold runspace jobs")
        $Script:runspaces = New-Object System.Collections.ArrayList        
        #endregion Runspace Creation
    }

    Process {
        ForEach ($Computer in $Computername) {
            #Create the powershell instance and supply the scriptblock with the other parameters 
            $powershell = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer).AddArgument($Group).AddArgument($Depth).AddArgument($NetBIOSDomain).AddArgument($ObjNT).AddArgument($Translate)
           
            #Add the runspace into the powershell instance
            $powershell.RunspacePool = $runspacepool
           
            #Create a temporary collection for each runspace
            $temp = "" | Select-Object PowerShell,Runspace,Computer
            $Temp.Computer = $Computer
            $temp.PowerShell = $powershell
           
            #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
            $temp.Runspace = $powershell.BeginInvoke()
            Write-Verbose ("Adding {0} collection" -f $temp.Computer)
            $runspaces.Add($temp) | Out-Null
           
            Write-Verbose ("Checking status of runspace jobs")
            Get-RunspaceData @runspacehash   
        }
    }
    End {
        Write-Verbose ("Finish processing the remaining runspace jobs: {0}" -f (@(($runspaces | Where {$_.Runspace -ne $Null}).Count)))
        $runspacehash.Wait = $true
        Get-RunspaceData @runspacehash
    
        #region Cleanup Runspace
        Write-Verbose ("Closing the runspace pool")
        $runspacepool.close()  
        $runspacepool.Dispose() 
        #endregion Cleanup Runspace    
    }
}
function Get-EventViewerLogs{
	[CmdletBinding()]
	param(
		[Parameter(Position=0, Mandatory=$true)]
		[System.String]
		$ParameterA,
		[Parameter(Position=1)]
		[System.Int32]
		$ParameterB
	)
	begin {
				try {
				}
				catch {
				}
	}
	process {
				try {
					
				}
				catch {
				}
	}
	end {
			try {
			}
			catch {
			}
	}
}
Function Get-TCPResponse{
	[cmdletbinding()]
	Param (
		[parameter(ValueFromPipeline = $True)]
		$Computername = $env:Computername,
		$Port = 902,
		$TCPTimeout = 1000
	)
	Process
	{
		$tcpClient = New-Object System.Net.Sockets.TCPClient
		$connect = $tcpClient.BeginConnect($computername, $port, $null, $null)
		$wait = $connect.AsyncWaitHandle.WaitOne($TCPtimeout, $false)
		If (-NOT $wait)
		{
			New-Object PSObject -Property @{
				Computername = $Computername
				Port = $Port
				IsOpen = $False
				Response = $Null
			}
		}
		Else
		{
			#Let buffer
			Start-Sleep -Milliseconds 1000
			Write-Verbose "Bytes available: $($tcpClient.Available)"
			If ([int64]$tcpClient.Available -gt 0)
			{
				$stream = $TcpClient.GetStream()
				$bindResponseBuffer = New-Object Byte[] -ArgumentList $tcpClient.Available
				[Int]$response = $stream.Read($bindResponseBuffer, 0, $bindResponseBuffer.count)
				New-Object PSObject -Property @{
					Computername = $Computername
					Port = $Port
					IsOpen = $True
					Response = ($bindResponseBuffer | ForEach { [char][int]$_ }) -join ''
				}
			}
			Else
			{
				New-Object PSObject -Property @{
					Computername = $Computername
					Port = $Port
					IsOpen = $True
					Response = $Null
				}
			}
			If ($stream)
			{
				$stream.Close()
				$stream.Dispose()
			}
			$tcpClient.Close()
			$tcpClient.Dispose()
		}
	}
}
Function Set-ServiceCredential{
    <#
    .SYNOPSIS
    Sets start credentials for one or more services on one or more computers.

    .DESCRIPTION
    Sets start credentials for one or more services on one or more computers.

    .PARAMETER ServiceName
    Specifies one or more service names. You can specify either the Name or DisplayName property for the services. Wildcards are not supported.

    .PARAMETER ComputerName
    Specifies one or more computer names. The default is the current computer. This parameter accepts pipeline input containing computer names or objects with a ComputerName property.

    .PARAMETER ServiceCredential
    Specifies the credentials to use to start the service(s).

    .PARAMETER ConnectionCredential
    Specifies credentials that have permissions to change the service(s) on the computer(s).

    .NOTES
    Default confirm impact is High. To suppress the prompt, specify -Confirm:$false or set the $ConfirmPreference variable to "None".
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
      [parameter(Position=0,Mandatory=$true)]
        [String[]] $ServiceName,
      [parameter(Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        $ComputerName,
      [parameter(Position=2,Mandatory=$true)]
        [Management.Automation.PSCredential] $ServiceCredential,
        [Management.Automation.PSCredential] $ConnectionCredential
    )

    begin 
        {
            function Set-ServiceCredential 
                {
                    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
                    param(
                      $serviceName,
                      $computerName,
                      $serviceCredential,
                      $connectionCredential
                    )
                    # Get computer name if passed by property name.
                    if ( $computerName.ComputerName ) 
                    {
                        $computerName = $computerName.ComputerName
                    }
                    # Empty computer name or . is local computer.
                    if ( (-not $computerName) -or $computerName -eq "." ) 
                    {
                        $computerName = [Net.Dns]::GetHostName()
                    }
                    $wmiFilter = "Name='{0}' OR DisplayName='{0}'" -f $serviceName
                    $params = @{
                      "Namespace" = "root\CIMV2"
                      "Class" = "Win32_Service"
                      "ComputerName" = $computerName
                      "Filter" = $wmiFilter
                      "ErrorAction" = "Stop"
                    }
                    if ( $connectionCredential ) 
                    {
                      # Specify connection credentials only when not connecting to the local computer.
                      if ( $computerName -ne [Net.Dns]::GetHostName() ) 
                      {
                        $params.Add("Credential", $connectionCredential)
                      }
                    }
                    try 
                    {
                      $service = Get-WmiObject @params
                    }
                    catch [System.Management.Automation.RuntimeException],[System.Runtime.InteropServices.COMException] 
                    {
                        Write-Error "Unable to connect to '$computerName' due to the following error: $($_.Exception.Message)"
                        return
                    }
                    if ( -not $service ) 
                    {
                        Write-Error "Unable to find service named '$serviceName' on '$computerName'."
                        return
                    }
                    if ( $PSCmdlet.ShouldProcess("Service '$serviceName' on '$computerName'","Set credentials") ) 
                    {
                        # See https://msdn.microsoft.com/en-us/library/aa384901.aspx
                        $returnValue = ($service.Change($null,                 # DisplayName
                        $null,                                               # PathName
                        $null,                                               # ServiceType
                        $null,                                               # ErrorControl
                        $null,                                               # StartMode
                        $null,                                               # DesktopInteract
                        $serviceCredential.UserName,                         # StartName
                        $serviceCredential.GetNetworkCredential().Password,  # StartPassword
                        $null,                                               # LoadOrderGroup
                        $null,                                               # LoadOrderGroupDependencies
                        $null)).ReturnValue                                  # ServiceDependencies
                        $errorMessage = "Error setting credentials for service '$serviceName' on '$computerName'"
                        switch ( $returnValue ) {
                        0  { Write-Verbose "Set credentials for service '$serviceName' on '$computerName'" }
                        1  { Write-Error "$errorMessage - Not Supported" }
                        2  { Write-Error "$errorMessage - Access Denied" }
                        3  { Write-Error "$errorMessage - Dependent Services Running" }
                        4  { Write-Error "$errorMessage - Invalid Service Control" }
                        5  { Write-Error "$errorMessage - Service Cannot Accept Control" }
                        6  { Write-Error "$errorMessage - Service Not Active" }
                        7  { Write-Error "$errorMessage - Service Request timeout" }
                        8  { Write-Error "$errorMessage - Unknown Failure" }
                        9  { Write-Error "$errorMessage - Path Not Found" }
                        10 { Write-Error "$errorMessage - Service Already Stopped" }
                        11 { Write-Error "$errorMessage - Service Database Locked" }
                        12 { Write-Error "$errorMessage - Service Dependency Deleted" }
                        13 { Write-Error "$errorMessage - Service Dependency Failure" }
                        14 { Write-Error "$errorMessage - Service Disabled" }
                        15 { Write-Error "$errorMessage - Service Logon Failed" }
                        16 { Write-Error "$errorMessage - Service Marked For Deletion" }
                        17 { Write-Error "$errorMessage - Service No Thread" }
                        18 { Write-Error "$errorMessage - Status Circular Dependency" }
                        19 { Write-Error "$errorMessage - Status Duplicate Name" }
                        20 { Write-Error "$errorMessage - Status Invalid Name" }
                        21 { Write-Error "$errorMessage - Status Invalid Parameter" }
                        22 { Write-Error "$errorMessage - Status Invalid Service Account" }
                        23 { Write-Error "$errorMessage - Status Service Exists" }
                        24 { Write-Error "$errorMessage - Service Already Paused" }
          }
        }
      }
        }

    process 
        {
            foreach ( $computerNameItem in $ComputerName ) 
            {
                foreach ( $serviceNameItem in $ServiceName ) 
                {
                    Set-ServiceCredential $serviceNameItem $computerNameItem $ServiceCredential $ConnectionCredential
                }
            }
        }
}

Export-ModuleMember -Variable MyToolsDriveTypePreference, MyToolsErrorLogFile, MyToolsLogFile -Function Update-IISLogs,
                                                                                                        Watch-Command,
																										Copy-ItemWithProgress,
                                                                                                        Get-ComputerCounter,
                                                                                                        Get-DiskSpaceInfo,
																										Set-computerState,
																										Get-ComputerDetails,
																										Get-ServerEventLog,
																										Test-Computer,
																										Update-Servers,
																										Get-Computernamesfordiskdetailsfromdatabase,
																										Backup-Database,
																										Restore-Database,
																										ConvertTo-EnhancedHTML,
																										ConvertTo-EnhancedHTMLFragment,
																										Set-ServicePassword,
																										Remove-LogFile,
																										Get-SystemInfo,
																										Get-NetAdaptIPAddress,
																										Get-LocalGroupMembership,
																										Get-EventViewerLogs,
																										Get-TCPResponse,
                                                                                                        Set-ServiceCredential,
                                                                                                        Get-LocalConnections,
                                                                                                        Update-ActiveComputers