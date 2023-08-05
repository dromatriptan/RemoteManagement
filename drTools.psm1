$GetInstalled = {
	$ComputerName = $args[0]
	$ProductList = @()
	try {
		$hive = [Microsoft.Win32.RegistryHive]::LocalMachine
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $ComputerName)
		
		$Products = @{ }
		$keyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
		$key = $reg.OpenSubKey($keyPath)
		$Uninstalls = $key.GetSubKeyNames() | Sort-Object
		
		foreach ($Uninstall in $Uninstalls) {
			$product = $reg.OpenSubKey("$keyPath\$Uninstall")
			$displayName = $product.GetValue('DisplayName')
			$displayVersion = $product.GetValue('DisplayVersion')
			if ($displayName.length -gt 0 -and $displayVersion -gt 0) {
				if (-not $Products.ContainsKey($displayName)) {
					$Products.Add($displayName, $displayVersion)
					$ProductDetails = [PSCustomObject]@{
						Device		     = [String]$computerName
						Vendor		     = [String]$($product.GetValue('Publisher'))
						Name			 = [String]$($product.GetValue('DisplayName'))
						Version		     = [String]$($product.GetValue('DisplayVersion'))
						Description	     = [String]$($product.GetValue('Comments'))
						InstallDate	     = [String]($product.GetValue('InstallDate'))
						InstallSource    = [String]$($product.GetValue('InstallSource'))
						UninstallString  = [String]$($product.GetValue('UninstallString'))
					}
					$ProductList += $ProductDetails
				}
			}
		}
		
		$keyPath = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
		$key = $reg.OpenSubKey($keyPath)
		$Uninstalls = $key.GetSubKeyNames() | Sort-Object
		foreach ($Uninstall in $Uninstalls) {
			$product = $reg.OpenSubKey("$keyPath\$Uninstall")
			$displayName = $product.GetValue('DisplayName')
			$displayVersion = $product.GetValue('DisplayVersion')
			if ($displayName.length -gt 0 -and $displayVersion -gt 0) {
				if (-not $Products.ContainsKey($displayName)) {
					$Products.Add($displayName, $displayVersion)
					$ProductDetails = [PSCustomObject]@{
						Device		     = [String]$computerName
						Vendor		     = [String]$($product.GetValue('Publisher'))
						Name			 = [String]$($product.GetValue('DisplayName'))
						Version		     = [String]$($product.GetValue('DisplayVersion'))
						Description	     = [String]$($product.GetValue('Comments'))
						InstallDate	     = [String]($product.GetValue('InstallDate'))
						InstallSource    = [String]$($product.GetValue('InstallSource'))
						UninstallString  = [String]$($product.GetValue('UninstallString'))
					}
					$ProductList += $ProductDetails
				}
			}
		}
		
		$key.Close()
		$reg.Close()
		$hive = $null
	}
	catch [Exception] { <# "Could not fetch Installations: $_" #> }
	
	return $ProductList
}
$GetLoggedon = {
	$ComputerName = $args[0]
	
	$logonType = @{
		"0"  = "Local System"
		"2"  = "Interactive" #(Local logon)
		"3"  = "Network" # (Remote logon)
		"4"  = "Batch" # (Scheduled task)
		"5"  = "Service" # (Service account logon)
		"7"  = "Unlock" #(Screen saver)
		"8"  = "Network Cleartext" # (Cleartext network logon)
		"9"  = "New Credentials" #(RunAs using alternate credentials)
		"10" = "Remote Interactive" #(RDP\TS\RemoteAssistance)
		"11" = "Cached Interactive" #(Local w\cached credentials)
	}
	
	try {
		$Win32NetworkLoginProfiles = Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkLoginProfile -Namespace 'root\cimv2' -Property Name, Caption, Comment, FullName, LastLogon, UserType, NumberOfLogons -Filter "UserType = 'Normal Account'" -ErrorAction SilentlyContinue -ErrorVariable ev
	}
	catch [Exception] { $Win32NetworkLoginProfiles = $null }
	
	$Comments = $null
	try {
		$locked = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Filter "name like '%logonui%'" -Property * -ErrorAction SilentlyContinue -ErrorVariable CouldNotGet
		if ($null -ne $locked) {
			[String]$aString = $locked.CreationDate
			$lockedDateTime = Get-Date -Year $aString.Substring(0, 4) -Month $aString.Substring(4, 2) -Day $aString.Substring(6, 2) -Hour $aString.Substring(8, 2) -Minute $aString.Substring(10, 2) -Second $aString.Substring(12, 2)
			$Comments = "Workstation locked since: $lockedDateTime"
		}
		else { $Comments = $null }
	}
	catch [Exception] { $Comments = "Could not connect to $($ComputerName)." }
	
	$ProfileList = @()
	foreach ($Profile in $Win32NetworkLoginProfiles) {
		try {
			$userProfiles = Get-WmiObject -ComputerName $ComputerName -Class Win32_UserProfile -Namespace 'root\cimv2' -Property SID, LocalPath, Loaded, Special -Filter "LocalPath Like '%$($Profile.Caption)' and Loaded = True and Special = False" -ErrorAction SilentlyContinue -ErrorVariable ev | Select-Object -Property SID, LocalPath
		}
		catch {
			$userProfiles = $null
		}
		foreach ($userProfile in $userProfiles) {
			$Processes = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Property * -Filter "Name = 'explorer.exe'";
			[String]$logonId = $null
			[String]$processOwner = $null
			foreach ($process in $processes) {
				$processOwner = ($process.GetOwner()).User
				if ($processOwner -eq $Profile.Caption) {
					try {
						$logonId = ((Get-WmiObject -Class Win32_SessionProcess -ComputerName $ComputerName -Property * | Where-Object { $_.Dependent -match $process.handle } | Select-Object -Property Antecedent).Antecedent).Split("=")[1].Replace('"', '')
					}
					catch {
						$logonId = $null
					}
					if ($null -ne $logonId) {
						try {
							$sessionInfo = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogonSession -Filter "LogonId = '$logonId'"
						}
						catch {
							$sessionInfo = $null
						}
					}
					else {
						$sessionInfo = $null
					}
					if ($null -ne $sessionInfo) {
						$sessionLogonDateTime = "{0:yyyy-MM-dd HH:mm:ss}" -f (Get-Date -Year ($sessionInfo.StartTime).Substring(0, 4) -Month ($sessionInfo.StartTime).Substring(4, 2) -Day ($sessionInfo.StartTime).Substring(6, 2) -Hour ($sessionInfo.StartTime).Substring(8, 2) -Minute ($sessionInfo.StartTime).Substring(10, 2) -Second ($sessionInfo.StartTime).Substring(12, 2))
						$sessionType = $logonType.Item($sessionInfo.LogonType.ToString())
					}
					else {
						$sessionLogonDateTime = $null
						$sessionType = $null
					}
					
					$UserDetails = [PSCustomObject]@{
						Device  = $ComputerName
						SID	    = $userProfile.SID
						Name    = $Profile.Caption
						FullName = $Profile.FullName
						LastLogon = $sessionLogonDateTime
						LocalPath = $userProfile.LocalPath
						NumLogons = $Profile.NumberOfLogons
						LogonType = $sessionType
						Comments = $Comments
					}
					$ProfileList += $UserDetails
				}
			}
		}
	}
	if ($ProfileList.Cont -eq 0) { return "This is bullshit" }
	else { return $ProfileList }
}
$GetLocalGroups = {
	$ComputerName = $args[0]
	$Groups = Get-WmiObject -ComputerName $ComputerName -Class Win32_GroupUser -Property GroupComponent, PartComponent |
	Sort-Object -Property GroupComponent |
	Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } },
				  @{ Name = "GroupName"; Expression = { $_.GroupComponent.ToString().Split(",")[1].Replace("Name=", "").Replace('"', "") } },
				  @{ Name = "GroupMember"; Expression = { $_.PartComponent.ToString().Split(",")[1].Replace("Name=", "").Replace('"', "") } }
	return $Groups
}
$GetRebootStatus = {
	$ComputerName = $args[0]
	function ReadRegKey {
		param ([String]$ComputerName,
			[String]$aKeyPath,
			[String]$aValue)
		
		$hive = [Microsoft.Win32.RegistryHive]::LocalMachine
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $ComputerName)
		
		$keyPath = $aKeyPath
		$key = $reg.OpenSubKey($keyPath)
		$value = $aValue
		$data = $key.GetValue($value)
		$key.Close()
		$reg.Close()
		$hive = $null
		
		$results = @{ keyPath = $keyPath; regValue = $value; regData = $data }
		
		return $results
	}
	
	$keyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
	$value = 'RebootPending'
	$PendingReboot = ReadRegKey -ComputerName $ComputerName -aKeyPath $keyPath -aValue $value
	
	$keyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
	$value = 'RebootRequired'
	$RebootRequired = ReadRegKey -ComputerName $ComputerName -aKeyPath $keyPath -aValue $value
	
	$keyPath = 'SYSTEM\CurrentControlSet\Control\Session Manager'
	$value = 'PendingFileRenameOperations'
	$PendingRenames = ReadRegKey -ComputerName $ComputerName -aKeyPath $keyPath -aValue $value
	
	if ($PendingReboot.regData.Length -eq 0) { $PendingReboot.regData = "False" }
	if ($RebootRequired.regData.Length -eq 0) { $RebootRequired.regData = "False" }
	if ($PendingRenames.regData.Length -eq 0) { $PendingRenames.regData = "False" }
	
	$Status = [PSCustomObject]@{
		Device		   = $ComputerName
		PendingReboot  = $PendingReboot.regData
		RebootRequired = $RebootRequired.regData
		PendingRenames = $PendingRenames.regData
	}
	Return $Status
}
$GetBattery = {
	[String]$ComputerName = $args[0]
	try {
		$Battery = Get-WmiObject -ComputerName $ComputerName -Class Win32_Battery -Namespace 'root\cimv2' -Property Name, BatteryStatus, Caption, EstimatedChargeRemaining, EstimatedRunTime -ErrorAction SilentlyContinue -ErrorVariable ev |
		Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } },
					  Name,
					  Caption,
					  @{
			Name  = "BatteryStatus"; Expression = {
				switch (($_.BatteryStatus)) {
					1 { "Other" }
					2 { "Unknown" }
					3 { "Fully Charged" }
					4 { "Low" }
					5 { "Critical" }
					6 { "Charging" }
					7 { "Charging and High" }
					8 { "Charging and Low" }
					9 { "Charging and Critical" }
					10 { "Undefined" }
					11 { "Partially Charged" }
					default { "Unknown" }
				}
			}
		},
					  @{ Name = "RemainingCharge"; Expression = { $_.EstimatedChargeRemaining } },
					  @{ Name = "RunTime"; Expression = { $_.EstimatedRunTime } }
	}
	catch [Exception] {
		$Battery = $null
        <# Write-Host "Could not fetch Battery Details: $_" #>		
	}
	return $Battery
}
$GetComputerSystem = {
	$ComputerName = $args[0]
	try {
		$ComputerSystem = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem -Namespace 'root\cimv2' -Property Manufacturer, Model, SystemFamily, TotalPhysicalMemory -ErrorAction SilentlyContinue -ErrorVariable ev |
		Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } },
					  Manufacturer,
					  SystemFamily,
					  Model,
					  @{ Name = "TotalRam"; Expression = { "{0:N2}" -f ($_.TotalPhysicalMemory / [math]::pow(1024, 3)) } }
	}
	catch [Exception] {
		$ComputerSystem = $null
        <# "Could not fetch System Details: $_" #>
	}
	return $ComputerSystem
}
$GetDiskDrives = {
	$ComputerName = $args[0]
	
	try {
		$DiskDrives = Get-WmiObject -ComputerName $ComputerName -Class Win32_DiskDrive -Namespace 'root\cimv2' -Property DeviceID, Model, Partitions, Size -Filter "DeviceID Like '%PHYSICALDRIVE%'" -ErrorAction SilentlyContinue -ErrorVariable ev |
		Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } },
					  DeviceID,
					  Model,
					  Partitions,
					  @{ Name = "Size"; Expression = { "{0:N2}" -f ($_.Size / [math]::pow(1024, 3)) } }
	}
	catch [Exception] {
		$DiskDrives = $null
        <# "Could not fetch Disk Details: $_" #>
	}
	return $DiskDrives
}
$GetLogicalDisks = {
	[String]$ComputerName = $args[0]
	
	try {
		$LogicalDisks = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk -Namespace 'root\cimv2' -Property Name, Description, FileSystem, FreeSpace, Size -ErrorAction SilentlyContinue -ErrorVariable ev |
		Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } },
					  Name,
					  Description,
					  FileSystem,
					  @{ Name = "FreeSpace"; Expression = { "{0:N2}" -f ($_.FreeSpace / [math]::pow(1024, 3)) } },
					  @{ Name = "Size"; Expression = { "{0:N2}" -f ($_.Size / [math]::pow(1024, 3)) } }
	}
	catch [Exception] {
		$LogicalDisks = $null
        <# "Could not fetch volume details: $_" #>		
	}
	return $LogicalDisks
}
$GetNetworkAdapters = {
	[String]$ComputerName = $args[0]
	
	$NetworkAdapters = @()
	try {
		$Win32NetworkAdapters = Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapter -Namespace 'root\cimv2' -Property DeviceID, Manufacturer, ProductName, MACAddress, PhysicalAdapter, NetEnabled -Filter "NetEnabled = True and PhysicalAdapter = True" -ErrorAction SilentlyContinue -ErrorVariable ev
	}
	catch { <# "Could not fetch network adapters: $_" #> }
	
	foreach ($NetworkAdapter in $Win32NetworkAdapters) {
		try {
			$NetworkAdapters += Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapterConfiguration -Namespace 'root\cimv2' -Property DHCPEnabled, DNSDomain, IPAddress, IPSubnet, DefaultIPGateway, Index -filter "Index = $($NetworkAdapter.DeviceID)" -ErrorAction SilentlyContinue -ErrorVariable ev |
			Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } },
						  @{ Name = "Manufacturer"; Expression = { $NetworkAdapter.Manufacturer } },
						  @{ Name = "Name"; Expression = { $NetworkAdapter.ProductName } },
						  @{ Name = "MACAddress"; Expression = { $NetworkAdapter.MACAddress } },
						  @{ Name = "DHCPEnabled"; Expression = { $_.DHCPEnabled } },
						  @{ Name = "DNSDomain"; Expression = { $_.DNSDomain } },
						  @{ Name = "IPAddress"; Expression = { $_.IPAddress[0] } },
						  @{ Name = "IPSubnet"; Expression = { $_.IPSubnet[0] } },
						  @{ Name = "DefaultGateway"; Expression = { $_.DefaultIPGateway[0] } }
		}
		catch [Exception] {
			$NetworkAdapters = $null
            <# "Could not fetch network adapter settings: $_" #>
		}
	}
	return $NetworkAdapters
}
$GetOperatingSystem = {
	[String]$ComputerName = $args[0]
	
	try {
		$OperatingSystem = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -Namespace 'root\cimv2' -Property BuildNumber, Caption, InstallDate, LastBootUpTime, LocalDateTime, OperatingSystemSKU, OSArchitecture, Version, FreePhysicalMemory -ErrorAction SilentlyContinue -ErrorVariable ev |
		Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } },
					  @{ Name = "BuildNumber"; Expression = { $_.BuildNumber } },
					  @{ Name = "Caption"; Expression = { $_.Caption } },
					  @{
			Name		  = "InstallDate"; Expression = {
				$InstallDate = "{0}/{1}/{2}" -f [String]($_.InstallDate).Substring(4, 2), [String]($_.InstallDate).Substring(6, 2), [String]($_.InstallDate).Substring(0, 4)
				$InstallTime = "{0}:{1}:{2}" -f [String]($_.InstallDate).Substring(8, 2), [String]($_.InstallDate).Substring(10, 2), [String]($_.InstallDate).Substring(12, 2)
				$TheOffset = [int]([String]($_.InstallDate).Substring(21, 4))
				"{0:yyyy-MM-dd} {1:h:mm:ss tt}" -f $InstallDate, $(([DateTime]($InstallTime)).AddMinutes($TheOffset))
			}
		},
					  @{
			Name			 = "LastBootUp"; Expression = {
				$LastBootUpDate = "{0}/{1}/{2}" -f [String]($_.LastBootUpTime).Substring(4, 2), [String]($_.LastBootUpTime).Substring(6, 2), [String]($_.LastBootUpTime).Substring(0, 4)
				$LastBootUpTime = "{0}:{1}:{2}" -f [String]($_.LastBootUpTime).Substring(8, 2), [String]($_.LastBootUpTime).Substring(10, 2), [String]($_.LastBootUpTime).Substring(12, 2)
				$TheOffset = [int]([String]($_.LastBootUpTime).Substring(21, 4))
				"{0} {1:h:mm:ss tt}" -f $LastBootUpDate, $(([DateTime]($LastBootUpTime)).AddMinutes($TheOffset))
			}
		},
					  @{ Name = "SKU"; Expression = { $_.OperatingSystemSKU } },
					  @{ Name = "Architecture"; Expression = { $_.OSArchitecture } },
					  @{ Name = "Version"; Expression = { $_.Version } },
					  @{ Name = "FreePhysicalMemory"; Expression = { "{0:N2} GB" -f ($_.FreePhysicalMemory / [math]::pow(1024, 2)) } }
	}
	catch [Exception] {
		$OperatingSystem = $null
        <# "Could not fetch Operating System details: $_" #>
	}
	return $OperatingSystem
}
$GetPrinters = {
	[String]$ComputerName = $args[0]
	
	try {
		$Printers = Get-WmiObject -ComputerName $ComputerName -Class Win32_Printer -Namespace 'root\cimv2' -Property Name, Default, DriverName -ErrorAction SilentlyContinue -ErrorVariable ev |
		Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } }, Name, Default, DriverName
	}
	catch [Exception] {
		$Printers = $null
        <# "Could not fetch printers: $_" #>
	}
	return $Printers
}
$GetStartupCommands = {
	[String]$ComputerName = $args[0]
	
	try {
		$Commands = Get-WmiObject -ComputerName $ComputerName -Class Win32_StartupCommand -Namespace 'root\cimv2' -Property Name, User, Location, Command -ErrorAction SilentlyContinue -ErrorVariable ev |
		Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } }, Name, User, Location, Command
	}
	catch [Exception] {
		$Commands = $null
        <# "Could not fetch Startup Commands: $_" #>
	}
	Return $Commands
}
$GetHotfixes = {
	[String]$ComputerName = $args[0]
	
	try {
		$Hotfixes = Get-WmiObject -ComputerName $ComputerName -Class Win32_QuickFixEngineering -Namespace 'root\cimv2' -Property HotfixID, Description, Caption, InstalledBy, InstalledOn -ErrorAction SilentlyContinue -ErrorVariable ev |
		Sort-Object -Property @{ Expression = { (Get-Date -Date $_.InstalledOn) } }, HotfixID |
		Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } },
					  HotFixID,
					  Description,
					  Caption,
					  InstalledBy,
					  @{
			Name  = "InstallDate"; Expression = {
				try {
					"{0:yyyy-MM-dd}" -f (Get-Date -Date $_.InstalledOn)
				}
				catch [Exception] {
					$_.InstalledOn
				}
			}
		}
	}
	catch [Exception] {
		$Hotfixes = $null
        <# "Could not fetch Updates: $_" #>
	}
	return $Hotfixes
}
$GetProcesses = {
	[String]$ComputerName = $args[0]
	try {
		$Processes = Get-WmiObject -Class Win32_Process -ComputerName $ComputerName |
		Sort-Object -Property Name |
		Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } }, Name, ProcessId, CommandLine
	}
	catch [Exception] {
		$Processes = $null
        <# "Could not fetch processes: $_" #>
	}
	return $Processes
}
$GetShares = {
	$ComputerName = $args[0]
	
	$ShareList = @()
	try {
		$Win32Shares = Get-WmiObject -ComputerName $ComputerName -Class Win32_Share -Namespace 'root\cimv2' -Property Name, Caption, Path -ErrorAction SilentlyContinue -ErrorVariable ev
	}
	catch [Exception] { $Win32Shares = $null }
	
	if ($null -ne $Win32Shares) {
		foreach ($share in $Win32Shares) {
			$ShareDetails = [PSCustomObject]@{
				Device  = $ComputerName
				Name    = [String]$($share.Name)
				Caption = [String]$($share.Caption)
				Path    = [String]$($share.Path)
			}
			$ShareList += $ShareDetails
		}
	}
	else { $ShareList = $null }
	return $ShareList
}
$GetBios = {
	$ComputerName = $args[0]
	
	try {
		$Win32Bios = Get-WmiObject -ComputerName $ComputerName -Class Win32_Bios -Namespace 'root\cimv2' -Property Manufacturer, Name, SerialNumber, Version -ErrorAction SilentlyContinue -ErrorVariable ev
	}
	catch [Exception] { $Win32Bios = $null }
	
	if ($null -ne $Win32Bios) {
		$BiosDetails = [PSCustomObject] @{
			Device  		= $ComputerName
			Manufacturer    = [String]$($Win32Bios.Manufacturer)
			Name 			= [String]$($Win32Bios.Name)
			SerialNumber    = [String]$($Win32Bios.SerialNumber)
			Version 		= [String]$($Win32Bios.Version)
		}
	}
	else { $BiosDetails = $null }
	return $BiosDetails
}
$GetNetworkDrives = {
	[String]$ComputerName = $args[0]
	
	try {
		$NetworkDrives = Get-WmiObject -Class Win32_MappedLogicalDisk -ComputerName $ComputerName |
		Select-Object -Property @{ Name = "Device"; Expression = { $ComputerName } },
					  SystemName,
					  Name,
					  ProviderName,
					  VolumeName,
					  @{ Name = "Size"; Expression = { "{0:N0}" -f ($_.Size/([math]::Pow(1024, 3))) } },
					  @{ Name = "FreeSpace"; Expression = { "{0:N0}" -f ($_.FreeSpace/([math]::Pow(1024, 3))) } }
	}
	catch [exception] {
		$NetworkDrives = $null
        <# "Could not fetch Mapped Drives: $($_.Exception)" #>
	}
	return $NetworkDrives
}
$GetCPUTop20 = {
	$ComputerName = $args[0]
	try {
		$Counter = Get-Counter "\\$ComputerName\Process(*)\% Processor Time" |
		Select-Object -ExpandProperty countersamples |
		Where-Object { $_.InstanceName -notmatch "Idle" -and $_.InstanceName -notmatch "Total" } |
		Select-Object -Property instancename, cookedvalue |
		Sort-Object -Property cookedvalue -Descending |
		Select-Object -First 20 -Property @{ Name = "Device"; Expression = { $ComputerName } }, InstanceName, @{ Name = 'CPU'; Expression = { ($_.Cookedvalue/100).ToString('P') } }
	}
	catch [Exception] {
		$Counter = $null
	}
	return $Counter
}
$EnableRemRegService = {
	[String]$ComputerName = $args[0]
	
	try {
		$Service = Get-Service -ComputerName $ComputerName -Name RemoteRegistry -ErrorAction SilentlyContinue -ErrorVariable ServiceError
		
		if ($Service.Status -ne 'Running') {
			Set-Service -InputObject $Service -StartupType Automatic
			Stop-Service -InputObject $Service -Force
			Start-Service -InputObject $Service
			if ((Get-Service -ComputerName $ComputerName -Name RemoteRegistry | Select-Object -ExpandProperty Status) -eq 'Running') {
				return $true
			}
			else {
				return $false
			}
		}
		else {
			return $true
		}
	}
	catch [System.Exception] {
		return $false
	}
}
function WaitForJob {
	param ([System.Management.Automation.Job]$job,
		[int]$timeout,
		[String]$activity = "Waiting for data...")
	
	Do {
		Write-Progress -Activity $activity -Id 0 -SecondsRemaining $timeout -Status "$($job.Name)"
		Start-Sleep -Seconds 1
		$timeout--
	}
	Until ($job.State -eq 'Completed' -or $timeout -le 0)
	
	Write-Progress -Activity "Waiting for data..." -Id 0 -Completed
	if ($timeout -le 0) { return $true }
	else { return $false }
}
function drtRemoteRegStatus {
	param ([String]$ComputerName = $env:COMPUTERNAME, [int]$timeout = 60)
	$job = Start-Job -Name EnableRemRegService -ScriptBlock $EnableRemRegService -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job
		Remove-Job -Job $job -Force
	}
}
function drtInstallations {
	param ([String]$ComputerName = $env:COMPUTERNAME, [int]$timeout = 60)
	$job = Start-Job -Name GetInstalled -ScriptBlock $GetInstalled -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, Vendor, Name, Version, Description, InstallDate, InstallSource, UninstallString
		Remove-Job -Job $job -Force
	}
}
function drtLoggedOn {
	param ([String]$ComputerName = $env:COMPUTERNAME, [int]$timeout = 60)
	$job = Start-Job -Name GetLoggedOn -ScriptBlock $GetLoggedOn -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	$jobResults = $null
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		$jobResults = Receive-Job -Job $job | Select-Object -property Device, SID, Name, FullName, LastLogon, LocalPath, NumLogons, LogonType, Comments
		Remove-Job -Job $job -Force
	}
	return $jobResults
}
function drtLocalGroups {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetLocalGroups -ScriptBlock $GetLocalGroups -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, GroupName, GroupMember
		Remove-Job -Job $job -Force
	}
}
function drtRebootStatus {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetRebootStatus -ScriptBlock $GetRebootStatus -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, PendingReboot, RebootRequired, PendingRenames
		Remove-Job -Job $job -Force
	}
}
function drtBattery {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetBattery -ScriptBlock $GetBattery -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, Name, Caption, BatteryStatus, RemainingCharge, RunTime
		Remove-Job -Job $job -Force
	}
}
function drtBios {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetBios -ScriptBlock $GetBios -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, Name, Manufacturer, Version, SerialNumber, ReleaseDate
		Remove-Job -Job $job -Force
	}
}
function drtComputerSystem {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetComputerSystem -ScriptBlock $GetComputerSystem -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, Manufacturer, SystemFamily, Model, TotalRam
		Remove-Job -Job $job -Force
	}
}
function drtDiskDrives {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetDiskDrives -ScriptBlock $GetDiskDrives -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, DeviceId, Model, Partitions, Size
		Remove-Job -Job $job -Force
	}
}
function drtLogicalDisks {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetLogicalDisks -ScriptBlock $GetLogicalDisks -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, Name, Description, FileSystem, FreeSpace, Size
		Remove-Job -Job $job -Force
	}
}
function drtNetworkAdapters {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetNetworkAdapters -ScriptBlock $GetNetworkAdapters -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, Manufacturer, Name, MACAddres, DHCPEnabled, DNSDomain, IPAddress, IPSubnet, DefaultGateway
		Remove-Job -Job $job -Force
	}
}
function drtOperatingSystem {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetOperatingSystem -ScriptBlock $GetOperatingSystem -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, BuildNumber, Caption, InstallDate, LastBootUp, SKU, Architecture, Version, FreePhysicalMemory
		Remove-Job -Job $job -Force
	}
}
function drtPrinters {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetPrinters -ScriptBlock $GetPrinters -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, Name, Default, DriverName
		Remove-Job -Job $job -Force
	}
}
function drtStartupCommands {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetStartupCommands -ScriptBlock $GetStartupCommands -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, Name, User, Location, Command
		Remove-Job -Job $job -Force
	}
}
function drtHotfixes {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetHotfixes -ScriptBlock $GetHotfixes -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, HotfixID, Description, Caption, InstalledBy, InstallDate
		Remove-Job -Job $job -Force
	}
}
function drtProcesses {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetProcesses -ScriptBlock $GetProcesses -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, Name, ProcessId, CommandLine
		Remove-Job -Job $job -Force
	}
}
function drtShares {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetShares -ScriptBlock $GetShares -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, Name, Caption, Path
		Remove-Job -Job $job -Force
	}
}
function drtNetworkDrives {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetNetworkDrives -ScriptBlock $GetNetworkDrives -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, SystemName, Name, ProviderName, VolumeName, Size, FreeSpace
		Remove-Job -Job $job -Force
	}
}
function drtCPUTop20 {
	param ([String]$ComputerName = $env:COMPUTERNAME,
		[int]$timeout = 60)
	$job = Start-Job -Name GetCPUTop20 -ScriptBlock $GetCPUTop20 -ArgumentList $ComputerName
	$TimedOut = WaitForJob -job $job -timeout $timeout
	if ($TimedOut) {
		Stop-Job -Job $job
		Remove-Job -Job $job -Force
		return "error"
	}
	else {
		Receive-Job -Job $job | Select-Object -property Device, InstanceName, CPU
		Remove-Job -Job $job -Force
	}
}
function isOnline {
	param ([String]$WorkstationName,[int]$timeout = 60)
	
	$job = Test-Connection -ComputerName $WorkstationName -Count 1 -AsJob
	WaitForJob -job $job -timeout $timeout -activity "Pinging Workstation ..." | Out-Null
	$result = Receive-Job -Job $job
	if ($result.StatusCode -eq 0) {
		return $true
	}
	else {
		return $false
	}
}

Export-ModuleMember -function drtRemoteRegStatus
Export-ModuleMember -function drtCPUTop20
Export-ModuleMember -function drtNetworkDrives
Export-ModuleMember -function drtShares
Export-ModuleMember -function drtProcesses
Export-ModuleMember -function drtHotfixes
Export-ModuleMember -function drtStartupCommands
Export-ModuleMember -function drtPrinters
Export-ModuleMember -function drtOperatingSystem
Export-ModuleMember -function drtNetworkAdapters
Export-ModuleMember -function drtLogicalDisks
Export-ModuleMember -function drtDiskDrives
Export-ModuleMember -function drtComputerSystem
Export-ModuleMember -function drtBios
Export-ModuleMember -function drtBattery
Export-ModuleMember -function drtRebootStatus
Export-ModuleMember -function drtLocalGroups
Export-ModuleMember -function drtLoggedOn
Export-ModuleMember -function drtInstallations