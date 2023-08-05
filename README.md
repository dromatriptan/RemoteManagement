# The POWERshell

## SchedTaskBasedPopup.ps1

**Overview:** Simple Script to Schedule a task that runs as the user that's logged in. You'll want to write something that will figure out the computername and username of the logged on user this script will be targeting, however.

## ConfigureRDP-LowBandwidth.ps1

**Overview:** This script will configure the RDP registry settings for a low-bandwidth scenario. This was created as a means to help manage how end users connect to their workstations. I find it easier to manage RDP settings at the host because we can't always know (with 100% confidence) what RDP client an end user has chosen, the RDP protocol used by said client, much less what individual settings a user may have chosen within their respective client's settings.

How to use:

To set the registry settings: `.\ConfigureRDP-LowBandwidth.ps1 -aComputerName $env:COMPUTERNAME -set`

Note: This will save the current RDP settings to ``.\TSClient-Settings_2022-05-18_09-29-11.json`` in case you need to roll-back to the original settings before the script executed against your target machine

To simply get a backup of the existing registry entries and refrain from making any changes: `\ConfigureRDP-LowBandwidth.ps1 -aComputerName $env:COMPUTERNAME -backup`

Note: Again, this will save the current RDP settings to `.\TSClient-Settings_2022-05-18_09-29-11.json`

To restore settings from a previous backup: `\ConfigureRDP-LowBandwidth.ps1 -aComputerName $env:COMPUTERNAME -restore -restoreFrom .\TSClient-Settings_2022-05-18_09-29-11.json`

Note: This will import the json stringified backup file to a PowerShell object and re-write to the registry.

Pre-Conditions: 

  * You have administrator privileges to the target computer
  * Remote Registry service is accessible and allowed to start
  * PowerShell ExecutionPolicy has been changed accordingly

## drTools.psm1

Overview: Wrote a module that queries machines over the network via WMI for all sorts of things. My favorite module member written gets me the actively logged on person and the type of session they're in (i.e., RDP, Console, etc.).

How to Use:

1. Import the module: `Import-Module -Name drTools`
2. Verify it's imported: `Get-Module -Name drTools`
3. Spit out the list of exported commands: `Get-Module -Name drtools | Select-Object -ExpandProperty ExportedCommands`
4. Try out some commands!

```

PS C:\> Import-Module .\drTools.psm1
PS C:\> Get-Module -Name drtools

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     0.0        drTools                             {drtBattery, drtBios, drtComputerSystem, drtCPUTop20...}

PS C:\> drtComputerSystem -ComputerName $env:computername

Device       : VAULT76
Manufacturer : LENOVO 
SystemFamily : ThinkPad E14 Gen 2
Model        : 20T6CTO1WW
TotalRam     : 23.23

```

## Install-IISWebsite.ps1

**Overview:** This was something I put together to aid a DevOps team. The team needed to package a web service for Windows Servers that required IIS be installed along with an application pool. Turns out there is a native way to do this in PowerShell without resorting to command-line arguments that provide inconsistent error codes and dubious output to determine the success of an installation (and configuration).

## VMwareTools.psm1

**Overview:** Wrote a module that leverages VMware's PowerCLi primarily for two functions: To extend the OS drives on Windows VMs without having to shut them down, and to enable CPU virtualization which allows for the Windows Subsystem for Linux (WSL) to be installed within desktop VMs.

How to Use:

1. Import the module: `Import-Module -Name VMwareTools`
2. Verify it's imported: `Get-Module -Name VMwareTools`
3. Spit out the list of exported commands: `Get-Module -Name VMwareTools | Select-Object -ExpandProperty ExportedCommands`
4. Try out some commands!

```

PS C:\> Import-Module .\VMwareTools.psm1
PS C:\> Get-Module -Name VMwareTools

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     0.0        VMwareTools                             {ConnectTo-vSphere, StopGuest, StartGuest, CreateGuest,..}

PS C:\> ExtendVMDisk -vmName $env:computername -SizeInGB 50

cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameter:
Get-Credential
Attempting to extend hard disk capacity ...done.
Attempting to extend volume within VM guest ...done.


Name        : C:
Description : Local Fixed Disk
FileSystem  : NTFS
FreeSpace   : 19.32
Size        : 78.59

Name        : C:
Description : Local Fixed Disk
FileSystem  : NTFS
FreeSpace   : 19.32
Size        : 128.64
```