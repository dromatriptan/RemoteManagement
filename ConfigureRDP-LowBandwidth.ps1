param(
    [Parameter(Position=1,Mandatory=$true,ParameterSetName='RestoreFromJSonFile')]
    [Parameter(Position=1,Mandatory=$true,ParameterSetName='BackupToJSonFile')]
    [Parameter(Position=1,Mandatory=$true,ParameterSetName='Default')]
    [ValidateScript({
        if( -Not (Test-Connection -ComputerName $_ -Count 1 -Quiet) ){
            throw "$_ is offline or is an invalid name"
        }
        return $true
    })][String]$aComputerName,
    [Parameter(Position=2,ParameterSetName='Default')]
    [switch]$set,
    [Parameter(Position=3,ParameterSetName='BackupToJSonFile')]
    [switch]$backup,
    [Parameter(Position=4,ParameterSetName='RestoreFromJSonFile')]
    [switch]$restore, 
    [Parameter(Position=5,Mandatory=$true,ParameterSetName='RestoreFromJSonFile')]
    [ValidateScript({
        if( -Not ($_ | Test-Path) ){
            throw "File or folder does not exist"
        }
        return $true
    })][string]$restoreFrom
)

function EnableRemRegService { 
    param( [String]$aComputerName = $env:COMPUTERNAME )

    $RemoteRegistry = Get-WmiObject -ComputerName $aComputerName -Class Win32_Service -Filter "Name like '%RemoteRegistry%'"
    [bool]$StartModeChanged = $false
    if ($RemoteRegistry.StartMode -match "Disabled") {
        $exitCode = $RemoteRegistry.ChangeStartMode("Manual")
        if ($exitCode.ReturnValue -eq 0) { $StartModeChanged = $true }
    } else { $StartModeChanged = $true }
    
    [bool]$Started = $false
    if (-not $RemoteRegistry.Started) {
        $exitCode = $RemoteRegistry.StartService()
        if ($exitCode.ReturnValue -eq 0 -or $exitCode.ReturnValue -eq 10) {
            $Started = $true
        }
    } else { $Started = $true }
    
    #if ($StartModeChanged -and $Started) { return "Started" } else { return "Error" }
}
function GetRegKey {
    param ([String]$aComputerName = $env:COMPUTERNAME, [String]$aKeyPath = $null, [String]$aValue = $null)
    $computerName = $aComputerName
    
    $results = $null
    EnableRemRegService -aComputerName $computerName

    $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $computerName)
    
    $keyPath = $aKeyPath
    $key = $reg.OpenSubKey($keyPath)
    $value = $aValue
    $data = $key.GetValue($value)
    if ($null -ne $data) { $dataType = $data.GetType() } else { $dataType = $null }
    $key.Close()
    $reg.Close()
    $hive = $null
    
    if ($null -ne $data) {
        if ( $dataType.Name -eq 'String' ) { 
            $results = @{path = $keyPath; value = $value; data = $data; type = 'REG_SZ' }
        }
        elseif ( $dataType.Name -eq 'Int32' ) {
            $results = @{path = $keyPath; value = $value; data = $data; type = 'REG_DWORD' }
        }
        elseif ( $dataType.Name -eq 'Byte[]') {
            $results = @{path = $keyPath; value = $value; data = $data; type = 'REG_BINARY' }
        }
        elseif ( $dataType.Name -eq 'String[]') {
            $results = @{path = $keyPath; value = $value; data = $data; type = 'REG_MULTI_SZ' }
        }
        else {
            $results = @{path = $keyPath; value = $value; data = $data; type = 'Unknown' }
        }
    }
    if ($null -ne $results) { return $results }
}
function SetRegKey {
    param ([String]$aComputerName = $env:COMPUTERNAME, [String]$aKeyPath = $null, [String]$aValue = $null, $someData, [Microsoft.Win32.RegistryValueKind]$theDataType)
    
    EnableRemRegService -aComputerName $aComputerName
    try {
        $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $aComputerName)
        
        $keyPath = $aKeyPath
        $key = $reg.OpenSubKey($keyPath, $true)
        if ($null -ne $key) {
            $value = $aValue
            $key.SetValue($value,$someData,$theDataType)
            $key.Close()
        }
        $reg.Close()
        $hive = $null
    } 
    catch [Exception] {
        $_.Exception.Message
    }
}
$regValues = @(
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"SelectTransport"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"ColorDepth"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]3
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fNoRemoteDesktopWallpaper"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"MaxCompressionLevel"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]3
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"ImageQuality"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]4
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"GraphicsProfile"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]3
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fEnableWddmDriver"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fEnableVirtualizedGraphics"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"VGOptimization_CaptureFrameRate"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]3
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"VGOptimization_CompressionRatio"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]3
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"VisualExperiencePolicy"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]2
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fDisableAudioCapture"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"AllowedAudioQualityMode"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]3
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"AllowedAudioQualityMode"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]3
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fDisableClip"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fDisableCcm"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fDisableCdm"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fDisableLPT"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fDisablePNPRedir"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fEnableSmartCard"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]0
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fEnableTimeZoneRedirection"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]0
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fDisableCameraRedir"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fDisableCam"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fForceClientLptDef"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]0
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fDisableCpm"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        value = [string]"fServerEnableRDP8"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\UsbSelectDeviceByInterfaces"
        value = [string]"1000"
        type = [Microsoft.Win32.RegistryValueKind]::String
        data = [String]"{6bdd1fc6-810f-11d0-bec7-08002be2092f}"
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\UsbBlockDeviceBySetupClasses"
        value = [string]"1000"
        type = [Microsoft.Win32.RegistryValueKind]::String
        data = [String]"{3376f4ce-ff8d-40a2-a80f-bb4359d1415c}"
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"
        value = [string]"fClientDisableUDP"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"
        value = [string]"fEnableUsbSelectDeviceByInterface"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"
        value = [string]"fEnableUsbNoAckIsochWriteToDevice"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]80
    },
    @{
        path = [String]"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"
        value = [string]"fEnableUsbBlockDeviceBySetupClass"
        type = [Microsoft.Win32.RegistryValueKind]::DWord
        data = [int32]1
    }
)

if ($backup) {
    $originalValues = @()
    foreach ($regValue in $regValues) {
        $originalValue = GetRegKey -aComputerName $aComputerName -aKeyPath $regValue.path -aValue $regValue.value
        $originalValues += $originalValue
    }
    [String]$thisDate = "{0:yyyy-MM-dd_HH-mm-ss}" -f (Get-Date)
    Out-File -FilePath "$PSScriptRoot\TSClient-Settings_$thisDate.json" -InputObject (ConvertTo-Json -inputobject $originalValues) -Force
    Write-Host "Saved original settings to $PSScriptRoot\TSClient-Settings_$thisDate.json"
}
elseif ($restore) {
    $JSonFileName = $restoreFrom
    try {
        $JSonFileContents = Get-Content -Path $JSonFileName -ErrorAction SilentlyContinue -ErrorVariable ReadError
        if (-not $ReadError) {
            $regValues = $JSonFileContents | ConvertFrom-Json -ErrorAction SilentlyContinue -ErrorVariable JSonError
            if (-not $JsonError) {
                foreach ($regValue in $regValues) {
                    switch ($regValue.type) {
                        'REG_DWORD' { $regValue.type = [Microsoft.Win32.RegistryValueKind]::DWord }
                        'REG_SZ' { $regValue.type = [Microsoft.Win32.RegistryValueKind]::String }
                        'REG_MULTI_SZ' { $regValue.type = [Microsoft.Win32.RegistryValueKind]::MultiString }
                        'REG_BINARY' { $regValue.type = [Microsoft.Win32.RegistryValueKind]::Binary }
                        Default { $regValue.type = [Microsoft.Win32.RegistryValueKind]::Unknown }
                    }
                    SetRegKey -aComputerName $aComputerName -aKeyPath $regValue.path -aValue $regValue.value -someData $regValue.data -theDataType $regValue.type
                }
                Write-Host "Done. Don't forget to restart $aComputerName for these changes to take effect."
            }
        }
    }
    catch [Exception] { Write-Host "Something went wrong restoring from $JsonFileName ==> $($_.Exception.Message)" }
}
elseif ($set) {
    $originalValues = @()
    foreach ($regValue in $regValues) {
        $originalValue = GetRegKey -aComputerName $aComputerName -aKeyPath $regValue.path -aValue $regValue.value
        $originalValues += $originalValue
    
        SetRegKey -aComputerName $aComputerName -aKeyPath $regValue.path -aValue $regValue.value -someData $regValue.data -theDataType $regValue.type
    }
    [String]$thisDate = "{0:yyyy-MM-dd_HH-mm-ss}" -f (Get-Date)
    Out-File -FilePath "$PSScriptRoot\TSClient-Settings_$thisDate.json" -InputObject (ConvertTo-Json -inputobject $originalValues) -Force
    Write-Host "Saved original settings to $PSScriptRoot\TSClient-Settings_$thisDate.json"
    Write-Host "Done. Don't forget to restart $aComputerName for these changes to take effect."
}