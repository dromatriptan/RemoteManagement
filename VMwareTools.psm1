function Initialize {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [pscredential]$credentials,
        [Parameter(Position = 2, Mandatory = $true)]
        [Array]$serverNames
    )

    [bool]$successful = $false
    if ($null -eq (Get-Module -Name "vmware.powercli") ) {
        Import-Module vmware.powercli -ErrorAction SilentlyContinue -ErrorVariable importError
        if (-not $importError) {
            $configured = Set-PowerCLIConfiguration -Scope User -ParticipateInCeip $false -Confirm:$false
            if ($null -ne $configured) {
                $connected = Connect-VIServer -Server $serverNames -Credential $credentials -Force
                if ($null -ne $connected) {
                    $successful = $true
                }
            }  
        } 
    }
    return $successful
}
function StopGuest {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$vmName
    )

    [int]$timeout = 60
    [int]$elapsed = 0

    $vm = Get-VM -Name $vmName
    $status = Stop-VMGuest -VM $vm -Confirm:$false -ErrorAction SilentlyContinue
    Do {
        Start-Sleep -Seconds 1
        $elapsed++
        $status = Get-VMGuest -VM $vm
    } Until ($status.state -eq 'NotRunning' -or $elapsed -ge $timeout)
    if ($status.state -eq 'NotRunning') { return $true } else { return $false }
}
function StartGuest {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$vmName
    )

    [int]$timeout = 60
    [int]$elapsed = 0

    $vm = Get-VM -Name $vmName
    $status = Start-VMGuest -VM $vm -Confirm:$false -ErrorAction SilentlyContinue
    Do {
        Start-Sleep -Seconds 1
        $elapsed++
        $status = Get-VMGuest -VM $vm
    } Until ($null -ne $status.IPAddress -or $elapsed -ge $timeout)
    if ($null -ne $status.IPAddress) { return $true } else { return $false }
}
function HasGpuAssigned {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$vmName
    )

    $vm = Get-VM -Name $vmName
    $gpu = $vm.ExtensionData.Config.Hardware.Device | Where-Object { $_.backing.vgpu }
    $gpuDetails = $gpu | Select-Object -Property Key, ControllerKey, UnitNumber, @{Name="Device";Expression={$_.DeviceInfo.Label}},@{Name="Summary";Expression={$_.DeviceInfo.Summary}}
    if ($null -ne $gpuDetails) { return $true } else { return $false }
}
function EnableCPUVirtualization {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$vmName
    )

    [bool]$successful = $false
    if (-not (HasGpuAssigned -vmName $vmName)) {
        Write-Host "Stopping $vmName ..." -NoNewline
        $stopped = StopGuest -vmName $vmName
        if ($stopped) {
            Write-Host "done" -ForegroundColor Green
            Write-Host "Enabling CPU Virtualization ..." -NoNewline
            $vm = Get-VM -Name $vmName
            $configSpec = New-Object -Typeame VMware.Vim.VirtualMachineConfigSpec
            $configSpec.NestedHVEnabled = $true
            try {
                $vm.ExtensionData.ReconfigVM($configSpec)
                Write-Host "done" -ForegroundColor Green
                $successful = $true
            } 
            catch [Exception]{
                Write-Host "failed" -ForegroundColor Red
            }
            Write-Host "Starting $vmName ..." -NoNewline
            $started = StartGuest -vmName $vmName
            if ($started) { Write-Host "done" -ForegroundColor Green } else {  Write-Host "failed" -ForegroundColor Red }
        } else { Write-Host "failed" -ForegroundColor Red }
    } else { Write-Host "vGPU assigned to $vmName, cannot enable CPU Virtualization." -ForegroundColor Yellow; $successful = $true }

    return $successful
}
function GetVolumeDetails {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$computerName,
        [Parameter(Position = 2, Mandatory = $true)]
        [Char]$driveLetter
    )

    try {
        $volumeDetails = Get-WmiObject -ComputerName $computerName -Class Win32_LogicalDisk -Filter "DeviceID like '$driveLetter%'" -Property Name, Description, FileSystem, FreeSpace, Size | `
            Select-Object -Property Name, Description, FileSystem, @{ Name = "FreeSpace"; Expression = {"{0:N2}" -f ($_.FreeSpace / [math]::pow(1024,3))} },@{ Name = "Size"; Expression = {"{0:N2}" -f ($_.Size / [math]::pow(1024,3))} }
    }
    catch {
        $volumeDetails = $null
    }

    return $volumeDetails
}
function RunRemote {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$computerName,
        [Parameter(Position = 2, Mandatory = $true)]
        [String]$commandLine
    )

    $returnVal = Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $computerName -ArgumentList @($commandLine, $null, $null)
    if ($returnVal) {
        switch( [String]($returnVal.ReturnValue) ) {
            '0' { $status = [PSCustomObject]@{ExitCode = 0; Message = "Process ID [$computerName]: $($returnVal.ProcessId)"} }
            '2' { $status = [PSCustomObject]@{ExitCode = 2; Message = "Access Denied"} }
            '3' { $status = [PSCustomObject]@{ExitCode = 3; Message = "Insufficient Privilege"} }
            '8' { $status = [PSCustomObject]@{ExitCode = 8; Message = "Unknown Failure"} }
            '9' { $status = [PSCustomObject]@{ExitCode = 9; Message = "Path not Found"} }
            '21' { $status = [PSCustomObject]@{ExitCode = 21; Message = "Invalid Parameter"} }
            default { $status = [PSCustomObject]@{ExitCode = [int]($returnVal.ReturnValue); Message = "Unknown Failure"} }
        }
    } else { $status = [PSCustomObject]@{ExitCode = [int]-1; Message = "Unknown Failure"} }
    return $status
}
function ExtendVolume {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$vmName
    )

    [bool]$successful = $false
    [string]$fileName = "ExtendVolume.ps1"
    [string]$commands = '
        $diskNumber = Get-Disk | Select-Object -ExpandProperty Number
        $partitionNumber = Get-Partition -DiskNumber | Where-Object -Property Type -eq "Recovery" | Select-Object -ExpandProperty PartitionNumber
        if ($null -ne $diskNumber -and $null -ne $partitionNumber) {
            Remove-Partition -DiskNumber $diskNumber -PartitionNumber $partitionNumber -Confirm"$false -ErrorAction SilentlyContinue -ErrorVariable removalError
            if (-not $removalError) { $recoveryPartitionRemoved = $true } else { $recoveryPartitionRemoved = $false }
        } else { $recoveryPartitionRemoved = $true }

        $diskNumber = Get-Disk | Select-Object -ExpandProperty Number
        $partitionNumber = Get-Partition -DiskNumber $diskNumber | Where-Object -Property Type -eq "Basic" | Select-Object -ExpandProperty PartitionNumber
        Out-File = -FilePath "$PSScriptRoot\rescan.txt" -InputObject "rescan" -Force -ErrorAction SilentlyContinue
        Start-Process -FilePath "DiskPark.exe" -ArgumentList "/s `"$PSScriptRoot\rescan.txt`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 10
        $maxSize = Get-PartitionSupportedSize -DiskNumber $diskNumber -PartitionNumber $partitionNumber | Select-Object -ExpandProperty SizeMax

        if ($null -ne $diskNumber -and $null -ne $partitionNumber -and $null -ne $maxSize) {
            Resize-Partition -DiskNumber $diskNumber -PartitionNumber $partitionNumber -Size $maxSize -ErrorAction SilentlyContinue -ErrorVariable resizingError
            if (-not $resizingError) { $partitionResized = $true } else { $partitionResized = $false }
        }
        if ($recoveryPartitionRemove -and $partitionResized) { [System.Environment]::Exit(0) } else { [System.Environment]::Exit(1) }
    '
    Write-Host "Extending Volume ..." -NoNewline
    Out-File -InputObject $commands -FilePath (Join-Path -Path "${env:TEMP}" -ChildPath $fileName) -Encoding utf8 -Force -ErrorAction SilentlyContinue -ErrorVariable fileError
    if (-not $fileError) {
        Copy-Item -Path (Join-Path -Path "${env:TEMP}" -ChildPath $fileName) -Destination (Join-Path -Path "\\$vmName" -ChildPath "C$") -Force -ErrorAction SilentlyContinue -ErrorVariable copyError
        if (-not $copyError) {
            $status = RunRemote -computerName $vmName -commandLine "Powershell.exe -ExecutionPolicy Bypass -File C:\$fileName"
            if ($status.ExitCode -eq 0) {
                [int]$timeout = 120
                [int]$elapsed = 0
                Do {
                    Start-Sleep -Seconds 1
                    $elapsed++
                    $wmiProcess = Get-WmiObject -Class Win32_Process -Property CommandLine -ComputerName $vmName -Filter "CommandLine like '%$fileName%'" -ErrorAction SilentlyContinue
                } Until ($null -eq $wmiProcess -or $elapsed -ge $timeout)
                if ($null -eq $wmiProcess) { 
                    Write-Host "done" -ForegroundColor Green

                } else { 
                    Write-Host "failed" -ForegroundColor Red 
                }
            } else { Write-Host "failed" -ForegroundColor Red }
        } else { Write-Host "failed" -ForegroundColor Red }
    } else { Write-Host "failed" -ForegroundColor Red }
    return $successful
}
function ExtendVMDisk {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$vmName,
        [Parameter(Position = 2, Mandatory = $true)]
        [int]$sizeGB
    )

    [bool]$successful = $false
    $volumeDetailsBefore = GetVolumeDetails -computerName $vmName -driveLetter 'C'
    Write-Host "Extending VM Disk Capacity ..." -NoNewline
    $vm = Get-VM -Name $vmName
    $hardDisk = Get-HardDisk -VM $vm | Where-Object -Property Name -eq "Hard Disk 1"
    $newCapacityGB = [double]$sizeGB + [double]($hardDisk | Select-Object -ExpandProperty CapacityGB)
    Set-HardDisk -CapacityGB $newCapacityGB -HardDisk $hardDisk -Confirm:$false | Out-Null
    $actualCapacityGB = Get-HardDisk -VM $vm | Where-Object -Property Name -eq "Hard Disk 1" | Select-Object -ExpandProperty CapacityGB
    if ($newCapacityGB -eq $actualCapacityGB) {
        Write-Host "done" -ForegroundColor Green
        Write-Host "Attempting to extend volume within guest OS ..." -NoNewline
        if ( (ExtendVolume -vmName $vmName) ) {
            $volumeDetailsAfter = GetVolumeDetails -computerName $vmName -driveLetter 'C'
            if ( ($volumeDetailsAfter.Size - $volumeDetailsBefore) -eq $sizeGB ) {
                Write-Host "done" -ForegroundColor Green
                $successful = $true
            } else {
                Write-Host "failed" -ForegroundColor Red
            }
        }
    } else { Write-Host "failed" -ForegroundColor Red }

    if ($successful) {
        Write-Host "Before ..."
        $volumeDetailsBefore
        Write-Host "After ..."
        $volumeDetailsAfter
    }
    return $successful
}
function NewVM {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$vmName,
        [Parameter(Position = 2, Mandatory = $true)]
        [String]$templateName,
        [Parameter(Position = 3, Mandatory = $true)]
        [String]$resourcePoolName,
        [Parameter(Position = 4, Mandatory = $true)]
        [String]$datastoreName
    )   

    [bool]$successful = $false
    $created = New-VM -Name $vmName -Template $templateName -ResourcePool $resourcePoolName -Datastore $datastoreName | Out-Null
    if ($null -ne $created) {
        Write-Host "done" -ForegroundColor Green
        $successful = $true
    } else {
        Write-Host "failed" -ForegroundColor Red
    }
    return $successful
}

Export-ModuleMember -Function Initialize -Alias ConnectTo-vSphere
Export-ModuleMember -Function StopGuest
Export-ModuleMember -Function StartGuest
Export-ModuleMember -Function NewVM -Alias CreateGuest
Export-ModuleMember -Function HasGpuAssigned
Export-ModuleMember -Function EnableCPUVirtualization
Export-ModuleMember -Function GetVolumeDetails
Export-ModuleMember -Function ExtendVMDisk
Export-ModuleMember -Function ExtendVolume -Alias ExtendGuestOSVolume