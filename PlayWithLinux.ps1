function LogWrite {
    param(
        [Parameter(Position = 1, Mandatory = $true)][String]$message,
        [Parameter(Position = 2, Mandatory = $false)][Switch]$new
    )

    $timeStamp = "{0:yyyy-MM-dd`tHH:mm:ss}" -f (Get-Date)
    $scriptName = Split-Path -Path ($MyInvocation.ScriptName) -LeafBase
    if ($null -ne $scriptName) { 
        $logName = "$scriptName.log"
        if ($new) {
            Out-File -InputObject "$timeStamp`t$message" -FilePath "$scriptDir/$logName" -Encoding ascii -Force
        } else {
            Out-File -InputObject "$timeStamp`t$message" -FilePath "$scriptDir/$logName" -Encoding ascii -Append    
        }
    }
}
function CreateLogicalVolume {
    $vgName = "myVolumeGroup"
    $lvName = "myLogicalVolume"
    $snapshotName = "mysnap"
    Get-ChildItem -Path "$scriptDir/lvcreate.output" -ErrorAction SilentlyContinue | Remove-Item -Force
    $params = @{
        FilePath = "/usr/sbin/lvcreate"
        ArgumentList = "--snapshot --name `"$snapshotName`" --extents 25%ORIGIN --permission r `"$vgName/$lvName`""
        PassThru = $true
        Wait = $true
        RedirectStandardOutput = 'lvcreate.output'
    }
    Start-Process @params | Out-Null
    $output = Get-Content -Path ./lvcreate.output -ErrorAction SilentlyContinue
    if ($output -match "Logical volume `"$snapshotName`" created") { return $true } else { return $false }
}
function DestroyLogicalVolume {
    $vgName = "myVolumeGroup"
    $lvName = "myLogicalVolume"
    $snapshotName = "mysnap"
    Get-ChildItem -Path "$scriptDir/lvremove.output" -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Path "$scriptDir/lvremove.error" -ErrorAction SilentlyContinue | Remove-Item -Force
    $params = @{
        FilePath = "/usr/sbin/lvremove"
        ArgumentList = "`"$vgName/$lvName`" --quiet --force"
        PassThru = $true
        Wait = $true
        RedirectStandardOutput = 'lvremove.output'
        RedirectStandardError = 'lvremove.error'
    }
    Start-Process @params | Out-Null
    $output = Get-Content -Path "$scriptDir/lvremove.output" -ErrorAction SilentlyContinue
    if ($output -match "Logical volume `"$snapshotName`" successfully removed") { return $true } else { return $false }
}
function MountLogicalVolume {
    $vgName = "myVolumeGroup"
    $lvName = "myLogicalVolume"
    $mountDir = "/mnt/snapshot"
    Get-ChildItem -Path "$scriptDir/mount.output" -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Path "$scriptDir/mount.error" -ErrorAction SilentlyContinue | Remove-Item -Force
    $params = @{
        FilePath = "/bin/mount"
        ArgumentList = "`"/dev/mapper/$vgName-$lvName`" `"$mountDir`""
        PassThru = $true
        Wait = $true
        RedirectStandardOutput = "mount.output"
        RedirectStandardError = "mount.error"
    }
    Start-Process @params | Out-Null
    $mounted = mount | Where-Object { $_ -match "/dev/mapper/$vgName-$lvName on $mountDir" }
    if ($null -ne $mounted) { return $true } 
    else { return $false }
}
function UnmountLogicalVolume {
    $vgName = "myVolumeGroup"
    $lvName = "myLogicalVolume"
    $mountDir = "/mnt/snapshot"
    Get-ChildItem -Path "$scriptDir/umount.output" -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Path "$scriptDir/umount.error" -ErrorAction SilentlyContinue | Remove-Item -Force
    umount "/mnt/snapshot"
    $params = @{
        FilePath = "/bin/umount"
        ArgumentList = "`"$mountDir`""
        PassThru = $true
        Wait = $true
        RedirectStandardOutput = "umount.output"
        RedirectStandardError = "umount.error"
    }
    Start-Process @params | Out-Null
    $unmounted = mount | Where-Object { $_ -match "/dev/mapper/$vgName-$lvName on $mountdir" }
    if ($null -eq $unmounted) { return $true }
    else { return $false }
}
function GetWinVMs {
    param(
        [Parameter(Position = 1, Mandatory = $true)][String]$hostName,
        [Parameter(Position = 2, Mandatory = $true)][String]$userName
    )
    

    $dnsSuffix = "domain.local"
    LogWrite -message "Establishing Powershell Session with $hostName"
    $session = New-PSSession -HostName "$hostName.$dnsSuffix" -UserName $userName
    if ($null -ne $session) {
        LogWrite -message "done"
        LogWrite -message "Gathering files from $hostName"
        $srcFiles = Invoke-Command -Session $session -ScriptBlock { 
            $results = @()
            $files = Get-ChildItem -Path C:\backup -Recurse 
            foreach ($f in $files) {
                if ($f.Attributes -eq [System.IO.FileAttributes]::Directory) {
                    $fileHash = $null
                    $isDirectory = $true
                }
                else {
                    $fileHash = Get-FileHash -Path $f.FullName -Algorithm MD5 | Select-Object -ExpandProperty Hash
                    $isDirectory = $false
                }
                $results += [PSCustomObject]@{
                    fileHash = $fileHash
                    isDirectory = $isDirectory
                    fullName = $f.fullName
                }
            }
            return $results
        } | Select-Object -Property fullName, fileHash, isDirectory
        LogWrite -message "done."
        foreach ($f in $srcFiles) {
            $tarFullName = [String]($f.fullname).Replace("C:\backup\","/mnt/recovery/$hostName/")
            LogWrite -message "$($f.FullName)"
            if ($f.isDirectory) {
                LogWrite -message "is a directory"
                $tarDirExists = Test-Path -Path $tarFullName -PathType Container
                if (-not $tarDirExists) {
                    LogWrite -message "does not exist, creating"
                    New-Item -Path (Split-Path -Path $tarFullName -Parent) -Name (Split-Path -Path $tarFullName -Leaf) -ItemType Directory -ErrorAction SilentlyContinue -ErrorVariable ErrorCreatingDirectory
                    if (-not $ErrorCreatingDirectory) { LogWrite -message "done." } else { LogWrite -message "failed." }
                } else { LogWrite -message "exists, continuing." }
            }
            else {
                LogWrite -message "is a file" 
                $tarFileExists = Test-Path -Path $tarFullName -PathType Leaf
                if (-not $tarFileExists) {
                    LogWrite -message "does not exist, copying" 
                    Copy-Item -FromSession $session -Path $f.FullName -Destination $tarFullName -ErrorAction SilentlyContinue -ErrorVariable ErrorCopyingFiles
                    if (-not $ErrorCopyingFiles) { LogWrite -message "done." } else { LogWrite -message "failed." }
                }
                else {
                    LogWrite -message "exists, comparing MD5 Hash" 
                    $tarFileHash = Get-FileHash -Path $tarFullName -Algorithm MD5 | Select-Object -ExpandProperty Hash
                    if ($f.fileHash -ne $tarFileHash) {
                        LogWrite -message "different, copying file" 
                        Copy-Item -FromSession $session -Path $f.FullName -Destination $tarFullName -ErrorAction SilentlyContinue -ErrorVariable ErrorCopyingFiles -Force
                        if (-not $ErrorCopyingFiles) { LogWrite -message "done." } else { LogWrite -message "failed." }
                    } else { LogWrite -message "the same, continuing." }
                }
            }
        }
        if (-not $ErrorCopyingFiles) { return $true } else { return $false }
    } else { LogWrite -message "failed."; return $false }
}
function GetPiHoleBackups {
    $userName = "me"
    $hostName = "hole.domain.local"
    $srcDir = "/path/to/backup/files"
    $tarDir = "/path/where/backups/will/be/stored/"
    Get-ChildItem -Path "$scriptDir/rsync_pi-hole.output" -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Path "$scriptDir/rsync_pi-hole.error" -ErrorAction SilentlyContinue | Remove-Item -Force
    $params = @{
        FilePath = "/usr/bin/rsync"
        ArgumentList = "-ab -e ssh $userName@$($hostName):$srcDir/* $tarDir"
        PassThru = $true
        Wait = $true
        NoNewWindow = $true
        RedirectStandardError = "rsync_pi-hole.error"
    }
    Start-Process @params
    Start-Sleep -Seconds 5
    $errors = Get-Content -Path "$scriptDir/rsync_pi-hole.error" -ErrorAction SilentlyContinue
    if ($null -eq $errors) { return $true } else { return $false }
}
function GetHassBackups {
    $userName = "me"
    $hostName = "hass.domain.local"
    $srcDir = "/path/to/backup/files"
    $tarDir = "/path/where/backup/files/will/be/stored"
    Get-ChildItem -Path "$scriptDir/scp_hass.output" -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Path "$scriptDir/scp_hass.error" -ErrorAction SilentlyContinue | Remove-Item -Force
    
    $params = @{
        FilePath = "/usr/bin/scp"
        ArgumentList = $null
        PassThru = $true
        Wait = $true
        NoNewWindow = $true
        RedirectStandardError = "scp_hass.error"
    }

    LogWrite -message "Getting files list from Home Assistant backups"
    $srcFiles = ssh $me@$hostName ls -1 $srcDir
    LogWrite -message "done"
    foreach ($f in $srcFiles) {
        if ( (Test-Path -Path "$tarDir/$f" -PathType Leaf) -eq $false ) {
            LogWrite -message "$f does not exist, copying"
            $params.ArgumentList = "-Cp $me@$($hostName):$(Join-Path -Path $srcDir -ChildPath $f) $tarDir"
            Start-Process @params
        }
        else {
            LogWrite -message "$f exists, skipping"
        }
    }
    $errors = Get-Content -Path "$scriptDir/scp_hass.error" -ErrorAction SilentlyContinue
    if ($null -eq $errors) { return $true } else { return $false }
}
function SynchronizeVolume {
    $tarDir = "/path/where/backup/files/will/be/stored/"
    Get-ChildItem -Path "$scriptDir/rsync.output" -ErrorAction SilentlyContinue | Remove-Item -Force
    $params = @{
        FilePath = "/bin/rsync"
        ArgumentList = "-ab --progress --exclude `"/*timeshift*/`" `"/mnt/snapshot/`" `"$tarDir`""
        PassThru = $true
        Wait = $true
        RedirectStandardOutput = "rsync.output"
        RedirectStandardError = "rsync.error"
    }
    Start-Process @params | Out-Null
    if ( (Test-Path -Path "$scriptDir/rsync.error" -PathType Leaf) -eq $false) {
        return $true
    } else { return $true }
}
function BackupToiDrive {
    $workingDirectory = "/path/to/iDrive/scripts/"
    $userName = "me"
    $iDriveLogin = "my.email@mail.com"
    $params = @{
        FilePath = "/usr/bin/perl"
        ArgumentList = Join-Path -Path $workingDirectory -ChildPath "Backup_Script.pl"
        WorkingDirectory = $workingDirectory
        Wait = $true
        NoNewWindow = $true
        PassThru = $true
    }
    Start-Process @params
    $iDriveLogPath = "/path/to/IDriveForLinux/idriveIt/user_profile/$userName/$iDriveLogin/Backup/DefaultBackupSet"
    $logStatsFile = Get-ChildItem -Path $iDriveLogPath -Filter "*logstat.json" -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
    $logStatsContent = Get-Content -Path $logStatsFile.FullName -Encoding utf8
    $logStatsJson = $logStatsContent.Remove(0,1).Insert(0,"[").Insert($logStatsContent.Length,"]") -replace '"[0-9]+":' | ConvertFrom-Json
    $results = $logStatsJson | Sort-Object -Property datetime -Descending  | Select-Object -First 1
    return $results
}
function Main {
    $vgName = "VolumeGroup"
    $lvName = "VolumeName"
    $mountDir = "/mnt/folder/"
    LogWrite -message "********** Beginning of Log **********" -new
    $mounted = mount | Where-Object { $_ -match "/dev/mapper/$vgName-$lvName on $mountDir" }
    if ( $null -ne $mounted ) {
        LogWrite -message "Unmounting snapshot volume" 
        $unmounted = UnmountLogicalVolume
        if ($unmounted -eq $true) { LogWrite -message "done." } else { LogWrite -message "failed." }
    }
    
    $logicalVolume = (/usr/sbin/lvs | Where-Object { $_ -match $lvName })
    if ($null -ne $logicalVolume) {
        LogWrite -message "Removing stale snapshot volume" 
        $destroyed = DestroyLogicalVolume
        if ($destroyed -eq $true) { LogWrite -message "done." } else { LogWrite -message "failed." }
    }
    
    LogWrite -message "Copying Duplicity Backups from Pi-Hole" 
    $copiedFromPiHole = GetPiHoleBackups
    if ($copiedFromPiHole -eq $true) { LogWrite -message "done." } else { LogWrite -message "failed." }
    
    LogWrite -message "Copying Home Assistant Backups"
    $copiedFromHass = GetHassBackups
    if ($copiedFromHass -eq $true) { LogWrite -message "done." } else { LogWrite -message "failed." }
    
    LogWrite -message "Copying Windows Virtual Desktops" 
    $copiedFromStarware = GetWinVMs -hostName "Hyper-V-Server"
    if ($copiedFromStarware -eq $true) { LogWrite -message "done." } else { LogWrite -message "failed." }
    
    $logicalVolume = (/usr/sbin/lvs | Where-Object { $_ -match $lvName })
    if ($null -eq  $logicalVolume) {
        LogWrite -message "Creating snapshot volume" 
        $created = CreateLogicalVolume
        if ($created -eq $true) {
            LogWrite -message "done."
            LogWrite -message "Mounting snapshot volume" 
            $mounted = MountLogicalVolume
            if ($mounted -eq $true) { 
                LogWrite -message "done." 
                LogWrite -message "Populating iDrive Volume with Snapshot data" 
                $synchronized = SynchronizeVolume
                if ($synchronized -eq $true) { 
                    LogWrite -message "done." 
                    LogWrite -message "Performing Backup" 
                    $results = BackupToiDrive
                    LogWrite -message "done"
                    LogWrite -message "DateTime: $($results.datetime)"
                    LogWrite -message "Status: $($results.status)"
                    LogWrite -message "Size: $($results.size)"
                    LogWrite -message "Duration: $($results.duration)"
                    LogWrite -message "Files Count: $($results.filescount)"
                    LogWrite -message "Files Backed Up: $($results.bkpfiles)"
                    LogWrite -message "Unmounting snapshot volume"
                    $unmounted = UnmountLogicalVolume
                    if ($unmounted -eq $true) { LogWrite -message "done." } else { LogWrite -message "failed." }
                    LogWrite -message "Destroying snapshot volume" 
                    $destroyed = DestroyLogicalVolume
                    if ($destroyed -eq $true) { LogWrite -message "done." } else { LogWrite -message "failed." }
                    LogWrite -message "All Tasks Completed."
                } else { LogWrite -message "failed." }
            } else { LogWrite -message "failed." }
        } else { LogWrite -message "failed." }
    }
}

$global:scriptDir = "/home/david/scripts"
Set-Location -Path $scriptDir
Main
