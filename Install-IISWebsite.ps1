[String]$webRoot = "${env:SystemDrive}\web\mysite"
[String]$siteName = "My Site"
[int32]$portNumber = 8081

[Array]$applicationPools = @(
    [PSCustomObject]@{
        name = "MyApplication"
        path = "${siteName}:\Sites\MyApplication"
        queueLength = 4000
        processModel = [PSCustomObject]@{
            identityType = "SpecificUser"
            userName = "DOMAIN\ServiceAccount"
            password = "PASSWORD"
        }
        cpu = [PSCustomObject]@{
            resetInterval = "00:00:00"
        }
    }
)
if ( (Get-ExecutionPolicy) -notlike 'remotesigned') {
    Write-Host "Setting Powershell Execution Policy to RemoteSigned ..." -NoNewline
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    Write-Host "done" -ForegroundColor Green
}
[Version]$packageProviderVersion = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
if ($packageProviderVersion -lt [Version]"2.8.5.201") {
    Write-Host "Installing NuGet ..." -NoNewline
    Install-PackageProvider -Name NuGet -Scope AllUsers -Force -MinimumVersion '2.8.5.201' -ErrorAction SilentlyContinue -ErrorVariable providerError | Out-Null
    if ($providerError) { Write-Host "failed" -ForegroundColor Red } else { Write-Host "done" -ForegroundColor Green }
}
$installationPolicy = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InstallationPolicy
if ($installationPolicy -notlike 'trusted') {
    Write-Host "Registering PSGallery ..." -NoNewline
    Register-PSRepository -Default -InstallationPolicy Trusted -ErrorAction SilentlyContinue -ErrorVariable registrationError
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorVariable registrationError
    if ($registrationError) { Write-Host "failed" -ForegroundColor Red } else { Write-Host "done" -ForegroundColor Green }
}
[Version]$moduleVersion = Get-Module -Name PowerShellGet -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
if ($ModuleVersion -lt [Version]'2.2.5') {
    Write-Host "Installing PowerShellGet ..." -NoNewline
    Install-Module -Name PowerShellGet -Scope AllUsers -Force -AllowClobber -ErrorAction SilentlyContinue -ErrorVariable moduleError
    if ($moduleError) { Write-Host "failed" -ForegroundColor Red } else { Write-Host "done" -ForegroundColor Green }
}
if ($null -eq (Get-Module -Name IISAdministration -ErrorAction SilentlyContinue) ) {
    Write-Host "Importing IIS Administration Module ..." -NoNewline
    Import-Module IISAdministration -Scope Global -Force -ErrorAction SilentlyContinue -ErrorVariable importError
    if ($importError) { Write-Host "failed" -ForegroundColor Red } else { Write-Host "done" -ForegroundColor Green }
}
if ($null -eq (Get-Module -Name ServerManager -ErrorAction SilentlyContinue) ) {
    Write-Host "Importing ServerManager Module ..." -NoNewline
    Import-Module ServerManager -ErrorAction SilentlyContinue -ErrorVariable importError
    if ($moduleError) { Write-Host "failed" -ForegroundColor Red } else { Write-Host "done" -ForegroundColor Green }
}

if ((Get-WindowsFeature -Name Web-Scripting-Tools | Select-Object -ExpandProperty Installed) -eq $false) {
    Write-Host "Installing Windows Feature: Web-Scripting-Tools ..." -NoNewline
    Add-WindowsFeature Web-Scripting-Tools -ErrorAction SilentlyContinue -ErrorVariable featureError
    if ($featureError) { Write-Host "failed" -ForegroundColor Red } else { Write-Host "done" -ForegroundColor Green }
}
if ($null -eq (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue) ) {
    Write-Host "Importing Web Administration Module ..." -NoNewline
    Import-Module WebAdministration -Scope Global -Force -ErrorAction SilentlyContinue -ErrorVariable importError
    if ($importError) { Write-Host "failed" -ForegroundColor Red } else { Write-Host "done" -ForegroundColor Green }
}

Write-Host "Creating $siteName PS-Drive ..." -NoNewline
Get-PSDrive -Name $siteName -ErrorAction SilentlyContinue | Remove-PSDrive -Force
New-PSDrive -Name $siteName -PSProvider WebAdministration -Root "\\${env:COMPUTERNAME}" -ErrorAction SilentlyContinue -ErrorVariable driveError | Out-Null
if (-not $driveError) {
    Write-Host "done"
    Write-Host "Creating IIS Site ..." -NoNewline
    New-IISSite -BingindInformation "*:${portNumber}:" -Name $siteName -PhysicalPath $webRoot -ErrorAction SilentlyContinue -ErrorVariable siteError
    if (-not $siteError) {
        Write-Host "done" -ForegroundColor Green
        foreach ($pool in $applicationPools) {
            Write-Host "Creating Application Pool `"$($pool.Name)`" ..." -NoNewline
            if ($null -eq (Get-ChildItem -Path "${siteName}:\AppPools" |  Where-Object -Property Name -like $pool.Name)) {
                # Pool does not exist, create
                $poolCreated = New-WebAppPool -Name $pool.Name
                if ($null -ne $poolCreated) {
                    if ($null -ne $pool.queueLength) { Set-ItemProperty -Path $pool.path -Name queueLength -Value $pool.queueLength }
                    if ($null -ne $pool.processModel.identityType) { Set-ItemProperty -Path $pool.path -Name processModel.identityType -Value $pool.processModel.identityType }
                    if ($null -ne $pool.processModel.userName) { Set-ItemProperty -Path $pool.path -Name processModel.userName -Value $pool.processModel.userName }
                    if ($null -ne $pool.processModel.password) { Set-ItemProperty -Path $pool.path -Name processModel.password -Value $pool.processModel.password }
                    if ($null -ne $pool.cpu.resetInterval) { Set-ItemProperty -Path $pool.path -Name cpu.resetInterval -Value $pool.cpu.resetInterval }
                    ConvertTo-WebApplication -PSPath $pool.path -ApplicationPool $pool.name -ErrorAction SilentlyContinue -ErrorVariable conversionError | Out-Null
                    if (-not $conversionError) { Write-Host "done" -ForegroundColor Green } else { Write-Host "exists, skipping." -ForegroundColor Yellow }
                } else { Write-Host "failed" -ForegroundColor Red }
            } else { Write-Host "exists, skipping." -ForegroundColor Yellow }
        }
    } else { Write-Host "failed" -ForegroundColor Red }
} else { Write-Host "failed" -ForegroundColor Red }
