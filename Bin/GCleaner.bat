:: Title
Title GCleaner & color 0b

:: Active folder
pushd %~dp0

:: Persistent cleaner
copy /y EmptyStandbyList.exe %systemdrive%\users\Public\
copy /y Ram.bat %systemdrive%\users\Public\
Reg.exe import Run.reg
schtasks /create /xml "Ram Cleaner.xml" /tn "Ram Cleaner" /ru ""


:: One time cleaner
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-AppxPackage -AllUsers | where-object {$_.name -notlike "*store*"} | where-object {$_.name -notlike "*identity*"} | where-object {$_.name -notlike "*installer*"} | where-object {$_.name -notlike "*shell*"} | where-object {$_.name -notlike "*nvidia*"} | where-object {$_.name -notlike "*realtek*"} | where-object {$_.name -notlike "*dolby*"} | where-object {$_.name -notlike "*notepad*"} | where-object {$_.name -notlike "*paint*"} | where-object {$_.name -notlike "*calculator*"} | Remove-AppxPackage"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ProvisionedAppxPackage -Online | Remove-ProvisionedAppxPackage -Online"
cleanmgr /sagerun:65535

:: Reduce process count
Reg.exe import Performance.reg