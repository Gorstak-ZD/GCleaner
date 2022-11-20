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
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ProvisionedAppxPackage -Online | Remove-ProvisionedAppxPackage -Online"
cleanmgr /sagerun:65535