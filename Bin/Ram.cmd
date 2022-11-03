@echo off
:ram
%SystemDrive%\users\Public\EmptyStandbyList.exe workingsets
%SystemDrive%\users\Public\EmptyStandbyList.exe modifiedpagelist
timeout /t 10
goto:ram
