:: Active folder
pushd %~dp0

:Cleaner
emptystandbylist.exe workingsets
emptystandbylist.exe modifiedpagelist
timeout /t 10 /nobreak > NUL
goto:Cleaner