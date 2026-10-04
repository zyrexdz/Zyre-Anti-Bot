@echo off
setlocal

set "MVN_CMD=mvn"
where mvn >nul 2>nul
if %errorlevel% equ 0 goto build

for /r "%USERPROFILE%\.gemini" %%F in (mvn.cmd) do (
    if exist "%%F" (
        set "MVN_CMD=%%F"
        goto build
    )
)

echo Maven was not found on your system PATH.
echo Please install Maven from https://maven.apache.org and add it to PATH.
exit /b 1

:build
call "%MVN_CMD%" clean package
if %errorlevel% equ 0 (
    echo.
    echo =======================================================
    echo  Build Successful!
    echo  Bungee: bungee\target\ZAB-Bungee-1.0.0.jar
    echo  Bukkit: bukkit\target\ZAB-Bukkit-1.0.0.jar
    echo =======================================================
    exit /b 0
) else (
    echo.
    echo Build failed with error code %errorlevel%.
    exit /b %errorlevel%
)
