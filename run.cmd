@echo off
rem Launch the newest built jar (main, or the -alt fallback when the main jar is locked).
setlocal enabledelayedexpansion
cd /d "%~dp0"
set NEWEST=
set NEWTIME=0
for %%F in (p2s-detector.jar p2s-detector-alt.jar) do (
  if exist "%%F" (
    for %%T in ("%%F") do set FT=%%~tT
    rem 用文件大小+时间粗排：直接比较修改时间字符串（同格式可比）
    if "!NEWEST!"=="" (
      set NEWEST=%%F
      set NEWTIME=!FT!
    ) else (
      if "!FT!" GTR "!NEWTIME!" (
        set NEWEST=%%F
        set NEWTIME=!FT!
      )
    )
  )
)
if "!NEWEST!"=="" (
  echo no jar found, building...
  call build.cmd || goto fail
  set NEWEST=p2s-detector.jar
  if not exist "!NEWEST!" set NEWEST=p2s-detector-alt.jar
)
echo launching !NEWEST!
start "" javaw -jar "%~dp0!NEWEST!"
exit /b 0
:fail
echo Build failed. Run build.cmd to see details.
pause
exit /b 1
