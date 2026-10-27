@echo off
rem Build a single-runnable jar.  (ASCII only: cmd.exe uses GBK codepage)
rem   build.cmd            -> p2s-detector.jar, falls back to p2s-detector-alt.jar if locked
rem   build.cmd <name>     -> custom output name
setlocal enabledelayedexpansion
cd /d "%~dp0"
if not exist out mkdir out

echo [1/3] compiling...
javac -encoding UTF-8 -d out src\p2s\*.java
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)

set OUT=p2s-detector.jar
if not "%~1"=="" set OUT=%~1

echo [2/3] packaging...
if exist "!OUT!" del /f /q "!OUT!" >nul 2>&1
if exist "!OUT!" (
  if "%~1"=="" (
    set OUT=p2s-detector-alt.jar
    echo       main jar locked, using "!OUT!"
    if exist "!OUT!" del /f /q "!OUT!" >nul 2>&1
  )
)
if exist "!OUT!" (
  echo ERROR: "!OUT!" is locked. Close the running detector window and retry.
  exit /b 1
)

jar --create --file "!OUT!" --main-class p2s.Main -C out .
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)
echo [3/3] done: %cd%\!OUT!
