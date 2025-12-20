@echo off
echo ============================================
echo BAS Reviewer - Windows Build Script
echo ============================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed!
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Installing required packages...
pip install pandas openpyxl requests pyinstaller

echo.
echo Building executable...
pyinstaller -y --onefile --windowed --name "BAS_Reviewer" --hidden-import=pandas --hidden-import=openpyxl --hidden-import=requests bas_reviewer_gui.py

echo.
echo ============================================
if exist "dist\BAS_Reviewer.exe" (
    echo BUILD SUCCESSFUL!
    echo.
    echo Your executable is located at:
    echo   dist\BAS_Reviewer.exe
    echo.
    echo Copy this file to your work laptop and double-click to run!
) else (
    echo BUILD FAILED - Please check the errors above
)
echo ============================================
pause
