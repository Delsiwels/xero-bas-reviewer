============================================
BAS REVIEWER - WINDOWS BUILD INSTRUCTIONS
============================================

WHAT YOU NEED:
- A Windows computer where you CAN install software
- Internet connection

STEP 1: Install Python (if not already installed)
-------------------------------------------------
1. Go to: https://www.python.org/downloads/
2. Download Python 3.11 or later
3. Run the installer
4. IMPORTANT: Check the box "Add Python to PATH" at the bottom!
5. Click "Install Now"

STEP 2: Build the Executable
----------------------------
1. Copy this entire "windows_build" folder to the Windows computer
2. Open the folder
3. Double-click "build_windows.bat"
4. Wait for the build to complete (may take 2-5 minutes)
5. When done, you'll find: dist\BAS_Reviewer.exe

STEP 3: Transfer to Work Laptop
-------------------------------
1. Copy the file "dist\BAS_Reviewer.exe" to a USB drive
   (or email it to yourself, or use cloud storage)
2. Copy it to your work laptop
3. Double-click BAS_Reviewer.exe to run!

NOTES:
------
- The .exe file is standalone - no Python needed on work laptop
- Output files are saved to your Downloads folder
- You need an internet connection for the AI review to work
  (it calls the DeepSeek API)

TROUBLESHOOTING:
----------------
- If Windows Defender blocks the app, click "More info" then "Run anyway"
- If the build fails, make sure Python is in your PATH
- If you see "pip not found", reinstall Python with PATH option checked

============================================
