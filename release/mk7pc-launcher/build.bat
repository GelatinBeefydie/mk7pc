@echo off
REM Builds MK7PC-Launcher.exe (run on Windows with Python 3.10+ installed)
py -3 -m pip install --upgrade pyinstaller || goto :err
py -3 -m unittest test_core || goto :err
py -3 -m PyInstaller --onefile --windowed --name MK7PC-Launcher mk7_launcher.py || goto :err
echo.
echo Done: dist\MK7PC-Launcher.exe
exit /b 0
:err
echo Build failed.
exit /b 1
