@echo off
title CI/CD Pipeline - Stopping All Services
color 0C
cls

echo.
echo  ============================================
echo    Stopping all CI/CD Pipeline services...
echo  ============================================
echo.

echo [*] Stopping Python services...
taskkill /F /IM python.exe /T >nul 2>&1
echo [OK] Python services stopped

echo [*] Stopping Redis...
docker stop redis >nul 2>&1
echo [OK] Redis stopped

echo [*] Stopping Jenkins...
docker stop jenkins >nul 2>&1
echo [OK] Jenkins stopped

echo.
echo  ============================================
echo    All services stopped.
echo  ============================================
echo.
pause
