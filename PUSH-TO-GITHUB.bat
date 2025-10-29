@echo off
chcp 65001 >nul
color 0A
cls
echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║     📤 PUSH SEB PROXY LÊN GITHUB                               ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.

REM ====================================================================
REM HƯỚNG DẪN:
REM 1. Tạo repo trên GitHub: https://github.com/new
REM    - Repository name: seb-proxy-server
REM    - Chọn: Public
REM    - KHÔNG chọn "Add README"
REM 2. Chạy script này
REM 3. Nhập GitHub username
REM ====================================================================

echo 📝 Nhập GitHub username của bạn:
set /p GITHUB_USER=Username: 

if "%GITHUB_USER%"=="" (
    echo.
    echo ❌ Lỗi: Username không được để trống!
    echo.
    pause
    exit /b 1
)

echo.
echo ✅ GitHub username: %GITHUB_USER%
echo ✅ Repository: seb-proxy-server
echo.

REM Check git
where git >nul 2>nul
if errorlevel 1 (
    echo ❌ Lỗi: Git chưa được cài đặt!
    echo.
    echo 📥 Download Git tại: https://git-scm.com/download/win
    echo.
    pause
    exit /b 1
)

echo 🔄 Bắt đầu push...
echo.

REM Initialize git
if not exist ".git" (
    echo 📦 [1/5] Khởi tạo Git repository...
    git init
    if errorlevel 1 (
        echo ❌ Failed!
        pause
        exit /b 1
    )
    echo ✅ Done!
    echo.
)

REM Add files
echo 📂 [2/5] Thêm files...
git add .
if errorlevel 1 (
    echo ❌ Failed!
    pause
    exit /b 1
)
echo ✅ Done!
echo.

REM Commit
echo 💾 [3/5] Commit changes...
git commit -m "SEB MITM Proxy Server for Koyeb"
if errorlevel 1 (
    echo ⚠️ Không có thay đổi hoặc đã commit rồi
)
echo ✅ Done!
echo.

REM Set remote
echo 🔗 [4/5] Kết nối GitHub...
git remote remove origin 2>nul
git remote add origin https://github.com/%GITHUB_USER%/seb-proxy-server.git
if errorlevel 1 (
    echo ❌ Failed!
    pause
    exit /b 1
)
git branch -M main
echo ✅ Done!
echo.

REM Push
echo 🚀 [5/5] Pushing to GitHub...
echo.
echo ⚠️ Nếu hỏi password, dùng PERSONAL ACCESS TOKEN:
echo    Tạo tại: https://github.com/settings/tokens
echo    Scopes: repo (full control)
echo.

git push -u origin main

if errorlevel 1 (
    echo.
    echo ❌ Push thất bại!
    echo.
    echo 🔧 TROUBLESHOOTING:
    echo.
    echo 1. Nếu lỗi authentication:
    echo    → Dùng Personal Access Token thay password
    echo    → Tạo tại: https://github.com/settings/tokens
    echo.
    echo 2. Nếu lỗi "repository not found":
    echo    → Tạo repo: https://github.com/new
    echo    → Tên: seb-proxy-server
    echo    → Public
    echo.
    pause
    exit /b 1
)

echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║     ✅ PUSH THÀNH CÔNG!                                        ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.
echo 🌐 Repository: https://github.com/%GITHUB_USER%/seb-proxy-server
echo.
echo ═══════════════════════════════════════════════════════════════
echo NEXT STEPS - DEPLOY LÊN KOYEB:
echo ═══════════════════════════════════════════════════════════════
echo.
echo 1. 🌐 Truy cập: https://app.koyeb.com/
echo.
echo 2. 🔐 Sign up with GitHub
echo.
echo 3. 🚀 Create Web Service
echo    → Chọn: GitHub
echo    → Repository: seb-proxy-server
echo    → Branch: main
echo.
echo 4. ⚙️ Configure:
echo    Build method: Dockerfile
echo    Service name: seb-proxy
echo    Instance: Nano (512MB RAM) - FREE
echo    Port: 8080
echo.
echo    Environment variables:
echo      PORT = 8080
echo      NODE_ENV = production
echo.
echo 5. 🎯 Click Deploy!
echo.
echo 6. ⏳ Chờ 2-5 phút để deploy xong
echo.
echo 7. 📋 Copy Koyeb URL (dạng: seb-proxy-XXXXX.koyeb.app)
echo.
echo 8. 🔒 Chạy: .\INSTALL-CERT.bat để cài certificate
echo.
echo ═══════════════════════════════════════════════════════════════
echo.
pause

