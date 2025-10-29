@echo off
chcp 65001 >nul
color 0B
cls
echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║     🔒 DOWNLOAD VÀ CÀI CERTIFICATE TỪ KOYEB                    ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.

echo 📝 Nhập Koyeb URL của bạn:
echo    (VD: seb-proxy-abc123.koyeb.app)
echo    ⚠️ KHÔNG cần https://
echo.
set /p KOYEB_URL=URL: 

if "%KOYEB_URL%"=="" (
    echo.
    echo ❌ URL không được để trống!
    echo.
    pause
    exit /b 1
)

REM Remove protocol if entered
set KOYEB_URL=%KOYEB_URL:https://=%
set KOYEB_URL=%KOYEB_URL:http://=%

echo.
echo ✅ Koyeb URL: %KOYEB_URL%
echo.

REM Check curl
where curl >nul 2>nul
if errorlevel 1 (
    echo ❌ curl không tìm thấy!
    echo    curl có sẵn trên Windows 10/11
    pause
    exit /b 1
)

echo ═══════════════════════════════════════════════════════════════
echo BƯỚC 1: DOWNLOAD CERTIFICATE
echo ═══════════════════════════════════════════════════════════════
echo.

echo 📥 Downloading từ: https://%KOYEB_URL%/cert
echo.

curl -L -o "%TEMP%\koyeb-ca-cert.pem" "https://%KOYEB_URL%/cert"

if errorlevel 1 (
    echo.
    echo ❌ Download thất bại!
    echo.
    echo 🔧 Kiểm tra:
    echo    1. URL có đúng không: https://%KOYEB_URL%/
    echo    2. Proxy đã deploy chưa?
    echo    3. Internet connection OK?
    echo.
    pause
    exit /b 1
)

echo.
echo ✅ Certificate downloaded!
echo    📁 %TEMP%\koyeb-ca-cert.pem
echo.

REM Verify file
if not exist "%TEMP%\koyeb-ca-cert.pem" (
    echo ❌ File không tồn tại!
    pause
    exit /b 1
)

for %%A in ("%TEMP%\koyeb-ca-cert.pem") do set size=%%~zA
if %size% LSS 100 (
    echo ❌ File quá nhỏ, có thể download lỗi!
    type "%TEMP%\koyeb-ca-cert.pem"
    pause
    exit /b 1
)

echo ═══════════════════════════════════════════════════════════════
echo BƯỚC 2: INSTALL CERTIFICATE
echo ═══════════════════════════════════════════════════════════════
echo.
echo ⚠️ Cần quyền Administrator!
echo.
echo 📋 LÀM THEO CÁC BƯỚC:
echo.
echo    1. File certificate sẽ mở tự động
echo    2. Click "Install Certificate..."
echo    3. Chọn "Local Machine" → Next
echo    4. UAC sẽ hỏi admin → Click Yes
echo    5. Chọn "Place all certificates in the following store"
echo    6. Click "Browse"
echo    7. Chọn "Trusted Root Certification Authorities"
echo    8. OK → Next → Finish
echo    9. Click "Yes" khi được hỏi
echo.
echo Bấm phím bất kỳ để mở certificate...
pause >nul

echo.
echo 🔓 Opening certificate...
start "" "%TEMP%\koyeb-ca-cert.pem"

echo.
echo ⏳ Chờ bạn install certificate...
echo    (Làm theo hướng dẫn ở trên)
echo.
echo Sau khi install xong, bấm phím bất kỳ để tiếp tục...
pause >nul

echo.
echo ═══════════════════════════════════════════════════════════════
echo BƯỚC 3: VERIFY
echo ═══════════════════════════════════════════════════════════════
echo.

echo 🔍 Checking certificate...
echo.

certutil -store Root | findstr /i "SEB-MITM-Proxy" >nul
if errorlevel 1 (
    echo ⚠️ Không tìm thấy certificate trong Trusted Root!
    echo.
    echo 🔧 Kiểm tra thủ công:
    echo    Win + R → certmgr.msc
    echo    Trusted Root Certification Authorities → Certificates
    echo    Tìm: SEB-MITM-Proxy-CA
    echo.
) else (
    echo ✅ Certificate đã installed!
    echo.
)

echo ═══════════════════════════════════════════════════════════════
echo BƯỚC 4: TEST PROXY
echo ═══════════════════════════════════════════════════════════════
echo.

echo 🧪 Testing HTTP proxy...
curl -x https://%KOYEB_URL%:443 http://httpbin.org/ip
if errorlevel 1 (
    echo ⚠️ HTTP test failed
) else (
    echo.
    echo ✅ HTTP proxy OK!
)

echo.
echo 🧪 Testing HTTPS proxy...
curl -x https://%KOYEB_URL%:443 https://httpbin.org/ip
if errorlevel 1 (
    echo ⚠️ HTTPS test failed
) else (
    echo.
    echo ✅ HTTPS proxy OK!
)

echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║     ✅ HOÀN THÀNH!                                             ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.
echo ═══════════════════════════════════════════════════════════════
echo NEXT STEPS - CONFIG SEB:
echo ═══════════════════════════════════════════════════════════════
echo.
echo 1. 📖 Mở SEB Config Tool
echo.
echo 2. ⚙️ Network → Proxy:
echo.
echo    ☑ Enable HTTP Proxy
echo      Proxy Address: %KOYEB_URL%
echo      Port: 443
echo.
echo    ☑ Enable HTTPS Proxy
echo      Proxy Address: %KOYEB_URL%
echo      Port: 443
echo.
echo    ☐ Bypass proxy for local addresses
echo.
echo 3. 📝 Network → Request Headers:
echo.
echo    Add header:
echo      Name: X-Custom-Header
echo      Value: StudentID-12345
echo.
echo 4. 💾 File → Save As → exam-config.seb
echo.
echo 5. 🚀 Double-click exam-config.seb để test
echo.
echo 6. 🧪 Test: https://httpbin.org/headers
echo    → Kiểm tra X-Custom-Header có xuất hiện
echo.
echo ═══════════════════════════════════════════════════════════════
echo.
echo 🎯 SẴN SÀNG SỬ DỤNG! 🎉
echo.
pause

