# 🚀 SEB MITM Proxy - Koyeb Deployment

Forward proxy server with HTTPS interception để inject custom headers cho Safe Exam Browser.

---

## ⚡ **QUICK START:**

### **1. Push lên GitHub:**

```bash
# Chạy script tự động
.\PUSH-TO-GITHUB.bat

# Nhập GitHub username khi được hỏi
```

---

### **2. Deploy lên Koyeb:**

1. Truy cập: https://app.koyeb.com/
2. Sign up with GitHub
3. Create Web Service
4. Chọn: GitHub → `seb-proxy-server`
5. Configure:
   ```
   Build method: Dockerfile
   Service name: seb-proxy
   Instance: Nano (512MB) - FREE
   Port: 8080
   
   Environment variables:
   PORT=8080
   NODE_ENV=production
   ```
6. Click: **Deploy**
7. Chờ 2-5 phút

---

### **3. Install Certificate:**

```bash
# Chạy script tự động
.\INSTALL-CERT.bat

# Nhập Koyeb URL: seb-proxy-XXXXX.koyeb.app
```

---

### **4. Config SEB:**

```
Network → Proxy:

☑ HTTP Proxy:  seb-proxy-XXXXX.koyeb.app:443
☑ HTTPS Proxy: seb-proxy-XXXXX.koyeb.app:443
```

---

### **5. Test:**

```
Truy cập: https://httpbin.org/headers
Kiểm tra: X-Custom-Header có xuất hiện
```

✅ **DONE!** 🎉

---

## 📋 **FILES:**

```
seb-proxy-koyeb/
├── proxy-mitm.js          # Core proxy logic
├── index.js               # Entry point
├── setup-certificates.js  # Certificate generator
├── config.json            # Custom headers config
├── package.json           # Dependencies
├── package-lock.json      # Lock file
├── Dockerfile             # Docker build
├── .dockerignore          # Docker ignore
├── .gitignore             # Git ignore
├── README.md              # This file
├── PUSH-TO-GITHUB.bat     # Push script
└── INSTALL-CERT.bat       # Install cert script
```

---

## ⚙️ **CONFIGURATION:**

### **Custom Headers (config.json):**

```json
{
  "headers": {
    "X-Custom-Header": "StudentID-12345"
  }
}
```

Sửa file này để thay đổi headers.

---

## 🔒 **CERTIFICATE:**

**Download:**
```
https://seb-proxy-XXXXX.koyeb.app/cert
```

**Install:**
- Double-click `ca-cert.pem`
- Install → Local Machine
- Trusted Root Certification Authorities
- Finish

---

## 🧪 **TESTING:**

```powershell
# Test HTTP
curl -x https://seb-proxy-XXXXX.koyeb.app:443 http://httpbin.org/ip

# Test HTTPS
curl -x https://seb-proxy-XXXXX.koyeb.app:443 https://httpbin.org/ip

# Test headers
# Truy cập: https://httpbin.org/headers trong SEB
```

---

## 🔧 **TROUBLESHOOTING:**

### **Build failed:**
- Kiểm tra Logs trong Koyeb
- Đảm bảo có `package-lock.json`

### **Certificate not trusted:**
- Install lại vào Trusted Root
- Restart browser/SEB

### **Proxy connection refused:**
- Port phải là 443 (Koyeb force HTTPS)
- URL KHÔNG có `https://`

### **Headers not injected:**
- Kiểm tra `config.json`
- Redeploy service

---

## ✨ **FEATURES:**

```
✅ Forward Proxy (HTTP & HTTPS)
✅ MITM SSL/TLS interception
✅ Inject custom headers
✅ Auto-generate CA certificate
✅ Web endpoint (/cert)
✅ Docker deployment
✅ Koyeb-ready
✅ KHÔNG cần credit card
✅ FREE tier: 512MB RAM
✅ KHÔNG sleep
```

---

## 📊 **INFO:**

```
Platform: Koyeb (https://www.koyeb.com/)
Free tier: 512MB RAM, 2GB storage
No credit card required
No sleep policy
Docker support
```

---

**🎯 BẮT ĐẦU: Chạy `.\PUSH-TO-GITHUB.bat`** 🚀

