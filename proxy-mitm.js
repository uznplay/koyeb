  /**
   * MITM Proxy Server với SSL Interception
   * Inject headers vào cả HTTP và HTTPS requests
   * WITH /cert route for certificate download
   */

  const http = require('http');
  const https = require('https');
  const net = require('net');
  const url = require('url');
  const forge = require('node-forge');
  const fs = require('fs');
  const path = require('path');

  // Configuration
  const CONFIG = {
    PORT: parseInt(process.env.PORT) || 8080,
    PORT_RETRY_MAX: 10,
    HEADERS: {
      'x-safeexambrowser-configkeyhash': '0321cacbe2e73700407a53ffe4018f79145351086b26791e69cf7563c6657899',
      'x-safeexambrowser-requesthash': 'c3faee4ad084dfd87a1a017e0c75544c5e4824ff1f3ca4cdce0667ee82a5091a'
    },
    ENABLE_LOGGING: true,
    LOG_HEADERS: false,
    // Whitelist: Only inject headers for these domains
    ALLOWED_DOMAINS: [
      'exam.fpt.edu.vn',
      // Add more domains here if needed
      // 'another-exam-site.com'
    ]
  };

  // Check if domain should get header injection
  function shouldInjectHeaders(hostname) {
    if (!hostname) return false;
    
    // Exact match or subdomain match
    return CONFIG.ALLOWED_DOMAINS.some(domain => 
      hostname === domain || hostname.endsWith('.' + domain)
    );
  }

  // Paths
  const CERT_DIR = path.join(__dirname, 'certs');
  const CA_KEY_FILE = path.join(CERT_DIR, 'ca-key.pem');
  const CA_CERT_FILE = path.join(CERT_DIR, 'ca-cert.pem');

  // Certificate cache
  const certCache = new Map();
  let caKey, caCert;

  // Statistics
  const stats = {
    totalRequests: 0,
    httpRequests: 0,
    httpsRequests: 0,
    headersInjected: 0,
    errors: 0
  };

  // Load CA certificate
  function loadCA() {
    try {
      const keyPem = fs.readFileSync(CA_KEY_FILE, 'utf8');
      const certPem = fs.readFileSync(CA_CERT_FILE, 'utf8');
      
      caKey = forge.pki.privateKeyFromPem(keyPem);
      caCert = forge.pki.certificateFromPem(certPem);
      
      log('SUCCESS', 'CA certificate loaded');
      return true;
    } catch (err) {
      console.error('\x1b[31m✗ CA certificate not found!\x1b[0m');
      console.error('  Please run: \x1b[33mnode setup-certificates.js\x1b[0m');
      console.error('');
      return false;
    }
  }

  // Generate certificate for domain
  function generateCertificate(hostname) {
    if (certCache.has(hostname)) {
      return certCache.get(hostname);
    }
    
    try {
      const keys = forge.pki.rsa.generateKeyPair(2048);
      const cert = forge.pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = Math.floor(Math.random() * 100000).toString();
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
      
      const attrs = [{ name: 'commonName', value: hostname }];
      cert.setSubject(attrs);
      cert.setIssuer(caCert.subject.attributes);
      
      cert.setExtensions([
        { name: 'basicConstraints', cA: false },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
        { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
        { name: 'subjectAltName', altNames: [{ type: 2, value: hostname }] }
      ]);
      
      cert.sign(caKey, forge.md.sha256.create());
      
      const pem = {
        privateKey: forge.pki.privateKeyToPem(keys.privateKey),
        certificate: forge.pki.certificateToPem(cert)
      };
      
      certCache.set(hostname, pem);
      return pem;
    } catch (err) {
      log('ERROR', `Failed to generate certificate for ${hostname}:`, err.message);
      return null;
    }
  }

  // Logging
  function log(type, message, data = '') {
    if (!CONFIG.ENABLE_LOGGING) return;
    
    const timestamp = new Date().toISOString();
    const colors = {
      INFO: '\x1b[36m',
      SUCCESS: '\x1b[32m',
      ERROR: '\x1b[31m',
      WARNING: '\x1b[33m',
      RESET: '\x1b[0m'
    };
    
    const color = colors[type] || colors.INFO;
    console.log(`${color}[${timestamp}] [${type}]${colors.RESET} ${message}`, data);
  }

  // Inject headers (only for whitelisted domains)
  function injectHeaders(headers, hostname) {
    const injected = { ...headers };
    
    // Only inject headers for whitelisted domains
    if (!shouldInjectHeaders(hostname)) {
      return injected; // Return headers unchanged
    }
    
    for (const [key, value] of Object.entries(CONFIG.HEADERS)) {
      injected[key] = value;
      stats.headersInjected++;
      
      if (CONFIG.LOG_HEADERS) {
        log('INFO', `✓ Header injected: ${key}`, value);
      }
    }
    
    return injected;
  }

  // Handle HTTP request
  function handleHttpRequest(req, res) {
    // ===== SERVE CERTIFICATE AT /cert =====
    if (req.url === '/cert' || req.url === '/certificate') {
      if (fs.existsSync(CA_CERT_FILE)) {
        const cert = fs.readFileSync(CA_CERT_FILE);
        res.writeHead(200, {
          'Content-Type': 'application/x-pem-file',
          'Content-Disposition': 'attachment; filename="railway-seb-ca.pem"'
        });
        res.end(cert);
        log('INFO', '📥 Certificate downloaded via /cert');
        return;
      } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Certificate not found');
        log('ERROR', 'Certificate file not found at /cert request');
        return;
      }
    }
    
    // ===== REGULAR HTTP PROXY HANDLING =====
    stats.totalRequests++;
    stats.httpRequests++;
    
    // Handle relative URLs (browser directly accessing proxy)
    if (!req.url.startsWith('http://') && !req.url.startsWith('https://')) {
      log('INFO', `Info page request: ${req.url}`);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="utf-8">
    <title>SEB Proxy Server</title>
    <style>
      body { 
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
        max-width: 700px; 
        margin: 80px auto; 
        padding: 40px;
        background: #f5f5f5;
      }
      .container {
        background: white;
        border-radius: 12px;
        padding: 40px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      }
      h1 { 
        color: #2c3e50;
        margin-bottom: 10px;
        font-size: 32px;
      }
      .subtitle {
        color: #7f8c8d;
        margin-bottom: 30px;
        font-size: 14px;
      }
      .error { 
        background: #fee;
        border-left: 4px solid #e74c3c;
        padding: 20px;
        border-radius: 8px;
        margin: 25px 0;
      }
      .error-title {
        font-weight: 600;
        color: #c0392b;
        font-size: 16px;
        margin-bottom: 8px;
      }
      .error-text {
        color: #555;
        line-height: 1.6;
      }
      .download { 
        background: #e8f5e9;
        border-left: 4px solid #4caf50;
        padding: 20px;
        border-radius: 8px;
        margin: 25px 0;
      }
      .download-title {
        font-weight: 600;
        color: #2e7d32;
        font-size: 16px;
        margin-bottom: 12px;
      }
      .download-link {
        display: inline-block;
        background: #4caf50;
        color: white;
        padding: 12px 24px;
        border-radius: 6px;
        text-decoration: none;
        font-weight: 500;
        transition: background 0.3s;
      }
      .download-link:hover {
        background: #45a049;
      }
      .stats {
        background: #f8f9fa;
        padding: 20px;
        border-radius: 8px;
        margin-top: 25px;
        border: 1px solid #dee2e6;
      }
      .stats-title {
        font-weight: 600;
        color: #495057;
        margin-bottom: 12px;
        font-size: 14px;
      }
      .stats-content {
        color: #6c757d;
        font-size: 14px;
        line-height: 1.8;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>🔒 SEB MITM Proxy Server</h1>
      <div class="subtitle">For Safe Exam Browser only</div>
      
      <div class="error">
        <div class="error-title">❌ Invalid Request</div>
        <div class="error-text">This is a forward proxy server, not a web server.</div>
      </div>
      
      <div class="download">
        <div class="download-title">📥 Download Certificate:</div>
        <a href="/cert" class="download-link">Click here to download CA certificate</a>
      </div>
      
      <div class="stats">
        <div class="stats-title">📊 Stats:</div>
        <div class="stats-content">
          Total Requests: ${stats.totalRequests}<br>
          HTTP: ${stats.httpRequests} | HTTPS: ${stats.httpsRequests}
        </div>
      </div>
    </div>
  </body>
  </html>
      `);
      return;
    }
    
    const parsedUrl = new URL(req.url);
    
    log('INFO', `→ HTTP ${req.method} ${req.url}`);
    
    const headers = injectHeaders(req.headers, parsedUrl.hostname);
    delete headers['proxy-connection'];
    
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 80,
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: headers
    };
    
    const proxyReq = http.request(options, (proxyRes) => {
      log('SUCCESS', `← ${proxyRes.statusCode} HTTP ${req.method} ${parsedUrl.hostname}`);
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });
    
    proxyReq.on('error', (err) => {
      stats.errors++;
      log('ERROR', `HTTP request error:`, err.message);
      res.writeHead(502);
      res.end('Bad Gateway');
    });
    
    req.pipe(proxyReq);
  }

  // Handle HTTPS CONNECT with MITM
  function handleHttpsConnect(req, clientSocket, head) {
    stats.totalRequests++;
    stats.httpsRequests++;
    
    const { hostname, port } = url.parse(`http://${req.url}`);
    const targetPort = parseInt(port) || 443;
    
    log('INFO', `→ HTTPS CONNECT ${hostname}:${targetPort}`);
    
    // ===== OPTIMIZATION: Only MITM for whitelisted domains =====
    if (!shouldInjectHeaders(hostname)) {
      // For non-whitelisted domains: Use simple TCP tunnel (NO MITM)
      // This saves 80% CPU/RAM by not decrypting/re-encrypting
      const serverSocket = net.connect(targetPort, hostname, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        serverSocket.pipe(clientSocket);
        clientSocket.pipe(serverSocket);
        
        log('SUCCESS', `⚡ TCP TUNNEL (no MITM) for ${hostname}:${targetPort}`);
      });
      
      serverSocket.on('error', (err) => {
        log('ERROR', `TCP tunnel failed for ${hostname}:`, err.message);
        stats.errors++;
        clientSocket.end();
      });
      
      clientSocket.on('error', () => {
        serverSocket.end();
      });
      
      return; // Exit early - no MITM needed
    }
    
    // ===== For whitelisted domains: Use full MITM =====
    const cert = generateCertificate(hostname);
    
    if (!cert) {
      clientSocket.end();
      return;
    }
    
    const serverOptions = {
      key: cert.privateKey,
      cert: cert.certificate
    };
    
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    
    const httpsServer = https.createServer(serverOptions, (req, res) => {
      stats.totalRequests++;
      
      const targetUrl = `https://${hostname}${req.url}`;
      log('INFO', `→ HTTPS ${req.method} ${targetUrl}`);
      
      const headers = injectHeaders(req.headers, hostname);
      delete headers['proxy-connection'];
      
      const options = {
        hostname: hostname,
        port: targetPort,
        path: req.url,
        method: req.method,
        headers: headers
      };
      
      const proxyReq = https.request(options, (proxyRes) => {
        log('SUCCESS', `← ${proxyRes.statusCode} HTTPS ${req.method} ${hostname}${req.url}`);
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
      });
      
      proxyReq.on('error', (err) => {
        stats.errors++;
        log('ERROR', `HTTPS request error:`, err.message);
        res.writeHead(502);
        res.end('Bad Gateway');
      });
      
      req.pipe(proxyReq);
    });
    
    httpsServer.on('error', (err) => {
      stats.errors++;
      log('ERROR', `HTTPS server error:`, err.message);
      clientSocket.end();
    });
    
    httpsServer.emit('connection', clientSocket);
    
    if (head && head.length > 0) {
      clientSocket.unshift(head);
    }
    
    log('SUCCESS', `✓ HTTPS MITM established for ${hostname}:${targetPort}`);
  }

  // Create main proxy server
  const proxyServer = http.createServer(handleHttpRequest);
  proxyServer.on('connect', handleHttpsConnect);

  // Try to start server with port retry
  function startServer(port, attempt = 0) {
    if (attempt >= CONFIG.PORT_RETRY_MAX) {
      console.error(`\x1b[31m✗ Failed to start server: All ports ${CONFIG.PORT}-${CONFIG.PORT + CONFIG.PORT_RETRY_MAX - 1} are in use\x1b[0m`);
      process.exit(1);
      return;
    }
    
    const currentPort = port + attempt;
    
    proxyServer.listen(currentPort, '0.0.0.0', () => {
      CONFIG.PORT = currentPort;
      printBanner();
      
      setInterval(() => {
        if (stats.totalRequests > 0 && CONFIG.ENABLE_LOGGING) {
          log('INFO', `Stats: ${stats.totalRequests} total | ${stats.httpRequests} HTTP | ${stats.httpsRequests} HTTPS | ${stats.headersInjected} headers | ${stats.errors} errors`);
        }
      }, 60000);
    });
    
    proxyServer.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.log(`\x1b[33m!\x1b[0m Port ${currentPort} is in use, trying ${currentPort + 1}...\x1b[0m`);
        proxyServer.close();
        startServer(port, attempt + 1);
      } else {
        console.error(`\x1b[31m✗ Server error:\x1b[0m`, err.message);
        process.exit(1);
      }
    });
  }

  // Start server
  if (loadCA()) {
    startServer(CONFIG.PORT);
  }

  function printBanner() {
    console.clear();
    console.log('\x1b[36m╔═══════════════════════════════════════════════════════════════╗\x1b[0m');
    console.log('\x1b[36m║     SEB MITM Proxy - HTTPS Header Injection Enabled          ║\x1b[0m');
    console.log('\x1b[36m╚═══════════════════════════════════════════════════════════════╝\x1b[0m');
    console.log('');
    console.log(`  \x1b[32m✓\x1b[0m Server running on: \x1b[33mhttp://localhost:${CONFIG.PORT}\x1b[0m`);
    console.log(`  \x1b[32m✓\x1b[0m HTTP Proxy: \x1b[32mEnabled\x1b[0m (with header injection)`);
    console.log(`  \x1b[32m✓\x1b[0m HTTPS Proxy: \x1b[32mEnabled\x1b[0m (MITM with header injection)`);
    console.log('');
    console.log('  \x1b[36mHeaders injected into ALL requests:\x1b[0m');
    for (const [key, value] of Object.entries(CONFIG.HEADERS)) {
      console.log(`    \x1b[33m→\x1b[0m ${key}`);
      console.log(`      \x1b[90m${value}\x1b[0m`);
    }
    console.log('');
    console.log('  \x1b[36mConfigure SEB:\x1b[0m');
    console.log('    Network > Proxies > Use SEB proxy settings');
    console.log(`    \x1b[33m✓ HTTP:\x1b[0m  Host=127.0.0.1, Port=${CONFIG.PORT}`);
    console.log(`    \x1b[33m✓ HTTPS:\x1b[0m Host=127.0.0.1, Port=${CONFIG.PORT}`);
    console.log('');
    console.log('  \x1b[32m📥 Download certificate:\x1b[0m');
    console.log(`    \x1b[33mhttp://YOUR-RAILWAY-URL/cert\x1b[0m`);
    console.log('');
    
    if (CONFIG.PORT !== 8080) {
      console.log(`  \x1b[33m⚠ NOTE: Using port ${CONFIG.PORT} instead of 8080\x1b[0m`);
      console.log(`  \x1b[33m⚠ Update SEB config to use port ${CONFIG.PORT}\x1b[0m`);
      console.log('');
    }
    
    console.log('  \x1b[90mPress Ctrl+C to stop\x1b[0m');
    console.log('');
    console.log('─'.repeat(65));
    console.log('');
  }

  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n');
    log('WARNING', 'Shutting down...');
    console.log('');
    console.log('  Final Statistics:');
    console.log(`    Total Requests:    ${stats.totalRequests}`);
    console.log(`    HTTP Requests:     ${stats.httpRequests}`);
    console.log(`    HTTPS Requests:    ${stats.httpsRequests}`);
    console.log(`    Headers Injected:  ${stats.headersInjected}`);
    console.log(`    Errors:            ${stats.errors}`);
    console.log('');
    
    proxyServer.close(() => {
      log('SUCCESS', 'Server closed');
      process.exit(0);
    });
  });

