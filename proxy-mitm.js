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
  const pino = require('pino');

  // ===== OPTIMIZATION 1: Pino Async Logger =====
  const isProd = process.env.NODE_ENV === 'production';
  const logger = pino({
    level: process.env.LOG_LEVEL || (isProd ? 'warn' : 'info'),
    // In production: use fast JSON output (no pretty printing)
    ...(isProd ? {} : {
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:yyyy-mm-dd HH:MM:ss.l',
          ignore: 'pid,hostname'
        }
      }
    })
  });

  // ===== OPTIMIZATION 2: Keep-Alive Agents for Connection Reuse =====
  const httpAgent = new http.Agent({
    keepAlive: true,
    maxSockets: 100,
    keepAliveMsecs: 10000,
    maxFreeSockets: 10
  });

  const httpsAgent = new https.Agent({
    keepAlive: true,
    maxSockets: 100,
    keepAliveMsecs: 10000,
    maxFreeSockets: 10
  });

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
    ],
    // Performance optimization
    CERT_CACHE_MAX_SIZE: 50,        // Max 50 certs (enough for most use cases)
    CERT_CACHE_TTL: 86400000,       // 24 hours (1 day) - long enough for exam sessions
    LOG_ONLY_WHITELISTED: true,     // Only log whitelisted domains
    DISABLE_TCP_TUNNEL_LOGS: true   // Don't log TCP tunnel connections
  };

  // Check if domain should get header injection
  function shouldInjectHeaders(hostname, urlPath = '') {
    if (!hostname) return false;
    
    // Skip header injection for static files (CSS, JS, images, fonts, etc.)
    // These don't need headers and can use simple TCP tunnel (saves 80% CPU!)
    const staticFileExtensions = [
      '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', 
      '.ico', '.woff', '.woff2', '.ttf', '.eot', '.otf',
      '.mp4', '.webm', '.mp3', '.wav', '.pdf', '.zip'
    ];
    
    if (urlPath && staticFileExtensions.some(ext => urlPath.toLowerCase().endsWith(ext))) {
      return false; // Don't inject headers for static files
    }
    
    // Exact match or subdomain match
    return CONFIG.ALLOWED_DOMAINS.some(domain => 
      hostname === domain || hostname.endsWith('.' + domain)
    );
  }

  // Paths
  const CERT_DIR = path.join(__dirname, 'certs');
  const CA_KEY_FILE = path.join(CERT_DIR, 'ca-key.pem');
  const CA_CERT_FILE = path.join(CERT_DIR, 'ca-cert.pem');

  // Certificate cache with TTL and size limit
  const certCache = new Map();
  const certCacheTimes = new Map();
  let caKey, caCert;

// Statistics
const stats = {
  totalRequests: 0,
  httpRequests: 0,
  httpsRequests: 0,
  headersInjected: 0,
  getRequestsBypassed: 0,  // GET requests không inject headers
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

  // Clean expired certificates from cache
  function cleanCertCache() {
    const now = Date.now();
    const toDelete = [];
    
    for (const [hostname, timestamp] of certCacheTimes.entries()) {
      if (now - timestamp > CONFIG.CERT_CACHE_TTL) {
        toDelete.push(hostname);
      }
    }
    
    toDelete.forEach(hostname => {
      certCache.delete(hostname);
      certCacheTimes.delete(hostname);
    });
    
    // If cache is still too big, remove oldest entries
    if (certCache.size > CONFIG.CERT_CACHE_MAX_SIZE) {
      const entries = Array.from(certCacheTimes.entries())
        .sort((a, b) => a[1] - b[1]);
      
      const toRemove = entries.slice(0, certCache.size - CONFIG.CERT_CACHE_MAX_SIZE);
      toRemove.forEach(([hostname]) => {
        certCache.delete(hostname);
        certCacheTimes.delete(hostname);
      });
    }
  }

  // Load or generate persistent certificate for a domain
  function loadOrGeneratePersistentCert(hostname) {
    const certFile = path.join(CERT_DIR, `${hostname}.pem`);
    const keyFile = path.join(CERT_DIR, `${hostname}-key.pem`);
    
    // Try to load existing cert from disk
    if (fs.existsSync(certFile) && fs.existsSync(keyFile)) {
      try {
        const certificate = fs.readFileSync(certFile, 'utf8');
        const privateKey = fs.readFileSync(keyFile, 'utf8');
        
        log('SUCCESS', `📁 Loaded persistent cert for ${hostname}`);
        return { privateKey, certificate };
      } catch (err) {
        log('ERROR', `Failed to load cert for ${hostname}:`, err.message);
      }
    }
    
    // Generate new cert if not exists
    try {
      log('INFO', `🔨 Generating persistent cert for ${hostname}...`);
      
      const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });
      const cert = forge.pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = '01'; // Fixed serial number for consistency
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10); // Valid for 10 years!
      
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
      
      // Save to disk for persistence
      fs.writeFileSync(keyFile, pem.privateKey);
      fs.writeFileSync(certFile, pem.certificate);
      
      log('SUCCESS', `💾 Saved persistent cert for ${hostname} (valid 10 years)`);
      
      return pem;
    } catch (err) {
      log('ERROR', `Failed to generate cert for ${hostname}:`, err.message);
      return null;
    }
  }

  // Generate certificate for domain (with persistent storage)
  function generateCertificate(hostname) {
    // Check memory cache first (fastest)
    if (certCache.has(hostname)) {
      return certCache.get(hostname);
    }
    
    // Load or generate persistent cert
    const pem = loadOrGeneratePersistentCert(hostname);
    
    if (pem) {
      // Add to memory cache (no TTL needed - cert is persistent)
      certCache.set(hostname, pem);
      certCacheTimes.set(hostname, Date.now());
    }
    
    return pem;
  }

  // Optimized async logging with Pino
  function log(type, message, data = '', hostname = '') {
    if (!CONFIG.ENABLE_LOGGING) return;
    
    // Skip logging for TCP tunnels if configured
    if (CONFIG.DISABLE_TCP_TUNNEL_LOGS && message.includes('TCP TUNNEL')) {
      return;
    }
    
    // Only log whitelisted domains if configured
    if (CONFIG.LOG_ONLY_WHITELISTED && hostname && !shouldInjectHeaders(hostname)) {
      return;
    }
    
    // Map type to pino log levels
    const levelMap = {
      'INFO': 'info',
      'SUCCESS': 'info',
      'ERROR': 'error',
      'WARNING': 'warn'
    };
    
    const level = levelMap[type] || 'info';
    const logData = {
      msg: message,
      ...(hostname && { hostname }),
      ...(data && { data })
    };
    
    logger[level](logData);
  }

// Inject headers (only for whitelisted domains and non-GET requests)
function injectHeaders(headers, hostname, urlPath = '', method = 'GET') {
  const injected = { ...headers };
  
  // ===== OPTIMIZATION: Skip GET requests only - kệ nó luôn! =====
  if (method === 'GET') {
    stats.getRequestsBypassed++;
    return injected; // GET không cần headers, cho đi thẳng
  }
  
  // Only inject headers for whitelisted domains and non-static files
  if (!shouldInjectHeaders(hostname, urlPath)) {
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
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="utf-8">
    <title>SEB Server</title>
    <style>
      body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;max-width:500px;margin:100px auto;padding:40px;background:#f5f5f5}
      .c{background:#fff;border-radius:12px;padding:40px;box-shadow:0 2px 10px rgba(0,0,0,.1)}
      h1{color:#2c3e50;margin-bottom:10px;font-size:28px}
      .s{color:#7f8c8d;margin-bottom:30px;font-size:13px}
      .d{background:#e8f5e9;border-left:4px solid #4caf50;padding:20px;border-radius:8px;margin:25px 0}
      .dt{font-weight:600;color:#2e7d32;font-size:15px;margin-bottom:12px}
      .dl{display:inline-block;background:#4caf50;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:500;transition:background .3s}
      .dl:hover{background:#45a049}
    </style>
  </head>
  <body>
    <div class="c">
      <h1>🔒 SEB Server</h1>
      <div class="s">For Safe Exam Browser</div>
      <div class="d">
        <div class="dt">📥 Download Certificate</div>
        <a href="/cert" class="dl">Download CA Certificate</a>
      </div>
    </div>
  </body>
  </html>
      `);
      return;
    }
    
    const parsedUrl = new URL(req.url);
    
    log('INFO', `→ HTTP ${req.method} ${req.url}`, '', parsedUrl.hostname);
    
    const headers = injectHeaders(req.headers, parsedUrl.hostname, parsedUrl.pathname, req.method);
    delete headers['proxy-connection'];
    
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 80,
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: headers,
      agent: httpAgent  // Keep-Alive agent for connection reuse
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
    
    log('INFO', `→ HTTPS CONNECT ${hostname}:${targetPort}`, '', hostname);
    
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
      log('INFO', `→ HTTPS ${req.method} ${targetUrl}`, '', hostname);
      
      const headers = injectHeaders(req.headers, hostname, req.url, req.method);
      delete headers['proxy-connection'];
      
      const options = {
        hostname: hostname,
        port: targetPort,
        path: req.url,
        method: req.method,
        headers: headers,
        agent: httpsAgent  // Keep-Alive agent for connection reuse
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
          log('INFO', `Stats: ${stats.totalRequests} total | ${stats.httpRequests} HTTP | ${stats.httpsRequests} HTTPS | ${stats.headersInjected} headers | ${stats.getRequestsBypassed} GET bypassed | ${stats.errors} errors`);
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
    if (isProd) {
      // Production: Compact banner
      console.log('\x1b[32m✓\x1b[0m SEB Proxy Server');
      console.log(`\x1b[32m✓\x1b[0m Port: \x1b[33m${CONFIG.PORT}\x1b[0m | Cert: \x1b[33m/cert\x1b[0m`);
      console.log(`\x1b[32m✓\x1b[0m Optimized: Keep-Alive, Static Skip, Async Logging`);
    } else {
      // Development: Full banner
      console.clear();
      console.log('\x1b[36m╔════════════════════════════════════════╗\x1b[0m');
      console.log('\x1b[36m║    SEB Proxy - Header Injection       ║\x1b[0m');
      console.log('\x1b[36m╚════════════════════════════════════════╝\x1b[0m');
      console.log('');
      console.log(`  \x1b[32m✓\x1b[0m Port: \x1b[33m${CONFIG.PORT}\x1b[0m`);
      console.log(`  \x1b[32m✓\x1b[0m HTTP/HTTPS Proxy: \x1b[32mEnabled\x1b[0m`);
      console.log(`  \x1b[32m✓\x1b[0m Certificate: \x1b[33m/cert\x1b[0m`);
      console.log('');
      console.log('  \x1b[36mTargets:\x1b[0m ' + CONFIG.ALLOWED_DOMAINS.join(', '));
      console.log('  \x1b[90mPress Ctrl+C to stop\x1b[0m');
      console.log('');
    }
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
    console.log(`    GET Bypassed:      ${stats.getRequestsBypassed}`);
    console.log(`    Errors:            ${stats.errors}`);
    console.log('');
    
    // Cleanup Keep-Alive agents
    httpAgent.destroy();
    httpsAgent.destroy();
    
    proxyServer.close(() => {
      log('SUCCESS', 'Server closed');
      process.exit(0);
    });
  });

