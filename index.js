/**
 * Entry Point for Fly.io
 * Generate certificate then start proxy
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;

console.log('🚀 SEB Proxy Starting on Fly.io...');
console.log('📍 Port:', PORT);

// Check if certificate exists
const certPath = path.join(__dirname, 'certs', 'ca-cert.pem');

function generateCertificate() {
  return new Promise((resolve, reject) => {
    console.log('📜 Generating certificate...');
    
    const setup = spawn('node', ['setup-certificates.js'], {
      stdio: 'inherit'
    });
    
    setup.on('close', (code) => {
      if (code === 0 || fs.existsSync(certPath)) {
        console.log('✅ Certificate ready');
        resolve();
      } else {
        console.warn('⚠️ Certificate generation failed, will retry at runtime');
        // Don't fail, just continue
        resolve();
      }
    });
    
    setup.on('error', (err) => {
      console.warn('⚠️ Certificate generation error:', err.message);
      // Don't fail, just continue
      resolve();
    });
  });
}

function startProxy() {
  console.log('🔥 Starting proxy server...');
  
  const proxy = spawn('node', ['proxy-mitm.js'], {
    stdio: 'inherit',
    env: {
      ...process.env,
      PORT: PORT
    }
  });
  
  proxy.on('error', (err) => {
    console.error('❌ Proxy error:', err);
    process.exit(1);
  });
  
  proxy.on('close', (code) => {
    console.log('⚠️ Proxy exited with code:', code);
    process.exit(code || 0);
  });
  
  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('📴 Shutting down gracefully...');
    proxy.kill('SIGTERM');
    setTimeout(() => process.exit(0), 5000);
  });
  
  process.on('SIGINT', () => {
    console.log('📴 Shutting down...');
    proxy.kill('SIGINT');
    setTimeout(() => process.exit(0), 1000);
  });
}

async function main() {
  try {
    if (!fs.existsSync(certPath)) {
      await generateCertificate();
    } else {
      console.log('✅ Certificate already exists');
    }
    
    startProxy();
  } catch (err) {
    console.error('❌ Fatal error:', err);
    process.exit(1);
  }
}

main();
