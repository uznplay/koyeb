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
      if (code === 0) {
        // Wait a bit for file to be flushed to disk
        setTimeout(() => {
          if (fs.existsSync(certPath)) {
            const keyPath = path.join(__dirname, 'certs', 'ca-key.pem');
            if (fs.existsSync(keyPath)) {
              console.log('✅ Certificate ready and verified');
              resolve(true);
            } else {
              console.error('❌ Certificate key not found!');
              reject(new Error('Certificate key not found'));
            }
          } else {
            console.error('❌ Certificate not found after generation!');
            reject(new Error('Certificate not found'));
          }
        }, 1000); // Wait 1 second for file flush
      } else {
        console.error('❌ Certificate generation failed with code:', code);
        reject(new Error(`Certificate generation failed with code ${code}`));
      }
    });
    
    setup.on('error', (err) => {
      console.error('❌ Certificate generation error:', err.message);
      reject(err);
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
    // Always check both cert and key
    const keyPath = path.join(__dirname, 'certs', 'ca-key.pem');
    const certExists = fs.existsSync(certPath);
    const keyExists = fs.existsSync(keyPath);
    
    if (!certExists || !keyExists) {
      console.log('🔑 Generating certificates...');
      await generateCertificate();
    } else {
      console.log('✅ Certificates already exist');
    }
    
    // Double-check before starting proxy
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
      throw new Error('Certificates not found after generation!');
    }
    
    startProxy();
  } catch (err) {
    console.error('');
    console.error('═══════════════════════════════════════════════════════════════');
    console.error('❌ FATAL ERROR:', err.message);
    console.error('═══════════════════════════════════════════════════════════════');
    console.error('');
    process.exit(1);
  }
}

main();
