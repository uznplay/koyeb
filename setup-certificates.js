/**
 * Generate CA Certificate for MITM Proxy
 */

const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const CERT_DIR = path.join(__dirname, 'certs');
const CA_KEY_FILE = path.join(CERT_DIR, 'ca-key.pem');
const CA_CERT_FILE = path.join(CERT_DIR, 'ca-cert.pem');

console.log('');
console.log('Generating CA certificate...');
console.log('');

// Create certs directory if not exists
if (!fs.existsSync(CERT_DIR)) {
  console.log('Creating certs directory...');
  fs.mkdirSync(CERT_DIR, { recursive: true });
  console.log('✓ Directory created:', CERT_DIR);
}

try {
  // Generate key pair
  console.log('Generating RSA key pair (2048 bits)...');
  const keys = forge.pki.rsa.generateKeyPair(2048);
  console.log('✓ CA Private Key generated');
  
  // Create certificate
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
  
  const attrs = [
    { name: 'commonName', value: 'SEB-MITM-Proxy-CA' },
    { name: 'countryName', value: 'US' },
    { shortName: 'ST', value: 'California' },
    { name: 'localityName', value: 'San Francisco' },
    { name: 'organizationName', value: 'SEB MITM Proxy' },
    { shortName: 'OU', value: 'Certificate Authority' }
  ];
  
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  
  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: true
    },
    {
      name: 'keyUsage',
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
      codeSigning: true,
      emailProtection: true,
      timeStamping: true
    },
    {
      name: 'nsCertType',
      sslCA: true,
      emailCA: true,
      objCA: true
    },
    {
      name: 'subjectKeyIdentifier'
    }
  ]);
  
  // Self-sign certificate
  cert.sign(keys.privateKey, forge.md.sha256.create());
  console.log('✓ CA Certificate generated');
  
  // Convert to PEM format
  const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const certPem = forge.pki.certificateToPem(cert);
  
  // Save to files
  fs.writeFileSync(CA_KEY_FILE, privateKeyPem, 'utf8');
  console.log('✓ Saved to', CA_KEY_FILE);
  
  fs.writeFileSync(CA_CERT_FILE, certPem, 'utf8');
  console.log('✓ Saved to', CA_CERT_FILE);
  
  console.log('');
  console.log('✅ CA Certificate generation completed!');
  console.log('');
  console.log('Files created:');
  console.log('  - Private Key:', CA_KEY_FILE);
  console.log('  - Certificate:', CA_CERT_FILE);
  console.log('');
  
  // Verify files exist
  if (fs.existsSync(CA_KEY_FILE) && fs.existsSync(CA_CERT_FILE)) {
    const keySize = fs.statSync(CA_KEY_FILE).size;
    const certSize = fs.statSync(CA_CERT_FILE).size;
    console.log('File sizes:');
    console.log('  - Private Key:', keySize, 'bytes');
    console.log('  - Certificate:', certSize, 'bytes');
    console.log('');
    
    if (keySize > 0 && certSize > 0) {
      console.log('✓ Verification: Both files created successfully!');
      console.log('');
      process.exit(0);
    } else {
      console.error('❌ Error: Files are empty!');
      process.exit(1);
    }
  } else {
    console.error('❌ Error: Files were not created!');
    process.exit(1);
  }
  
} catch (err) {
  console.error('');
  console.error('❌ Error generating CA certificate:');
  console.error(err);
  console.error('');
  process.exit(1);
}

