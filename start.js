/**
 * Production startup script.
 * Generates the P12 certificate if it doesn't exist, then starts the server.
 */
const fs = require('fs');
const path = require('path');

const certPath = path.join(__dirname, 'cert', 'docseal.p12');

if (!fs.existsSync(certPath)) {
  console.log('No P12 certificate found. Generating...');
  require('./generate-cert');
}

require('./server');
