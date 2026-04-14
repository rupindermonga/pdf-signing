/**
 * One-time script to generate a self-signed P12 certificate for PDF signing.
 * Run: node generate-cert.js
 */
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const pki = forge.pki;

console.log('Generating RSA key pair (2048-bit)...');
const keys = pki.rsa.generateKeyPair(2048);

console.log('Creating self-signed certificate...');
const cert = pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '01';

// Valid for 10 years
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

const attrs = [
  { name: 'commonName', value: 'SealForge PDF Signing' },
  { name: 'organizationName', value: 'Finel AI' },
  { name: 'countryName', value: 'CA' },
  { name: 'stateOrProvinceName', value: 'Ontario' },
  { name: 'localityName', value: 'Ottawa' },
];

cert.setSubject(attrs);
cert.setIssuer(attrs); // self-signed

cert.setExtensions([
  { name: 'basicConstraints', cA: false },
  {
    name: 'keyUsage',
    digitalSignature: true,
    nonRepudiation: true,
  },
  {
    name: 'extKeyUsage',
    emailProtection: true,
  },
  {
    name: 'subjectAltName',
    altNames: [{ type: 6, value: 'https://rupindermonga.github.io/pdf-signing/' }]
  },
]);

cert.sign(keys.privateKey, forge.md.sha256.create());

console.log('Packaging as P12 (PKCS#12)...');
const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], 'sealforge', {
  algorithm: '3des', // widely compatible
});
const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
const p12Buffer = Buffer.from(p12Der, 'binary');

const certDir = path.join(__dirname, 'cert');
if (!fs.existsSync(certDir)) fs.mkdirSync(certDir);

fs.writeFileSync(path.join(certDir, 'sealforge.p12'), p12Buffer);
console.log(`Certificate saved to cert/sealforge.p12`);
console.log(`Password: sealforge`);
console.log('Done. This certificate is valid for 10 years.');
