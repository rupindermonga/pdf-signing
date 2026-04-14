// ─── RFC 3161 Timestamp Authority (TSA) client ───
//
// Requests a cryptographic timestamp token over a SHA-256 hash so that the
// signed document can be verified as having existed at a given time even
// after the signing certificate expires. This is the foundation for
// eIDAS "Advanced Electronic Signature" long-term validation (LTV).
//
// Public TSAs that work out of the box:
//   - https://freetsa.org/tsr                  (no charge, no auth)
//   - https://timestamp.digicert.com           (no charge, no auth)
//   - https://rfc3161timestamp.globalsign.com/advanced
//   - http://timestamp.apple.com/ts01
//
// Verify a .tst file offline with:
//   openssl ts -verify -data <pdf> -in <pdf>.tst -CAfile <tsa-root.pem>

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const forge = require('node-forge');

const TSA_URL = process.env.TSA_URL || '';
const TSA_TIMEOUT_MS = parseInt(process.env.TSA_TIMEOUT_MS || '10000', 10);

function isConfigured() {
  return !!TSA_URL;
}

// Build an RFC 3161 TimeStampReq ASN.1 structure for a sha-256 message imprint.
function buildTimestampRequest(sha256HashBuf) {
  const asn1 = forge.asn1;
  // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
  const messageImprint = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // sha-256 OID 2.16.840.1.101.3.4.2.1
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes()),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
    ]),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, sha256HashBuf.toString('binary')),
  ]);
  // nonce: 8 random bytes as INTEGER (prevents replay)
  const nonceBuf = crypto.randomBytes(8);
  // Strip leading zero-bytes so INTEGER is minimal (but keep one byte if all zero)
  let nonceBytes = nonceBuf;
  // Ensure positive: if high bit set, prepend 0x00
  if (nonceBytes[0] & 0x80) nonceBytes = Buffer.concat([Buffer.from([0]), nonceBytes]);

  const timeStampReq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version INTEGER { v1(1) }
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, String.fromCharCode(1)),
    messageImprint,
    // nonce INTEGER
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, nonceBytes.toString('binary')),
    // certReq BOOLEAN (request that signing certs be returned in the token)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BOOLEAN, false, String.fromCharCode(0xFF)),
  ]);
  return Buffer.from(asn1.toDer(timeStampReq).getBytes(), 'binary');
}

// Parse the TimeStampResp and return { token: Buffer, genTime: Date|null }
function parseTimestampResponse(bodyBuf) {
  const asn1 = forge.asn1;
  const resp = asn1.fromDer(forge.util.createBuffer(bodyBuf.toString('binary')));
  // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
  if (!resp.value || !resp.value.length) throw new Error('empty TSA response');
  const statusInfo = resp.value[0];
  const statusInt = statusInfo.value[0].value;
  const statusCode = typeof statusInt === 'string' ? statusInt.charCodeAt(0) : 0;
  // 0 = granted, 1 = grantedWithMods, 2 = rejection, 3 = waiting, 4 = revWarning, 5 = revNotification
  if (statusCode !== 0 && statusCode !== 1) {
    throw new Error(`TSA status ${statusCode} (request not granted)`);
  }
  if (resp.value.length < 2) throw new Error('TSA response missing token');
  const tokenNode = resp.value[1]; // ContentInfo (SignedData wrapper)
  const tokenDer = Buffer.from(asn1.toDer(tokenNode).getBytes(), 'binary');

  // Best-effort extraction of genTime from TSTInfo for display purposes.
  // The ContentInfo carries a SignedData whose eContent is TSTInfo (GeneralizedTime at index 4).
  let genTime = null;
  try {
    const signedData = tokenNode.value[1].value[0]; // [0] explicit → SignedData
    const encap = signedData.value[2];              // encapContentInfo
    const eContent = encap.value[1].value[0];       // OCTET STRING → TSTInfo DER
    const tstBytes = eContent.value;
    const tst = asn1.fromDer(forge.util.createBuffer(typeof tstBytes === 'string' ? tstBytes : ''));
    // TSTInfo fields: version, policy, messageImprint, serialNumber, genTime, [accuracy], [ordering]...
    for (const child of tst.value) {
      if (child.type === asn1.Type.GENERALIZEDTIME) {
        const s = typeof child.value === 'string' ? child.value : '';
        // GeneralizedTime e.g. 20260413083015Z
        const m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
        if (m) genTime = new Date(Date.UTC(+m[1], +m[2]-1, +m[3], +m[4], +m[5], +m[6]));
        break;
      }
    }
  } catch { /* genTime is best-effort; not fatal */ }

  return { token: tokenDer, genTime };
}

// Request a timestamp token from TSA_URL for a sha-256 hash buffer.
// Returns { token: Buffer (RFC 3161 TimeStampToken DER), genTime: Date|null, tsaUrl: string }
async function requestTimestamp(sha256HashBuf) {
  // Validate input first so programming errors surface consistently regardless
  // of whether TSA_URL happens to be configured.
  if (!Buffer.isBuffer(sha256HashBuf) || sha256HashBuf.length !== 32) {
    throw new Error('sha256 hash buffer (32 bytes) required');
  }
  if (!isConfigured()) throw new Error('TSA_URL is not configured');
  const reqDer = buildTimestampRequest(sha256HashBuf);
  const url = new URL(TSA_URL);
  const mod = url.protocol === 'https:' ? https : http;
  const opts = {
    method: 'POST',
    hostname: url.hostname,
    port: url.port || (url.protocol === 'https:' ? 443 : 80),
    path: url.pathname + (url.search || ''),
    headers: {
      'Content-Type': 'application/timestamp-query',
      'Content-Length': reqDer.length,
      'User-Agent': 'SealForge-TSA/1.0',
    },
    timeout: TSA_TIMEOUT_MS,
  };
  return new Promise((resolve, reject) => {
    const r = mod.request(opts, (resp) => {
      const chunks = [];
      resp.on('data', c => chunks.push(c));
      resp.on('end', () => {
        if (resp.statusCode !== 200) {
          return reject(new Error(`TSA HTTP ${resp.statusCode}`));
        }
        try {
          const parsed = parseTimestampResponse(Buffer.concat(chunks));
          resolve({ ...parsed, tsaUrl: TSA_URL });
        } catch (e) { reject(e); }
      });
    });
    r.on('error', reject);
    r.on('timeout', () => { r.destroy(); reject(new Error('TSA request timed out')); });
    r.write(reqDer);
    r.end();
  });
}

module.exports = { isConfigured, requestTimestamp, TSA_URL };
