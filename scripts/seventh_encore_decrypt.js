const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const MAGIC = Buffer.from('ORPHEUS-CAL-V1\0', 'binary');

const calibrationPath = process.argv[2];
if (!calibrationPath) {
  console.error('Usage: node decrypt.js <calibration.dat>');
  console.error('Example: node decrypt.js production-runner/npm-cache/.../package/calibration.dat');
  process.exit(1);
}

const blob = fs.readFileSync(calibrationPath);

if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) {
  console.error('Error: invalid calibration.dat (bad magic bytes)');
  process.exit(1);
}

const iv = blob.subarray(MAGIC.length, MAGIC.length + 16);
const data = blob.subarray(MAGIC.length + 16);

const trustedIntegrity = 'sha512-NgcsiI4YMhRDtXH2phJaxed4PtfJmjSadYpjNd5dghy/GpLy9n+SPsQqKNrfnje2OIBmm+nnelheFvzYepOc+Q==';
const key = crypto.createHash('sha256').update(trustedIntegrity, 'utf8').digest();

const dec = crypto.createDecipheriv('aes-256-ctr', key, iv);
const plaintext = Buffer.concat([dec.update(data), dec.final()]).toString('utf8');

const message = JSON.parse(plaintext);
console.log(JSON.stringify(message, null, 2));
console.log('\nFlag:', message.message);
