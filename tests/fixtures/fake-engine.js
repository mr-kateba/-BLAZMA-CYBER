#!/usr/bin/env node
// TEST FIXTURE ONLY: a stand-in for an external recovery engine, used to verify BLAZMA's
// session orchestration (argument passing, progress parsing, result reveal, cleanup).
// It performs no recovery; it prints fixed hashcat-style status lines and a fixed result.
const a = process.argv.slice(2);
if (a.includes('--version')) { process.stdout.write('6.2.6\n'); process.exit(0); }
if (a.includes('--show')) { process.stdout.write('target:REVEALED-SECRET:x\n'); process.exit(0); }
let n = 0;
const i = setInterval(() => {
  n++;
  process.stdout.write(JSON.stringify({ progress: [n * 1000, 3000], devices: [{ speed: 500 }], recovered_hashes: [n >= 3 ? 1 : 0, 1] }) + '\n');
  if (n >= 3) { clearInterval(i); process.exit(0); }
}, 30);
