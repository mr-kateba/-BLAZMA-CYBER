#!/usr/bin/env node
// TEST FIXTURE ONLY: a stand-in for John's *2john hash extractor. It reads no real archive; it
// prints one fixed hashcat-compatible ZIP hash line (login prefix + $zip2$… token).
process.stdout.write('target.zip:$zip2$*0*3*0*abc*def*0*0*0*$/zip2$::target.zip\n');
process.exit(0);
