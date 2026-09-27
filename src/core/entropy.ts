// Shannon entropy over bytes, used as ONE weak signal in file analysis.
// High entropy suggests compression/encryption/packing but is never, on its own,
// evidence that a file is malicious. The detection model combines it with other signals.

export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (const b of bytes) counts[b]!++;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy; // 0..8 bits per byte
}

/** Human label for an entropy value, for the UI. */
export function entropyLabel(entropy: number): 'low' | 'medium' | 'high' {
  if (entropy < 5.5) return 'low';
  if (entropy < 7.2) return 'medium';
  return 'high';
}
