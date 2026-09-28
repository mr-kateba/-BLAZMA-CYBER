// Decodes a QR code from image bytes inside the sandboxed renderer (Chromium's image decoders + jsQR).
// The image was size- and dimension-checked by the main process before it got here.

import jsQR from 'jsqr';

/** Returns the decoded text, or null when no QR code was found. */
export async function decodeQr(bytes: Uint8Array): Promise<string | null> {
  const bitmap = await createImageBitmap(new Blob([bytes as Uint8Array<ArrayBuffer>]));
  try {
    // Photos are large: try a fast downscaled pass first, then a sharper one.
    for (const maxSide of [1200, 2400, 4000]) {
      const scale = Math.min(1, maxSide / Math.max(bitmap.width, bitmap.height));
      const w = Math.max(1, Math.round(bitmap.width * scale));
      const h = Math.max(1, Math.round(bitmap.height * scale));
      const canvas = new OffscreenCanvas(w, h);
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      if (!ctx) return null;
      // Transparent pixels would read as black: put the image on white first.
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, w, h);
      ctx.drawImage(bitmap, 0, 0, w, h);
      const found = jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'attemptBoth' });
      if (found) return found.data;
      if (scale === 1) break;
    }
    return null;
  } finally {
    bitmap.close();
  }
}
