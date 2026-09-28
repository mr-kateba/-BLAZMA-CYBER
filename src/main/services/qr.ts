// QR check: the main process only reads the image bytes (size-limited, image signature checked) or the
// clipboard image. Decoding happens in the sandboxed renderer; the decoded text is classified by
// src/core/qr-content.ts. Nothing in the code is opened or looked up automatically.

import { readFile, stat } from 'node:fs/promises';
import { imageSize } from '../../core/image-size';
import { validateAbsolutePath } from '../../core/validation';

export class QrError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export const MAX_QR_IMAGE_BYTES = 20 * 1024 * 1024;
/** Larger bitmaps are refused before decoding (a small file can expand to gigabytes). */
export const MAX_QR_PIXELS = 50_000_000;

/** Throws when the image is not a supported format or would decode to an oversized bitmap. */
export function checkQrImage(bytes: Uint8Array): void {
  if (!isSupportedImage(bytes)) throw new QrError('qr_not_image');
  const size = imageSize(bytes);
  if (!size || size.width === 0 || size.height === 0) throw new QrError('qr_not_image');
  if (size.width * size.height > MAX_QR_PIXELS) throw new QrError('qr_image_too_large');
}

/** PNG, JPEG, GIF, BMP or WebP by signature (the extension is not trusted). */
export function isSupportedImage(b: Uint8Array): boolean {
  const at = (i: number, bytes: number[]) => bytes.every((x, j) => b[i + j] === x);
  return (
    at(0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) ||
    at(0, [0xff, 0xd8, 0xff]) ||
    at(0, [0x47, 0x49, 0x46, 0x38]) ||
    at(0, [0x42, 0x4d]) ||
    (at(0, [0x52, 0x49, 0x46, 0x46]) && at(8, [0x57, 0x45, 0x42, 0x50]))
  );
}

export async function readQrImage(rawPath: unknown): Promise<Uint8Array> {
  const v = validateAbsolutePath(rawPath);
  if (!v.ok) throw new QrError(v.reason);
  const st = await stat(v.path).catch(() => null);
  if (!st || !st.isFile()) throw new QrError('file_not_found');
  if (st.size > MAX_QR_IMAGE_BYTES) throw new QrError('qr_image_too_large');
  const bytes = await readFile(v.path);
  checkQrImage(bytes);
  return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}
