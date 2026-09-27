// Incremental capture-file reader (pure): classic libpcap and pcapng, as written by Wireshark,
// dumpcap, tcpdump and Windows pktmon (etl2pcap writes pcapng).
//
// Data arrives in arbitrary chunks (a file stream), so the reader buffers partial records and
// returns packets as soon as they are complete. It never throws: a corrupt file sets `error` and
// stops, with the packets read so far still valid.

import { u16, u16le, u32, u32le } from './bytes';

export interface CapturedFrame {
  /** Milliseconds since the epoch. */
  ts: number;
  /** Length on the wire (may exceed data.length when the capture was truncated). */
  wireLength: number;
  linkType: number;
  data: Uint8Array;
}

const MAX_FRAME = 262_144;
const MAX_BLOCK = 16 * 1024 * 1024;

export type CaptureFormat = 'pcap' | 'pcapng';

export class CaptureReader {
  private buf: Uint8Array = new Uint8Array(0);
  private format: CaptureFormat | null = null;
  private le = true;
  private nano = false;
  private pcapLinkType = 1;
  /** pcapng interfaces: link type and timestamp resolution (units per second). */
  private ifaces: Array<{ linkType: number; tsPerSec: number }> = [];
  error: string | null = null;

  get detectedFormat(): CaptureFormat | null {
    return this.format;
  }

  push(chunk: Uint8Array): CapturedFrame[] {
    if (this.error) return [];
    if (this.buf.length === 0) this.buf = chunk;
    else {
      const merged = new Uint8Array(this.buf.length + chunk.length);
      merged.set(this.buf, 0);
      merged.set(chunk, this.buf.length);
      this.buf = merged;
    }
    const out: CapturedFrame[] = [];
    let off = 0;
    if (!this.format) {
      if (this.buf.length < 24) return out;
      const magic = u32(this.buf, 0);
      if (magic === 0x0a0d0d0a) this.format = 'pcapng';
      else if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d) {
        this.format = 'pcap';
        this.le = false;
        this.nano = magic === 0xa1b23c4d;
      } else if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) {
        this.format = 'pcap';
        this.le = true;
        this.nano = magic === 0x4d3cb2a1;
      } else {
        this.error = 'not_a_capture';
        return out;
      }
      if (this.format === 'pcap') {
        this.pcapLinkType = this.r32(20);
        off = 24;
      }
    }
    off = this.format === 'pcap' ? this.readPcap(off, out) : this.readPcapng(off, out);
    this.buf = off === 0 ? this.buf : this.buf.slice(off);
    return out;
  }

  private r16(i: number): number {
    return this.le ? u16le(this.buf, i) : u16(this.buf, i);
  }
  private r32(i: number): number {
    return this.le ? u32le(this.buf, i) : u32(this.buf, i);
  }

  private readPcap(off: number, out: CapturedFrame[]): number {
    while (this.buf.length - off >= 16) {
      const sec = this.r32(off);
      const frac = this.r32(off + 4);
      const incl = this.r32(off + 8);
      const orig = this.r32(off + 12);
      if (incl > MAX_FRAME) {
        this.error = 'corrupt_capture';
        return this.buf.length;
      }
      if (this.buf.length - off - 16 < incl) break;
      out.push({
        ts: sec * 1000 + (this.nano ? frac / 1e6 : frac / 1000),
        wireLength: orig || incl,
        linkType: this.pcapLinkType,
        data: this.buf.slice(off + 16, off + 16 + incl),
      });
      off += 16 + incl;
    }
    return off;
  }

  private readPcapng(off: number, out: CapturedFrame[]): number {
    while (this.buf.length - off >= 12) {
      // The Section Header Block carries the byte-order magic for everything that follows.
      if (u32(this.buf, off) === 0x0a0d0d0a) {
        const bom = u32(this.buf, off + 8);
        if (bom === 0x1a2b3c4d) this.le = false;
        else if (bom === 0x4d3c2b1a) this.le = true;
        else {
          this.error = 'corrupt_capture';
          return this.buf.length;
        }
        this.ifaces = [];
      }
      const type = this.r32(off);
      const len = this.r32(off + 4);
      if (len < 12 || len > MAX_BLOCK || len % 4 !== 0) {
        this.error = 'corrupt_capture';
        return this.buf.length;
      }
      if (this.buf.length - off < len) break;
      const body = off + 8;
      if (type === 1) this.readIdb(body, off + len - 4);
      else if (type === 6) this.readEpb(body, off + len - 4, out);
      else if (type === 3) {
        // Simple Packet Block: interface 0, no timestamp.
        const orig = this.r32(body);
        const iface = this.ifaces[0];
        const incl = Math.min(orig, len - 16, MAX_FRAME);
        if (iface && incl > 0) out.push({ ts: 0, wireLength: orig, linkType: iface.linkType, data: this.buf.slice(body + 4, body + 4 + incl) });
      }
      off += len;
    }
    return off;
  }

  private readIdb(body: number, end: number): void {
    const linkType = this.r16(body);
    let tsPerSec = 1e6;
    let o = body + 8;
    while (o + 4 <= end) {
      const code = this.r16(o);
      const olen = this.r16(o + 2);
      if (code === 0) break;
      if (code === 9 && olen >= 1) {
        const v = this.buf[o + 4] ?? 6;
        tsPerSec = v & 0x80 ? 2 ** (v & 0x7f) : 10 ** (v & 0x7f);
      }
      o += 4 + Math.ceil(olen / 4) * 4;
    }
    this.ifaces.push({ linkType, tsPerSec });
  }

  private readEpb(body: number, end: number, out: CapturedFrame[]): void {
    const iface = this.ifaces[this.r32(body)];
    if (!iface) return;
    const ts = this.r32(body + 4) * 2 ** 32 + this.r32(body + 8);
    const incl = this.r32(body + 12);
    const orig = this.r32(body + 16);
    const start = body + 20;
    if (incl > MAX_FRAME || start + incl > end) return;
    out.push({ ts: (ts / iface.tsPerSec) * 1000, wireLength: orig || incl, linkType: iface.linkType, data: this.buf.slice(start, start + incl) });
  }
}
