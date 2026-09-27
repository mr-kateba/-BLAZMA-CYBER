// The single choke point for every EXTERNAL network request Blazma makes.
// - Offline Mode blocks all requests before any socket is opened.
// - Every attempted request (allowed or blocked) is recorded in the Network Activity log,
//   describing WHAT kind of data was sent, never the secret values themselves.
// Modules must not call fetch()/https directly; they receive a gate instance.

export interface NetworkActivityEntry {
  id: string;
  timestamp: string;
  module: string;
  service: string;
  /** Host only, never full URLs (they may embed API keys or queried indicators). */
  host: string;
  /** i18n key describing the category of data sent, e.g. "privacy.data.ip_address". */
  dataKind: string;
  outcome: 'allowed' | 'blocked_offline' | 'error';
}

export interface GateRequest {
  module: string;
  service: string;
  url: string;
  dataKind: string;
  init?: RequestInit;
  timeoutMs?: number;
}

export class OfflineModeError extends Error {
  readonly code = 'offline_mode';
  constructor() {
    super('External requests are blocked because Offline Mode is enabled.');
  }
}

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export class NetworkGate {
  constructor(
    private readonly isOffline: () => boolean,
    private readonly record: (entry: NetworkActivityEntry) => void,
    private readonly fetchImpl: FetchLike = (u, i) => fetch(u, i),
    private readonly now: () => Date = () => new Date(),
  ) {}

  async request(req: GateRequest): Promise<Response> {
    const url = new URL(req.url);
    if (url.protocol !== 'https:') throw new Error('insecure_protocol');
    const base = {
      id: `${this.now().getTime()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: this.now().toISOString(),
      module: req.module,
      service: req.service,
      host: url.host,
      dataKind: req.dataKind,
    };

    if (this.isOffline()) {
      this.record({ ...base, outcome: 'blocked_offline' });
      throw new OfflineModeError();
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), req.timeoutMs ?? 15000);
    try {
      const res = await this.fetchImpl(url.toString(), { ...req.init, signal: controller.signal, redirect: 'error' });
      this.record({ ...base, outcome: 'allowed' });
      return res;
    } catch (err) {
      this.record({ ...base, outcome: 'error' });
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}
