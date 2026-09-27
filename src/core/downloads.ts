// Downloads watcher helpers (pure): which files in the Downloads folder are finished downloads.

/** Browsers write to a temporary name first and rename when the download completes. */
const PARTIAL = /\.(crdownload|part|partial|download|opdownload|tmp|temp|!ut|aria2)$/i;
const IGNORED = /^(desktop\.ini|thumbs\.db|\.ds_store|~\$.*|\..*)$/i;

export function isFinishedDownloadName(name: string): boolean {
  return name.length > 0 && name.length <= 255 && !PARTIAL.test(name) && !IGNORED.test(name) && !name.includes('Zone.Identifier');
}

export interface DownloadEvent {
  id: string;
  path: string;
  name: string;
  at: string;
  status: 'queued' | 'analyzing' | 'done' | 'failed';
  verdict?: 'no_detections' | 'unknown' | 'suspicious' | 'malicious';
  /** Number of reasons behind the verdict. */
  reasons?: number;
  error?: string;
}

export interface DownloadsWatchState {
  enabled: boolean;
  /** true while the folder is actually being watched (false e.g. when it does not exist). */
  watching: boolean;
  folder: string | null;
  error: string | null;
  recent: DownloadEvent[];
}
