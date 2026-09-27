// Sandboxed preload: the ONLY bridge between the UI and the backend.
// It exposes a fixed, typed set of functions. No ipcRenderer, no Node APIs leak to the page.
import { contextBridge, ipcRenderer, webUtils } from 'electron';
import type { BlazmaApi, TaskProgress } from '../shared/api';

const invoke = (channel: string, ...args: unknown[]) => ipcRenderer.invoke(channel, ...args);

const api: BlazmaApi = {
  app: {
    info: () => invoke('app:info'),
    openDataFolder: () => invoke('app:openDataFolder'),
  },
  settings: {
    get: () => invoke('settings:get'),
    update: (patch) => invoke('settings:update', patch),
  },
  system: {
    snapshot: () => invoke('system:snapshot'),
    security: () => invoke('system:security'),
  },
  files: {
    pathForFile: (file) => webUtils.getPathForFile(file),
    pickFile: () => invoke('files:pick'),
    analyze: (path, taskId) => invoke('files:analyze', path, taskId),
    hash: (path, taskId) => invoke('files:hash', path, taskId),
    cancel: (taskId) => invoke('files:cancel', taskId),
    onProgress: (cb) => {
      const listener = (_e: unknown, p: TaskProgress) => cb(p);
      ipcRenderer.on('files:progress', listener);
      return () => ipcRenderer.removeListener('files:progress', listener);
    },
  },
  hashlab: {
    hashText: (text) => invoke('hashlab:hashText', text),
    identify: (value) => invoke('hashlab:identify', value),
  },
  privacy: {
    networkActivity: () => invoke('privacy:networkActivity'),
    clear: (target) => invoke('privacy:clear', target),
    publicIp: () => invoke('privacy:publicIp'),
  },
  activity: {
    recent: (limit) => invoke('activity:recent', limit),
  },
  secrets: {
    status: () => invoke('secrets:status'),
    set: (service, value) => invoke('secrets:set', service, value),
    remove: (service) => invoke('secrets:remove', service),
  },
};

contextBridge.exposeInMainWorld('blazma', api);
