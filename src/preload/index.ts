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
    pickFolder: () => invoke('files:pickFolder'),
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
  quarantine: {
    list: () => invoke('quarantine:list'),
    add: (path, reason) => invoke('quarantine:add', path, reason),
    restore: (id) => invoke('quarantine:restore', id),
    restoreTo: (id) => invoke('quarantine:restoreTo', id),
    remove: (id) => invoke('quarantine:remove', id),
    rescan: (id, taskId) => invoke('quarantine:rescan', id, taskId),
  },
  defender: {
    scan: (kind, target, taskId) => invoke('defender:scan', kind, target, taskId),
    history: () => invoke('defender:history'),
  },
  yara: {
    engine: () => invoke('yara:engine'),
    pickEngine: () => invoke('yara:pickEngine'),
    clearEngine: () => invoke('yara:clearEngine'),
    rules: () => invoke('yara:rules'),
    validate: () => invoke('yara:validate'),
    setEnabled: (id, enabled) => invoke('yara:setEnabled', id, enabled),
    source: (id) => invoke('yara:source', id),
    save: (name, source) => invoke('yara:save', name, source),
    importFile: () => invoke('yara:importFile'),
    remove: (id) => invoke('yara:remove', id),
    scan: (target, recursive, taskId) => invoke('yara:scan', target, recursive, taskId),
  },
  intel: {
    ip: (ip, options) => invoke('intel:ip', ip, options),
    domain: (domain, options) => invoke('intel:domain', domain, options),
    reputation: (kind, value, services) => invoke('intel:reputation', kind, value, services),
  },
  secrets: {
    status: () => invoke('secrets:status'),
    set: (service, value) => invoke('secrets:set', service, value),
    remove: (service) => invoke('secrets:remove', service),
  },
};

contextBridge.exposeInMainWorld('blazma', api);
