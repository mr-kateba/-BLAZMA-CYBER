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
  osint: {
    lookup: (type, value, options) => invoke('osint:lookup', type, value, options),
    openPivot: (type, value, pivotId) => invoke('osint:openPivot', type, value, pivotId),
  },
  intel: {
    ip: (ip, options) => invoke('intel:ip', ip, options),
    domain: (domain, options) => invoke('intel:domain', domain, options),
    reputation: (kind, value, services) => invoke('intel:reputation', kind, value, services),
  },
  forensics: {
    collect: (module) => invoke('forensics:collect', module),
    events: (log, levels, max) => invoke('forensics:events', log, levels, max),
    signatures: (paths, taskId) => invoke('forensics:signatures', paths, taskId),
    powershellHistory: () => invoke('forensics:psHistory'),
  },
  cases: {
    list: () => invoke('cases:list'),
    get: (id) => invoke('cases:get', id),
    create: (name, description, tags) => invoke('cases:create', name, description, tags),
    update: (id, patch) => invoke('cases:update', id, patch),
    remove: (id) => invoke('cases:remove', id),
    addEvidence: (id, ev) => invoke('cases:addEvidence', id, ev),
    removeEvidence: (id, evId) => invoke('cases:removeEvidence', id, evId),
    addNote: (id, text) => invoke('cases:addNote', id, text),
    updateNote: (id, noteId, text) => invoke('cases:updateNote', id, noteId, text),
    removeNote: (id, noteId) => invoke('cases:removeNote', id, noteId),
    addEvent: (id, title, detail, time) => invoke('cases:addEvent', id, title, detail, time),
  },
  reports: {
    generate: (caseId, options) => invoke('reports:generate', caseId, options),
    list: () => invoke('reports:list'),
    open: (id) => invoke('reports:open', id),
    reveal: (id) => invoke('reports:reveal', id),
    remove: (id) => invoke('reports:remove', id),
  },
  hunt: {
    search: (query, taskId) => invoke('hunt:search', query, taskId),
    persistence: () => invoke('hunt:persistence'),
  },
  recovery: {
    detect: (path) => invoke('recovery:detect', path),
    engine: (kind) => invoke('recovery:engine', kind),
    pickEngine: (kind) => invoke('recovery:pickEngine', kind),
    clearEngine: (kind) => invoke('recovery:clearEngine', kind),
    pickWordlist: () => invoke('recovery:pickWordlist'),
    start: (kind, target, mode, authorized) => invoke('recovery:start', kind, target, mode, authorized),
    stop: (id) => invoke('recovery:stop', id),
    setPaused: (id, paused) => invoke('recovery:setPaused', id, paused),
    onEvent: (cb) => {
      const listener = (_e: unknown, ev: import('../shared/api').RecoveryEventMsg) => cb(ev);
      ipcRenderer.on('recovery:event', listener);
      return () => ipcRenderer.removeListener('recovery:event', listener);
    },
  },
  net: {
    ping: (target, count, taskId) => invoke('net:ping', target, count, taskId),
    traceroute: (target, taskId) => invoke('net:traceroute', target, taskId),
    dns: (name) => invoke('net:dns', name),
    reverse: (ip) => invoke('net:reverse', ip),
    portCheck: (target, ports, taskId) => invoke('net:portCheck', target, ports, taskId),
    adapters: () => invoke('net:adapters'),
    routes: () => invoke('net:routes'),
    neighbors: () => invoke('net:neighbors'),
    subnets: () => invoke('net:subnets'),
    discover: (cidr, taskId) => invoke('net:discover', cidr, taskId),
  },
  secrets: {
    status: () => invoke('secrets:status'),
    set: (service, value) => invoke('secrets:set', service, value),
    remove: (service) => invoke('secrets:remove', service),
  },
};

contextBridge.exposeInMainWorld('blazma', api);
