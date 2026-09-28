// Sandboxed preload: the ONLY bridge between the UI and the backend.
// It exposes a fixed, typed set of functions. No ipcRenderer, no Node APIs leak to the page.
import { contextBridge, ipcRenderer, webUtils } from 'electron';
import type { BlazmaApi, TaskProgress } from '../shared/api';

const invoke = (channel: string, ...args: unknown[]) => ipcRenderer.invoke(channel, ...args);

const api: BlazmaApi = {
  app: {
    info: () => invoke('app:info'),
    openDataFolder: () => invoke('app:openDataFolder'),
    openLink: (url) => invoke('app:openLink', url),
    openTerminal: () => invoke('app:openTerminal'),
    checkUpdates: () => invoke('app:checkUpdates'),
    openReleasePage: () => invoke('app:openReleasePage'),
    bundledEngines: () => invoke('app:bundledEngines'),
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
  email: {
    pick: () => invoke('email:pick'),
    analyzeFile: (path) => invoke('email:analyzeFile', path),
    analyzeText: (source) => invoke('email:analyzeText', source),
    extractAttachment: (token, index) => invoke('email:extractAttachment', token, index),
  },
  password: {
    checkPwned: (password) => invoke('password:checkPwned', password),
  },
  memory: {
    engine: () => invoke('memory:engine'),
    scan: (taskId) => invoke('memory:scan', taskId),
  },
  downloads: {
    state: () => invoke('downloads:state'),
    onState: (cb) => {
      const listener = (_e: unknown, s: Parameters<typeof cb>[0]) => cb(s);
      ipcRenderer.on('downloads:state', listener);
      return () => ipcRenderer.removeListener('downloads:state', listener);
    },
    onOpen: (cb) => {
      const listener = (_e: unknown, ev: Parameters<typeof cb>[0]) => cb(ev);
      ipcRenderer.on('downloads:open', listener);
      return () => ipcRenderer.removeListener('downloads:open', listener);
    },
  },
  extensions: {
    audit: () => invoke('extensions:audit'),
  },
  device: {
    security: (force) => invoke('device:security', force === true),
    tamper: () => invoke('device:tamper'),
    openSettings: (link) => invoke('device:openSettings', link),
  },
  checkup: {
    last: () => invoke('checkup:last'),
    save: (summary) => invoke('checkup:save', summary),
    report: (input, language, format) => invoke('checkup:report', input, language, format),
  },
  fim: {
    list: () => invoke('fim:list'),
    presets: () => invoke('fim:presets'),
    create: (folder, name, taskId) => invoke('fim:create', folder, name, taskId),
    check: (id, taskId) => invoke('fim:check', id, taskId),
    accept: (id, taskId) => invoke('fim:accept', id, taskId),
    remove: (id) => invoke('fim:remove', id),
    resolve: (id, path) => invoke('fim:resolve', id, path),
  },
  nmap: {
    info: () => invoke('nmap:info'),
    targets: () => invoke('nmap:targets'),
    scan: (target, profile, authorized, taskId) => invoke('nmap:scan', target, profile, authorized, taskId),
  },
  wifi: {
    report: () => invoke('wifi:report'),
    openLocationSettings: () => invoke('wifi:openLocationSettings'),
  },
  traffic: {
    environment: () => invoke('traffic:environment'),
    interfaces: () => invoke('traffic:interfaces'),
    pickFile: () => invoke('traffic:pickFile'),
    analyzeFile: (path, taskId) => invoke('traffic:analyzeFile', path, taskId),
    capture: (options, taskId) => invoke('traffic:capture', options, taskId),
    openInWireshark: (path) => invoke('traffic:openInWireshark', path),
    openCapturesFolder: () => invoke('traffic:openCapturesFolder'),
  },
  osint: {
    lookup: (type, value, options) => invoke('osint:lookup', type, value, options),
    openPivot: (type, value, pivotId) => invoke('osint:openPivot', type, value, pivotId),
    accountSites: () => invoke('osint:accountSites'),
    accounts: (username, groups, taskId) => invoke('osint:accounts', username, groups, taskId),
    openAccount: (username, siteId) => invoke('osint:openAccount', username, siteId),
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
    eventEngine: () => invoke('hunt:eventEngine'),
    pickEvents: (kind) => invoke('hunt:pickEvents', kind),
    events: (source, options, taskId) => invoke('hunt:events', source, options, taskId),
  },
  recovery: {
    detect: (path) => invoke('recovery:detect', path),
    engine: (kind) => invoke('recovery:engine', kind),
    pickEngine: (kind) => invoke('recovery:pickEngine', kind),
    clearEngine: (kind) => invoke('recovery:clearEngine', kind),
    pickWordlist: () => invoke('recovery:pickWordlist'),
    start: (kind, target, mode, performance, authorized) => invoke('recovery:start', kind, target, mode, performance, authorized),
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
    knownDevices: () => invoke('net:knownDevices'),
    trustDevices: (macs) => invoke('net:trustDevices', macs),
    renameDevice: (mac, name) => invoke('net:renameDevice', mac, name),
    forgetDevice: (mac) => invoke('net:forgetDevice', mac),
  },
  secrets: {
    status: () => invoke('secrets:status'),
    set: (service, value) => invoke('secrets:set', service, value),
    remove: (service) => invoke('secrets:remove', service),
  },
};

contextBridge.exposeInMainWorld('blazma', api);
