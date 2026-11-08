'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('yarpa', {
  info: () => ipcRenderer.invoke('info'),
  login: a => ipcRenderer.invoke('login', a),
  resume: () => ipcRenderer.invoke('resume'),
  me: () => ipcRenderer.invoke('me'),
  logout: () => ipcRenderer.invoke('logout'),
  download: g => ipcRenderer.invoke('download', g),
  play: g => ipcRenderer.invoke('play', g),
  onProgress: cb => ipcRenderer.on('progress', (_e, d) => cb(d)),
  onAccess: cb => ipcRenderer.on('access', (_e, d) => cb(d))
});
