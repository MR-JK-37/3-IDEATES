const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('cybershield', {
  getThreats: () => ipcRenderer.invoke('get-threats'),
  scanFile: (filePath) => ipcRenderer.invoke('scan-file', filePath)
})
