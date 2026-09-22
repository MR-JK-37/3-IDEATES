const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const os = require('os')

let mainWindow

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  })

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'))
}

app.whenReady().then(() => {
  createWindow()

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })

  // Load platform-specific security engine placeholder
  const platform = os.platform()
  let securityEngine = null
  try {
    if (platform === 'win32') {
      securityEngine = require('./security/windows')
    } else if (platform === 'darwin') {
      securityEngine = require('./security/macos')
    } else {
      securityEngine = require('./security/linux')
    }

    if (securityEngine && typeof securityEngine.start === 'function') {
      securityEngine.start()
    }
  } catch (e) {
    console.warn('No platform security engine available:', e.message)
  }
})

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit()
})

// IPC handlers forwarded to security engine when present
ipcMain.handle('get-threats', async (event, args) => {
  try {
    const platform = os.platform()
    const engine = require('./security/' + (platform === 'win32' ? 'windows' : (platform === 'darwin' ? 'macos' : 'linux')))
    if (engine && engine.getRecentThreats) return await engine.getRecentThreats()
  } catch (e) {
    return []
  }
})

ipcMain.handle('scan-file', async (event, filePath) => {
  try {
    const platform = os.platform()
    const engine = require('./security/' + (platform === 'win32' ? 'windows' : (platform === 'darwin' ? 'macos' : 'linux')))
    if (engine && engine.scanFile) return await engine.scanFile(filePath)
  } catch (e) {
    return { error: e.message }
  }
})
