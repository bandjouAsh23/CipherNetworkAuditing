// @ts-nocheck
const { app, BrowserWindow, session } = require('electron');
const path = require('node:path');
const fs = require('node:fs');

let mainWindow = null;

async function startEmbeddedBackend() {
  const backendPath = path.join(__dirname, '..', 'dist-desktop', 'ciphernetwork-backend.cjs');
  if (fs.existsSync(backendPath)) {
    process.env.NODE_ENV = 'production';
    require(backendPath);
    return 'http://127.0.0.1:3000';
  }
  return 'http://127.0.0.1:3000';
}

function createWindow(targetUrl) {
  mainWindow = new BrowserWindow({
    width: 1380,
    height: 880,
    minWidth: 1024,
    minHeight: 700,
    title: 'CipherNetworkAuditing',
    backgroundColor: '#0B1120',
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWindow.loadURL(targetUrl);
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  const url = await startEmbeddedBackend();
  setTimeout(() => createWindow(url), 450);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow(url);
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
