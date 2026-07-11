const { app, BrowserWindow } = require('electron');

function createWindow() {
  const window = new BrowserWindow({ width: 1200, height: 850, minWidth: 720, minHeight: 560 });
  window.loadURL('http://127.0.0.1:8000');
}
app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
