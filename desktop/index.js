const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { spawn, execSync } = require('child_process');
const fs = require('fs');

let mainWindow;
let pythonProcess;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 800,
        icon: path.join(__dirname, 'build', 'icon.png'),
        titleBarStyle: 'hidden',
        backgroundColor: '#0f172a', // Slate 900
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
        },
    });

    // In development, we might use a dev server. 
    // For now, load a static HTML file.
    mainWindow.loadFile('src/index.html');

    // Open DevTools in debug mode
    // mainWindow.webContents.openDevTools();
}

// Start the Python Sidecar (gui_bridge.py / compiled binary)
function startPythonSidecar() {
    console.log('[*] Starting WSHawk Python Sidecar...');

    let executablePath;
    let args = [];
    let options = {};

    if (app.isPackaged) {
        // Run the compiled self-contained binary natively
        executablePath = path.join(process.resourcesPath, 'bin', 'wshawk-bridge');
        if (process.platform === 'win32') executablePath += '.exe';
        options = { stdio: 'pipe' };
    } else {
        // Development mode: Run the script using system python3 as a module
        executablePath = 'python3';
        // Go up one level from 'desktop' to the project root where 'wshawk' package is
        options = {
            cwd: path.join(__dirname, '..'),
            stdio: 'pipe'
        };
        args = ['-m', 'wshawk.gui_bridge'];
    }

    console.log(`[Main] Spawning: ${executablePath} ${args.join(' ')} (CWD: ${options.cwd || 'default'})`);
    pythonProcess = spawn(executablePath, args, options);

    pythonProcess.stdout.on('data', (data) => {
        console.log(`[Python] ${data}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`[Python Error] ${data}`);
    });
}

function checkPythonDependency() {
    try {
        let pyVersion = "";
        try {
            pyVersion = execSync('python3 --version', { encoding: 'utf8', stdio: 'pipe' });
        } catch (e) {
            pyVersion = execSync('python --version', { encoding: 'utf8', stdio: 'pipe' });
        }
        console.log(`[+] System Python Check Passed: ${pyVersion.trim()}`);
    } catch (err) {
        console.error("[-] Python not found on the system");
        const resp = dialog.showMessageBoxSync({
            type: 'error',
            title: 'Critical Dependency Missing',
            message: 'WSHawk requires Python 3.8+ to execute automated exploit payloads and verification sequences.\n\nPlease install Python and restart the application.',
            buttons: ['Download Python', 'Quit WSHawk']
        });

        if (resp === 0) {
            shell.openExternal('https://www.python.org/downloads/');
        }
        app.quit();
    }
}

app.whenReady().then(() => {
    checkPythonDependency();
    startPythonSidecar();
    createWindow();

    // Setup native dialog handlers for Project Management
    ipcMain.handle('dialog:openProject', async () => {
        const result = await dialog.showOpenDialog(mainWindow, {
            title: 'Open WSHawk Project',
            filters: [{ name: 'WSHawk Projects', extensions: ['wshawk'] }],
            properties: ['openFile']
        });

        if (!result.canceled && result.filePaths.length > 0) {
            try {
                const data = fs.readFileSync(result.filePaths[0], 'utf-8');
                return { success: true, data: JSON.parse(data), path: result.filePaths[0] };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:saveProject', async (event, projectData) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Save WSHawk Project',
            filters: [{ name: 'WSHawk Projects', extensions: ['wshawk'] }],
            defaultPath: `project_wshawk_${Date.now()}.wshawk`
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, JSON.stringify(projectData, null, 2), 'utf-8');
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:exportReport', async (event, htmlContent) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Export HTML Report',
            filters: [{ name: 'HTML Document', extensions: ['html'] }],
            defaultPath: `WSHawk_Report_${Date.now()}.html`
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, htmlContent, 'utf-8');
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:exportExploit', async (event, explData) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Export Exploit PoC',
            filters: [{ name: 'Python Script', extensions: ['py'] }],
            defaultPath: `exploit_${Date.now()}.py`
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, explData, 'utf-8');
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.on('window:minimize', () => {
        if (mainWindow) mainWindow.minimize();
    });

    ipcMain.on('window:maximize', () => {
        if (mainWindow) {
            if (mainWindow.isMaximized()) {
                mainWindow.restore();
            } else {
                mainWindow.maximize();
            }
        }
    });

    ipcMain.on('window:close', () => {
        if (mainWindow) mainWindow.close();
    });

    app.on('activate', function () {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', function () {
    // Kill Python sidecar when Electron exits
    if (pythonProcess) {
        pythonProcess.kill();
    }
    if (process.platform !== 'darwin') app.quit();
});
