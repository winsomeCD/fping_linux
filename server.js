/**
 * NETPULSE Hybrid Backend Bridge Integration Template (server.js)
 * 
 * This file serves as a reference implementation for migrating from local
 * client-side simulation to a real production environment. It uses Express,
 * WebSockets, and standard Node networking libraries to establish real
 * TCP/SSH connections to live network equipment.
 * 
 * INSTRUCTIONS FOR ACTIVATION:
 * 1. Initialize npm project: `npm init -y`
 * 2. Install dependencies: `npm install express ws ssh2 dotenv`
 * 3. Run server: `node server.js`
 * 4. In `api.js`, update REST endpoints to connect to http://localhost:3000/api
 *    and direct terminal connections to WebSocket ws://localhost:3000/ssh
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { Client } = require('ssh2'); // SSH2 library for live device operations
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, './'))); // Serve frontend static files

const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ssh' });

// Configuration variables
const PORT = process.env.PORT || 3000;

/**
 * -------------------------------------------------------------
 * API ROUTE: TRIGGER DEVICE CONFIG BACKUP (REAL NETWORKING)
 * -------------------------------------------------------------
 * This endpoint establishes a temporary SSH channel to execute a show-run command,
 * grabs the text stream, and returns it to the client.
 */
app.post('/api/devices/:id/backup', (req, res) => {
  const { host, port, username, password, type } = req.body;
  
  if (!host || !username || !password) {
    return res.status(400).json({ error: 'Missing connection settings parameters' });
  }

  const conn = new Client();
  let backupContent = '';

  conn.on('ready', () => {
    // Run backup cmd dependent on vendor platform
    const cmd = type === 'Switch' ? 'display current-configuration' : 'show running-config';
    
    conn.exec(cmd, (err, stream) => {
      if (err) {
        conn.end();
        return res.status(500).json({ error: `Command execution failed: ${err.message}` });
      }
      
      stream.on('data', (data) => {
        backupContent += data.toString();
      });

      stream.on('close', (code, signal) => {
        conn.end();
        res.json({
          success: true,
          timestamp: new Date().toISOString(),
          content: backupContent,
          notes: 'Automatic backup pulled from physical hardware'
        });
      });

      stream.stderr.on('data', (data) => {
        console.error('STDERR: ' + data);
      });
    });
  }).on('error', (err) => {
    res.status(500).json({ error: `Connection failed: ${err.message}` });
  }).connect({
    host: host,
    port: port || 22,
    username: username,
    password: password, // For private key, use: privateKey: require('fs').readFileSync('/path/to/key')
    readyTimeout: 10000
  });
});

/**
 * -------------------------------------------------------------
 * WEBSOCKET GATEWAY: STREAM INTERACTIVE SHELL OVER SSH
 * -------------------------------------------------------------
 * Connects WebSocket client streams directly to raw SSH virtual terminals.
 */
wss.on('connection', (ws, req) => {
  console.log('New client joined terminal WebSocket bridge');

  let sshConn = null;
  let sshShell = null;

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      // 1. Connection Handshake
      if (data.action === 'connect') {
        const { host, port, username, password } = data.credentials;

        ws.send(JSON.stringify({ type: 'system', data: `[Bridge] Initializing remote connection to ${host}...` }));

        sshConn = new Client();
        
        sshConn.on('ready', () => {
          ws.send(JSON.stringify({ type: 'system', data: '[Bridge] Credentials accepted. Loading pseudo-terminal...' }));
          
          sshConn.shell((err, stream) => {
            if (err) {
              ws.send(JSON.stringify({ type: 'error', data: `[Bridge] Failed to open shell: ${err.message}` }));
              ws.close();
              return;
            }

            sshShell = stream;

            // Stream from SSH output directly to WebSocket frontend
            sshShell.on('data', (sshData) => {
              ws.send(JSON.stringify({ type: 'output', data: sshData.toString() }));
            });

            sshShell.on('close', () => {
              ws.send(JSON.stringify({ type: 'system', data: '[Bridge] Connection closed by remote device.' }));
              ws.close();
            });
          });
        });

        sshConn.on('error', (err) => {
          ws.send(JSON.stringify({ type: 'error', data: `[Bridge] SSH link error: ${err.message}` }));
          ws.close();
        });

        sshConn.connect({
          host: host,
          port: port || 22,
          username: username,
          password: password
        });
      }

      // 2. Transmit CLI Command inputs
      if (data.action === 'input' && sshShell) {
        sshShell.write(data.command);
      }

    } catch (err) {
      ws.send(JSON.stringify({ type: 'error', data: `[Bridge] Protocol parse failure: ${err.message}` }));
    }
  });

  ws.on('close', () => {
    console.log('Terminal client disconnected from WebSocket bridge');
    if (sshShell) sshShell.end();
    if (sshConn) sshConn.end();
  });
});

// Start service listener
server.listen(PORT, () => {
  console.log(`================================================================`);
  console.log(` NETPULSE NOC Bridge Server running at http://localhost:${PORT}`);
  console.log(` WebSocket terminal routing endpoint bound to ws://localhost:${PORT}/ssh`);
  console.log(`================================================================`);
});
