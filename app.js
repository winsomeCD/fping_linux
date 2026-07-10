/**
 * NETPULSE Network Operations Center - Core Logic Engine
 */

class NetPulseApp {
  constructor() {
    this.currentView = 'dashboard';
    this.devices = [];
    this.backups = [];
    this.users = [];
    this.currentUser = null;
    
    // Syslogs state
    this.logs = [];
    this.logStreamActive = true;
    this.logInterval = null;
    this.syslogHistoryLimit = 200;
    
    // Terminal state
    this.terminalActiveDevice = null;
    this.terminalPromptSymbol = '> ';
    this.terminalHistoryIndex = -1;
    this.terminalCommandHistory = [];
    this.isTerminalConnecting = false;
    this.isTerminalConnected = false;
    
    // Chart animation state
    this.chartInterval = null;
  }

  async init() {
    // 1. Initial Data Fetch
    this.currentUser = await NetPulseAPI.getCurrentUser();
    this.devices = await NetPulseAPI.getDevices();
    this.backups = await NetPulseAPI.getBackups();
    this.users = await NetPulseAPI.getUsers();
    
    // 2. Pre-seed Logs
    this.seedLogs();

    // 3. UI Setup & Event Bindings
    this.setupViewNavigation();
    this.setupRoleSwitcher();
    this.setupFilters();
    this.setupTerminalKeybindings();
    this.setupCsvImportHandlers();
    this.updateClock();
    
    // 4. Initial Renders
    this.renderAll();
    this.applyPermissions();

    // 5. Start Background Loops
    this.startSyslogStream();
    this.startChartLoader();
    setInterval(() => this.updateClock(), 1000);
  }

  // Views Router
  setupViewNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        const view = e.currentTarget.getAttribute('data-view');
        this.switchView(view);
      });
    });
  }

  switchView(viewName) {
    this.currentView = viewName;
    
    // Update active nav-item
    document.querySelectorAll('.nav-item').forEach(item => {
      if (item.getAttribute('data-view') === viewName) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Update active view visibility
    document.querySelectorAll('.view-container').forEach(view => {
      if (view.id === `view-${viewName}`) {
        view.classList.add('active');
      } else {
        view.classList.remove('active');
      }
    });

    // Update Topbar Title & Subtitles
    const titleEl = document.getElementById('page-view-title');
    const subtitleEl = document.getElementById('page-view-subtitle');

    switch (viewName) {
      case 'dashboard':
        titleEl.textContent = "NOC Control Dashboard";
        subtitleEl.textContent = "Real-time status monitor of network infrastructures";
        this.renderDashboardCpu();
        break;
      case 'device-manager':
        titleEl.textContent = "Device Manager";
        subtitleEl.textContent = "Add, update, search, and delete routers, switches, and firewalls";
        this.renderDeviceList();
        break;
      case 'terminal':
        titleEl.textContent = "CLI Terminal Console";
        subtitleEl.textContent = "Secure virtual terminal gateway for remote SSH / Telnet connections";
        this.renderTerminalDeviceSidebar();
        break;
      case 'backups':
        titleEl.textContent = "Configuration Archives";
        subtitleEl.textContent = "Review configs, trigger backups, and run side-by-side differentials";
        this.renderBackupLists();
        break;
      case 'syslogs':
        titleEl.textContent = "Syslog Monitor Logstream";
        subtitleEl.textContent = "Active debugging stream capturing remote system events & alerts";
        this.renderSyslogsView();
        break;
      case 'users':
        titleEl.textContent = "RBAC Security Manager";
        subtitleEl.textContent = "Inspect user configurations and assign role permission maps";
        this.renderUserList();
        break;
    }
  }

  // Clock
  updateClock() {
    const timeEl = document.getElementById('current-system-time');
    const now = new Date();
    timeEl.textContent = now.toTimeString().split(' ')[0] + " " + now.toLocaleDateString();
  }

  // RBAC Permission Handlers
  setupRoleSwitcher() {
    const roleSelect = document.getElementById('rbac-session-role');
    
    // Sync UI selection to loaded role
    roleSelect.value = this.currentUser.role;

    roleSelect.addEventListener('change', async (e) => {
      const selectedRole = e.target.value;
      this.currentUser = await NetPulseAPI.setCurrentUserRole(selectedRole);
      
      // Update UI avatar labels
      const avatar = document.getElementById('profile-avatar');
      avatar.textContent = this.currentUser.fullname.split(' ').map(n=>n[0]).join('').substring(0,2).toUpperCase();
      
      document.getElementById('profile-username').textContent = this.currentUser.fullname;
      
      let displayRole = "Observer";
      if (this.currentUser.role === 'admin') displayRole = "Administrator";
      if (this.currentUser.role === 'operator') displayRole = "Operator";
      document.getElementById('profile-role-badge').textContent = displayRole;

      // Re-evaluate current actions locks
      this.applyPermissions();
      this.switchView(this.currentView);
      this.showToast(`Active profile switched to ${displayRole}`);
    });
  }

  applyPermissions() {
    const role = this.currentUser.role;
    
    // Permissions Rules:
    // Admin: CRUD Devices, Terminal execution, Backup creation, User modification
    // Operator: Connect CLI terminal, trigger backup. No device edit/delete, no user modification
    // Viewer: Read-only access. No terminal connects, no backup triggers, no edits.

    // 1. Add Device button
    const addDeviceBtn = document.getElementById('btn-add-device');
    if (role === 'admin') {
      addDeviceBtn.removeAttribute('disabled');
      addDeviceBtn.style.opacity = '1';
    } else {
      addDeviceBtn.setAttribute('disabled', 'true');
      addDeviceBtn.style.opacity = '0.5';
    }

    // 2. Add User profile button
    const addUserBtn = document.getElementById('btn-add-user');
    if (role === 'admin') {
      addUserBtn.removeAttribute('disabled');
      addUserBtn.style.opacity = '1';
    } else {
      addUserBtn.setAttribute('disabled', 'true');
      addUserBtn.style.opacity = '0.5';
    }

    // 3. Backup Compare (available to all roles)
    const compareBtn = document.getElementById('btn-compare-backups');
    compareBtn.removeAttribute('disabled');
  }

  checkPermission(action) {
    const role = this.currentUser.role;
    if (role === 'admin') return true;
    
    if (role === 'operator') {
      const allowed = ['terminal_connect', 'backup_trigger', 'syslog_view', 'config_diff'];
      return allowed.includes(action);
    }
    
    if (role === 'viewer') {
      const allowed = ['syslog_view', 'config_diff'];
      return allowed.includes(action);
    }
    return false;
  }

  // Dashboard Visual Renderers
  renderDashboardStats() {
    document.getElementById('card-total-devices').textContent = this.devices.length;
    
    const online = this.devices.filter(d => d.status === 'Online').length;
    document.getElementById('card-online-devices').textContent = online;
    
    const percent = this.devices.length ? Math.round((online / this.devices.length) * 100) : 0;
    document.getElementById('card-online-percent').textContent = `${percent}% reachability`;
    document.getElementById('stats-online-count').textContent = online;

    document.getElementById('card-backups-count').textContent = this.backups.length;
  }

  renderDashboardCpu() {
    const container = document.getElementById('cpu-chart-bars');
    container.innerHTML = '';
    
    const onlineDevices = this.devices.filter(d => d.status === 'Online');
    if (onlineDevices.length === 0) {
      container.innerHTML = '<div style="margin: auto; color: var(--text-dimmed); font-size: 0.9rem;">No online nodes to poll stats</div>';
      return;
    }

    onlineDevices.forEach(d => {
      const barCol = document.createElement('div');
      barCol.className = 'chart-bar-col';
      barCol.id = `chart-device-${d.id}`;
      
      barCol.innerHTML = `
        <div class="chart-bar-track">
          <div class="chart-bar-fill" id="bar-fill-${d.id}" style="height: ${d.cpu}%">
            <span class="chart-bar-value">${d.cpu}%</span>
          </div>
        </div>
        <div class="chart-bar-label">${d.name}</div>
      `;
      container.appendChild(barCol);
    });
  }

  startChartLoader() {
    if (this.chartInterval) clearInterval(this.chartInterval);
    
    this.chartInterval = setInterval(() => {
      if (this.currentView === 'dashboard') {
        this.devices.forEach(d => {
          if (d.status === 'Online') {
            // Oscillate values a bit
            let change = Math.floor(Math.random() * 9) - 4; // -4 to +4
            d.cpu = Math.max(2, Math.min(98, d.cpu + change));
            
            const fill = document.getElementById(`bar-fill-${d.id}`);
            if (fill) {
              fill.style.height = `${d.cpu}%`;
              const labelVal = fill.querySelector('.chart-bar-value');
              if (labelVal) labelVal.textContent = `${d.cpu}%`;
            }
          }
        });
      }
    }, 4000);
  }

  // Device Management Controller
  setupFilters() {
    const search = document.getElementById('device-search');
    const typeFilter = document.getElementById('device-filter-type');
    const statusFilter = document.getElementById('device-filter-status');

    const triggerFilter = () => {
      this.renderDeviceList(search.value, typeFilter.value, statusFilter.value);
    };

    search.addEventListener('input', triggerFilter);
    typeFilter.addEventListener('change', triggerFilter);
    statusFilter.addEventListener('change', triggerFilter);
  }

  renderDeviceList(search = '', type = 'all', status = 'all') {
    const tbody = document.getElementById('device-table-rows');
    tbody.innerHTML = '';

    const filtered = this.devices.filter(d => {
      const matchSearch = d.name.toLowerCase().includes(search.toLowerCase()) || 
                          d.ip.includes(search);
      const matchType = type === 'all' || d.type === type;
      const matchStatus = status === 'all' || d.status === status;
      return matchSearch && matchType && matchStatus;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dimmed); padding: 32px;">No matching devices found.</td></tr>`;
      return;
    }

    filtered.forEach(d => {
      const tr = document.createElement('tr');
      const role = this.currentUser.role;
      const isOnline = d.status === 'Online';
      
      const badgeClass = d.status === 'Online' ? 'online' : (d.status === 'Connecting' ? 'connecting' : 'offline');
      const indicatorClass = d.status === 'Online' ? 'online' : (d.status === 'Connecting' ? 'warning' : 'offline');

      tr.innerHTML = `
        <td style="font-weight: 600;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="indicator-dot ${indicatorClass}"></span>
            ${d.name}
          </div>
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.85rem;">${d.ip}</td>
        <td>${d.type}</td>
        <td>
          <span style="font-size: 0.85rem; color: var(--text-muted);">${d.protocol}</span>
          <span style="font-size: 0.75rem; color: var(--text-dimmed);">(${d.port})</span>
        </td>
        <td>
          <span class="status-badge ${badgeClass}">${d.status}</span>
        </td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">${d.lastBackup}</td>
        <td class="actions-cell">
          <button class="btn-icon connect" title="Connect CLI Terminal" onclick="app.connectTerminalFromDeviceList('${d.id}')">
            <svg viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
          </button>
          <button class="btn-icon backup" title="Backup Running-Config" onclick="app.triggerInstantBackup('${d.id}')">
            <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
          </button>
          <button class="btn-icon" title="Edit Device" onclick="app.openEditDeviceModal('${d.id}')" ${role !== 'admin' ? 'disabled style="opacity:0.3;"' : ''}>
            <svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 1 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
          </button>
          <button class="btn-icon delete" title="Delete Device" onclick="app.deleteDevice('${d.id}')" ${role !== 'admin' ? 'disabled style="opacity:0.3;"' : ''}>
            <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  openAddDeviceModal() {
    if (!this.checkPermission('admin')) return;
    document.getElementById('device-modal-title').textContent = "Add Network Device";
    document.getElementById('form-device-id').value = '';
    document.getElementById('device-form').reset();
    document.getElementById('form-device-port').value = 22;
    document.getElementById('btn-save-device').textContent = "Add Device";
    
    // Show tabs and default to manual
    document.getElementById('device-modal-tabs').style.display = 'flex';
    this.setDeviceModalTab('manual');
    
    document.getElementById('device-modal').classList.add('active');
  }

  openEditDeviceModal(id) {
    if (!this.checkPermission('admin')) return;
    const d = this.devices.find(dev => dev.id === id);
    if (!d) return;

    document.getElementById('device-modal-title').textContent = "Edit Device Details";
    document.getElementById('form-device-id').value = d.id;
    document.getElementById('form-device-name').value = d.name;
    document.getElementById('form-device-ip').value = d.ip;
    document.getElementById('form-device-type').value = d.type;
    document.getElementById('form-device-protocol').value = d.protocol;
    document.getElementById('form-device-port').value = d.port;
    document.getElementById('form-device-user').value = d.username;
    document.getElementById('form-device-pass').value = ''; // Let's keep empty for safety

    // Hide tabs and default to manual
    document.getElementById('device-modal-tabs').style.display = 'none';
    this.setDeviceModalTab('manual');

    document.getElementById('btn-save-device').textContent = "Save Changes";
    document.getElementById('device-modal').classList.add('active');
  }

  closeDeviceModal() {
    document.getElementById('device-modal').classList.remove('active');
  }

  handleProtocolChange() {
    const proto = document.getElementById('form-device-protocol').value;
    const portEl = document.getElementById('form-device-port');
    if (proto === 'SSH') portEl.value = 22;
    else if (proto === 'Telnet') portEl.value = 23;
    else if (proto === 'API') portEl.value = 443;
  }

  setDeviceModalTab(tab) {
    document.getElementById('form-active-tab').value = tab;
    
    // Toggle active tab buttons CSS class
    document.querySelectorAll('.modal-tab-btn').forEach(btn => {
      if (btn.id === `tab-btn-${tab}`) {
        btn.classList.add('active-tab');
      } else {
        btn.classList.remove('active-tab');
      }
    });

    // Toggle forms divs
    document.getElementById('modal-sec-manual').style.display = tab === 'manual' ? 'block' : 'none';
    document.getElementById('modal-sec-sql').style.display = tab === 'sql' ? 'block' : 'none';
    document.getElementById('modal-sec-csv').style.display = tab === 'csv' ? 'block' : 'none';

    // Update submit button description
    const saveBtn = document.getElementById('btn-save-device');
    if (tab === 'manual') {
      const isEdit = !!document.getElementById('form-device-id').value;
      saveBtn.textContent = isEdit ? "Save Changes" : "Save Device";
    } else if (tab === 'sql') {
      saveBtn.textContent = "Import SQL";
    } else if (tab === 'csv') {
      saveBtn.textContent = "Import CSV";
    }
  }

  setupCsvImportHandlers() {
    const dropZone = document.getElementById('csv-drop-zone');
    const fileInput = document.getElementById('csv-file-input');
    const csvTextarea = document.getElementById('csv-import-input');

    if (!dropZone || !fileInput) return;

    // Drag-over styling
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('drop-zone-active');
    });

    dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('drop-zone-active');
    });

    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('drop-zone-active');
      
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        this.readCsvFile(files[0], csvTextarea);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        this.readCsvFile(e.target.files[0], csvTextarea);
      }
    });
  }

  readCsvFile(file, textarea) {
    const reader = new FileReader();
    reader.onload = (e) => {
      textarea.value = e.target.result;
      this.showToast(`Imported text from file: ${file.name}`, 'success');
    };
    reader.readAsText(file);
  }

  async handleDeviceFormSubmit(e) {
    e.preventDefault();
    if (!this.checkPermission('admin')) return;

    const tab = document.getElementById('form-active-tab').value;

    if (tab === 'manual') {
      await this.submitManualForm();
    } else if (tab === 'sql') {
      await this.submitSqlImport();
    } else if (tab === 'csv') {
      await this.submitCsvImport();
    }
  }

  async submitManualForm() {
    const id = document.getElementById('form-device-id').value;
    const name = document.getElementById('form-device-name').value.trim();
    const ip = document.getElementById('form-device-ip').value.trim();
    const type = document.getElementById('form-device-type').value;
    const protocol = document.getElementById('form-device-protocol').value;
    const port = parseInt(document.getElementById('form-device-port').value);
    const username = document.getElementById('form-device-user').value.trim();
    const password = document.getElementById('form-device-pass').value;

    // Validate
    if (!name || !ip || !username) {
      this.showToast("Verification failed: Device Name, IP Host, and Username are required.", "error");
      return;
    }

    const payload = { name, ip, type, protocol, port, username };
    if (id) payload.id = id;
    if (password) payload.password = password;

    try {
      this.closeDeviceModal();
      this.showToast(id ? "Saving device modifications..." : "Provisioning network node...");
      
      await NetPulseAPI.saveDevice(payload);
      
      this.devices = await NetPulseAPI.getDevices();
      this.renderDeviceList();
      this.renderDashboardStats();
      this.showToast(id ? "Device successfully updated." : "Device successfully created.", 'success');
      this.logSyslog(name, 'INFO', `Device configured/modified in database by user ${this.currentUser.username}`);
    } catch(err) {
      this.showToast("Failed to write device details: " + err.message, 'error');
    }
  }

  async submitSqlImport() {
    const sqlText = document.getElementById('sql-import-input').value.trim();
    if (!sqlText) {
      this.showToast("SQL import textarea is empty.", "error");
      return;
    }

    // Split statements by semicolon
    const statements = sqlText.split(';').map(s => s.trim()).filter(s => s.length > 0);
    let successCount = 0;
    let failedCount = 0;

    const cleanSqlVal = (str) => {
      if (!str) return '';
      str = str.trim();
      if ((str.startsWith("'") && str.endsWith("'")) || (str.startsWith('"') && str.endsWith('"'))) {
        return str.slice(1, -1).replace(/\\'/g, "'").replace(/\\"/g, '"');
      }
      return str;
    };

    this.showToast("Parsing and importing SQL device insertions...");

    for (let stmt of statements) {
      // Regex search for columns and values: INSERT INTO devices (cols) VALUES (vals)
      const insertRegex = /insert\s+into\s+devices\s*\(([^)]+)\)\s*values\s*\((.+)\)/i;
      const match = stmt.match(insertRegex);
      
      if (!match) {
        failedCount++;
        continue;
      }

      const colNames = match[1].split(',').map(c => c.trim().toLowerCase().replace(/['"`]/g, ''));
      const valString = match[2];

      // Parse values string ignoring nested commas in single/double quotes
      const values = [];
      let currentVal = '';
      let inSingleQuote = false;
      let inDoubleQuote = false;

      for (let i = 0; i < valString.length; i++) {
        const char = valString[i];
        if (char === "'" && valString[i - 1] !== '\\') {
          inSingleQuote = !inSingleQuote;
          currentVal += char;
        } else if (char === '"' && valString[i - 1] !== '\\') {
          inDoubleQuote = !inDoubleQuote;
          currentVal += char;
        } else if (char === ',' && !inSingleQuote && !inDoubleQuote) {
          values.push(currentVal);
          currentVal = '';
        } else {
          currentVal += char;
        }
      }
      values.push(currentVal);

      // Map values
      const devObj = {};
      colNames.forEach((col, idx) => {
        const rawVal = values[idx];
        const val = cleanSqlVal(rawVal);
        
        if (col === 'name') devObj.name = val;
        else if (col === 'ip' || col === 'hostname') devObj.ip = val;
        else if (col === 'type') devObj.type = val;
        else if (col === 'protocol') devObj.protocol = val;
        else if (col === 'port') devObj.port = parseInt(val) || 22;
        else if (col === 'username') devObj.username = val;
        else if (col === 'password') devObj.password = val;
      });

      // Verification & defaults
      if (!devObj.name || !devObj.ip) {
        failedCount++;
        continue;
      }

      if (!devObj.type) devObj.type = 'Router';
      if (!devObj.protocol) devObj.protocol = 'SSH';
      if (!devObj.port) {
        if (devObj.protocol === 'SSH') devObj.port = 22;
        else if (devObj.protocol === 'Telnet') devObj.port = 23;
        else if (devObj.protocol === 'API') devObj.port = 443;
        else devObj.port = 22;
      }
      if (!devObj.username) devObj.username = 'admin';

      try {
        await NetPulseAPI.saveDevice(devObj);
        successCount++;
        this.logSyslog(devObj.name, 'INFO', `Device provisioned via SQL bulk insert by user ${this.currentUser.username}`);
      } catch (err) {
        failedCount++;
      }
    }

    this.closeDeviceModal();
    this.devices = await NetPulseAPI.getDevices();
    this.renderDeviceList();
    this.renderDashboardStats();

    if (successCount > 0) {
      this.showToast(`Successfully imported ${successCount} devices from SQL.`, 'success');
    }
    if (failedCount > 0) {
      this.showToast(`Failed to parse/import ${failedCount} SQL statement(s). Check format.`, 'error');
    }
  }

  async submitCsvImport() {
    const csvText = document.getElementById('csv-import-input').value.trim();
    if (!csvText) {
      this.showToast("CSV import textarea is empty.", "error");
      return;
    }

    const lines = csvText.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    if (lines.length === 0) {
      this.showToast("No valid lines detected in CSV input.", "error");
      return;
    }

    let headers = ['name', 'ip', 'type', 'protocol', 'port', 'username'];
    let startIdx = 0;

    // Detect header row keywords
    const firstLineCols = lines[0].split(',').map(c => c.trim().toLowerCase().replace(/['"`]/g, ''));
    if (firstLineCols.includes('name') || firstLineCols.includes('ip') || firstLineCols.includes('username') || firstLineCols.includes('hostname')) {
      headers = firstLineCols;
      startIdx = 1;
    }

    let successCount = 0;
    let failedCount = 0;

    this.showToast("Processing CSV batch import...");

    for (let k = startIdx; k < lines.length; k++) {
      const rowVals = lines[k].split(',').map(v => v.trim().replace(/^['"]|['"]$/g, ''));
      if (rowVals.length < 2) {
        failedCount++;
        continue;
      }

      const devObj = {};
      headers.forEach((h, idx) => {
        const val = rowVals[idx] || '';
        if (h.includes('name')) devObj.name = val;
        else if (h.includes('ip') || h.includes('host')) devObj.ip = val;
        else if (h.includes('type')) devObj.type = val;
        else if (h.includes('protocol') || h.includes('proto')) devObj.protocol = val;
        else if (h.includes('port')) devObj.port = parseInt(val) || 22;
        else if (h.includes('user')) devObj.username = val;
        else if (h.includes('pass')) devObj.password = val;
      });

      // Validation & defaults
      if (!devObj.name || !devObj.ip) {
        failedCount++;
        continue;
      }

      if (!devObj.type) devObj.type = 'Router';
      if (!devObj.protocol) devObj.protocol = 'SSH';
      if (!devObj.port) {
        if (devObj.protocol === 'SSH') devObj.port = 22;
        else if (devObj.protocol === 'Telnet') devObj.port = 23;
        else if (devObj.protocol === 'API') devObj.port = 443;
        else devObj.port = 22;
      }
      if (!devObj.username) devObj.username = 'admin';

      try {
        await NetPulseAPI.saveDevice(devObj);
        successCount++;
        this.logSyslog(devObj.name, 'INFO', `Device provisioned via CSV batch import by user ${this.currentUser.username}`);
      } catch (err) {
        failedCount++;
      }
    }

    this.closeDeviceModal();
    this.devices = await NetPulseAPI.getDevices();
    this.renderDeviceList();
    this.renderDashboardStats();

    if (successCount > 0) {
      this.showToast(`Successfully batch imported ${successCount} devices from CSV.`, 'success');
    }
    if (failedCount > 0) {
      this.showToast(`Skipped ${failedCount} CSV row(s) due to formatting anomalies.`, 'error');
    }
  }

  async deleteDevice(id) {
    if (!this.checkPermission('admin')) return;
    const dev = this.devices.find(d => d.id === id);
    if (!dev) return;

    if (confirm(`Are you sure you want to permanently delete device ${dev.name}?`)) {
      try {
        this.showToast("Decommissioning device from database...");
        await NetPulseAPI.deleteDevice(id);
        this.devices = await NetPulseAPI.getDevices();
        this.renderDeviceList();
        this.renderDashboardStats();
        this.showToast("Device deleted.", 'success');
        this.logSyslog(dev.name, 'WARNING', `Device configuration removed from DB by user ${this.currentUser.username}`);
      } catch(err) {
        this.showToast("Error deleting node: " + err.message, 'error');
      }
    }
  }

  // Terminal Console Controllers
  renderTerminalDeviceSidebar() {
    const container = document.getElementById('terminal-device-options');
    container.innerHTML = '';

    if (this.devices.length === 0) {
      container.innerHTML = `<div style="color: var(--text-dimmed); font-size: 0.8rem; text-align: center; margin-top: 12px;">No devices available</div>`;
      return;
    }

    this.devices.forEach(d => {
      const item = document.createElement('div');
      item.className = 'terminal-device-item';
      if (this.terminalActiveDevice && this.terminalActiveDevice.id === d.id) {
        item.classList.add('active');
      }
      
      const badgeClass = d.status === 'Online' ? 'online' : 'offline';
      
      item.innerHTML = `
        <div class="terminal-device-name">${d.name}</div>
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="terminal-device-type">${d.type}</span>
          <span class="indicator-dot ${badgeClass}"></span>
        </div>
      `;
      
      item.onclick = () => this.connectTerminal(d);
      container.appendChild(item);
    });
  }

  connectTerminalFromDeviceList(deviceId) {
    const dev = this.devices.find(d => d.id === deviceId);
    if (!dev) return;
    this.switchView('terminal');
    this.connectTerminal(dev);
  }

  async connectTerminal(device) {
    if (!this.checkPermission('terminal_connect')) {
      this.showToast("Security Exception: Unauthorized role (Viewer) blocked from CLI connections.", "error");
      return;
    }

    if (this.isTerminalConnecting) return;

    // Disconnect old session first
    if (this.isTerminalConnected) {
      this.disconnectTerminal(true);
    }

    this.terminalActiveDevice = device;
    this.isTerminalConnecting = true;
    this.renderTerminalDeviceSidebar();

    // Reset terminal visual prompts
    const history = document.getElementById('terminal-history');
    history.innerHTML = `
      <div class="terminal-line output-system">Initiating secure client handshake to remote host ${device.ip} via ${device.protocol} (port ${device.port})...</div>
    `;

    const indicator = document.getElementById('terminal-status-indicator');
    const title = document.getElementById('terminal-session-title');
    const meta = document.getElementById('terminal-session-meta');

    indicator.className = "pulse-dot connecting";
    title.textContent = `Connecting to ${device.name}...`;
    meta.textContent = `${device.protocol} session target: ${device.username}@${device.ip}`;

    try {
      // Async connect delay
      const resStatus = await NetPulseAPI.pingDevice(device.id);
      this.devices = await NetPulseAPI.getDevices(); // refresh states
      
      if (resStatus === 'Offline') {
        throw new Error("Connection timed out: remote host host unreachable or security rule drop.");
      }

      // Success Connection
      this.isTerminalConnecting = false;
      this.isTerminalConnected = true;
      indicator.className = "pulse-dot";
      title.textContent = `Connected: ${device.name}`;
      
      // Determine CLI Prompt Type
      if (device.type === 'Router') this.terminalPromptSymbol = `${device.name}> `;
      else if (device.type === 'Switch') this.terminalPromptSymbol = `<${device.name}> `;
      else if (device.type === 'Firewall') this.terminalPromptSymbol = `[${device.name}]# `;
      else this.terminalPromptSymbol = `${device.name}# `;

      const greetingLines = [
        `\n--- Connected Successfully via NetPulse Secure Bridge ---`,
        `Host IP: ${device.ip}`,
        `Environment Session Mode: Terminal Emulator Emulation`,
        `Vendor Platform: ${device.type === 'Router' ? 'Cisco IOS' : (device.type === 'Switch' ? 'Huawei VRP' : 'USG Firewall OS')}\n`,
        `User Access Verification: Authenticated as user "${device.username}"`
      ];

      greetingLines.forEach(line => this.appendTerminalLine(line, 'output-success'));
      this.appendTerminalInputLine();
      this.logSyslog(device.name, 'INFO', `SSH session opened by operator ${this.currentUser.username} (${this.currentUser.role})`);
    } catch(err) {
      this.isTerminalConnecting = false;
      this.isTerminalConnected = false;
      this.terminalActiveDevice = null;
      indicator.className = "pulse-dot offline";
      title.textContent = "Connection Failed";
      meta.textContent = "Session dropped";
      this.appendTerminalLine(`\nError: ${err.message}`, 'output-error');
      this.appendTerminalLine("Check network credentials or check logs if host routing is down.", 'output-system');
      this.renderTerminalDeviceSidebar();
      this.logSyslog(device.name, 'ERROR', `Failed connection request: ${err.message}`);
    }
  }

  disconnectTerminal(quiet = false) {
    if (!this.terminalActiveDevice) return;
    
    if (this.isTerminalConnected && !quiet) {
      this.appendTerminalLine("\n*** Connection terminated by client admin request ***", 'output-system');
      this.logSyslog(this.terminalActiveDevice.name, 'INFO', `CLI SSH connection terminated by user ${this.currentUser.username}`);
    }

    this.isTerminalConnected = false;
    this.isTerminalConnecting = false;
    this.terminalActiveDevice = null;

    const indicator = document.getElementById('terminal-status-indicator');
    indicator.className = "pulse-dot offline";
    indicator.style.background = "var(--text-dimmed)";
    indicator.style.boxShadow = "none";
    
    document.getElementById('terminal-session-title').textContent = "No Active Session";
    document.getElementById('terminal-session-meta').textContent = "Select a device to start CLI session";
    
    // Remove input elements
    const inputs = document.querySelectorAll('.terminal-input-row');
    inputs.forEach(i => i.remove());

    this.renderTerminalDeviceSidebar();
  }

  appendTerminalLine(text, cssClass = '') {
    const history = document.getElementById('terminal-history');
    const line = document.createElement('div');
    line.className = `terminal-line ${cssClass}`;
    line.textContent = text;
    history.appendChild(line);
    history.scrollTop = history.scrollHeight;
  }

  appendTerminalInputLine() {
    // Clean old inputs first
    const oldRows = document.querySelectorAll('.terminal-input-row');
    oldRows.forEach(row => row.remove());

    const history = document.getElementById('terminal-history');
    const inputRow = document.createElement('div');
    inputRow.className = 'terminal-input-row';
    inputRow.innerHTML = `
      <span class="terminal-prompt">${this.terminalPromptSymbol}</span>
      <input type="text" class="terminal-input-element" autofocus spellcheck="false" autocomplete="off">
      <span class="terminal-cursor"></span>
    `;

    history.appendChild(inputRow);
    const input = inputRow.querySelector('.terminal-input-element');
    input.focus();

    // Rebind focus keep
    inputRow.addEventListener('click', () => input.focus());
    
    input.addEventListener('keydown', (e) => this.handleTerminalInputKeyDown(e, input));
    history.scrollTop = history.scrollHeight;
  }

  handleTerminalInputKeyDown(e, inputEl) {
    if (e.key === 'Enter') {
      const command = inputEl.value.trim();
      if (command) {
        this.terminalCommandHistory.push(command);
        this.terminalHistoryIndex = this.terminalCommandHistory.length;
      }
      this.executeTerminalCommand(command);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (this.terminalCommandHistory.length > 0 && this.terminalHistoryIndex > 0) {
        this.terminalHistoryIndex--;
        inputEl.value = this.terminalCommandHistory[this.terminalHistoryIndex];
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (this.terminalCommandHistory.length > 0 && this.terminalHistoryIndex < this.terminalCommandHistory.length - 1) {
        this.terminalHistoryIndex++;
        inputEl.value = this.terminalCommandHistory[this.terminalHistoryIndex];
      } else if (this.terminalHistoryIndex === this.terminalCommandHistory.length - 1) {
        this.terminalHistoryIndex++;
        inputEl.value = '';
      }
    }
  }

  setupTerminalKeybindings() {
    // Keep focus when clicking anywhere inside terminal body
    const body = document.getElementById('terminal-history');
    body.addEventListener('click', () => {
      const input = body.querySelector('.terminal-input-element');
      if (input) input.focus();
    });
  }

  clearTerminal() {
    const history = document.getElementById('terminal-history');
    history.innerHTML = '';
    if (this.isTerminalConnected) {
      this.appendTerminalInputLine();
    } else {
      history.innerHTML = `<div class="terminal-welcome">Console cleared. Session closed.</div>`;
    }
  }

  // Simulated commands execution output
  executeTerminalCommand(commandString) {
    const cleanCmd = commandString.toLowerCase().replace(/\s+/g, ' ');
    this.appendTerminalLine(`${this.terminalPromptSymbol}${commandString}`, 'command-echo');
    
    if (cleanCmd === '') {
      this.appendTerminalInputLine();
      return;
    }

    if (cleanCmd === 'exit' || cleanCmd === 'quit') {
      this.disconnectTerminal();
      return;
    }

    if (cleanCmd === 'clear') {
      this.clearTerminal();
      return;
    }

    const type = this.terminalActiveDevice.type;
    const name = this.terminalActiveDevice.name;

    // Simulate Command Parsing Logic
    let output = '';
    let isError = false;

    // Help commands
    if (cleanCmd === 'help' || cleanCmd === '?') {
      output = `Supported diagnostic CLI commands for this simulated device:
  help / ?                       - Display this command dictionary
  show version                   - Display system inventory & engine uptime
  show ip interface brief        - (Cisco/Generic) List interface status and configuration
  display ip interface brief     - (Huawei) List interface status and configuration
  show interfaces                - (Juniper) List interface parameters
  show configuration / show run - View running-configuration configs text
  ping [destination_ip]          - Perform echo request checks
  write memory                   - Save configurations to flash nvram
  clear                          - Reset local terminal console log history
  exit / quit                    - Terminate SSH/Telnet terminal tunnel`;
    }
    // Version check
    else if (cleanCmd === 'show version' || cleanCmd === 'display version') {
      output = `${type} OS Core Engine software, Version 15.4(3)M3 (Simulated)
System uptime is 12 weeks, 4 days, 16 hours, 21 minutes
System returned to ROM by power-on
System image file is "flash:${type.toLowerCase()}-image-v15.bin"
Processor board System ID: SN-${this.terminalActiveDevice.id.toUpperCase()}
${type} with 2048M bytes of physical memory.
Control Processor: Octeon-II Multi-Core Network Engine
10 GigabitEthernet interfaces`;
    }
    // Ping
    else if (cleanCmd.startsWith('ping')) {
      const parts = cleanCmd.split(' ');
      const ip = parts[1] || '8.8.8.8';
      output = `PING ${ip} (${ip}) 56(84) bytes of data.
64 bytes from ${ip}: icmp_seq=1 ttl=54 time=14.2 ms
64 bytes from ${ip}: icmp_seq=2 ttl=54 time=10.5 ms
64 bytes from ${ip}: icmp_seq=3 ttl=54 time=11.1 ms
64 bytes from ${ip}: icmp_seq=4 ttl=54 time=12.0 ms

--- ${ip} ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 10.512/11.954/14.215/1.422 ms`;
      this.logSyslog(name, 'INFO', `CLI session: Executed network diagnostic ICMP ping check to ${ip}`);
    }
    // Interface check: Cisco
    else if (cleanCmd === 'show ip interface brief' || cleanCmd === 'sh ip int br') {
      if (type === 'Router') {
        output = `Interface                  IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0         ${this.terminalActiveDevice.ip}  YES NVRAM  up                    up      
GigabitEthernet0/1         192.168.1.1     YES manual up                    up      
GigabitEthernet0/2         unassigned      YES unset  administratively down down    
Loopback0                  127.0.0.1       YES manual up                    up      `;
      } else {
        output = `% Invalid command format for vendor device. Use 'display ip interface brief' for Huawei switch nodes.`;
        isError = true;
      }
    }
    // Interface check: Huawei
    else if (cleanCmd === 'display ip interface brief' || cleanCmd === 'disp ip int br') {
      if (type === 'Switch') {
        output = `*down: administratively down
^down: standby
Interface                         IP Address/Mask      Physical   Protocol  
Vlanif10                          ${this.terminalActiveDevice.ip}/24  up         up        
GigabitEthernet0/0/1              unassigned           up         up        
GigabitEthernet0/0/2              unassigned           up         up        
LoopBack0                         127.0.0.1/32         up         up(s)     `;
      } else {
        output = `Error: Unrecognized command. Cisco routers use 'show ip interface brief' instead.`;
        isError = true;
      }
    }
    // Interface check: Juniper
    else if (cleanCmd === 'show interfaces' || cleanCmd === 'show int') {
      if (type === 'Firewall') {
        output = `Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Link-level type: Ethernet, MTU: 1514, Speed: 1000mbps, Duplex: Full
  Logical interface ge-0/0/0.0 (Index 72) (SNMP ifIndex 501)
    Addresses, Flags: Dest-route-down Valids-interfaces
    Destination: Untrust, Local: ${this.terminalActiveDevice.ip}
Physical interface: ge-0/0/1, Enabled, Physical link is Up
  Logical interface ge-0/0/1.0 (Index 73)
    Destination: Trust, Local: 192.168.1.1`;
      } else {
        output = `Command error. Try "show ip interface brief" or check help menu.`;
        isError = true;
      }
    }
    // Show configuration/running config
    else if (cleanCmd === 'show running-config' || cleanCmd === 'show run' || cleanCmd === 'show configuration' || cleanCmd === 'display current-configuration' || cleanCmd === 'disp curr') {
      // Find latest backup configuration
      const devBaks = this.backups.filter(b => b.deviceId === this.terminalActiveDevice.id);
      if (devBaks.length > 0) {
        output = devBaks[0].content;
      } else {
        output = `! Building configuration...
! Running configuration has not been backed up yet. Displaying default baseline:
hostname ${this.terminalActiveDevice.name}
ip address ${this.terminalActiveDevice.ip}
! Configuration ends.`;
      }
      this.logSyslog(name, 'INFO', `CLI session: Pulled device running-configurations file to terminal screen`);
    }
    // Write configs
    else if (cleanCmd === 'write memory' || cleanCmd === 'wr' || cleanCmd === 'save') {
      output = `Building configuration...
[OK]
Saving current configuration to nvram:startup-config memory...
Update success. Configuration committed to system registers.`;
      this.logSyslog(name, 'INFO', `CLI session: Committed configurations to startup NVRAM`);
    }
    // Fallback: command not supported
    else {
      output = `Command unrecognized or security levels blocked execution: "${commandString}"
Type "help" or "?" to inspect available diagnostic scripts.`;
      isError = true;
    }

    // Print output block
    this.appendTerminalLine(output, isError ? 'output-error' : '');
    
    // Add new input line prompt
    this.appendTerminalInputLine();
  }

  // Backup System and Comparison diff view
  renderBackupLists() {
    // 1. Render Left panel: Trigger Backups
    const triggerContainer = document.getElementById('backup-trigger-list');
    triggerContainer.innerHTML = '';
    
    this.devices.forEach(d => {
      const item = document.createElement('div');
      item.className = 'backup-history-item';
      
      const isOffline = d.status === 'Offline';
      
      item.innerHTML = `
        <div class="backup-details">
          <div class="backup-device-title">${d.name}</div>
          <div class="backup-meta">
            <span>IP: ${d.ip}</span>
            <span>|</span>
            <span>Type: ${d.type}</span>
            <span>|</span>
            <span>Last Backup: <strong style="color:var(--accent-cyan);">${d.lastBackup}</strong></span>
          </div>
        </div>
        <button class="btn btn-secondary" 
                id="btn-trigger-bak-${d.id}"
                style="padding: 6px 12px; font-size: 0.8rem;" 
                onclick="app.triggerInstantBackup('${d.id}')"
                ${isOffline || this.currentUser.role === 'viewer' ? 'disabled' : ''}>
          Backup Now
        </button>
      `;
      triggerContainer.appendChild(item);
    });

    // 2. Render Right panel: History and select
    const historyContainer = document.getElementById('backup-history-list');
    historyContainer.innerHTML = '';

    if (this.backups.length === 0) {
      historyContainer.innerHTML = `<div style="text-align:center; padding: 24px; color:var(--text-dimmed); font-size: 0.9rem;">No version backups found.</div>`;
      return;
    }

    this.backups.forEach(b => {
      const item = document.createElement('div');
      item.className = 'backup-history-item';
      item.innerHTML = `
        <div class="backup-details">
          <div class="backup-device-title">${b.deviceName}</div>
          <div class="backup-meta">
            <span>Time: ${b.timestamp}</span>
            <span>|</span>
            <span>Notes: <i>"${b.notes}"</i></span>
          </div>
        </div>
        <div class="backup-select-box">
          <button class="btn btn-icon delete" style="padding: 4px;" title="Delete backup entry" onclick="app.deleteBackup('${b.id}')" ${this.currentUser.role !== 'admin' ? 'disabled style="opacity:0.3;"' : ''}>
            <svg viewBox="0 0 24 24" width="16" height="16"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
          </button>
          <button class="btn btn-icon" style="padding: 4px;" title="Download Config File" onclick="app.downloadConfig('${b.id}')">
            <svg viewBox="0 0 24 24" width="16" height="16"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          </button>
          <input type="checkbox" class="backup-checkbox" value="${b.id}" data-device="${b.deviceId}" onchange="app.handleBackupSelection(this)">
        </div>
      `;
      historyContainer.appendChild(item);
    });
  }

  async triggerInstantBackup(deviceId) {
    if (!this.checkPermission('backup_trigger')) {
      this.showToast("Security Exception: Access denied for current user role.", "error");
      return;
    }

    const dev = this.devices.find(d => d.id === deviceId);
    if (!dev) return;
    if (dev.status === 'Offline') {
      this.showToast("Connection Fail: Target device is unreachable/Offline.", "error");
      return;
    }

    // Spinner lock buttons
    const triggerBtn = document.getElementById(`btn-trigger-bak-${deviceId}`);
    if (triggerBtn) {
      triggerBtn.setAttribute('disabled', 'true');
      triggerBtn.textContent = "Connecting...";
    }
    this.showToast(`Logging in to ${dev.name}... Pulling current-configuration file via SSH...`);
    
    try {
      const notes = prompt("Enter configuration archive notes (optional):", "Regular backup verification");
      const savedNotes = notes ? notes.trim() : "Scheduled snapshot verification";

      await NetPulseAPI.createBackup(deviceId, savedNotes);
      this.backups = await NetPulseAPI.getBackups();
      this.devices = await NetPulseAPI.getDevices(); // updates timestamp
      
      this.renderBackupLists();
      this.renderDashboardStats();
      this.renderDeviceList();
      this.showToast(`Configuration snapshot for ${dev.name} successfully archived.`, 'success');
      this.logSyslog(dev.name, 'INFO', `Configuration backup snapshot saved to archive catalog (Version V${this.backups.filter(b=>b.deviceId===deviceId).length})`);
    } catch(err) {
      this.showToast("Backup sequence halted: " + err.message, 'error');
      if (triggerBtn) triggerBtn.removeAttribute('disabled');
    }
  }

  async deleteBackup(backupId) {
    if (!this.checkPermission('admin')) return;
    if (confirm("Confirm permanent removal of configuration archive entry from archive registers?")) {
      try {
        await NetPulseAPI.deleteBackup(backupId);
        this.backups = await NetPulseAPI.getBackups();
        this.renderBackupLists();
        this.renderDashboardStats();
        this.showToast("Config backup deleted.", 'success');
      } catch(err) {
        this.showToast("Error deleting config: " + err.message, 'error');
      }
    }
  }

  downloadConfig(backupId) {
    const backup = this.backups.find(b => b.id === backupId);
    if (!backup) return;
    
    const blob = new Blob([backup.content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${backup.deviceName}_config_${backup.timestamp.replace(/[: ]/g, '_')}.cfg`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    this.showToast(`Downloading configuration: ${a.download}`);
  }

  // Backup checkboxes limit (max 2)
  handleBackupSelection(checkbox) {
    const checkedBoxes = document.querySelectorAll('.backup-checkbox:checked');
    if (checkedBoxes.length > 2) {
      checkbox.checked = false;
      this.showToast("Please select exactly 2 backups to run visual comparison.", 'error');
    }
  }

  // Simple string line-by-line diff tool
  compareSelectedBackups() {
    const checked = Array.from(document.querySelectorAll('.backup-checkbox:checked')).map(cb => cb.value);
    
    if (checked.length !== 2) {
      this.showToast("Please choose exactly 2 configuration snapshots from archives list.", 'error');
      return;
    }

    const backupA = this.backups.find(b => b.id === checked[0]);
    const backupB = this.backups.find(b => b.id === checked[1]);

    if (!backupA || !backupB) return;

    // Order by timestamp so older is left, newer is right
    let oldBackup = backupA;
    let newBackup = backupB;
    if (new Date(backupA.timestamp) > new Date(backupB.timestamp)) {
      oldBackup = backupB;
      newBackup = backupA;
    }

    document.getElementById('diff-meta-label').innerHTML = `
      <span>Comparing older configuration on left with newer on right</span>
      <span>${oldBackup.deviceName} (Baseline: ${oldBackup.timestamp}) vs ${newBackup.deviceName} (Updated: ${newBackup.timestamp})</span>
    `;

    document.getElementById('diff-source-header').textContent = `${oldBackup.deviceName} (${oldBackup.timestamp})`;
    document.getElementById('diff-dest-header').textContent = `${newBackup.deviceName} (${newBackup.timestamp})`;

    this.runLineDiff(oldBackup.content, newBackup.content);
    document.getElementById('diff-modal').classList.add('active');
  }

  closeDiffModal() {
    document.getElementById('diff-modal').classList.remove('active');
  }

  runLineDiff(text1, text2) {
    const lines1 = text1.split('\n');
    const lines2 = text2.split('\n');

    const leftContainer = document.getElementById('diff-source-body');
    const rightContainer = document.getElementById('diff-dest-body');
    
    leftContainer.innerHTML = '';
    rightContainer.innerHTML = '';

    // Simple diff display:
    // Align identical elements, show updates
    let i = 0, j = 0;
    
    while (i < lines1.length || j < lines2.length) {
      const line1 = lines1[i];
      const line2 = lines2[j];

      if (line1 === line2) {
        // Line unchanged in both
        if (i < lines1.length) this.appendDiffLine(leftContainer, i + 1, line1, 'unchanged');
        if (j < lines2.length) this.appendDiffLine(rightContainer, j + 1, line2, 'unchanged');
        i++;
        j++;
      } else {
        // Simple heuristic: lookahead to align
        let foundMatch = false;
        
        // Check if line1 matches a subsequent line in lines2 (addition check)
        for (let searchJ = j + 1; searchJ < Math.min(j + 10, lines2.length); searchJ++) {
          if (line1 === lines2[searchJ]) {
            // Lines from j to searchJ-1 are additions on the right
            for (let addIdx = j; addIdx < searchJ; addIdx++) {
              this.appendDiffLine(leftContainer, '', '', 'unchanged'); // empty spacer on left
              this.appendDiffLine(rightContainer, addIdx + 1, `+ ${lines2[addIdx]}`, 'added');
            }
            j = searchJ;
            foundMatch = true;
            break;
          }
        }

        if (!foundMatch) {
          // Check if line2 matches a subsequent line in lines1 (deletion check)
          for (let searchI = i + 1; searchI < Math.min(i + 10, lines1.length); searchI++) {
            if (line2 === lines1[searchI]) {
              // Lines from i to searchI-1 are deletions on the left
              for (let delIdx = i; delIdx < searchI; delIdx++) {
                this.appendDiffLine(leftContainer, delIdx + 1, `- ${lines1[delIdx]}`, 'removed');
                this.appendDiffLine(rightContainer, '', '', 'unchanged'); // empty spacer on right
              }
              i = searchI;
              foundMatch = true;
              break;
            }
          }
        }

        if (!foundMatch) {
          // If no quick match found, mark left as deleted, right as added
          if (i < lines1.length) {
            this.appendDiffLine(leftContainer, i + 1, `- ${line1}`, 'removed');
            i++;
          } else {
            this.appendDiffLine(leftContainer, '', '', 'unchanged');
          }
          
          if (j < lines2.length) {
            this.appendDiffLine(rightContainer, j + 1, `+ ${line2}`, 'added');
            j++;
          } else {
            this.appendDiffLine(rightContainer, '', '', 'unchanged');
          }
        }
      }
    }
  }

  appendDiffLine(container, lineNum, content, statusClass) {
    const div = document.createElement('div');
    div.className = `diff-line ${statusClass}`;
    
    const numSpan = document.createElement('span');
    numSpan.style.display = 'inline-block';
    numSpan.style.width = '30px';
    numSpan.style.color = 'var(--text-dimmed)';
    numSpan.style.userSelect = 'none';
    numSpan.textContent = lineNum ? `${lineNum} ` : '   ';
    
    const textSpan = document.createElement('span');
    textSpan.textContent = content;

    div.appendChild(numSpan);
    div.appendChild(textSpan);
    container.appendChild(div);
  }

  // Syslogs Streaming Systems
  seedLogs() {
    const defaultMessages = [
      { dev: "core-router-01", level: "INFO", msg: "BGP neighbor 192.0.2.1 established session adjacency" },
      { dev: "border-fw-01", level: "WARNING", msg: "Packet drops exceeded alert threshold on untrust zone interface" },
      { dev: "dist-switch-02", level: "INFO", msg: "Interface GigabitEthernet0/0/1 state changed to UP" },
      { dev: "branch-router-03", level: "ERROR", msg: "OMP session down on peer 172.16.50.1 - handshake timeout" },
      { dev: "core-router-01", level: "INFO", msg: "SSH session authentication succeeded for user admin from host 10.0.12.44" },
      { dev: "border-fw-01", level: "WARNING", msg: "Intrusion protection engine signature database update successfully processed" },
      { dev: "dist-switch-02", level: "INFO", msg: "Spanning Tree Topology change detected on VLAN 10 (root port updated)" }
    ];

    const now = new Date();
    // Populate logs history
    for (let i = 0; i < 20; i++) {
      const msgTemplate = defaultMessages[Math.floor(Math.random() * defaultMessages.length)];
      const ts = new Date(now.getTime() - (20 - i) * 60000); // 1 minute intervals
      
      this.logs.unshift({
        id: "log-" + Math.random().toString(36).substring(2, 9),
        timestamp: ts.toISOString().slice(0, 19).replace('T', ' '),
        device: msgTemplate.dev,
        level: msgTemplate.level,
        message: msgTemplate.msg
      });
    }
  }

  startSyslogStream() {
    const randomTemplates = [
      { dev: "core-router-01", level: "INFO", msgs: ["OSPF neighbor state changed to FULL", "Interface Loopback0 changed state to UP", "Configured from console by console"] },
      { dev: "border-fw-01", level: "WARNING", msgs: ["Decryption cache limits reached on policy zone 3", "Deny rule hit limit trigger: Source 198.51.100.45", "SSL negotiation failed for external user"] },
      { dev: "dist-switch-02", level: "INFO", msgs: ["MAC address table learning cap reached on VLAN 20", "Port GigabitEthernet0/0/2 state changed to UP", "SNMP community validation success"] },
      { dev: "branch-router-03", level: "ERROR", msgs: ["Hardware sensor critical: Fan unit 2 RPM below limits", "Line protocol tunnel IPSEC down on ge-0/0/1.0", "Internal thermal sensor registers peak: 74C"] }
    ];

    this.logInterval = setInterval(() => {
      if (!this.logStreamActive) return;

      // Pull random device
      const node = randomTemplates[Math.floor(Math.random() * randomTemplates.length)];
      // Choose online/offline matching status to keep realism
      const dbDev = this.devices.find(d => d.name === node.dev);
      if (dbDev && dbDev.status === 'Offline' && node.level !== 'ERROR') {
        // If device is offline, only post error logs or skip
        if (Math.random() > 0.3) return;
      }

      const msgText = node.msgs[Math.floor(Math.random() * node.msgs.length)];
      const dateStr = new Date().toISOString().slice(0, 19).replace('T', ' ');

      this.logSyslog(node.dev, node.level, msgText);
    }, 5000);
  }

  logSyslog(deviceName, level, message) {
    const dateStr = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const newLog = {
      id: "log-" + Math.random().toString(36).substring(2, 9),
      timestamp: dateStr,
      device: deviceName,
      level: level,
      message: message
    };

    this.logs.unshift(newLog);
    if (this.logs.length > this.syslogHistoryLimit) {
      this.logs.pop();
    }

    // Refresh components
    if (this.currentView === 'dashboard') {
      this.renderDashboardSyslogPreview();
    }
    if (this.currentView === 'syslogs') {
      this.renderSyslogsView();
    }
  }

  toggleLogStreaming() {
    this.logStreamActive = !this.logStreamActive;
    const btn = document.getElementById('btn-toggle-log-stream');
    btn.textContent = this.logStreamActive ? "Pause Stream" : "Resume Stream";
    btn.className = this.logStreamActive ? "btn btn-primary" : "btn btn-secondary";
    this.showToast(this.logStreamActive ? "Syslog monitor stream active." : "Syslog monitor stream paused.");
  }

  clearLogs() {
    this.logs = [];
    this.renderSyslogsView();
    this.renderDashboardSyslogPreview();
    this.showToast("Syslog memory buffer cleared.");
  }

  renderDashboardSyslogPreview() {
    const container = document.getElementById('dashboard-syslogs-preview');
    container.innerHTML = '';

    const previewCount = 6;
    const slice = this.logs.slice(0, previewCount);

    if (slice.length === 0) {
      container.innerHTML = `<div style="text-align:center; color:var(--text-dimmed); font-size:0.8rem; margin-top:20px;">No syslogs received</div>`;
      return;
    }

    slice.forEach(log => {
      const item = document.createElement('div');
      item.className = 'activity-item';
      
      let dotColor = 'var(--accent-blue)';
      if (log.level === 'WARNING') dotColor = 'var(--accent-amber)';
      if (log.level === 'ERROR') dotColor = 'var(--accent-rose)';

      item.innerHTML = `
        <span class="activity-dot" style="background: ${dotColor}; box-shadow: 0 0 6px ${dotColor};"></span>
        <div class="activity-info">
          <div class="activity-desc">
            <strong style="color:var(--accent-cyan); font-size: 0.8rem;">${log.device}</strong>
            <span style="font-size:0.8rem;">${log.message}</span>
          </div>
          <span class="activity-time">${log.timestamp.split(' ')[1]}</span>
        </div>
      `;
      container.appendChild(item);
    });
  }

  renderSyslogsView() {
    const devSelect = document.getElementById('log-filter-device');
    const levelSelect = document.getElementById('log-filter-level');
    
    // Bind change listeners once
    if (!devSelect.dataset.bound) {
      devSelect.dataset.bound = "true";
      devSelect.addEventListener('change', () => this.renderSyslogsView());
      levelSelect.addEventListener('change', () => this.renderSyslogsView());
    }

    // Pre-populate device list filter
    const activeFilterDev = devSelect.value;
    devSelect.innerHTML = '<option value="all">All Devices</option>';
    this.devices.forEach(d => {
      const opt = document.createElement('option');
      opt.value = d.name;
      opt.textContent = d.name;
      devSelect.appendChild(opt);
    });
    devSelect.value = activeFilterDev || "all";

    const rowsContainer = document.getElementById('syslog-console-rows');
    rowsContainer.innerHTML = '';

    const filterDev = devSelect.value;
    const filterLevel = levelSelect.value;

    const filtered = this.logs.filter(log => {
      const devMatch = filterDev === 'all' || log.device === filterDev;
      const levelMatch = filterLevel === 'all' || log.level === filterLevel;
      return devMatch && levelMatch;
    });

    if (filtered.length === 0) {
      rowsContainer.innerHTML = `<div style="text-align:center; padding: 40px; color:var(--text-dimmed); font-size:0.85rem;">No syslogs match active filter parameters</div>`;
      return;
    }

    filtered.forEach(log => {
      const row = document.createElement('div');
      row.className = 'log-row';

      let lvlClass = 'info';
      if (log.level === 'WARNING') lvlClass = 'warning';
      if (log.level === 'ERROR') lvlClass = 'error';

      row.innerHTML = `
        <span class="log-timestamp">${log.timestamp}</span>
        <span class="log-device">${log.device}</span>
        <span class="log-level ${lvlClass}">${log.level}</span>
        <span class="log-message">${log.message}</span>
      `;
      rowsContainer.appendChild(row);
    });
  }

  // RBAC User Admin Controller
  renderUserList() {
    const tbody = document.getElementById('user-table-rows');
    tbody.innerHTML = '';
    const activeRole = this.currentUser.role;

    this.users.forEach(u => {
      const tr = document.createElement('tr');
      
      let modulesList = "All access (Admin configs, Terminal CLI write, back-ups)";
      if (u.role === 'operator') modulesList = "Diagnostic CLI connection + Backup archive control (No DB writes)";
      if (u.role === 'viewer') modulesList = "Read-Only Dashboard, Syslog, and Diff interfaces";

      tr.innerHTML = `
        <td style="font-weight: 600; font-family: var(--font-mono);">${u.username}</td>
        <td>${u.fullname}</td>
        <td><span class="role-badge ${u.role}">${u.role}</span></td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">${modulesList}</td>
        <td class="actions-cell">
          <button class="btn-icon" title="Edit User" onclick="app.openEditUserModal('${u.id}')" ${activeRole !== 'admin' ? 'disabled style="opacity:0.3;"' : ''}>
            <svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 1 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
          </button>
          <button class="btn-icon delete" title="Delete User" onclick="app.deleteUser('${u.id}')" ${activeRole !== 'admin' || u.username === 'admin' ? 'disabled style="opacity:0.3;"' : ''}>
            <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  openAddUserModal() {
    if (!this.checkPermission('admin')) return;
    document.getElementById('user-modal-title').textContent = "Create RBAC User";
    document.getElementById('form-user-id').value = '';
    document.getElementById('user-form').reset();
    document.getElementById('btn-save-user').textContent = "Create User";
    document.getElementById('user-modal').classList.add('active');
  }

  openEditUserModal(id) {
    if (!this.checkPermission('admin')) return;
    const u = this.users.find(usr => usr.id === id);
    if (!u) return;

    document.getElementById('user-modal-title').textContent = "Modify User Profile";
    document.getElementById('form-user-id').value = u.id;
    document.getElementById('form-username').value = u.username;
    document.getElementById('form-fullname').value = u.fullname;
    document.getElementById('form-user-role').value = u.role;

    document.getElementById('btn-save-user').textContent = "Save Details";
    document.getElementById('user-modal').classList.add('active');
  }

  closeUserModal() {
    document.getElementById('user-modal').classList.remove('active');
  }

  async handleUserFormSubmit(e) {
    e.preventDefault();
    if (!this.checkPermission('admin')) return;

    const id = document.getElementById('form-user-id').value;
    const username = document.getElementById('form-username').value.trim();
    const fullname = document.getElementById('form-fullname').value.trim();
    const role = document.getElementById('form-user-role').value;

    const payload = { username, fullname, role };
    if (id) payload.id = id;

    try {
      this.closeUserModal();
      this.showToast("Saving security credentials...");
      await NetPulseAPI.saveUser(payload);
      
      this.users = await NetPulseAPI.getUsers();
      this.renderUserList();
      this.showToast(id ? "User updated." : "New user created successfully.", 'success');
    } catch(err) {
      this.showToast("Failed to write user profile: " + err.message, 'error');
    }
  }

  async deleteUser(id) {
    if (!this.checkPermission('admin')) return;
    const user = this.users.find(u => u.id === id);
    if (!user) return;

    if (confirm(`Confirm permanent deletion of user profile "${user.fullname}" (${user.username})?`)) {
      try {
        await NetPulseAPI.deleteUser(id);
        this.users = await NetPulseAPI.getUsers();
        this.renderUserList();
        this.showToast("User profile deleted.", 'success');
      } catch(err) {
        this.showToast("Halted: " + err.message, 'error');
      }
    }
  }

  // Combined Render Refresher
  renderAll() {
    this.renderDashboardStats();
    this.renderDashboardCpu();
    this.renderDashboardSyslogPreview();
    
    // Fallback refresh for other views if they are selected
    this.renderDeviceList();
    this.renderTerminalDeviceSidebar();
    this.renderBackupLists();
    this.renderSyslogsView();
    this.renderUserList();
  }

  // Toast notifications component
  showToast(message, type = 'info') {
    // Check if toast wrapper exists, else make one
    let wrapper = document.getElementById('toast-container');
    if (!wrapper) {
      wrapper = document.createElement('div');
      wrapper.id = 'toast-container';
      wrapper.style.position = 'fixed';
      wrapper.style.bottom = '24px';
      wrapper.style.right = '24px';
      wrapper.style.zIndex = '9999';
      wrapper.style.display = 'flex';
      wrapper.style.flexDirection = 'column';
      wrapper.style.gap = '8px';
      document.body.appendChild(wrapper);
    }

    const toast = document.createElement('div');
    toast.className = 'toast-element';
    
    let borderClr = 'var(--accent-blue)';
    if (type === 'success') borderClr = 'var(--accent-emerald)';
    if (type === 'error') borderClr = 'var(--accent-rose)';

    toast.style.background = 'var(--bg-secondary)';
    toast.style.color = 'var(--text-main)';
    toast.style.padding = '12px 20px';
    toast.style.borderRadius = '6px';
    toast.style.borderLeft = `4px solid ${borderClr}`;
    toast.style.boxShadow = '0 10px 25px rgba(0,0,0,0.5)';
    toast.style.fontSize = '0.85rem';
    toast.style.fontWeight = '500';
    toast.style.minWidth = '280px';
    toast.style.maxWidth = '400px';
    toast.style.animation = 'slide-in 0.2s cubic-bezier(0, 0, 0.2, 1) forwards';
    toast.textContent = message;

    wrapper.appendChild(toast);

    // CSS Keyframe styles inline definition (once only)
    if (!document.getElementById('toast-style-def')) {
      const styles = document.createElement('style');
      styles.id = 'toast-style-def';
      styles.textContent = `
        @keyframes slide-in {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes fade-out {
          to { transform: translateY(8px); opacity: 0; }
        }
      `;
      document.head.appendChild(styles);
    }

    setTimeout(() => {
      toast.style.animation = 'fade-out 0.3s ease-in-out forwards';
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }
}

// Instantiate application
const app = new NetPulseApp();
window.addEventListener('DOMContentLoaded', () => {
  app.init().then(() => {
    console.log("NetPulse dashboard successfully running.");
  });
});
