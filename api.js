/**
 * NETPULSE Network Client API Simulation Service Layer
 * Deals with localStorage persistence and simulated asynchronous network calls.
 */

const NetPulseAPI = (() => {
  
  // Default Seed Data
  const DEFAULT_DEVICES = [
    {
      id: "dev-1",
      name: "core-router-01",
      ip: "192.168.100.1",
      type: "Router",
      protocol: "SSH",
      port: 22,
      username: "admin",
      status: "Online",
      cpu: 18,
      ram: 42,
      lastBackup: "2026-07-08 14:32:10"
    },
    {
      id: "dev-2",
      name: "dist-switch-02",
      ip: "192.168.100.10",
      type: "Switch",
      protocol: "Telnet",
      port: 23,
      username: "operator",
      status: "Online",
      cpu: 8,
      ram: 29,
      lastBackup: "2026-07-09 09:15:45"
    },
    {
      id: "dev-3",
      name: "border-fw-01",
      ip: "10.10.200.254",
      type: "Firewall",
      protocol: "API",
      port: 443,
      username: "secadmin",
      status: "Online",
      cpu: 31,
      ram: 58,
      lastBackup: "Never"
    },
    {
      id: "dev-4",
      name: "branch-router-03",
      ip: "172.16.50.1",
      type: "Router",
      protocol: "SSH",
      port: 2022,
      username: "admin",
      status: "Offline",
      cpu: 0,
      ram: 0,
      lastBackup: "Never"
    }
  ];

  const DEFAULT_USERS = [
    { id: "usr-1", username: "admin", fullname: "Super Admin", role: "admin" },
    { id: "usr-2", username: "jdoe", fullname: "Jane Doe", role: "operator" },
    { id: "usr-3", username: "ro_guest", fullname: "Read-only Observer", role: "viewer" }
  ];

  // Helper Configuration Generator
  const generateMockConfig = (name, type, ip, timestamp, version = 1) => {
    const banner = `! Configuration file for ${name} (${type})\n! Generated at ${timestamp}\n! Software Version 15.4(3)M3\n!\n`;
    
    if (type === "Router") {
      return banner + 
`hostname ${name}
!
boot-start-marker
boot-end-marker
!
security passwords encryption-type standard
enable secret 9 $9$F94c1A7F9
!
interface GigabitEthernet0/0
 description WAN-Uplink
 ip address ${ip} 255.255.255.0
 duplex auto
 speed auto
 no shutdown
!
interface GigabitEthernet0/1
 description Local-LAN
 ip address 192.168.1.1 255.255.255.0
 ${version === 1 ? "speed auto" : "speed 1000\n negotiation auto"}
 no shutdown
!
${version === 1 ? "! IP route not configured" : "ip route 0.0.0.0 0.0.0.0 " + ip.substring(0, ip.lastIndexOf('.')) + ".254"}
!
line con 0
 exec-timeout 15 0
 stopbits 1
line vty 0 4
 transport input ssh
 login local
!
end`;
    } else if (type === "Switch") {
      return banner +
`sysname ${name}
#
vlan batch 10 20 30
#
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20 30
#
interface GigabitEthernet0/0/2
 port link-type access
 port default vlan 10
#
${version === 1 ? "# loopback disabled" : "loop-detect eth-loop-protection enable"}
#
interface Vlanif10
 ip address ${ip} 255.255.255.0
#
user-interface vty 0 4
 authentication-mode scheme
 protocol inbound telnet
#
return`;
    } else { // Firewall
      return banner +
`# System settings for firewall
hostname ${name}
#
security-zone trust
 import interface GigabitEthernet0/1
#
security-zone untrust
 import interface GigabitEthernet0/0
#
security-policy
 rule name Trust_to_Untrust
  source-zone trust
  destination-zone untrust
  action permit
${version === 1 ? " rule name Block_Bad_IP\n  action deny" : " rule name Block_Bad_IP\n  source-ip 198.51.100.45\n  action deny"}
#
interface GigabitEthernet0/0
 ip address ${ip} 255.255.255.0
#
return`;
    }
  };

  const DEFAULT_BACKUPS = [
    {
      id: "bak-1",
      deviceId: "dev-1",
      deviceName: "core-router-01",
      timestamp: "2026-07-08 14:32:10",
      content: generateMockConfig("core-router-01", "Router", "192.168.100.1", "2026-07-08 14:32:10", 1),
      notes: "Baseline Config"
    },
    {
      id: "bak-2",
      deviceId: "dev-1",
      deviceName: "core-router-01",
      timestamp: "2026-07-09 18:44:00",
      content: generateMockConfig("core-router-01", "Router", "192.168.100.1", "2026-07-09 18:44:00", 2),
      notes: "Updated speed auto rules and standard gateway routes"
    },
    {
      id: "bak-3",
      deviceId: "dev-2",
      deviceName: "dist-switch-02",
      timestamp: "2026-07-09 09:15:45",
      content: generateMockConfig("dist-switch-02", "Switch", "192.168.100.10", "2026-07-09 09:15:45", 1),
      notes: "VLAN additions checkout"
    }
  ];

  // LocalStorage Keys
  const KEYS = {
    DEVICES: "netpulse_devices",
    USERS: "netpulse_users",
    BACKUPS: "netpulse_backups",
    CURRENT_USER: "netpulse_cur_user"
  };

  // Initialization
  const initStorage = () => {
    if (!localStorage.getItem(KEYS.DEVICES)) {
      localStorage.setItem(KEYS.DEVICES, JSON.stringify(DEFAULT_DEVICES));
    }
    if (!localStorage.getItem(KEYS.USERS)) {
      localStorage.setItem(KEYS.USERS, JSON.stringify(DEFAULT_USERS));
    }
    if (!localStorage.getItem(KEYS.BACKUPS)) {
      localStorage.setItem(KEYS.BACKUPS, JSON.stringify(DEFAULT_BACKUPS));
    }
    if (!localStorage.getItem(KEYS.CURRENT_USER)) {
      localStorage.setItem(KEYS.CURRENT_USER, JSON.stringify(DEFAULT_USERS[0])); // Default is admin
    }
  };

  initStorage();

  // Helper Delay Promise
  const delay = (ms = 400) => new Promise(resolve => setTimeout(resolve, ms));

  return {
    // Current User Session Roles APIs
    getCurrentUser: async () => {
      await delay(100);
      return JSON.parse(localStorage.getItem(KEYS.CURRENT_USER));
    },

    setCurrentUserRole: async (role) => {
      await delay(100);
      const users = JSON.parse(localStorage.getItem(KEYS.USERS));
      const match = users.find(u => u.role === role) || users[0];
      localStorage.setItem(KEYS.CURRENT_USER, JSON.stringify(match));
      return match;
    },

    // Devices CRUD API
    getDevices: async () => {
      await delay(300);
      return JSON.parse(localStorage.getItem(KEYS.DEVICES)) || [];
    },

    saveDevice: async (device) => {
      await delay(500);
      const devices = JSON.parse(localStorage.getItem(KEYS.DEVICES)) || [];
      if (device.id) {
        // Edit existing
        const idx = devices.findIndex(d => d.id === device.id);
        if (idx !== -1) {
          // Keep old statuses and metrics unless overwritten
          devices[idx] = { ...devices[idx], ...device };
        }
      } else {
        // Add new
        device.id = "dev-" + Math.random().toString(36).substring(2, 9);
        device.status = Math.random() > 0.15 ? "Online" : "Offline"; // Randomly check accessibility
        device.cpu = device.status === "Online" ? Math.floor(Math.random() * 50) + 5 : 0;
        device.ram = device.status === "Online" ? Math.floor(Math.random() * 60) + 10 : 0;
        device.lastBackup = "Never";
        devices.push(device);
      }
      localStorage.setItem(KEYS.DEVICES, JSON.stringify(devices));
      return device;
    },

    deleteDevice: async (id) => {
      await delay(450);
      let devices = JSON.parse(localStorage.getItem(KEYS.DEVICES)) || [];
      devices = devices.filter(d => d.id !== id);
      localStorage.setItem(KEYS.DEVICES, JSON.stringify(devices));
      return true;
    },

    // Simulated Pings
    pingDevice: async (id) => {
      await delay(800);
      const devices = JSON.parse(localStorage.getItem(KEYS.DEVICES)) || [];
      const idx = devices.findIndex(d => d.id === id);
      if (idx !== -1) {
        const isOnline = Math.random() > 0.15;
        devices[idx].status = isOnline ? "Online" : "Offline";
        devices[idx].cpu = isOnline ? Math.floor(Math.random() * 45) + 8 : 0;
        devices[idx].ram = isOnline ? Math.floor(Math.random() * 50) + 12 : 0;
        localStorage.setItem(KEYS.DEVICES, JSON.stringify(devices));
        return devices[idx].status;
      }
      return "Offline";
    },

    // Config backups APIs
    getBackups: async () => {
      await delay(250);
      return JSON.parse(localStorage.getItem(KEYS.BACKUPS)) || [];
    },

    createBackup: async (deviceId, notes = "Manual Archive Checkin") => {
      await delay(1200); // Backups take a bit longer
      const devices = JSON.parse(localStorage.getItem(KEYS.DEVICES)) || [];
      const device = devices.find(d => d.id === deviceId);
      if (!device) throw new Error("Device not found");
      if (device.status === "Offline") throw new Error("Device unreachable (Offline)");

      const backups = JSON.parse(localStorage.getItem(KEYS.BACKUPS)) || [];
      const devBackups = backups.filter(b => b.deviceId === deviceId);
      const version = devBackups.length + 1;

      const dateStr = new Date().toISOString().slice(0, 19).replace('T', ' ');

      const newBackup = {
        id: "bak-" + Math.random().toString(36).substring(2, 9),
        deviceId: deviceId,
        deviceName: device.name,
        timestamp: dateStr,
        content: generateMockConfig(device.name, device.type, device.ip, dateStr, version),
        notes: notes
      };

      backups.unshift(newBackup); // Add to beginning
      localStorage.setItem(KEYS.BACKUPS, JSON.stringify(backups));

      // Update device last backup timestamp
      device.lastBackup = dateStr;
      localStorage.setItem(KEYS.DEVICES, JSON.stringify(devices));

      return newBackup;
    },

    deleteBackup: async (id) => {
      await delay(300);
      let backups = JSON.parse(localStorage.getItem(KEYS.BACKUPS)) || [];
      backups = backups.filter(b => b.id !== id);
      localStorage.setItem(KEYS.BACKUPS, JSON.stringify(backups));
      return true;
    },

    // Users & Roles APIs
    getUsers: async () => {
      await delay(200);
      return JSON.parse(localStorage.getItem(KEYS.USERS)) || [];
    },

    saveUser: async (user) => {
      await delay(400);
      const users = JSON.parse(localStorage.getItem(KEYS.USERS)) || [];
      if (user.id) {
        const idx = users.findIndex(u => u.id === user.id);
        if (idx !== -1) users[idx] = user;
      } else {
        user.id = "usr-" + Math.random().toString(36).substring(2, 9);
        users.push(user);
      }
      localStorage.setItem(KEYS.USERS, JSON.stringify(users));
      return user;
    },

    deleteUser: async (id) => {
      await delay(300);
      let users = JSON.parse(localStorage.getItem(KEYS.USERS)) || [];
      const target = users.find(u => u.id === id);
      if (target && target.username === "admin") {
        throw new Error("Cannot delete root admin account");
      }
      users = users.filter(u => u.id !== id);
      localStorage.setItem(KEYS.USERS, JSON.stringify(users));
      return true;
    }
  };
})();
