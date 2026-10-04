markdown
# Network Automation GUI

A modern, all-in-one graphical interface for network automation built with PySide6. Manage device inventories, edit command sets, and execute batch SSH operations with ease.

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![PySide6](https://img.shields.io/badge/PySide6-6.4+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

## ✨ Features

- 📋 **Device Inventory Management** – Add, edit, delete, and persist devices in CSV format
- 📝 **Command Set Editor** – Add, remove, reorder commands, and save as plain text
- 🚀 **Batch SSH Execution** – Run commands concurrently with password or SSH key authentication
- 📊 **Real-time Feedback** – Progress bar, status bar, and results table (success/failure/details)
- 🛑 **Task Cancellation** – Stop running jobs at any time
- 🎨 **Modern UI** – Flat design, responsive layout, and clean aesthetics
- ⚙️ **Persistent Settings** – Remembers window geometry, username, and file paths

## 🖥️ Screenshots

*(Insert screenshots here if available)*

## 📦 Dependencies

- Python 3.8+
- PySide6 >= 6.4
- paramiko >= 2.8
- (Core business logic) `network_automation.py` module (must be provided separately – see below)

## 🔧 Installation

### 1. Clone or download the code

```bash
git clone https://github.com/yourusername/netauto-gui.git
cd netauto-gui
2. Install Python dependencies
bash
pip install PySide6 paramiko
3. Prepare the business logic module
This GUI relies on network_automation.py, which must export the following five functions with exact signatures:

python
def load_inventory(path: str) -> list[dict]:
    """Read CSV inventory, return list of dicts with keys: hostname, ip, device_type, group"""

def save_inventory(path: str, rows: list[dict]) -> None:
    """Write inventory dict list to CSV"""

def load_commands(path: str) -> list[str]:
    """Read command text file, return list of command strings (one per line)"""

def save_commands(path: str, lines: list[str]) -> None:
    """Write command list to text file"""

def run_commands_on_device(device: dict, commands: list[str], auth: dict, output_dir: str) -> dict:
    """
    Execute commands on a single device. Return result dict.
    auth format: {'method': 'password', 'username': str, 'password': str}
               or {'method': 'key', 'username': str, 'key_file': str}
    Return dict must contain: hostname, ip, success (bool),
                              error (if failed), outfile (if success, path to saved output)
    """
Place your existing network_automation.py in the same directory, or adjust the import path as needed.

4. Run the application
bash
python netauto_gui.py
📂 File Descriptions
netauto_gui.py – Main GUI application (all code in one file)

inventory.csv – Default inventory file (auto‑created/loaded on startup)

commands.txt – Default command file (auto‑created/loaded on startup)

output/ – Default output directory; each device’s raw CLI output is saved as {hostname}.txt

🧭 User Guide
1. Manage Inventory (Inventory Tab)
Add – Click Add, fill in hostname, IP, device type (dropdown or manual input), and optional group.

Edit – Select a row, click Edit, modify fields.

Delete – Select a row, click Delete, confirm removal.

Save – Click Save to write current in‑memory inventory to inventory.csv.

Reload – Click Reload to discard unsaved changes and reload from file.

💡 Device types include common vendors (Cisco, Aruba, Juniper, HP, etc.), but you can also type any custom value.

2. Edit Commands (Commands Tab)
Add – Click Add, enter a CLI command (e.g., show version) in the dialog.

Edit – Select a command, click Edit to modify it.

Delete – Select a command, click Delete.

Move – Select a command, use Move Up / Move Down to reorder execution sequence.

Save – Click Save to write to commands.txt.

Reload – Click Reload to discard changes and reload from file.

3. Run Automation (Run Tab)
Authentication – Choose Password or SSH Key and provide credentials.

For SSH Key, click Browse to select your private key file (e.g., id_rsa).

Concurrency – Set the number of parallel SSH connections (recommended 5–10).

Start – Click Start Run. The program will sequentially execute the current command list on each device.

Full raw CLI output is saved to output/ as {hostname}.txt.

The results table shows only success/failure status and a brief detail (output file path on success, error message on failure).

Stop – Click Stop to cancel pending tasks. Already running commands may complete, but their results are ignored.

Progress bar and status bar provide real‑time feedback.

⚙️ Configuration & Customization
Default file paths can be changed by modifying DEFAULT_INVENTORY, DEFAULT_COMMANDS, DEFAULT_OUTPUT_DIR at the top of the code.

The application uses QSettings to remember window size, position, and the last used username – no extra config file needed.

UI styling can be customized by editing the STYLE variable (Qt Style Sheet).

🐛 Troubleshooting
Q: ModuleNotFoundError: No module named 'PySide6'
A: Ensure PySide6 is installed: pip install PySide6.

Q: ImportError: cannot import name 'load_inventory' from 'network_automation'
A: Verify that network_automation.py exists and exports all required functions. If function names differ, adjust the import or modify your module.

Q: The application freezes during a run?
A: Check network connectivity and device reachability. Also verify authentication credentials. If concurrency is too high, try lowering the value.

Q: Where can I see the full SSH output?
A: Output files are saved under output/ (e.g., output/router1.txt). Open them with any text editor.

Q: The Stop button doesn't work immediately?
A: Stop sends a cancellation signal, but a command that is already executing (e.g., show running-config) cannot be aborted until it completes.

🤝 Contributing
Issues and pull requests are welcome. Before submitting code, please ensure:

Code follows PEP 8 style

New features include appropriate comments

Simplicity, readability, and robustness are maintained

📄 License
This project is licensed under the MIT License – see the LICENSE file for details.