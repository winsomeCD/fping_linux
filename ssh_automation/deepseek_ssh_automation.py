#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Automation GUI - PySide6 version
简洁、现代、健壮的一体化网络自动化工具
依赖: PySide6, paramiko, concurrent.futures
"""

import sys
import os
import csv
import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

from PySide6.QtCore import (
    Qt, QSettings, QThread, Signal, Slot, QObject, QRunnable, QThreadPool
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableView, QHeaderView, QPushButton, QLineEdit,
    QListWidget, QListWidgetItem, QAbstractItemView, QComboBox,
    QLabel, QProgressBar, QSpinBox, QFileDialog, QMessageBox,
    QInputDialog, QDialog, QDialogButtonBox, QFormLayout,
    QGroupBox, QRadioButton, QButtonGroup, QFrame, QStatusBar,
    QTableWidget, QTableWidgetItem, QAbstractButton
)
from PySide6.QtGui import QStandardItemModel, QStandardItem, QAction, QIcon

# ---------- 复用原有业务函数 ----------
# 请确保 network_automation.py 存在且包含以下函数：
# load_inventory(path) -> list[dict]
# save_inventory(path, rows)
# load_commands(path) -> list[str]
# save_commands(path, lines)
# run_commands_on_device(device, commands, auth, output_dir) -> dict
from network_automation import (
    load_inventory, save_inventory,
    load_commands, save_commands,
    run_commands_on_device
)

# ---------- 常量 ----------
KNOWN_DEVICE_TYPES = [
    "cisco_ios", "cisco_xe", "cisco_nxos",
    "aruba_aoscx", "aruba_osswitch", "aruba_os",
    "hp_comware", "juniper_junos", "juniper"
]
INVENTORY_COLUMNS = ["hostname", "ip", "device_type", "group"]
DEFAULT_INVENTORY = "inventory.csv"
DEFAULT_COMMANDS = "commands.txt"
DEFAULT_OUTPUT_DIR = "output"

# ---------- 设备编辑对话框 ----------
class DeviceDialog(QDialog):
    def __init__(self, parent=None, title="Add Device", initial: Optional[Dict] = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.initial = initial or {col: "" for col in INVENTORY_COLUMNS}
        self.result_data = None
        self._build_ui()
        self._load_initial()

    def _build_ui(self):
        layout = QFormLayout(self)
        self.hostname_edit = QLineEdit()
        self.ip_edit = QLineEdit()
        self.type_combo = QComboBox()
        self.type_combo.addItems(KNOWN_DEVICE_TYPES)
        self.type_combo.setEditable(True)  # 允许手动输入
        self.group_edit = QLineEdit()

        layout.addRow("Hostname:", self.hostname_edit)
        layout.addRow("IP:", self.ip_edit)
        layout.addRow("Device type:", self.type_combo)
        layout.addRow("Group (optional):", self.group_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _load_initial(self):
        self.hostname_edit.setText(self.initial.get("hostname", ""))
        self.ip_edit.setText(self.initial.get("ip", ""))
        idx = self.type_combo.findText(self.initial.get("device_type", ""))
        if idx >= 0:
            self.type_combo.setCurrentIndex(idx)
        else:
            self.type_combo.setEditText(self.initial.get("device_type", ""))
        self.group_edit.setText(self.initial.get("group", ""))

    def accept(self):
        hostname = self.hostname_edit.text().strip()
        ip = self.ip_edit.text().strip()
        device_type = self.type_combo.currentText().strip()
        group = self.group_edit.text().strip()
        if not hostname or not ip or not device_type:
            QMessageBox.critical(self, "Missing fields", "Hostname, IP, and device type are required.")
            return
        self.result_data = {
            "hostname": hostname,
            "ip": ip,
            "device_type": device_type,
            "group": group,
        }
        super().accept()


# ---------- Inventory 数据模型 ----------
class InventoryModel(QStandardItemModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHorizontalHeaderLabels(INVENTORY_COLUMNS)
        self.rows = []  # 原始字典列表

    def load_from_list(self, rows: List[Dict]):
        """从字典列表加载数据"""
        self.rows = rows[:]
        self.clear()
        self.setHorizontalHeaderLabels(INVENTORY_COLUMNS)
        for row in rows:
            items = [QStandardItem(row[col]) for col in INVENTORY_COLUMNS]
            self.appendRow(items)

    def get_rows(self) -> List[Dict]:
        """将模型数据转回字典列表"""
        rows = []
        for r in range(self.rowCount()):
            row_data = {}
            for c, col in enumerate(INVENTORY_COLUMNS):
                item = self.item(r, c)
                row_data[col] = item.text() if item else ""
            rows.append(row_data)
        return rows

    def add_row(self, row_dict: Dict):
        self.rows.append(row_dict)
        items = [QStandardItem(row_dict[col]) for col in INVENTORY_COLUMNS]
        self.appendRow(items)

    def update_row(self, index: int, row_dict: Dict):
        if 0 <= index < self.rowCount():
            self.rows[index] = row_dict
            for c, col in enumerate(INVENTORY_COLUMNS):
                self.setData(self.index(index, c), row_dict[col])

    def delete_row(self, index: int):
        if 0 <= index < self.rowCount():
            self.removeRow(index)
            del self.rows[index]

    def save_to_file(self, path: str):
        save_inventory(path, self.get_rows())

    def load_from_file(self, path: str):
        rows = load_inventory(path)
        self.load_from_list(rows)


# ---------- 后台执行 Worker (QRunnable) ----------
class RunSignals(QObject):
    """用于跨线程通信的信号集合"""
    result_received = Signal(dict)   # 每个设备完成时发送结果字典
    progress = Signal(int, int)      # (completed, total)
    finished = Signal()              # 全部完成
    error = Signal(str)              # 发生致命错误


class RunWorker(QRunnable):
    def __init__(self, devices, commands, auth, output_dir, max_workers):
        super().__init__()
        self.devices = devices
        self.commands = commands
        self.auth = auth
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.signals = RunSignals()
        self._cancel = False

    def cancel(self):
        """设置取消标志"""
        self._cancel = True

    @Slot()
    def run(self):
        """在后台线程池中执行"""
        total = len(self.devices)
        completed = 0
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_device = {
                    executor.submit(
                        run_commands_on_device,
                        device, self.commands, self.auth, self.output_dir
                    ): device
                    for device in self.devices
                }
                for future in as_completed(future_to_device):
                    if self._cancel:
                        # 取消时不再处理剩余任务，但已经提交的任务无法取消，只能忽略结果
                        # 此处我们简单退出，不等待未完成的任务（但线程池会继续执行，不过结果被丢弃）
                        break
                    device = future_to_device[future]
                    try:
                        result = future.result(timeout=60)  # 可设置超时
                    except Exception as e:
                        result = {
                            "hostname": device.get("hostname", "unknown"),
                            "ip": device.get("ip", ""),
                            "success": False,
                            "error": str(e),
                            "outfile": ""
                        }
                    completed += 1
                    self.signals.progress.emit(completed, total)
                    self.signals.result_received.emit(result)
        except Exception as e:
            self.signals.error.emit(str(e))
        finally:
            self.signals.finished.emit()


# ---------- 主窗口 ----------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Automation")
        self.resize(900, 650)

        # 加载 QSettings
        self.settings = QSettings("MyCompany", "NetAutoGUI")

        # 文件路径
        self.inventory_path = self.settings.value("inventory_path", DEFAULT_INVENTORY)
        self.commands_path = self.settings.value("commands_path", DEFAULT_COMMANDS)
        self.output_dir = self.settings.value("output_dir", DEFAULT_OUTPUT_DIR)

        # 数据模型
        self.inv_model = InventoryModel(self)
        self._load_inventory()

        self.command_lines = []
        self._load_commands()

        # 后台线程池
        self.threadpool = QThreadPool.globalInstance()
        self.current_worker = None

        # 构建 UI
        self._create_menubar()
        self._create_central_widget()
        self._create_statusbar()

        # 恢复窗口几何
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)

    # ---------- 初始化数据 ----------
    def _load_inventory(self):
        try:
            rows = load_inventory(self.inventory_path)
            self.inv_model.load_from_list(rows)
        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load inventory: {e}")
            self.inv_model.load_from_list([])

    def _load_commands(self):
        try:
            self.command_lines = load_commands(self.commands_path)
        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load commands: {e}")
            self.command_lines = []
        self._refresh_command_list()

    def _save_inventory(self):
        try:
            self.inv_model.save_to_file(self.inventory_path)
            self.statusBar().showMessage(f"Inventory saved to {self.inventory_path}", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save inventory: {e}")

    def _save_commands(self):
        try:
            save_commands(self.commands_path, self.command_lines)
            self.statusBar().showMessage(f"Commands saved to {self.commands_path}", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save commands: {e}")

    # ---------- 构建 UI ----------
    def _create_menubar(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")
        # 快速保存
        save_inv_act = QAction("Save Inventory", self)
        save_inv_act.triggered.connect(self._save_inventory)
        file_menu.addAction(save_inv_act)
        save_cmd_act = QAction("Save Commands", self)
        save_cmd_act.triggered.connect(self._save_commands)
        file_menu.addAction(save_cmd_act)
        file_menu.addSeparator()
        exit_act = QAction("Exit", self)
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        run_menu = menubar.addMenu("&Run")
        run_act = QAction("Start Run", self)
        run_act.triggered.connect(self._start_run)
        run_menu.addAction(run_act)
        stop_act = QAction("Stop", self)
        stop_act.triggered.connect(self._stop_run)
        run_menu.addAction(stop_act)

    def _create_central_widget(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(6, 6, 6, 6)

        # 选项卡
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # 三个标签页
        self.inv_tab = self._create_inventory_tab()
        self.cmd_tab = self._create_commands_tab()
        self.run_tab = self._create_run_tab()
        self.tab_widget.addTab(self.inv_tab, "Inventory")
        self.tab_widget.addTab(self.cmd_tab, "Commands")
        self.tab_widget.addTab(self.run_tab, "Run")

    def _create_statusbar(self):
        self.statusBar().showMessage("Ready")

    # ---------- Inventory 标签页 ----------
    def _create_inventory_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 表格
        self.inv_table = QTableView()
        self.inv_table.setModel(self.inv_model)
        self.inv_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.inv_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.inv_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.inv_table)

        # 工具栏
        toolbar = QHBoxLayout()
        btn_add = QPushButton("Add")
        btn_add.clicked.connect(self._add_device)
        toolbar.addWidget(btn_add)

        btn_edit = QPushButton("Edit")
        btn_edit.clicked.connect(self._edit_device)
        toolbar.addWidget(btn_edit)

        btn_delete = QPushButton("Delete")
        btn_delete.clicked.connect(self._delete_device)
        toolbar.addWidget(btn_delete)

        btn_refresh = QPushButton("Reload")
        btn_refresh.clicked.connect(self._reload_inventory)
        toolbar.addWidget(btn_refresh)

        btn_save = QPushButton("Save")
        btn_save.clicked.connect(self._save_inventory)
        toolbar.addWidget(btn_save)

        toolbar.addStretch()
        layout.addLayout(toolbar)
        return tab

    def _add_device(self):
        dlg = DeviceDialog(self, "Add Device")
        if dlg.exec() == QDialog.Accepted and dlg.result_data:
            self.inv_model.add_row(dlg.result_data)
            self.statusBar().showMessage("Device added (unsaved)", 2000)

    def _edit_device(self):
        idx = self._get_selected_inv_index()
        if idx is None:
            return
        row_dict = self.inv_model.get_rows()[idx]
        dlg = DeviceDialog(self, "Edit Device", initial=row_dict)
        if dlg.exec() == QDialog.Accepted and dlg.result_data:
            self.inv_model.update_row(idx, dlg.result_data)
            self.statusBar().showMessage("Device updated (unsaved)", 2000)

    def _delete_device(self):
        idx = self._get_selected_inv_index()
        if idx is None:
            return
        row = self.inv_model.get_rows()[idx]
        reply = QMessageBox.question(
            self, "Delete Device",
            f"Remove {row['hostname']} ({row['ip']}) from inventory?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.inv_model.delete_row(idx)
            self.statusBar().showMessage("Device deleted (unsaved)", 2000)

    def _reload_inventory(self):
        reply = QMessageBox.question(
            self, "Reload",
            "Discard unsaved changes and reload from file?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self._load_inventory()
            self.statusBar().showMessage("Inventory reloaded", 2000)

    def _get_selected_inv_index(self) -> Optional[int]:
        selection = self.inv_table.selectionModel().selectedRows()
        if not selection:
            QMessageBox.information(self, "No Selection", "Select a device row first.")
            return None
        return selection[0].row()

    # ---------- Commands 标签页 ----------
    def _create_commands_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.cmd_list = QListWidget()
        self.cmd_list.setSelectionMode(QAbstractItemView.SingleSelection)
        layout.addWidget(self.cmd_list)

        toolbar = QHBoxLayout()
        btn_add = QPushButton("Add")
        btn_add.clicked.connect(self._add_command)
        toolbar.addWidget(btn_add)

        btn_edit = QPushButton("Edit")
        btn_edit.clicked.connect(self._edit_command)
        toolbar.addWidget(btn_edit)

        btn_delete = QPushButton("Delete")
        btn_delete.clicked.connect(self._delete_command)
        toolbar.addWidget(btn_delete)

        btn_up = QPushButton("Move Up")
        btn_up.clicked.connect(lambda: self._move_command(-1))
        toolbar.addWidget(btn_up)

        btn_down = QPushButton("Move Down")
        btn_down.clicked.connect(lambda: self._move_command(1))
        toolbar.addWidget(btn_down)

        btn_refresh = QPushButton("Reload")
        btn_refresh.clicked.connect(self._reload_commands)
        toolbar.addWidget(btn_refresh)

        btn_save = QPushButton("Save")
        btn_save.clicked.connect(self._save_commands)
        toolbar.addWidget(btn_save)

        toolbar.addStretch()
        layout.addLayout(toolbar)
        return tab

    def _refresh_command_list(self):
        self.cmd_list.clear()
        for line in self.command_lines:
            self.cmd_list.addItem(line)

    def _add_command(self):
        text, ok = QInputDialog.getText(self, "Add Command", "Enter CLI command:")
        if ok and text.strip():
            self.command_lines.append(text.strip())
            self.cmd_list.addItem(text.strip())
            self.statusBar().showMessage("Command added (unsaved)", 2000)

    def _edit_command(self):
        idx = self._get_selected_cmd_index()
        if idx is None:
            return
        current = self.command_lines[idx]
        text, ok = QInputDialog.getText(self, "Edit Command", "Edit CLI command:", text=current)
        if ok and text.strip():
            self.command_lines[idx] = text.strip()
            self.cmd_list.item(idx).setText(text.strip())
            self.statusBar().showMessage("Command updated (unsaved)", 2000)

    def _delete_command(self):
        idx = self._get_selected_cmd_index()
        if idx is None:
            return
        reply = QMessageBox.question(
            self, "Delete Command",
            f"Remove command: {self.command_lines[idx]!r}?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            del self.command_lines[idx]
            self.cmd_list.takeItem(idx)
            self.statusBar().showMessage("Command deleted (unsaved)", 2000)

    def _move_command(self, direction):
        idx = self._get_selected_cmd_index()
        if idx is None:
            return
        new_idx = idx + direction
        if 0 <= new_idx < len(self.command_lines):
            self.command_lines[idx], self.command_lines[new_idx] = (
                self.command_lines[new_idx], self.command_lines[idx]
            )
            self._refresh_command_list()
            self.cmd_list.setCurrentRow(new_idx)
            self.statusBar().showMessage("Moved (unsaved)", 2000)

    def _reload_commands(self):
        reply = QMessageBox.question(
            self, "Reload",
            "Discard unsaved changes and reload from file?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self._load_commands()
            self.statusBar().showMessage("Commands reloaded", 2000)

    def _get_selected_cmd_index(self) -> Optional[int]:
        items = self.cmd_list.selectedItems()
        if not items:
            QMessageBox.information(self, "No Selection", "Select a command first.")
            return None
        return self.cmd_list.row(items[0])

    # ---------- Run 标签页 ----------
    def _create_run_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 顶部说明
        info = QLabel(
            f"Runs against devices/commands shown in tabs (even if unsaved). "
            f"Full CLI output saved to '{self.output_dir}/' as .txt files."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # 认证区域
        auth_group = QGroupBox("Authentication")
        auth_layout = QVBoxLayout(auth_group)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Username:"))
        self.username_edit = QLineEdit()
        self.username_edit.setText(self.settings.value("username", ""))
        row1.addWidget(self.username_edit)

        # 认证方式单选
        self.auth_group = QButtonGroup(self)
        self.pw_radio = QRadioButton("Password")
        self.key_radio = QRadioButton("SSH Key")
        self.auth_group.addButton(self.pw_radio)
        self.auth_group.addButton(self.key_radio)
        self.pw_radio.setChecked(True)
        row1.addWidget(self.pw_radio)
        row1.addWidget(self.key_radio)
        row1.addStretch()
        auth_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Password:"))
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        row2.addWidget(self.password_edit)

        row2.addWidget(QLabel("Key File:"))
        self.key_file_edit = QLineEdit()
        self.key_file_edit.setEnabled(False)
        row2.addWidget(self.key_file_edit)
        self.key_browse_btn = QPushButton("Browse")
        self.key_browse_btn.setEnabled(False)
        self.key_browse_btn.clicked.connect(self._browse_key)
        row2.addWidget(self.key_browse_btn)
        row2.addStretch()
        auth_layout.addLayout(row2)

        # 连接认证切换
        self.pw_radio.toggled.connect(self._toggle_auth)
        self.key_radio.toggled.connect(self._toggle_auth)

        layout.addWidget(auth_group)

        # 控制区域
        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("Concurrency:"))
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 50)
        self.concurrency_spin.setValue(5)
        control_layout.addWidget(self.concurrency_spin)

        self.start_btn = QPushButton("Start Run")
        self.start_btn.clicked.connect(self._start_run)
        control_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_run)
        control_layout.addWidget(self.stop_btn)

        control_layout.addStretch()
        layout.addLayout(control_layout)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # 结果表格
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(4)
        self.result_table.setHorizontalHeaderLabels(["Hostname", "IP", "Status", "Detail"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.result_table)

        return tab

    def _toggle_auth(self):
        if self.pw_radio.isChecked():
            self.password_edit.setEnabled(True)
            self.key_file_edit.setEnabled(False)
            self.key_browse_btn.setEnabled(False)
        else:
            self.password_edit.setEnabled(False)
            self.key_file_edit.setEnabled(True)
            self.key_browse_btn.setEnabled(True)

    def _browse_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select SSH Private Key")
        if path:
            self.key_file_edit.setText(path)

    # ---------- 运行控制 ----------
    def _start_run(self):
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)

        # 验证输入
        devices = self.inv_model.get_rows()
        if not devices:
            QMessageBox.warning(self, "No Devices", "Inventory is empty.")
            return
        if not self.command_lines:
            QMessageBox.warning(self, "No Commands", "Command list is empty.")
            return

        username = self.username_edit.text().strip()
        if not username:
            QMessageBox.warning(self, "Missing Username", "Enter a username.")
            return

        if self.pw_radio.isChecked():
            password = self.password_edit.text()
            if not password:
                QMessageBox.warning(self, "Missing Password", "Enter a password.")
                return
            auth = {"method": "password", "username": username, "password": password}
        else:
            key_file = self.key_file_edit.text().strip()
            if not key_file:
                QMessageBox.warning(self, "Missing Key File", "Select an SSH private key.")
                return
            auth = {"method": "key", "username": username, "key_file": key_file}

        # 保存设置
        self.settings.setValue("username", username)

        # 清空旧结果
        self.result_table.setRowCount(0)
        self.progress_bar.setValue(0)

        # 启动后台worker
        self.current_worker = RunWorker(
            devices, self.command_lines, auth, self.output_dir,
            self.concurrency_spin.value()
        )
        # 连接信号
        self.current_worker.signals.result_received.connect(self._on_result)
        self.current_worker.signals.progress.connect(self._on_progress)
        self.current_worker.signals.finished.connect(self._on_finished)
        self.current_worker.signals.error.connect(self._on_worker_error)

        # 禁用启动按钮，启用停止
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.statusBar().showMessage("Running...")

        # 提交任务到线程池
        self.threadpool.start(self.current_worker)

    def _stop_run(self):
        if self.current_worker:
            self.current_worker.cancel()
            self.stop_btn.setEnabled(False)
            self.statusBar().showMessage("Stopping... (pending tasks may complete)")

    def _on_result(self, result: dict):
        """接收到单个设备结果"""
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        self.result_table.setItem(row, 0, QTableWidgetItem(result.get("hostname", "")))
        self.result_table.setItem(row, 1, QTableWidgetItem(result.get("ip", "")))
        status = "Success" if result.get("success") else "Failed"
        item = QTableWidgetItem(status)
        if result.get("success"):
            item.setForeground(Qt.green)
        else:
            item.setForeground(Qt.red)
        self.result_table.setItem(row, 2, item)
        detail = result.get("outfile") if result.get("success") else result.get("error", "")
        self.result_table.setItem(row, 3, QTableWidgetItem(detail))

    def _on_progress(self, completed, total):
        """进度更新"""
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(completed)
        self.statusBar().showMessage(f"Running... {completed}/{total}")

    def _on_finished(self):
        """全部完成"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.current_worker = None
        self.statusBar().showMessage("Run completed")

    def _on_worker_error(self, error_msg):
        QMessageBox.critical(self, "Run Error", f"Worker error: {error_msg}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.current_worker = None

    # ---------- 关闭事件 ----------
    def closeEvent(self, event):
        # 保存窗口几何
        self.settings.setValue("geometry", self.saveGeometry())
        # 如果有任务运行，询问是否退出
        if self.current_worker:
            reply = QMessageBox.question(
                self, "Run in progress",
                "A run is still in progress. Quit anyway?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
        event.accept()


# ---------- 样式表 ----------
STYLE = """
QMainWindow {
    background: #f0f0f0;
}
QTabWidget::pane {
    border: 1px solid #ccc;
    background: white;
}
QTableView, QListWidget, QTableWidget {
    alternate-background-color: #fafafa;
    selection-background-color: #d0e0ff;
}
QPushButton {
    background: #e1e1e1;
    border: 1px solid #aaa;
    border-radius: 4px;
    padding: 4px 10px;
}
QPushButton:hover {
    background: #d0d0d0;
}
QPushButton:pressed {
    background: #c0c0c0;
}
QLineEdit, QComboBox, QSpinBox {
    border: 1px solid #aaa;
    border-radius: 3px;
    padding: 3px;
}
QProgressBar {
    border: 1px solid #aaa;
    border-radius: 4px;
    text-align: center;
}
QProgressBar::chunk {
    background: #4caf50;
    width: 10px;
}
"""


# ---------- 入口 ----------
def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()