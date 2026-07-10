# SPEC.md — Project Specification

> **Status**: `FINALIZED`

## Vision
A unified, web-based control center for network administrators to monitor, manage, back up, and connect to multi-vendor network devices (routers, switches, and firewalls) via SSH, Telnet, and APIs, featuring a hybrid mock/real execution design.

## Goals
1. **Unified Dashboard**: High-fidelity dashboard displaying device health, activity charts, configuration backups, and real-time network logs.
2. **Device List Management**: Ability to add, remove, and modify routers, switches, and firewalls, along with connection parameters.
3. **Interactive Terminal Session**: A simulated CLI shell with dynamic prompt adjustments depending on device types (Cisco, Huawei, Juniper, generic), capable of mimicking command execution outputs.
4. **Configuration Control**: Backup device running-configs, download config archives, and highlight differences between backups using a native diff tool.
5. **Multi-User Security**: Role-based access control with distinct permission profiles (Administrator, Operator, Viewer).
6. **Real-time Log Stream**: A simulated scrolling console capturing network event logging.

## Non-Goals (Out of Scope for initial milestone)
- Real routing table sync or network topology auto-discovery.
- Integration with external directory services (e.g., LDAP, Active Directory, OAuth) beyond simulated local RBAC.

## Users
- **Network Administrators**: Need full configuration, backup, user administration, and terminal access.
- **Operations Staff (Operators)**: Need to inspect lists, trigger backups, and use terminal CLI to diagnose issues.
- **Support Staff (Viewers)**: Need read-only access to verify statuses, logs, and configuration differences without command execution capabilities.

## Constraints
- Must be a pure web-friendly client with simulated APIs utilizing LocalStorage for persistence.
- Built without complex heavy frontend frameworks (React/Vue/Angular) unless explicitly requested; standard HTML, CSS grid/flexbox, and vanilla Javascript will run directly in browsers.
- Must provide clean integration hooks for real Node.js SSH terminals.

## Success Criteria
- [ ] Responsive dark-theme dashboard renders perfectly across device dimensions.
- [ ] Terminal allows command input, shows responsive vendor-specific syntax output, and maintains history.
- [ ] Users can edit/delete devices and save states persistently.
- [ ] Backups can be triggered, compared visually, and downloaded.
- [ ] Role constraints are enforced correctly, locking down buttons and terminal sessions according to current session profile.
