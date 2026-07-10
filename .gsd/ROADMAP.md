# ROADMAP.md

> **Current Phase**: Phase 1: Foundation and UI Skeleton
> **Milestone**: v1.0.0

## Must-Haves (from SPEC)
- [ ] Premium dark mode responsive layout dashboard.
- [ ] LocalStorage-backed CRUD for network devices.
- [ ] Simulated SSH/Telnet terminal console.
- [ ] Config backup, view, comparison (diff) and file download.
- [ ] User role selection/switching (Admin, Operator, Viewer) with permission locking.
- [ ] Real-time active simulated syslog stream.

## Phases

### Phase 1: Foundation and Layout Styling
**Status**: ⬜ Not Started
**Objective**: Build core page layout, apply slate-dark premium style rules, set up navigation tabs, and construct visual UI dashboards widgets/grids.
**Deliverables**: `index.html`, `style.css` base.

### Phase 2: Client APIs and Persistence Services
**Status**: ⬜ Not Started
**Objective**: Establish local mock database schema in Javascript, create simulated network adapter latency requests, and persist user/device states.
**Deliverables**: `api.js`.

### Phase 3: Core Dashboards and Terminal Mechanics
**Status**: ⬜ Not Started
**Objective**: Implement core CLI shell console parser, custom input terminal layout, syslog generator stream, configuration diff renderer, and role permissions locks.
**Deliverables**: `app.js`.

### Phase 4: Hybrid Server Shell Template
**Status**: ⬜ Not Started
**Objective**: Add Node.js connection middleware boilerplate to facilitate real integration for SSH/WS terminals.
**Deliverables**: `server.js`.
