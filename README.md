# 🛡️ SOC Shield — Cybersecurity Incident Response Database

> **DBMS Mini Project** — Demonstrating SQL Role-Based Access Control (RBAC) and Database Security

A full-stack **Security Operations Center (SOC)** incident management system built with Node.js, Express, and MySQL. The project simulates how a real SOC enforces **SQL-based access control**, where every database action is gated by role permissions — exactly like `GRANT` and `REVOKE` in SQL.

---

## � Preview

| Login Page | Dashboard | RBAC Permissions |
|---|---|---|
| *Dark cyberpunk login with quick-demo buttons* | *Stats, charts, recent incidents* | *SQL GRANT matrix per role* |

---

## ✨ Features

- 🔐 **SQL RBAC** — Permissions stored in a `RolePermissions` table, mirroring SQL `GRANT` statements
- 👥 **4 Roles** — Admin, SOC Manager, Security Analyst, Auditor
- 🚨 **Incident Management** — Full CRUD with severity color-coding (Critical → Low)
- � **Threat Reports** — Analysts submit IOC-rich investigation reports
- 📜 **Audit Logs** — Every action (including denied attempts) is logged with IP and timestamp
- 🖥️ **Systems Inventory** — Track monitored assets and their compromise status
- 📊 **Live Dashboard** — Doughnut + bar charts via Chart.js, animated stat counters
- 🎨 **Cyberpunk Dark Theme** — Neon cyan/green, glowing icons, blinking DEFCON indicator

---

## 🗄️ Database Schema

```
Roles           — role_id, role_name, description
Users           — user_id, name, email, password (bcrypt), role_id
Incidents       — incident_id, title, description, severity, status, reported_by, assigned_to
Systems         — system_id, system_name, ip_address, owner, status
ThreatReports   — report_id, incident_id, analyst_id, report_text, findings, ioc_data
AccessLogs      — log_id, user_id, action, resource, status, ip_address, timestamp
RolePermissions — role_name, resource, action  ← Core RBAC table
```

---

## 🔒 SQL RBAC — How It Works

Permissions are stored in a `RolePermissions` table and checked at the middleware layer before every API call. This mirrors real SQL `GRANT`/`REVOKE` semantics:

```sql
-- Admin: Full access
GRANT SELECT, INSERT, UPDATE, DELETE ON incidents TO admin;

-- SOC Manager: View + assign
GRANT SELECT, INSERT, UPDATE ON incidents TO soc_manager;

-- Security Analyst: View assigned + submit reports
GRANT SELECT, UPDATE ON incidents TO security_analyst;
GRANT SELECT, INSERT ON threat_reports TO security_analyst;

-- Auditor: Read-only
GRANT SELECT ON incidents TO auditor;
GRANT SELECT ON access_logs TO auditor;
```

When a role lacks permission, the server returns a structured **Access Denied** response:
```json
{
  "error": "Access Denied: Role 'auditor' does not have UPDATE permission on 'incidents'.",
  "rbac_info": {
    "role": "auditor",
    "resource": "incidents",
    "action": "UPDATE",
    "sql_equivalent": "REVOKE UPDATE ON incidents FROM auditor;"
  }
}
```

---

## 🎭 Demo Accounts

| Role | Email | Password | Access Level |
|------|-------|----------|--------------|
| **Admin** | admin@soc.com | admin123 | Full CRUD on all resources |
| **SOC Manager** | manager@soc.com | manager123 | Assign analysts, view all |
| **Security Analyst** | analyst@soc.com | analyst123 | Assigned incidents only |
| **Auditor** | auditor@soc.com | auditor123 | Read-only, no writes |

---

## 🚀 Setup & Run

### Prerequisites
- [Node.js](https://nodejs.org) v16+
- [MySQL](https://dev.mysql.com/downloads/) 8.0+

### 1. Clone the repo
```bash
git clone https://github.com/HarshitJK/Cybersecurity-Incident-Response-Database.git
cd Cybersecurity-Incident-Response-Database
```

### 2. Configure environment
```bash
cp .env.example .env
```
Edit `.env` and set your MySQL credentials:
```
DB_USER=root
DB_PASSWORD=your_mysql_password
```

### 3. Install dependencies
```bash
npm install
```

### 4. Seed the database
```bash
node database/seed.js
```
This creates all tables, inserts demo data, and sets up the RBAC permission matrix.

### 5. Start the server
```bash
node server.js
```

### 6. Open the app
```
http://localhost:3000
```

---

## 📁 Project Structure

```
soc-shield/
├── server.js               # Express entry point
├── .env.example            # Environment template
├── database/
│   ├── schema.sql          # CREATE TABLE + GRANT statements
│   ├── seed.js             # Demo data seeder
│   └── db.js               # MySQL connection pool
├── middleware/
│   └── auth.js             # RBAC enforcement + access logging
├── routes/
│   ├── auth.js             # Login / logout
│   ├── incidents.js        # Incident CRUD
│   ├── users.js            # User management
│   ├── reports.js          # Threat reports
│   ├── logs.js             # Audit logs
│   └── systems.js          # Systems inventory
└── public/
    ├── index.html          # SPA shell
    ├── css/style.css       # Cyberpunk dark theme
    └── js/app.js           # Frontend logic
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML5 · Vanilla CSS · Vanilla JavaScript |
| Charts | [Chart.js](https://chartjs.org) 4.4 |
| Backend | Node.js · Express.js |
| Auth | express-session · bcryptjs |
| Database | MySQL 8.0 |
| DB Driver | mysql2 (raw SQL — no ORM) |

---

## 📖 RBAC Demo Scenarios

1. **Analyst updates status** — Login as `analyst@soc.com`, edit an assigned incident, change status → ✅ Allowed
2. **Auditor blocked from writing** — Login as `auditor@soc.com`, attempt any edit → ❌ Access Denied (logged)
3. **Manager assigns analyst** — Login as `manager@soc.com`, assign an incident to an analyst → ✅ Allowed
4. **Admin creates user** — Login as `admin@soc.com`, go to User Management, create new account → ✅ Allowed

---

## � License

MIT — Free to use for educational purposes.

---

*Made for DBMS Mini Project — SQL Role-Based Access Control & Database Security*
