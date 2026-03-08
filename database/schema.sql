-- ============================================================
-- SOC SHIELD - Cybersecurity Incident Response Database
-- Database Schema with SQL Role-Based Access Control (RBAC)
-- ============================================================

CREATE DATABASE IF NOT EXISTS soc_shield;
USE soc_shield;

-- ============================================================
-- DROP TABLES (for clean setup)
-- ============================================================
DROP TABLE IF EXISTS AccessLogs;
DROP TABLE IF EXISTS ThreatReports;
DROP TABLE IF EXISTS Systems;
DROP TABLE IF EXISTS Incidents;
DROP TABLE IF EXISTS Users;
DROP TABLE IF EXISTS Roles;

-- ============================================================
-- TABLE: Roles
-- ============================================================
CREATE TABLE Roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- TABLE: Users
-- ============================================================
CREATE TABLE Users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES Roles(role_id)
);

-- ============================================================
-- TABLE: Incidents
-- ============================================================
CREATE TABLE Incidents (
    incident_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL DEFAULT 'Medium',
    status ENUM('Open', 'Investigating', 'Resolved', 'Closed') NOT NULL DEFAULT 'Open',
    reported_by INT NOT NULL,
    assigned_to INT NULL,
    affected_system VARCHAR(200),
    vector VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (reported_by) REFERENCES Users(user_id),
    FOREIGN KEY (assigned_to) REFERENCES Users(user_id)
);

-- ============================================================
-- TABLE: Systems
-- ============================================================
CREATE TABLE Systems (
    system_id INT AUTO_INCREMENT PRIMARY KEY,
    system_name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    owner VARCHAR(100),
    os_type VARCHAR(50),
    location VARCHAR(100),
    status ENUM('Online', 'Offline', 'Compromised', 'Under Maintenance') DEFAULT 'Online',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- TABLE: ThreatReports
-- ============================================================
CREATE TABLE ThreatReports (
    report_id INT AUTO_INCREMENT PRIMARY KEY,
    incident_id INT NOT NULL,
    analyst_id INT NOT NULL,
    report_text TEXT NOT NULL,
    findings TEXT,
    recommendations TEXT,
    ioc_data VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES Incidents(incident_id),
    FOREIGN KEY (analyst_id) REFERENCES Users(user_id)
);

-- ============================================================
-- TABLE: AccessLogs
-- ============================================================
CREATE TABLE AccessLogs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    user_email VARCHAR(150),
    action VARCHAR(500) NOT NULL,
    resource VARCHAR(100),
    status ENUM('Success', 'Denied', 'Warning') DEFAULT 'Success',
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE SET NULL
);

-- ============================================================
-- SQL ROLE-BASED ACCESS CONTROL (RBAC) SIMULATION
-- These represent the privilege model enforced by the app layer
-- ============================================================

-- Create application-level RBAC permissions table
DROP TABLE IF EXISTS RolePermissions;
CREATE TABLE RolePermissions (
    permission_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    UNIQUE KEY unique_perm (role_name, resource, action)
);

-- ============================================================
-- GRANT PERMISSIONS (Simulating SQL GRANT statements)
-- ============================================================

-- ADMIN: Full access
INSERT INTO RolePermissions (role_name, resource, action) VALUES
('admin', 'incidents', 'SELECT'),
('admin', 'incidents', 'INSERT'),
('admin', 'incidents', 'UPDATE'),
('admin', 'incidents', 'DELETE'),
('admin', 'users', 'SELECT'),
('admin', 'users', 'INSERT'),
('admin', 'users', 'UPDATE'),
('admin', 'users', 'DELETE'),
('admin', 'threat_reports', 'SELECT'),
('admin', 'threat_reports', 'INSERT'),
('admin', 'threat_reports', 'UPDATE'),
('admin', 'threat_reports', 'DELETE'),
('admin', 'access_logs', 'SELECT'),
('admin', 'systems', 'SELECT'),
('admin', 'systems', 'INSERT'),
('admin', 'systems', 'UPDATE'),
('admin', 'systems', 'DELETE');

-- SOC MANAGER: View all, assign, update status
INSERT INTO RolePermissions (role_name, resource, action) VALUES
('soc_manager', 'incidents', 'SELECT'),
('soc_manager', 'incidents', 'INSERT'),
('soc_manager', 'incidents', 'UPDATE'),
('soc_manager', 'threat_reports', 'SELECT'),
('soc_manager', 'users', 'SELECT'),
('soc_manager', 'systems', 'SELECT'),
('soc_manager', 'access_logs', 'SELECT');

-- SECURITY ANALYST: View assigned, add reports, update status
INSERT INTO RolePermissions (role_name, resource, action) VALUES
('security_analyst', 'incidents', 'SELECT'),
('security_analyst', 'incidents', 'UPDATE'),
('security_analyst', 'threat_reports', 'SELECT'),
('security_analyst', 'threat_reports', 'INSERT');

-- AUDITOR: Read-only access
INSERT INTO RolePermissions (role_name, resource, action) VALUES
('auditor', 'incidents', 'SELECT'),
('auditor', 'threat_reports', 'SELECT'),
('auditor', 'access_logs', 'SELECT'),
('auditor', 'systems', 'SELECT');
