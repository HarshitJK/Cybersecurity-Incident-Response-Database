// database/seed.js — Seeds the database with demo data
require('dotenv').config();
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

async function seed() {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    multipleStatements: true,
    port: process.env.DB_PORT || 3306,
  });

  console.log('🔗 Connected to MySQL...');

  // Run schema
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await connection.query(schema);
  console.log('✅ Schema created successfully!');

  // Use the database
  await connection.query('USE soc_shield');

  // Hash passwords
  const adminHash    = await bcrypt.hash('admin123', 12);
  const managerHash  = await bcrypt.hash('manager123', 12);
  const analystHash  = await bcrypt.hash('analyst123', 12);
  const auditorHash  = await bcrypt.hash('auditor123', 12);

  // Insert Roles
  await connection.query(`
    INSERT INTO Roles (role_name, description) VALUES
    ('admin', 'Full system access - manage users, roles, all data'),
    ('soc_manager', 'Manage incidents, assign analysts, review reports'),
    ('security_analyst', 'Investigate assigned incidents, write threat reports'),
    ('auditor', 'Read-only access for compliance and audit purposes')
    ON DUPLICATE KEY UPDATE description=VALUES(description)
  `);
  console.log('✅ Roles seeded!');

  // Insert Users
  await connection.query(`
    INSERT INTO Users (name, email, password, role_id) VALUES
    ('Admin User',         'admin@soc.com',   '${adminHash}',   1),
    ('Sarah Mitchell',     'manager@soc.com', '${managerHash}', 2),
    ('Alex Rivera',        'analyst@soc.com', '${analystHash}', 3),
    ('Jordan Lee',         'auditor@soc.com', '${auditorHash}', 4),
    ('Emily Chen',         'emily@soc.com',   '${analystHash}', 3),
    ('Marcus Johnson',     'marcus@soc.com',  '${analystHash}', 3)
    ON DUPLICATE KEY UPDATE name=VALUES(name)
  `);
  console.log('✅ Users seeded!');

  // Insert Systems
  await connection.query(`
    INSERT INTO Systems (system_name, ip_address, owner, os_type, location, status) VALUES
    ('Web Server Alpha',      '192.168.1.10',  'IT Dept',     'Ubuntu 22.04',    'DMZ', 'Online'),
    ('Database Server',       '192.168.1.20',  'DBA Team',    'CentOS 8',        'Internal', 'Online'),
    ('Mail Gateway',          '192.168.1.30',  'IT Dept',     'Postfix/Linux',   'DMZ', 'Online'),
    ('File Server Beta',      '192.168.1.40',  'HR Dept',     'Windows Server',  'Internal', 'Compromised'),
    ('VPN Concentrator',      '10.0.0.1',      'Network Ops', 'Palo Alto',       'Perimeter', 'Online'),
    ('Dev Environment',       '192.168.2.10',  'Dev Team',    'Ubuntu 20.04',    'Dev Zone', 'Online'),
    ('Active Directory',      '192.168.1.5',   'IT Dept',     'Windows Server',  'Internal', 'Online'),
    ('Security SIEM',         '192.168.3.1',   'SOC Team',    'Splunk/Linux',    'SOC Zone', 'Online')
  `);
  console.log('✅ Systems seeded!');

  // Insert Incidents
  await connection.query(`
    INSERT INTO Incidents (title, description, severity, status, reported_by, assigned_to, affected_system, vector) VALUES
    (
      'Ransomware Detected on File Server',
      'Ransomware variant detected encrypting files on the HR file server. Multiple users reporting inability to access documents. Suspicious process "svchost32.exe" identified.',
      'Critical', 'Investigating', 1, 3, 'File Server Beta', 'Phishing Email'
    ),
    (
      'SQL Injection Attempt on Web Portal',
      'WAF logs show repeated SQL injection attempts targeting the customer portal login page. Payloads include UNION SELECT statements. IP 185.220.101.45 flagged.',
      'High', 'Investigating', 2, 3, 'Web Server Alpha', 'External Attack'
    ),
    (
      'Unauthorized VPN Access',
      'Employee credentials used to login to VPN from geolocation Russia while employee is at office. Possible credential compromise. Account temporarily suspended.',
      'High', 'Open', 2, NULL, 'VPN Concentrator', 'Credential Compromise'
    ),
    (
      'Phishing Campaign Targeting Finance',
      'Multiple finance department employees received spear-phishing emails impersonating CFO. 3 employees clicked malicious links. Password resets initiated.',
      'Medium', 'Resolved', 1, 4, 'Mail Gateway', 'Phishing Email'
    ),
    (
      'Privilege Escalation on Dev Server',
      'Unusual sudo commands executed on dev server by junior developer account. Commands include modifications to /etc/passwd and /etc/sudoers. Possible insider threat.',
      'High', 'Open', 3, NULL, 'Dev Environment', 'Insider Threat'
    ),
    (
      'DDoS Attack on Public Website',
      'Volumetric DDoS attack detected. Traffic spike to 45 Gbps. CDN mitigation activated. Attack vectors: UDP flood and HTTP GET flood from botnet.',
      'Critical', 'Resolved', 2, 5, 'Web Server Alpha', 'DDoS'
    ),
    (
      'Malware in Email Attachment',
      'Trojan horse detected in PDF attachment sent to accounting department. Attachment hash matches known Emotet variant. Files quarantined.',
      'Medium', 'Investigating', 3, 6, 'Mail Gateway', 'Phishing Email'
    ),
    (
      'Brute Force Attack on Admin Panel',
      'Over 10,000 failed login attempts on admin panel within 30 minutes. Source IPs from Tor exit nodes. Account lockout policy triggered. No successful logins.',
      'Medium', 'Resolved', 1, 3, 'Web Server Alpha', 'Brute Force'
    ),
    (
      'Data Exfiltration Attempt',
      'Unusual outbound traffic detected from database server to external IP 45.33.32.156. Large volume of data (2.3 GB) being transferred via port 443. Ongoing investigation.',
      'Critical', 'Investigating', 2, 5, 'Database Server', 'Data Exfiltration'
    ),
    (
      'Zero-Day Vulnerability Exploit',
      'Exploitation of CVE-2024-1234 detected on web server. Attacker gained shell access. Patch not yet available from vendor. Temporary mitigations applied.',
      'Critical', 'Open', 1, NULL, 'Web Server Alpha', 'Zero-Day'
    )
  `);
  console.log('✅ Incidents seeded!');

  // Insert ThreatReports
  await connection.query(`
    INSERT INTO ThreatReports (incident_id, analyst_id, report_text, findings, recommendations, ioc_data) VALUES
    (
      1, 3,
      'Initial analysis of ransomware attack confirms LockBit 3.0 variant. The malware entered via a phishing email containing a malicious macro-enabled Word document. Lateral movement detected across 3 network segments.',
      'Malware family: LockBit 3.0. Entry point: Phishing email to hr@company.com. Encryption key stored in C2 server at 185.x.x.x. 847 files encrypted.',
      '1. Isolate infected systems. 2. Restore from clean backups dated 2 days prior. 3. Implement email filtering for macro-enabled documents. 4. Conduct phishing awareness training.',
      'MD5: a1b2c3d4e5f6... | C2: 185.220.101.99 | Domain: evil-domain.xyz'
    ),
    (
      2, 3,
      'SQL injection attempts analyzed. Attacker using automated SQLMap tool. No successful data extraction confirmed. WAF successfully blocked 98% of payloads.',
      'Attack tool: SQLMap v1.7.8. Total attempts: 4,532. Blocked: 4,442. Passed WAF: 90 (all failed at app layer). No data exfiltration confirmed.',
      '1. Update WAF signature rules. 2. Implement parameterized queries review. 3. Block IP range 185.220.x.x. 4. Enable rate limiting on login endpoint.',
      'Attacker IP: 185.220.101.45 | Tool: SQLMap | Payload: UNION SELECT 1,2,3--'
    ),
    (
      4, 4,
      'Phishing campaign has been fully remediated. Password resets completed for all affected users. Email security enhanced with DMARC/SPF/DKIM records updated.',
      '3 users clicked malicious links. 1 user entered credentials on fake login page (credentials reset). No persistent malware installed. Campaign originated from compromised hosting provider.',
      'Campaign fully resolved. No further action required. Recommend quarterly phishing simulation training.',
      'Phishing domain: secure-login-portal.xyz | IP: 45.156.23.89'
    ),
    (
      6, 5,
      'DDoS attack fully mitigated. Cloudflare CDN absorb peak traffic of 45 Gbps. Attack lasted 4 hours 23 minutes. Botnet of approximately 50,000 compromised IoT devices.',
      'Attack type: UDP Flood + HTTP GET Flood. Peak: 45 Gbps / 8.2 Mpps. Duration: 4h 23min. Mitigation: Cloudflare Magic Transit + rate limiting.',
      'Attack resolved. Recommend upgrading DDoS protection plan. Implement anycast network diffusion.',
      'Botnet C2: Multiple IPs | Attack vectors: UDP/80, HTTP GET floods'
    ),
    (
      8, 3,
      'Brute force attack contained by account lockout policies. No unauthorized access achieved. Attack traced to automated credential stuffing using leaked password database.',
      'Total attempts: 10,847. Lockout triggered after 5 failures (NIST compliant). Credentials tested appear from RockYou2024 dump. No successful authentications.',
      '1. Implement CAPTCHA on login. 2. Enable IP-based rate limiting. 3. Deploy MFA for admin accounts. 4. Monitor for credential stuffing patterns.',
      'Source IPs: Tor exit nodes | Credential list: RockYou2024 subset'
    )
  `);
  console.log('✅ Threat Reports seeded!');

  // Insert AccessLogs
  await connection.query(`
    INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address) VALUES
    (1, 'admin@soc.com',   'User login successful',                          'auth',           'Success', '192.168.1.100'),
    (2, 'manager@soc.com', 'User login successful',                          'auth',           'Success', '192.168.1.101'),
    (3, 'analyst@soc.com', 'User login successful',                          'auth',           'Success', '192.168.1.102'),
    (4, 'auditor@soc.com', 'User login successful',                          'auth',           'Success', '192.168.1.103'),
    (3, 'analyst@soc.com', 'Viewed incident #1',                             'incidents',      'Success', '192.168.1.102'),
    (3, 'analyst@soc.com', 'Updated incident #1 status to Investigating',    'incidents',      'Success', '192.168.1.102'),
    (4, 'auditor@soc.com', 'Attempted to update incident #2 - ACCESS DENIED','incidents',      'Denied',  '192.168.1.103'),
    (4, 'auditor@soc.com', 'Attempted to create new incident - ACCESS DENIED','incidents',     'Denied',  '192.168.1.103'),
    (2, 'manager@soc.com', 'Assigned incident #3 to analyst (user_id: 3)',   'incidents',      'Success', '192.168.1.101'),
    (1, 'admin@soc.com',   'Created new user emily@soc.com',                 'users',          'Success', '192.168.1.100'),
    (3, 'analyst@soc.com', 'Submitted threat report for incident #2',        'threat_reports', 'Success', '192.168.1.102'),
    (1, 'admin@soc.com',   'Viewed access logs',                             'access_logs',    'Success', '192.168.1.100'),
    (5, 'emily@soc.com',   'User login successful',                          'auth',           'Success', '192.168.1.104'),
    (5, 'emily@soc.com',   'Updated incident #6 status to Resolved',         'incidents',      'Success', '192.168.1.104'),
    (6, 'marcus@soc.com',  'Submitted threat report for incident #8',        'threat_reports', 'Success', '192.168.1.105'),
    (4, 'auditor@soc.com', 'Attempted to delete audit log - ACCESS DENIED',  'access_logs',    'Denied',  '192.168.1.103'),
    (2, 'manager@soc.com', 'Reviewed threat report #1',                      'threat_reports', 'Success', '192.168.1.101'),
    (1, 'admin@soc.com',   'System configuration updated',                   'systems',        'Success', '192.168.1.100'),
    (3, 'analyst@soc.com', 'Attempted to delete user - ACCESS DENIED',       'users',          'Denied',  '192.168.1.102'),
    (1, 'admin@soc.com',   'Bulk export of incident data',                   'incidents',      'Warning', '192.168.1.100')
  `);
  console.log('✅ Access Logs seeded!');

  await connection.end();
  console.log('\n🎉 Database seeded successfully!');
  console.log('\n📋 Demo Accounts:');
  console.log('   admin@soc.com    / admin123   (Admin)');
  console.log('   manager@soc.com  / manager123 (SOC Manager)');
  console.log('   analyst@soc.com  / analyst123 (Security Analyst)');
  console.log('   auditor@soc.com  / auditor123 (Auditor)');
}

seed().catch(err => {
  console.error('❌ Seed failed:', err.message);
  process.exit(1);
});
