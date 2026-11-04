// GraphOps — Enterprise Security Graph Dataset & MITRE Knowledge Base
// Fictional-but-realistic enterprise: "Acme Corp" · 10.x on-prem + AWS ap-south-1 VPC.
// Node groups: asset | identity | network.
// Business Criticality (1-5): Impact if compromised (editable live in UI).
// Edge Weight (1-5): Attacker attractiveness / traversal ease.
// Typed Relationships: NETWORK_REACHABILITY, LOGGED_INTO, CAN_ACCESS, ADMIN_OF, DOMAIN_TRUST, EXTERNAL_INGRESS, API_DISPATCH.

const NODES = [
  // ---- network fabric ----
  { id: "inet",       label: "Internet",            group: "network",  criticality: 1, ip: "0.0.0.0/0",       desc: "Public internet address space" },
  { id: "vpn-gw",     label: "vpn.acme-corp.com",   group: "network",  criticality: 4, ip: "203.0.113.10",    desc: "Perimeter SSL-VPN concentrator" },
  { id: "fw-edge",    label: "Edge firewall",       group: "network",  criticality: 4, ip: "203.0.113.1",     desc: "Stateful boundary inspection firewall" },
  { id: "sw-dmz",     label: "DMZ segment",         group: "network",  criticality: 3, ip: "10.10.0.0/24",    desc: "Isolated perimeter service network" },
  { id: "sw-corp",    label: "Corp LAN core",       group: "network",  criticality: 4, ip: "10.20.0.0/16",    desc: "Core distribution switch for office subnet" },
  { id: "sw-srv",     label: "Server VLAN",         group: "network",  criticality: 4, ip: "10.30.0.0/24",    desc: "Protected datacenter server VLAN" },
  { id: "vpc-prod",   label: "AWS VPC ap-south-1",  group: "network",  criticality: 4, ip: "172.16.0.0/16",   desc: "Cloud production VPC peering gateway" },
  { id: "wifi-corp",  label: "Corp Wi-Fi",          group: "network",  criticality: 2, ip: "10.21.0.0/24",    desc: "802.1x enterprise authenticated wireless LAN" },

  // ---- human identities ----
  { id: "u-alice",    label: "alice.sharma (dev)",  group: "identity", criticality: 2, role: "Backend Developer", privilege: "standard" },
  { id: "u-bob",      label: "bob.nair (ops)",      group: "identity", criticality: 3, role: "Infrastructure Ops", privilege: "elevated" },
  { id: "u-carol",    label: "carol.d (finance)",   group: "identity", criticality: 2, role: "Financial Analyst",  privilege: "standard" },
  { id: "u-dave",     label: "dave.k (devops)",     group: "identity", criticality: 3, role: "DevOps Engineer",    privilege: "elevated" },
  { id: "u-frank",    label: "frank.m (sales)",     group: "identity", criticality: 2, role: "Sales Director",     privilege: "standard" },
  { id: "u-helpdesk", label: "helpdesk01",          group: "identity", criticality: 3, role: "IT Service Desk",    privilege: "tier1-admin" },
  { id: "u-admin",    label: "CORP\\da-admin",      group: "identity", criticality: 5, role: "Domain Administrator", privilege: "domain-admin" },

  // ---- non-human identities (service accounts) ----
  { id: "svc-backup", label: "svc-backup (SA)",     group: "identity", criticality: 4, role: "Veeam Backup Service Account", privilege: "service-privileged" },
  { id: "svc-web",    label: "svc-webapp (SA)",     group: "identity", criticality: 3, role: "Web Application Pool Identity", privilege: "service-standard" },
  { id: "svc-ci",     label: "svc-cicd (SA)",       group: "identity", criticality: 4, role: "Jenkins/GitHub Runner Service", privilege: "service-elevated" },
  { id: "svc-mon",    label: "svc-monitor (SA)",    group: "identity", criticality: 2, role: "Prometheus & SIEM Agent Identity", privilege: "service-read" },

  // ---- workstations ----
  { id: "ws-0142",    label: "WS-0142 · Alice",     group: "asset",    criticality: 3, ip: "10.20.14.42",     os: "Windows 11 Pro 23H2" },
  { id: "ws-0207",    label: "WS-0207 · Bob",       group: "asset",    criticality: 3, ip: "10.20.20.7",      os: "Ubuntu 22.04 LTS" },
  { id: "ws-0311",    label: "WS-0311 · Carol",     group: "asset",    criticality: 2, ip: "10.20.31.11",     os: "Windows 11 Pro 23H2" },
  { id: "ws-0405",    label: "WS-0405 · Dave",      group: "asset",    criticality: 3, ip: "10.20.40.5",      os: "macOS Sonoma 14.4" },
  { id: "ws-0521",    label: "WS-0521 · Frank",     group: "asset",    criticality: 2, ip: "10.21.5.21",      os: "Windows 11 Pro 23H2" },

  // ---- DMZ ----
  { id: "web01",      label: "web01.acme-corp.com", group: "asset",    criticality: 3, ip: "10.10.0.21",      os: "Debian 12 / Nginx" },

  // ---- server VLAN ----
  { id: "bastion",    label: "jump-01 (bastion)",   group: "asset",    criticality: 4, ip: "10.30.0.2",       os: "Hardened Alpine Linux" },
  { id: "app01",      label: "app01.corp",          group: "asset",    criticality: 4, ip: "10.30.0.11",      os: "RHEL 9 / Node.js API" },
  { id: "app02",      label: "app02.corp",          group: "asset",    criticality: 3, ip: "10.30.0.12",      os: "RHEL 9 / Worker Daemon" },
  { id: "db01",       label: "db01 · Customer DB",  group: "asset",    criticality: 5, ip: "10.30.0.50",      os: "PostgreSQL 16 Cluster", crownJewel: true },
  { id: "dc01",       label: "dc01 · Domain Ctrl",  group: "asset",    criticality: 5, ip: "10.30.0.5",       os: "Windows Server 2022 DC", crownJewel: true },
  { id: "dc02",       label: "dc02 · Domain Ctrl",  group: "asset",    criticality: 4, ip: "10.30.0.6",       os: "Windows Server 2022 Backup DC" },
  { id: "file01",     label: "file01 (file share)", group: "asset",    criticality: 3, ip: "10.30.0.20",      os: "SMB File Server / NAS" },
  { id: "backup01",   label: "backup01 (Veeam)",    group: "asset",    criticality: 4, ip: "10.30.0.30",      os: "Veeam B&R Server" },
  { id: "ci01",       label: "ci01 (CI runner)",    group: "asset",    criticality: 3, ip: "10.30.0.40",      os: "Ubuntu Runner Host" },
  { id: "siem",       label: "siem-01 (collector)", group: "asset",    criticality: 3, ip: "10.30.0.60",      os: "Elastic / Syslog Collector" },

  // ---- cloud VPC ----
  { id: "ec2-bastion",label: "ec2 jump box",        group: "asset",    criticality: 3, ip: "172.16.1.10",     os: "Amazon Linux 2023" },
  { id: "eks-node1",  label: "eks-worker-1",        group: "asset",    criticality: 4, ip: "172.16.2.11",     os: "EKS Bottlerocket Node" },
  { id: "rds-replica",label: "rds replica (PII)",   group: "asset",    criticality: 5, ip: "172.16.3.20",     os: "AWS RDS Aurora PostgreSQL", crownJewel: true }
];

const EDGES = [
  // Perimeter & Ingress
  { from: "inet",        to: "vpn-gw",      label: "vpn",   weight: 4, rel: "EXTERNAL_INGRESS", confidence: "HIGH", riskContribution: 16,
    evidence: "Public SSL-VPN portal listening on 443 with exposed authentication endpoint." },
  { from: "inet",        to: "fw-edge",     label: "http",  weight: 3, rel: "EXTERNAL_INGRESS", confidence: "HIGH", riskContribution: 12,
    evidence: "Direct public inbound HTTPS traffic permitted by perimeter ACL rules." },
  { from: "vpn-gw",      to: "sw-corp",     label: "vpn",   weight: 4, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 18,
    evidence: "Split-tunnel VPN routing pushes 10.20.0.0/16 corporate route to remote clients." },
  { from: "vpn-gw",      to: "ec2-bastion", label: "vpn",   weight: 4, rel: "NETWORK_REACHABILITY", confidence: "MEDIUM", riskContribution: 15,
    evidence: "IPsec Site-to-Site tunnel connects perimeter concentrator to AWS VPC subnet." },
  { from: "fw-edge",     to: "sw-dmz",      label: "http",  weight: 3, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 12,
    evidence: "Firewall static NAT forwards public port 443 into DMZ segment." },
  { from: "sw-dmz",      to: "web01",       label: "http",  weight: 3, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 14,
    evidence: "DMZ VLAN route allows HTTP/HTTPS ingress directly to Nginx reverse proxy." },

  // Corporate LAN
  { from: "sw-corp",     to: "ws-0142",     label: "lan",   weight: 2, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 10,
    evidence: "Layer 2 switched connection on Core Port GigabitEthernet1/0/14." },
  { from: "sw-corp",     to: "ws-0207",     label: "lan",   weight: 2, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 10,
    evidence: "Layer 2 switched connection on Core Port GigabitEthernet1/0/20." },
  { from: "sw-corp",     to: "ws-0311",     label: "lan",   weight: 2, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 10,
    evidence: "Layer 2 switched connection on Core Port GigabitEthernet1/0/31." },
  { from: "sw-corp",     to: "ws-0405",     label: "lan",   weight: 2, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 10,
    evidence: "Layer 2 switched connection on Core Port GigabitEthernet1/0/40." },
  { from: "wifi-corp",   to: "ws-0521",     label: "lan",   weight: 2, rel: "NETWORK_REACHABILITY", confidence: "MEDIUM", riskContribution: 8,
    evidence: "Active 802.1X wireless association on SSID 'Corp-Internal'." },
  { from: "sw-corp",     to: "sw-srv",      label: "lan",   weight: 4, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 22,
    evidence: "Inter-VLAN 10Gbps trunk line connecting office LAN to production datacenter switch." },
  { from: "sw-corp",     to: "wifi-corp",   label: "lan",   weight: 2, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 10,
    evidence: "Trunk link connecting wireless LAN controllers to internal core router." },

  // Server VLAN Internal Routing
  { from: "sw-srv",      to: "bastion",     label: "ssh",   weight: 3, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 14,
    evidence: "Management port 22 reachable across Server VLAN subnet." },
  { from: "sw-srv",      to: "app01",       label: "http",  weight: 3, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 14,
    evidence: "Internal REST endpoints on port 8080 accessible without mutual TLS." },
  { from: "sw-srv",      to: "app02",       label: "http",  weight: 3, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 12,
    evidence: "RPC task broker on port 5000 accessible across Server VLAN." },
  { from: "sw-srv",      to: "db01",        label: "db",    weight: 5, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 28,
    evidence: "PostgreSQL port 5432 reachable with password-based authentication enabled." },
  { from: "sw-srv",      to: "dc01",        label: "ad",    weight: 5, rel: "DOMAIN_TRUST", confidence: "HIGH", riskContribution: 30,
    evidence: "Active Directory Kerberos (88), LDAP (389) and RPC endpoint mapper (135) exposed." },
  { from: "sw-srv",      to: "dc02",        label: "ad",    weight: 4, rel: "DOMAIN_TRUST", confidence: "HIGH", riskContribution: 24,
    evidence: "Replication and authentication services exposed on backup domain controller." },
  { from: "sw-srv",      to: "file01",      label: "smb",   weight: 4, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 18,
    evidence: "SMB port 445 listening with SMB signing not enforced." },
  { from: "sw-srv",      to: "backup01",    label: "smb",   weight: 4, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 20,
    evidence: "Veeam management API and shared repository accessible on internal LAN." },
  { from: "sw-srv",      to: "ci01",        label: "ssh",   weight: 3, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 15,
    evidence: "CI deployment runner agent reachable via internal SSH." },
  { from: "sw-srv",      to: "siem",        label: "api",   weight: 2, rel: "NETWORK_REACHABILITY", confidence: "MEDIUM", riskContribution: 10,
    evidence: "Log shipper ingestion port 5044 open to all VLAN hosts." },

  // Cloud VPC Links
  { from: "vpc-prod",    to: "ec2-bastion", label: "ssh",   weight: 3, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 14,
    evidence: "Security group allows SSH ingress from internal RFC1918 addresses." },
  { from: "ec2-bastion", to: "eks-node1",   label: "ssh",   weight: 4, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 20,
    evidence: "Node IAM role and internal SSH keys allow bridging to Kubernetes nodes." },
  { from: "eks-node1",   to: "rds-replica", label: "db",    weight: 5, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 28,
    evidence: "Kubernetes pod secrets contain live RDS PostgreSQL credentials for PII replica." },

  // Application Tier Pivots
  { from: "web01",       to: "app01",       label: "http",  weight: 3, rel: "NETWORK_REACHABILITY", confidence: "HIGH", riskContribution: 15,
    evidence: "Backend reverse proxy upstream configured to forward requests to app01:8080." },
  { from: "app01",       to: "db01",        label: "db",    weight: 5, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 30,
    evidence: "Hardcoded production connection string found in app01 environment variables." },
  { from: "app02",       to: "db01",        label: "db",    weight: 4, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 22,
    evidence: "Batch processing worker holds read/write connection pool to customer database." },
  { from: "backup01",    to: "db01",        label: "db",    weight: 4, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 25,
    evidence: "Scheduled snapshot job executes with direct DBA privileges on db01." },
  { from: "bastion",     to: "app01",       label: "ssh",   weight: 4, rel: "ADMIN_OF", confidence: "HIGH", riskContribution: 20,
    evidence: "Root SSH keypair on bastion grants passwordless sudo access to app01." },

  // User <-> Workstation / Asset Bindings
  { from: "u-alice",     to: "ws-0142",     label: "login", weight: 2, rel: "LOGGED_INTO", confidence: "HIGH", riskContribution: 12,
    evidence: "Active interactive logon session detected in Windows Security Event Log (ID 4624)." },
  { from: "u-alice",     to: "web01",       label: "http",  weight: 2, rel: "CAN_ACCESS", confidence: "MEDIUM", riskContribution: 10,
    evidence: "Alice's developer account has admin privileges on the web staging portal." },
  { from: "u-bob",       to: "ws-0207",     label: "login", weight: 2, rel: "LOGGED_INTO", confidence: "HIGH", riskContribution: 12,
    evidence: "Interactive local desktop session active." },
  { from: "u-bob",       to: "bastion",     label: "ssh",   weight: 3, rel: "LOGGED_INTO", confidence: "HIGH", riskContribution: 18,
    evidence: "Public key authentication configured for user bob on bastion host." },
  { from: "u-bob",       to: "dc01",        label: "rdp",   weight: 4, rel: "ADMIN_OF", confidence: "HIGH", riskContribution: 26,
    evidence: "Bob is a member of the Server Operators group with remote desktop authorization." },
  { from: "u-carol",     to: "ws-0311",     label: "login", weight: 2, rel: "LOGGED_INTO", confidence: "HIGH", riskContribution: 10,
    evidence: "Interactive logon recorded on finance workstation." },
  { from: "u-carol",     to: "file01",      label: "smb",   weight: 2, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 12,
    evidence: "Mounted SMB share '\\file01\\finance$' with read/write access." },
  { from: "u-dave",      to: "ws-0405",     label: "login", weight: 2, rel: "LOGGED_INTO", confidence: "HIGH", riskContribution: 12,
    evidence: "Console user session on developer workstation." },
  { from: "u-dave",      to: "ci01",        label: "ssh",   weight: 4, rel: "ADMIN_OF", confidence: "HIGH", riskContribution: 22,
    evidence: "Dave's SSH key matches authorized_keys on CI deployment orchestrator." },
  { from: "u-dave",      to: "eks-node1",   label: "ssh",   weight: 4, rel: "ADMIN_OF", confidence: "HIGH", riskContribution: 24,
    evidence: "AWS IAM AssumeRole grant for EKS ClusterAdmin permissions." },
  { from: "u-frank",     to: "ws-0521",     label: "login", weight: 2, rel: "LOGGED_INTO", confidence: "HIGH", riskContribution: 10,
    evidence: "Cached domain credentials on mobile sales laptop." },
  { from: "u-helpdesk",  to: "ws-0311",     label: "rdp",   weight: 3, rel: "ADMIN_OF", confidence: "HIGH", riskContribution: 16,
    evidence: "Remote Assistance and LAPS local administrator privileges on corporate workstations." },
  { from: "u-helpdesk",  to: "dc01",        label: "rdp",   weight: 3, rel: "CAN_ACCESS", confidence: "MEDIUM", riskContribution: 18,
    evidence: "Helpdesk group has delegated account reset privileges in Active Directory." },
  { from: "u-admin",     to: "dc01",        label: "rdp",   weight: 5, rel: "ADMIN_OF", confidence: "HIGH", riskContribution: 30,
    evidence: "Enterprise Admin token active in LSASS process on Domain Controller." },
  { from: "u-admin",     to: "dc02",        label: "rdp",   weight: 4, rel: "ADMIN_OF", confidence: "HIGH", riskContribution: 25,
    evidence: "Replication and administrative authority across all Active Directory nodes." },

  // Service Account Privileges
  { from: "svc-backup",  to: "backup01",    label: "smb",   weight: 5, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 28,
    evidence: "Service account runs the backup daemon with full local system authority." },
  { from: "svc-backup",  to: "db01",        label: "db",    weight: 5, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 30,
    evidence: "Database superuser credentials assigned to automated backup routines." },
  { from: "svc-backup",  to: "file01",      label: "smb",   weight: 4, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 20,
    evidence: "Backup operators group bypasses NTFS access control lists on file shares." },
  { from: "svc-web",     to: "app01",       label: "api",   weight: 3, rel: "LOGGED_INTO", confidence: "HIGH", riskContribution: 15,
    evidence: "Web service application pool identity executing backend API processes." },
  { from: "svc-web",     to: "db01",        label: "db",    weight: 4, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 25,
    evidence: "Connection pooling account has DDL and DML permissions on customer schema." },
  { from: "svc-ci",      to: "ci01",        label: "api",   weight: 4, rel: "ADMIN_OF", confidence: "HIGH", riskContribution: 22,
    evidence: "CI service token holds administrative control over deployment pipelines." },
  { from: "svc-ci",      to: "eks-node1",   label: "api",   weight: 4, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 24,
    evidence: "Automated container registry push token allows arbitrary image deployment." },
  { from: "svc-mon",     to: "siem",        label: "api",   weight: 2, rel: "CAN_ACCESS", confidence: "MEDIUM", riskContribution: 10,
    evidence: "Monitoring agent API key with read-only metrics collection rights." },
  { from: "svc-mon",     to: "app01",       label: "api",   weight: 2, rel: "CAN_ACCESS", confidence: "MEDIUM", riskContribution: 10,
    evidence: "Node health check probe permitted to query internal status endpoints." },

  // Domain Control Plane
  { from: "dc01",        to: "sw-corp",     label: "ad",    weight: 5, rel: "DOMAIN_TRUST", confidence: "HIGH", riskContribution: 28,
    evidence: "Group Policy Objects deployed domain-wide across corporate workstation subnet." },
  { from: "dc01",        to: "svc-backup",  label: "ad",    weight: 4, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 25,
    evidence: "Active Directory manages Kerberos SPN ticket for svc-backup identity." },
  { from: "dc02",        to: "sw-srv",      label: "ad",    weight: 4, rel: "DOMAIN_TRUST", confidence: "HIGH", riskContribution: 22,
    evidence: "Secondary domain directory synchronization line across Server VLAN." },

  // Remote Access & Phishing Vectors
  { from: "ws-0142",     to: "vpn-gw",      label: "vpn",   weight: 4, rel: "CAN_ACCESS", confidence: "HIGH", riskContribution: 20,
    evidence: "Workstation stores cached VPN session tokens and persistent client certificate." },
  { from: "ws-0142",     to: "u-alice",     label: "phish", weight: 5, rel: "LOGGED_INTO", confidence: "HIGH", riskContribution: 25,
    evidence: "Malicious macro payload executed in Alice's user context following spear-phishing email." }
];

// MITRE ATT&CK Mapping
const TECHNIQUES = {
  phish: { id: "T1566",     name: "Phishing", tactic: "Initial Access", weight: 20,
           desc: "Adversaries send spear-phishing attachments or links to gain initial access to employee endpoints." },
  vpn:   { id: "T1133",     name: "External Remote Services", tactic: "Initial Access / Persistence", weight: 18,
           desc: "Adversaries leverage external remote gateways (VPN/Citrix) to access internal networks." },
  http:  { id: "T1190",     name: "Exploit Public-Facing Application", tactic: "Initial Access", weight: 16,
           desc: "Adversaries take advantage of software vulnerabilities in Internet-facing web servers." },
  ssh:   { id: "T1021.004", name: "Remote Services: SSH", tactic: "Lateral Movement", weight: 16,
           desc: "Adversaries abuse valid accounts to log into internal Unix/Linux systems over SSH." },
  login: { id: "T1078",     name: "Valid Accounts", tactic: "Privilege Escalation / Defense Evasion", weight: 22,
           desc: "Adversaries obtain and abuse credentials of existing user or admin accounts." },
  rdp:   { id: "T1021.001", name: "Remote Services: RDP", tactic: "Lateral Movement", weight: 20,
           desc: "Adversaries log into remote Windows hosts via Remote Desktop Protocol using stolen credentials." },
  smb:   { id: "T1021.002", name: "Remote Services: SMB Shares", tactic: "Lateral Movement", weight: 18,
           desc: "Adversaries move laterally by interacting with administrative Windows shares (ADMIN$, C$)." },
  db:    { id: "T1005",     name: "Data from Local System", tactic: "Collection", weight: 25,
           desc: "Adversaries query sensitive database tables and local file stores prior to exfiltration." },
  api:   { id: "T1071.001", name: "Application Layer Protocol: Web APIs", tactic: "Command & Control", weight: 14,
           desc: "Adversaries abuse standard REST/HTTP protocols for command, control and automated task dispatch." },
  ad:    { id: "T1482",     name: "Domain Trust Discovery", tactic: "Discovery", weight: 22,
           desc: "Adversaries query Active Directory LDAP/RPC to map trusts, groups, and domain controllers." },
  lan:   { id: "T1018",     name: "Remote System Discovery", tactic: "Discovery", weight: 12,
           desc: "Adversaries scan local IP subnets and ARP caches to identify adjacent live enterprise targets." }
};

// Crown Jewels — BloodHound-style Tier-0 high-value target assets
const CROWN_JEWELS = ["db01", "dc01"];

const GROUP_LABEL = { asset: "Asset", identity: "Identity", network: "Network" };

// 3 Curated Attack Scenarios for Judge Demonstrations
const PRESET_SCENARIOS = [
  {
    id: "scen-phish",
    name: "Scenario 1 — Compromised Workstation (Insider / Phishing)",
    entryId: "ws-0142",
    depth: 3,
    tag: "Workstation Breach",
    narrative: "Alice opens a weaponized invoice on WS-0142. The attacker uses LAN discovery (T1018) to reach the Corporate LAN core switch, then pivots into Server VLAN to compromise the Domain Controller (T1482) and Customer Database (T1005).",
    keyChoke: "sw-corp"
  },
  {
    id: "scen-vpn",
    name: "Scenario 2 — External Perimeter Breach (Stolen VPN)",
    entryId: "vpn-gw",
    depth: 4,
    tag: "Perimeter Ingress",
    narrative: "Stolen MFA session tokens allow external adversaries to access the perimeter SSL-VPN concentrator. From the VPN gateway, attackers traverse corporate routing into cloud bastion nodes and corporate LAN workstations.",
    keyChoke: "sw-corp"
  },
  {
    id: "scen-webapp",
    name: "Scenario 3 — Web App Supply Chain (Service Account Abuse)",
    entryId: "web01",
    depth: 4,
    tag: "Service Compromise",
    narrative: "Vulnerability in public-facing web01 allows RCE. Attacker pivots to app01, extracts cached svc-backup and svc-web credentials, bypassing network firewalls directly into db01.",
    keyChoke: "app01"
  }
];

if (typeof global !== "undefined") {
  global.NODES = NODES;
  global.EDGES = EDGES;
  global.TECHNIQUES = TECHNIQUES;
  global.CROWN_JEWELS = CROWN_JEWELS;
  global.GROUP_LABEL = GROUP_LABEL;
  global.PRESET_SCENARIOS = PRESET_SCENARIOS;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { NODES, EDGES, TECHNIQUES, CROWN_JEWELS, GROUP_LABEL, PRESET_SCENARIOS };
}
