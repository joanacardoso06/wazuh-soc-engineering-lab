#  Wazuh SOC Engineering & Custom SIEM Parsers Lab *(Work in Progress)*

> **Project Status: Architecture & Engineering Design Specification (Under Active Development)**  
> This repository currently serves as the **architectural blueprint and engineering specification** for a multi-platform SOC Home Lab integrating **Wazuh (SIEM/HIDS)**, **Suricata (NIDS)**, and **Windows Sysmon (EDR)**. Configuration files, custom XML/Regex decoders, and dashboard exports will be progressively committed as each deployment phase is completed.

---

##  Project Overview & Goal

This project is designed to simulate the **Cyber Defense & Security Engineering lifecycle** rather than just standard alert triage. 

When fully implemented, this laboratory will demonstrate end-to-end **SIEM Engineering**: platform installation and health monitoring, multi-OS agent onboarding, log normalization through **custom XML/Regex parsers (decoders)**, custom correlation rules, and **Kibana/Wazuh dashboard development**.

---

##  Planned Lab Architecture & Data Pipeline

| Architecture Layer | Planned Components & Telemetry Flow |
| :--- | :--- |
| **1. Target Endpoints** | • **Windows 11 / Server VM:** Windows Security Events, Sysmon (EDR Telemetry), Wazuh Agent (HIDS)<br>• **GNU/Linux Server:** Suricata (NIDS), Firewall (`UFW`/`iptables`), Auth/Syslog & Web Logs |
| **2. Transport Channel** | • Encrypted Wazuh Agent Channel (`TCP 1514`) & Standard `Syslog` ingestion |
| **3. Wazuh SIEM & Indexer** | • **Log Collector:** Will ingest Sysmon, Suricata `eve.json`, and Syslog<br>• **Custom Parsers:** `local_decoder.xml` (Pre-match & Regex field extraction)<br>• **Rule Engine:** `local_rules.xml` (Event correlation & severity scoring)<br>• **Wazuh Indexer:** OpenSearch / Elasticsearch structured storage |
| **4. Visualization & Health** | • **Custom Kibana / Wazuh Dashboards:** Security Alerts & Operational KPIs<br>• **Platform Monitoring:** SOC Platform Health, EPS & Agent Connectivity status |

---

##  Planned Engineering Capabilities

### 1. Multi-Platform Telemetry & Agent Integration
* **GNU/Linux Endpoint (Planned):** Will be configured with **Suricata (NIDS)** to inspect network traffic in real time (`eve.json`), `iptables`/`UFW` firewall logging, and SSH authentication telemetry (`/var/log/auth.log`).
* **Microsoft Windows Endpoint (Planned):** Will be configured with **Sysmon** (using a modular XML configuration) and Windows Security Auditing to capture process creation, network connections, and authentication activity (**Event IDs 4624, 4625, 4688**, and Sysmon Event ID 1).

### 2. Custom SIEM Parsers (Decoders) & Rules Design
Many proprietary applications and custom firewall scripts generate logs that are not natively recognized by a SIEM. This project will implement custom parsers inside `/decoders/local_decoder.xml` following a 3-stage pipeline:
* **Phase 1 (Pre-Decoding):** Extracting static syslog headers (`timestamp`, `hostname`, `program_name`).
* **Phase 2 (Custom Decoding via Regex):** Using parent `<prematch>` and child `<regex>` tags with `<order>` mapping to extract key security fields (`srcip`, `dstip`, `srcport`, `user`, `action`, `url`).
* **Phase 3 (Custom Rule Matching):** Correlating decoded fields in `/rules/local_rules.xml` (Rule IDs `100001+`) to trigger high-fidelity alerts for:
  * SSH & Windows Brute-Force attacks;
  * SQL Injection (SQLi) & Web Application Firewall (WAF) evasion attempts;
  * Suspicious process execution on Windows endpoints.

### 3. Target Validation Workflow (`wazuh-logtest`)
During the implementation phase, all custom decoders and rules will be tested via `/var/ossec/bin/wazuh-logtest` to verify expected field extraction before loading them into production. Below is the **target parsing specification** for our custom firewall log format:

```text
**Phase 1: Completed pre-decoding.
    full event: 'Oct 12 14:22:10 sec-gw custom-fw[2041]: ACTION=DROP SRC=192.168.1.55 DST=10.0.0.12 SPT=54321 DPT=22 PROTO=TCP USER=admin'
    timestamp: 'Oct 12 14:22:10'
    hostname: 'sec-gw'
    program_name: 'custom-fw'

**Phase 2: Completed decoding.
    name: 'custom-fw-decoder'
    action: 'DROP'
    srcip: '192.168.1.55'
    dstip: '192.168.1.12'
    srcport: '54321'
    dstport: '22'
    protocol: 'TCP'
    dstuser: 'admin'

**Phase 3: Completed filtering (rules).
    id: '100010'
    level: '8'
    description: 'Custom Firewall: Blocked unauthorized SSH connection attempt.'
