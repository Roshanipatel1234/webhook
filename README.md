                                                               # 🛡️ SOC Flow: Wazuh + VirusTotal + n8n

A Security Operations Center (SOC) automation workflow that integrates **Wazuh**, **VirusTotal**, and **n8n** to detect, enrich, and respond to threats in real time.  

This project demonstrates how to create an automated pipeline where:
- Wazuh generates security alerts (FIM, Sysmon, DB Audit).
- Alerts are sent via **custom webhook integrations** to n8n.
- n8n enriches alerts with **VirusTotal file/hash lookups**.
- Security teams receive structured notifications (JSON, Email, Discord, etc.).

---

## 🚀 Features
- 🔗 **Wazuh ↔ n8n Webhook Integration**
- 📂 File Integrity Monitoring (FIM) & Sysmon rules
- 🧪 Malware detection with **EICAR test file**
- 🔑 Auto-extraction of `md5`, `sha1`, and `sha256` hashes from alerts
- 🌐 VirusTotal API integration for threat intelligence
- 📬 Flexible outputs (Email, Discord, HTML reports)

---

## 📂 Project Flow
1. **Wazuh** detects suspicious activity (e.g., file changes, process injection, DB audit events).
2. Alerts are pushed to **n8n via webhook**.
3. **Custom JS Code Node** parses the alert and extracts:
   - Hashes (`md5`, `sha1`, `sha256`)
   - File path
   - Agent info
   - Rule description & severity
4. **VirusTotal API** checks file hashes for reputation data.
5. Results are sent to **Discord / Gmail / Custom HTML dashboards**.

---

## ⚙️ Setup

### 1. Configure Wazuh Integration
Edit `/var/ossec/etc/ossec.conf` on the Wazuh Manager:
```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>https://your-ngrok-url/webhook-windows</hook_url>
  <rule_id>550,554</rule_id> <!-- Sysmon process injection -->
  <alert_format>json</alert_format>
</integration>

<integration>
  <name>custom-n8n</name>
  <hook_url>https://your-ngrok-url/webhook-db</hook_url>
  <rule_id>5503</rule_id> <!-- MariaDB Audit rules -->
  <alert_format>json</alert_format>
</integration>
Restart Wazuh Manager:

bash
Copy code
sudo systemctl restart wazuh-manager
Verify integration:

bash
Copy code
tail -f /var/ossec/logs/integration.log
2. Configure Agent (FIM)
On endpoints (/var/ossec/etc/ossec.conf):

xml
Copy code
<directories check_all="yes">/root,/home,/home/download</directories>
Trigger with:

Wrong root password attempts

File download (e.g., EICAR test file)

3. n8n Workflow
Add Webhook Node (match Wazuh integration URLs).

Add Code Node to extract hashes:

js
Copy code
const body = items[0].json.body || {};
const allFields = body.all_fields || {};
const syscheck = allFields.syscheck || {};
const rule = allFields.rule || {};

return [{
  json: {
    type: 'file_alert',
    md5: syscheck.md5_after || null,
    sha1: syscheck.sha1_after || null,
    sha256: syscheck.sha256_after || null,
    file_path: syscheck.path || null,
    description: rule.description || 'No description',
    agent: allFields.agent?.name || 'unknown',
    level: rule.level || 'unknown',
    full_alert: body
  }
}];
Connect to VirusTotal Node (file/hash reputation lookup).

Send enriched results via:

Gmail

Discord

HTML report

🧪 Testing
Download EICAR test file on the monitored agent:

bash
Copy code
wget https://secure.eicar.org/eicar.com.txt -O /home/download/eicar.com
Check if alert triggers Wazuh → n8n → VirusTotal lookup.

📊 Example Output
json
Copy code
{
  "type": "file_alert",
  "md5": "44d88612fea8a8f36de82e1278abb02f",
  "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
  "sha256": "275a021bbfb648..." ,
  "file_path": "/home/download/eicar.com",
  "description": "File integrity checksum changed.",
  "agent": "ubuntu-agent",
  "level": 7,
  "virustotal": {
    "malicious": 60,
    "harmless": 0,
    "suspicious": 2
  }
}
📌 Requirements
Wazuh

n8n (self-hosted or cloud)

VirusTotal API Key

Ngrok (for exposing webhook URLs in dev)

🌟 Future Improvements
🔄 Add automated response (quarantine or kill process)

📑 SIEM dashboard integration (e.g., Kibana)

🤖 AI-driven threat scoring

📝 License
This project is licensed under the MIT License.

💡 Author
Created by [Your Name] ✨
SOC Workflow Automation | Security Monitoring | Threat Intelligence

yaml
Copy code







