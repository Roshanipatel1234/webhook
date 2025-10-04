SOC Flow: Wazuh + VirusTotal + n8n
A Security Operations Center (SOC) automation workflow that integrates Wazuh, VirusTotal, and n8n to detect, enrich, and respond to threats in real time.

This project demonstrates how to create an automated pipeline where:
- Wazuh generates security alerts (FIM, Sysmon, DB Audit).
- Alerts are sent via custom webhook integrations to n8n.
- n8n enriches alerts with VirusTotal file/hash lookups.
- Security teams receive structured notifications (JSON, Email, Discord, etc.).
Features
🔗 Wazuh ↔ n8n Webhook Integration
📂 File Integrity Monitoring (FIM) & Sysmon rules
🧪 Malware detection with EICAR test file
🔑 Auto-extraction of md5, sha1, and sha256 hashes from alerts
🌐 VirusTotal API integration for threat intelligence
📬 Flexible outputs (Email, Discord, HTML reports)
Project Flow
1. Wazuh detects suspicious activity (file changes, process injection, DB audit events).
2. Alerts are pushed to n8n via webhook.
3. Custom JS Code Node parses the alert and extracts:
   - Hashes (md5, sha1, sha256)
   - File path
   - Agent info
   - Rule description & severity
4. VirusTotal API checks file hashes for reputation data.
5. Results are sent to Discord / Gmail / Custom HTML dashboards.
Setup
1. Configure Wazuh Integration
Edit /var/ossec/etc/ossec.conf on the Wazuh Manager:

<integration>
  <name>custom-n8n</name>
  <hook_url>https://your-ngrok-url/webhook-windows</hook_url>
  <rule_id>550,554</rule_id>
  <alert_format>json</alert_format>
</integration>
Restart Wazuh Manager:

sudo systemctl restart wazuh-manager
2. Configure Agent (FIM)
On endpoints (/var/ossec/etc/ossec.conf):

<directories check_all="yes">/root,/home,/home/download</directories>

Trigger with:
- Wrong root password attempts
- File download (EICAR test file)
3. n8n Workflow
Add Webhook Node → Code Node → VirusTotal Node → Output.

Custom JS Code Node:

const body = items[0].json.body || {};
const allFields = body.all_fields || {};
const syscheck = allFields.syscheck || {};
const rule = allFields.rule || {};

return [{ json: {
  type: 'file_alert',
  md5: syscheck.md5_after || null,
  sha1: syscheck.sha1_after || null,
  sha256: syscheck.sha256_after || null,
  file_path: syscheck.path || null,
  description: rule.description || 'No description',
  agent: allFields.agent?.name || 'unknown',
  level: rule.level || 'unknown',
  full_alert: body
} }];
Testing
Download EICAR test file on monitored agent:
wget https://secure.eicar.org/eicar.com.txt -O /home/download/eicar.com

Check if alert triggers Wazuh → n8n → VirusTotal lookup.
Example Output
{
  "type": "file_alert",
  "md5": "44d88612fea8a8f36de82e1278abb02f",
  "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
  "sha256": "275a021bbfb648...",
  "file_path": "/home/download/eicar.com",
  "description": "File integrity checksum changed.",
  "agent": "ubuntu-agent",
  "level": 7,
  "virustotal": { "malicious": 60, "harmless": 0, "suspicious": 2 }
}
Requirements
- Wazuh
- n8n (self-hosted or cloud)
- VirusTotal API Key
- Ngrok (for webhook exposure)
Future Improvements
- Add automated response (quarantine or kill process)
- SIEM dashboard integration (Kibana)
- AI-driven threat scoring
License
This project is licensed under the MIT License.
Author
Created by [Your Name]
SOC Workflow Automation | Security Monitoring | Threat Intelligence
