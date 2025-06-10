```
let TimeRange = 50d;
let UserDeviceLogon = 
    DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where ActionType == "LogonSuccess"
    | where LogonType == "Interactive"
    | extend IsLocalLogon = tostring(parse_json(AdditionalFields)["IsLocalLogon"])
    | where IsLocalLogon == "true"
    | distinct DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(TimeRange)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 445
| where RemoteIPType == "Public"
| join kind=inner (UserDeviceLogon) on DeviceName
| project 
    DeviceName,
    RemoteIP,
    RemoteIPType,
    RemotePort,
    ActionType,
    InitiatingProcessFileName,
    Timestamp
| order by Timestamp desc
```

### SMB Connections to Public IPs (Port 445)

This query detects **outbound SMB connections** (port 445) to **public IP addresses** from devices where:

- Users have recently logged in **interactively** (local logons).
- The **connection was successful**.

---

## Key Indicators

- Targets **SMB (port 445)**, a protocol that utilizes **NTLM authentication**.
- Focuses on **connections to public IPs** (untrusted external systems).
- Lists the **initiating process** using `InitiatingProcessFileName`.

## NTLMv2 Hash Leaks

### SMB (Port 445) as a Vector for NTLM Hash Theft

- **SMB port 445** is a common channel for stealing **NTLMv2 hashes**.
- When a Windows device connects to an **external SMB server**, it may automatically send the user's **NTLMv2 hash** as part of the authentication process.

---

### COM-Based Attacks Trigger SMB Connections

- **Malicious COM objects** (e.g., embedded in Office documents) can force a Windows device to initiate **outbound SMB connections**.
- These techniques are often used to **leak NTLM hashes** to attacker-controlled servers.
