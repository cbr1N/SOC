

## Key Concepts

- **NTLMv2**: A Microsoft authentication protocol that uses hashed credentials; vulnerable to capture and relay attacks.
- **COM (Component Object Model)**: A Windows technology that allows programs to communicate; can be abused to trigger network connections.
- **SMB (Server Message Block)**: A protocol for file and printer sharing over a network; automatically sends NTLM hashes when connecting to servers.

---

## The query

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

### Key Indicators

- Targets **SMB (port 445)**, a protocol that utilizes **NTLM authentication**.
- Focuses on **connections to public IPs** (untrusted external systems).
- Lists the **initiating process** using `InitiatingProcessFileName`.

In essence, the query is trying to find devices that have had a successful local logon and then made a successful network connection to a public IP on port 445, which could indicate a potential NTLMv2 hash leak.

---

## NTLMv2 Hash Leaks

### SMB (Port 445) as a Vector for NTLM Hash Theft

- **SMB port 445** is a common channel for stealing **NTLMv2 hashes**.
- When a Windows device connects to an **external SMB server**, it may automatically send the user's **NTLMv2 hash** as part of the authentication process.

### COM-Based Attacks Trigger SMB Connections

- **Malicious COM objects** (e.g., embedded in Office documents) can force a Windows device to initiate **outbound SMB connections**.
- These techniques are often used to **leak NTLM hashes** to attacker-controlled servers.

---

## MITRE ATT&CK Mapping

- **Technique:** Forced Authentication (T1187)

- **Tactic:** Credential Access (TA0006)

---

## Useful links

- [NTLMv2 Hash Leak via COM Auto-Execution — Andrea Bocchetti](https://medium.com/@andreabocchetti88/ntlmv2-hash-leak-via-com-auto-execution-543919e577cb)
- [5 NTLM Vulnerabilities: Unpatched Privilege Escalation Threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft)
