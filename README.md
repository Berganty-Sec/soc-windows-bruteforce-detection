# SOC Lab – Windows Failed Login Analysis (Event ID 4625)

## Objective
Simulate and investigate failed login attempts to understand how a SOC Analyst detects brute-force behavior.

## Environment
- Windows 10 (Target)
- BruteForce Local
- VirtualBox / VMware
- Local network (Host-only)

## Attack Simulation
Multiple failed authentication attempts were generated using incorrect credentials over the network.

## Investigation Steps

1. Open Event Viewer
2. Navigate to:
   Windows Logs → Security
3. Filter by Event ID:
   4625

## Key Findings

- Event ID: 4625 (Failed Logon)
- Target Account: Administrator
- Logon Type: 2 (Local)
- Multiple attempts within a short period

This behavior indicates a possible brute-force attack.

## Screenshots
See the screenshots folder for evidence.

## SOC Analysis

Logon Type Reference:
- 2 = Local
- 3 = Network
- 10 = Remote Desktop

Events without Source IP were identified as local authentication attempts.

## Conclusion
This lab demonstrates basic Windows log analysis and brute-force detection, a core skill for SOC Analysts and Blue Team roles.
