# Resumen de detecciones

Total de detecciones high/critical: **549** en **150** ficheros EVTX.

## Reglas mas frecuentes

| Regla | Severidad | Detecciones | Tecnicas ATT&CK |
|---|---|---|---|
| RunMRU Registry Key Deletion - Registry | high | 25 | T1070.003 |
| Suspicious SYSTEM User Process Creation | high | 25 | T1003, T1027, T1134 |
| Security Audit Logs Cleared | critical | 24 | - |
| HackTool - UACMe Akagi Execution | high | 23 | T1548.002 |
| Powerview Add-DomainObjectAcl DCSync AD Extend Right | high | 20 | T1098 |
| Microsoft IIS Service Account Password Dumped | high | 18 | T1003 |
| Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths | high | 16 | - |
| Whoami.EXE Execution From Privileged Process | high | 11 | T1033 |
| User Authentication Succeeded | critical | 11 | - |
| Abused Debug Privilege by Arbitrary Parent Processes | high | 11 | T1548 |
| Windows Defender | critical | 11 | - |
| Windows Defender Threat Detected | high | 11 | T1059 |
| Suspicious Process Parents | high | 9 | T1036 |
| LSASS Memory Access by Tool With Dump Keyword In Name | high | 7 | T1003.001 |
| Mshtml.DLL RunHTMLApplication Suspicious Usage | high | 7 | - |

## Ficheros con mas detecciones

| Fichero | Detecciones |
|---|---|
| `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` | 50 |
| `Persistence/persistence_sysmon_11_13_1_shime_appfix.evtx` | 27 |
| `Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx` | 24 |
| `AutomatedTestingTools/WinDefender_Events_1117_1116_AtomicRedTeam.evtx` | 22 |
| `AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx` | 21 |
| `Persistence/DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.evtx` | 19 |
| `Lateral Movement/LM_sysmon_3_12_13_1_SharpRDP.evtx` | 17 |
| `Discovery/dicovery_4661_net_group_domain_admins_target.evtx` | 13 |
| `AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx` | 12 |
| `Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx` | 11 |
