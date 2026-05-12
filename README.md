\# Windows SIEM Mini Log Analyzer



A beginner-friendly SOC project that exports Windows Security logs, analyzes suspicious event IDs, and generates a basic incident-style report.



\## Skills Demonstrated



\- Windows Event Log analysis

\- PowerShell log collection

\- Python CSV parsing

\- Basic SIEM detection logic

\- SOC-style reporting

\- Security event ID research



\## Detections



This tool currently detects:



| Event ID | Meaning |

|---|---|

| 4625 | Failed login |

| 4624 | Successful login |

| 4672 | Special privileges assigned |

| 4720 | New user account created |

| 4726 | User account deleted |

| 4732 | User added to local group |

| 1102 | Security log cleared |



\## How It Works



1\. Run the PowerShell script to export Windows Security events.

2\. Run the Python analyzer.

3\. Review the generated report in the `reports` folder.



\## Usage



Export logs:



```powershell

powershell -ExecutionPolicy Bypass -File scripts/export\_logs.ps1

