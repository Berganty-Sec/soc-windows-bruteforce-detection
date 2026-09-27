# Windows Authentication Failure Analyzer

A Python command-line tool that reviews Windows authentication failure events, reports every failed attempt it finds, and highlights patterns that may indicate brute-force activity or password spraying.

The analyzer can query the current Windows **Security** event log directly, so you do not need to export or import a log file. It can also read `.evtx` files and exported event XML files.

## Features

- Reports every detected failed authentication event, regardless of whether it meets a brute-force alert threshold.
- Reads Windows Security event IDs:
  - **4625** — failed logon.
  - **4771** — Kerberos pre-authentication failure.
  - **4776** — NTLM credential validation; successful validations are excluded.
  - **4777** — failed NTLM credential validation.
- Classifies logon attempts as local, network, or remote using the event's logon type and authentication protocol.
- Creates a readable `.txt` report with event-by-event details.
- Supports `.evtx` and exported XML input for offline analysis.
- Uses Windows' built-in `wevtutil` for live log queries and EVTX files; no third-party package is required on Windows.

## Requirements

- Windows 10/11 or Windows Server for live Security log queries.
- Python 3.10 or later.
- Run PowerShell or Command Prompt as **Administrator** to read the Security log. Reading a saved EVTX file only requires access to that file.

No Python dependencies are required on Windows. On another platform, live Windows log queries are unavailable; install `python-evtx` if you need to read an EVTX file there:

```bash
python -m pip install python-evtx
```

## Installation

Clone the repository and open a terminal in the project directory:

```powershell
git clone https://github.com/Berganty-Sec/soc-windows-bruteforce-detection.git
cd windows-event-logs
```

The analyzer uses only the Python standard library and Windows' built-in event log utility.

## Run an automatic scan

Open PowerShell as Administrator, navigate to the project directory, and run:

```powershell
python analisar_logins.py
```

By default, this queries the last **24 hours**, up to **5,000 matching events**. The terminal lists each failure found and prints the path to the detailed report. The report is saved in the current directory with a timestamped name, such as `relatorio_logins_20260927_153000.txt`.

To look further back or increase the event limit:

```powershell
python analisar_logins.py --horas 48 --max-eventos 10000
```

Choose a specific report path with `--relatorio`:

```powershell
python analisar_logins.py --relatorio "C:\reports\authentication-failures.txt"
```

## Analyze a saved log

Pass an EVTX file or an event XML export as the positional argument:

```powershell
python analisar_logins.py "C:\logs\Security.evtx"
python analisar_logins.py "C:\logs\security.xml"
```

To save the report to a chosen location:

```powershell
python analisar_logins.py "C:\logs\Security.evtx" --relatorio "C:\reports\security-review.txt"
```

## How detection works

Each supported failure event is included in the report. Brute-force alerts are an additional signal; they do not determine whether an event is reported.

With the default settings, the analyzer raises:

- **Brute force against one account** when one source produces at least **5 failed attempts against the same account within 10 minutes**.
- **Possible password spraying** when one source attempts to authenticate to at least **5 distinct accounts within 10 minutes**.

Change the thresholds and time window with these options:

```powershell
python analisar_logins.py --limite 8 --contas-limite 10 --janela 15
```

Here, `--limite` is the number of failures for one account, `--contas-limite` is the number of distinct accounts, and `--janela` is the time window in minutes. The same options can be used when analyzing a saved file.

## What the report contains

The report starts with the scan source, time range, number of failures, and any brute-force alerts. It then includes an entry for each event with the available details:

- Timestamp, event ID, and record ID.
- Target account and domain.
- Logon type and local, network, or remote classification.
- Source IP, port, and workstation when recorded.
- A readable failure description, plus the original Status and SubStatus codes.
- Authentication package, logon process, related process, and requesting account when available.

For event 4625, logon type **2** typically means an interactive local sign-in, **3** means network authentication, and **10** means a remote interactive sign-in such as RDP. Kerberos and NTLM failure events are classified as network authentication. Some Windows events omit the attempted username or source details; the report marks these fields as not provided by Windows instead of guessing.

## Important notes

- Alerts identify patterns that may be suspicious; they do not prove that an attack occurred. Repeated mistakes, services, or configuration problems can produce similar patterns.
- Windows must be configured to audit failed logons. If the operating system did not record an event, the analyzer cannot report it. Check the applicable **Audit logon events: Failure** policy if expected attempts are missing.
- If a live scan returns **Access denied**, rerun the terminal as Administrator or grant the account permission to read the Security log.
- Live scans only cover the selected time range and event limit. Increase `--horas` or `--max-eventos` if needed.

## Run the automated tests

```powershell
python -m unittest discover -v
```

## Lab screenshots

The repository also preserves screenshots from the original SOC lab in [`screnshots/`](screnshots/).
