---

# Domain/IP Investigation Tool

A comprehensive **Domain/IP Investigation Tool** built with **C++** for Linux/WSL and **C# Windows Forms** for Windows, allowing users to perform network reconnaissance, DNS lookups, WHOIS queries, traceroutes, and save results in **JSON format**.

---

## Features

### Core Functionalities

* Domain and IP resolution
* NSLookup
* Ping test
* WHOIS information
* JSON report generation
* Traceroute (Linux version)
* Service scan (limited)

### C++ Version (Linux/WSL)

* Uses system commands: `nslookup`, `ping`, `whois`, `traceroute`
* Optional colorized output for terminal
* Saves output to `report.json`
* Robust error handling
* Compatible with **WSL / GCC / g++**
* Supports both domain names and IP addresses
* Uses `libcurl` and `OpenSSL` for network requests

### Windows Version (C# Windows Forms)

* Full GUI application with text input and result display
* Requires **.NET Framework 4.8** or newer
* JSON output saved as `report.json`
* Resolves IPs using `Dns.GetHostAddresses()`
* Runs `nslookup`, `ping`, and `whois` via `cmd.exe`
* Modern UI layout with scrollable result box
* Fully functional `scan` button
* Includes error handling and validation

---

## Dependencies

### Linux C++ Version

* GCC / g++
* `libcurl` (network requests)
* `OpenSSL` (`-lssl -lcrypto`)
* System commands: `nslookup`, `ping`, `whois`, `traceroute`

Compile:

```bash
g++ domain_report.cpp -o domain_report -lcurl -lssl -lcrypto
```

Run:

```bash
./domain_report
```

---

### Windows C# Version

* Visual Studio 2022 (or newer)
* .NET Framework 4.8+
* NuGet Package: `Newtonsoft.Json` (for JSON handling)

Add `Newtonsoft.Json` via NuGet:

```bash
Install-Package Newtonsoft.Json
```

Build & Run:

* Open solution in Visual Studio
* Build project
* Run `Form1` (main form)
* Enter domain/IP and click **Scan**
* Results shown in the GUI and saved as `report.json`

---

## Sample Output

**JSON Example:**

```json
{
  "Target": "dns.google",
  "ResolvedIP": "8.8.8.8",
  "NSLookup": "...nslookup output...",
  "Ping": "...ping output...",
  "Whois": "...whois output...",
  "Timestamp": "2025-12-10 20:00:00"
}
```

**Terminal/GUI Output Example:**

```
TARGET: dns.google
IP: 8.8.8.8

---- NSLOOKUP ----
...
---- WHOIS ----
...
---- PING ----
...

Saved: report.json
```

---

## Troubleshooting

1. **Form1 Not Found (Windows)**

   * Ensure file names: `Form1.cs` and `Form1.Designer.cs`
   * Class definition: `public partial class Form1 : Form`
   * All files share the same namespace (e.g., `DomainTool`)

2. **Newtonsoft / JObject Missing**

   * Install via NuGet: `Install-Package Newtonsoft.Json`
   * Add `using Newtonsoft.Json.Linq;` to your files

3. **Linux C++ Warnings**

   * Use `unique_ptr` correctly for `popen`/`pclose`
   * Use `-Wno-ignored-attributes` to suppress template warnings

4. **JSON errors / null strings**

   * Validate system command output
   * Handle exceptions when converting to string

---

## Future Improvements

* Add full **traceroute visualization** in GUI
* Add **DNS records parsing** with color-coded output
* Include **service scan results** in Windows version
* Implement **multi-threaded lookups** for faster results
* Add **custom themes** to Windows Forms GUI

---

## Project Structure

```
C++ Version (Linux/WSL)
│   domain_report.cpp
│   report.json
│
Windows Version (C#)
│   DomainTool.sln
│   Form1.cs
│   Form1.Designer.cs
│   Program.cs
│   report.json
```

---
