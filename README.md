# RunAsHidden

**Version:** 4.0.7.2  
**Author:** [BorizzK](https://github.com/BorizzK / https://s-platoon.ru/profile/14721-borizzk/)  
**License:** MIT  
**Platform:** Windows 7+ / Server 2008 R2+ (x64 only)

---

**RunAsHidden** is a command-line utility for Windows x64 that executes a command or process **under a different user account**, optionally hiding the window and redirecting output.  
Useful for system administration, automation, service tasks, and privilege separation scenarios.  
RunAs alternative for use in scripts.

---

## 🔧 Usage

```cmd
RunAsHidden.exe -u <username> -p <password> [options] -c <command>
```

### Options

| Option | Description |
|--------|-------------|
| `-u`, `--username <username>` | Target username. Formats:<br> &nbsp;&nbsp;'user' &nbsp;&nbsp;&nbsp;&nbsp;- local user<br> &nbsp;&nbsp;'domain\\user' - domain user<br> &nbsp;&nbsp;'user@domain' - domain user<br> &nbsp;&nbsp;'auto' - automatically create temporary hidden admin user with isolated profile in `%SystemRoot%\Temp\RAH\`. User is deleted after command unless `-k` is specified. |
| `-p`, `--password <password>` | Password for the user.<br> Can be empty (`-p=.`) for logged-in session.<br> `'auto'` generates a strong random password for temporary user. |
| `-k`, `--keep` | Keep the automatically created temporary user for future use. |
| `-n`, `--nowait` | Do not wait for the command to finish.<br> Returns `0` if process started successfully, otherwise `1`. |
| `-t`, `--timeout <seconds>` | Wait the specified time before exiting and/or deleting temporary user.<br> Maximum allowed: 60 seconds. |
| `-d`, `--direct` | Run the command directly without `cmd.exe /c`.<br> Shell operators like `>`, `|`, `&` are **not interpreted**.<br> Useful for direct execution or capturing output manually. |
| `-v`, `--visible` | Run the command interactively (window visible) in the active session. |
| `-verb`, `--verbose` | Enable small debug output of command details. |
| `-debug`, `--debug` | Enable debug output, diagnostics, and full command details. |
| `-c`, `--command <command>` | Command line to execute. Can include full path.<br> Quotes inside must be escaped with backslash (`\\`). |
| `-params <parameters>` | Optional parameters for the command. Passed exactly as-is.<br> Use quotes if parameters contain spaces; escape internal quotes with `\\`. |
| `-h`, `--help`, `-?` | Show this help message. |

---

### Examples

```cmd
RunAsHidden.exe -u user -p pass -c "whoami"
RunAsHidden.exe -u=domain\\user -p=pass -c "dism.exe /online /get-packages"
RunAsHidden.exe -u=auto -p=auto -c "\"C:\\Program Files\\app.exe\" -arg1 -arg2"
RunAsHidden.exe -u=auto -p=auto -c "\"script.cmd\" JJJ \"222\""
RunAsHidden.exe -u=auto -p=auto -c "\"script.cmd\"" -params="\"222\" 333"      // Equivalent to: "script.cmd" "222" 333
RunAsHidden.exe -u=auto -p=auto -c "\"Updater.cmd\"" -params="--file=\"C:\\Logs\\log.txt\" --mode=fast"
RunAsHidden.exe -u auto -p auto -d -c "C:\\Windows\\System32\\whoami.exe"
RunAsHidden.exe -u auto -p auto -d -t 2 -k -c "whoami"
RunAsHidden.exe -u=auto -p=auto -debug -c "chcp 437 && C:\\Windows\\System32\\dism.exe && chcp 866"
RunAsHidden.exe -u=auto -p=auto -debug -c "chcp 437 && C:\Windows\System32\dism.exe && chcp 866"
RunAsHidden.exe -u user1 -p=. -v -d -debug -c "explorer.exe \\server\share" // Open folder \\server\shar in explorer window under user user1 session
RunAsHidden.exe -u user1 -p=. -v -d -debug -c "c:\Program Files\Microsoft Office\Office16\Outlook.exe" // Open Outlook under user user1 interactive session
```

---

## 💡 Notes

- Experiment option `--query-procs` not used.
- `--direct` mode does not support operators like `>`, `&&`, or `|` inside in Command line (-c option).
- To capture output, redirect **RunAsHidden's own stdout**, e.g.:
```
RunAsHidden.exe ... > result.txt
```

---

## 📦 Building

- Language: C++
- Platform: **Windows 7 / 10 / 11 / Server 2022 (x64 only)**
- Requires: MinGW-w64 or any Windows x64 C++ compiler

---

## 🚧 Roadmap

- [ ] Write to log file along with console output
- [ ] GUI wrapper (optional)
- [ ] GUI window with console output and/or progress instead of console only

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file.

