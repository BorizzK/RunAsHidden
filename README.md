# RunAsHidden

**Version:** 3.0.9.0  
**Author:** [BorizzK](https://github.com/BorizzK / https://s-platoon.ru/profile/14721-borizzk/)  
**License:** MIT  
**Platform:** Windows x64 only

---

**RunAsHidden** is a command-line utility for Windows x64 that executes a command or process **under a different user account**, optionally hiding the window and redirecting output.
Useful for system administration, automation, service tasks, and privilege separation scenarios.
RanAs alternative for use in scripts.

---

## 🔧 Usage

```bash
RunAsHidden.exe -u <username> -p <password> [options] -c <command>
```


### Options

| Option | Description |
|--------|-------------|
| `-u`, `--username <username>` | Username: `'user'`, `'domain\\user'`, or `'user@domain'`. <br> `--username=auto` creates a hidden temporary administrator account with an isolated profile in `%SystemRoot%\Temp\RAH\`. The user is deleted after the command completes unless the `-k` option is specified. |
| `-p`, `--password <password>` | Password. <br> `--password=auto` generates a strong random password. |
| `-k`, `--keep` | Keep the automatically created user for future use. |
| `-n`, `--nowait` | Do not wait for the command to finish. Returns `0` if the process started successfully, otherwise `1`. |
| `-t`, `--timeout <time in sec>` | Wait for the specified timeout before the program exits, and before deleting the temporary user and its profile. Can be used in multiple scenarios. |
| `-d`, `--direct` | Run the command directly (without `cmd.exe /c`). In this mode, shell operators (like `>`) are not interpreted. To capture output, redirect RunAsHidden's own output. |
| `-v`, `--visible` | Run the command interactively (with a window) in the active session of the logged-on user. |
| `-debug`, `--debug` | Enable debug output (command line and diagnostics). |
| `-c`, `--command <command>` | Command line to run (must be the last argument). Quotes inside arguments must be escaped with a backslash (`\\`). |
| `-h`, `--help`, `-?` | Show this help message. |

---

### Examples

```bash
RunAsHidden.exe -u user -p pass -c "whoami"
RunAsHidden.exe --username=domain\\user --password=pass --debug -c "dism.exe /online /get-packages"
RunAsHidden.exe --username user --password pass --debug -c "dism.exe /online /get-packages"
RunAsHidden.exe -u user@domain -p pass -c "whoami >\"C:\\Log Files\\whoami.log\""
RunAsHidden.exe -u=auto -p=auto -debug -c "dism /english /online /get-packages >c:\\dism.log 2>&1"
RunAsHidden.exe -u=auto -p=auto -c "my_script.bat"
```

---

## 💡 Notes

- `--direct` mode does not support operators like `>`, `&&`, or `|`.  
- To capture output, redirect **RunAsHidden's own stdout**, e.g.:

```
RunAsHidden.exe ... > result.txt
```

---

## 📦 Building

- Language: C++
- Platform: **Windows x64 only**
- Requires: MinGW-w64 or any Windows x64 C++ compiler

---

## 🚧 Roadmap

- [ ] Write to log file along with console output
- [ ] GUI wrapper (optional)
- [ ] GUI windows with condole output and/or progress instead console output

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file.
