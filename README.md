# RunAsHidden

**Version:** 4.5.2.0  
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
| `-u`, `--username <username>` | Target username. Formats:<br> &nbsp;&nbsp;'user' &nbsp;&nbsp;&nbsp;&nbsp;- local user<br> &nbsp;&nbsp;'domain\\user' - domain user<br> &nbsp;&nbsp;'user@domain' - domain user<br> &nbsp;&nbsp;'.' - current user (use with the `-p=.` option)<br> &nbsp;&nbsp;'auto' - automatically create temporary hidden admin user with isolated profile in `%SystemRoot%\Temp\RAH\` folder.<br> &nbsp;&nbsp;By default uses base name `rah_tmp_user_` with 8 random characters appended (random suffix).<br> &nbsp;&nbsp;Example: `rah_tmp_user_89nvDoQF`.<br> &nbsp;&nbsp;This user will always be removed after execution. |
| `-p`, `--password <password>` | Password for the user.<br> Can be empty (`-p=.`) to use the current session.<br> `'auto'` generates a strong random password for temporary hidden admin user. |
| `-tn`, `--tempusername <username>` | Used only with `-u=auto`. Specifies the base name for the temporary hidden admin user.<br> By default, 8 random characters are appended to ensure uniqueness:<br> &nbsp;&nbsp;`-tn=username` (max 11 characters) → `username_89nvDoQF`<br> Using `-tn` with random suffix enabled automatically disables `-k (--keep)`, so the temporary user and profile will always be removed.<br> To disable random suffix generation append a dot (`.`) to the name:<br> &nbsp;&nbsp;`-tn=username.` (max 20 characters without dot) → `username` |
| `-k`, `--keep` | Keep the automatically created temporary hidden admin user for future use.<br> Can only be used with `-tn` when random suffix is disabled (name ends with a dot). |
| `-nofb`, `--nofb` | Disables automatic fallback to a new randomized username if the specified name (`-tn` or `-u`) is already taken by an existing non-temporary user.<br> By default, if the utility cannot reuse an existing user (due to a name conflict or missing *temporary* registry flag), it will create a new temporary hidden admin user with a random suffix (`<username>_$random$`) so the scenario continues without interruption. |
| `-n`, `--nowait` | Do not wait for the command to finish.<br> Returns `0` if process started successfully, otherwise `1`.<br> Incompatible with temporary admin user creation (`-u=auto`, `-tn`). |
| `-t`, `--timeout <seconds>` | Wait the specified time before exiting and/or deleting temporary user.<br> Maximum allowed: **60 seconds**. |
| `-d`, `--direct` | Run the command directly without `cmd.exe /d /c`.<br> Shell operators like `>`, `|`, `&` are **not interpreted**.<br> Useful for direct execution or capturing output manually. |
| `-v`, `--visible` | Run the command interactively (window visible) in the active session of the specified user. Use the -d option to run GUI applications directly. Does not require a password.|
| `-verb`, `--verbose` | Enable small debug output of command details. |
| `-debug`, `--debug` | Enable full debug output, diagnostics, and command details. |
| `-c`, `--command <command>` | Command line to execute. Can include full path.<br> Quotes inside must be escaped with backslash (`\\`). |
| `-params <parameters>` | Optional parameters for the command. Passed exactly as-is.<br> Use quotes if parameters contain spaces; escape internal quotes with `\\`. |
| `-cleanup`, `--cleanup` | Removes previously created temporary users (excluding those created with the `-k` option) that were not removed automatically.<br> Cannot be used with other options. |
| `-cleanup-all`, `--cleanup-all` | Removes previously created temporary users (including those created with the `-k` option) that were not removed automatically.<br> Cannot be used with other options. |
| `-cl`, `--cl` | Can be used with other options.<br> Removes previously created temporary users (excluding those created with the `-k` option) that were not removed automatically.<br> Temporary users will be removed **before command execution**. |
| `-cla`, `--cla` | Can be used with other options.<br> Removes previously created temporary users (including those created with the `-k` option) that were not removed automatically.<br> Temporary users will be removed **before command execution**. |
| `-h`, `--help`, `-?` | Show this help message. |

---

### Examples

```cmd
RunAsHidden.exe -u user -p pass -c "whoami"
RunAsHidden.exe -u=user -p=* -d -v -c "mspaint.exe"
RunAsHidden.exe -u=domain\\user -p=pass -c "dism.exe /online /get-packages"
RunAsHidden.exe -u=auto -p=auto -c "\"C:\\Program Files\\app.exe\" -arg1 -arg2"
RunAsHidden.exe -u=auto -p=auto -c "\"script.cmd\" JJJ \"222\""
RunAsHidden.exe -u=auto -p=auto -c "\"script.cmd\"" -params="\"222\" 333"      // Equivalent to: "script.cmd" "222" 333
RunAsHidden.exe -u=auto -p=auto -c "\"Updater.cmd\"" -params="--file=\"C:\\Logs\\log.txt\" --mode=fast"
RunAsHidden.exe -u auto -p auto -d -c "C:\\Windows\\System32\\whoami.exe"
RunAsHidden.exe -u auto -p auto -d -c "C:\Windows\System32\whoami.exe"
RunAsHidden.exe -u auto -p auto -d -c "%systemroot%\System32\whoami.exe"
RunAsHidden.exe -tn=queen -u auto -p auto -d -t 2 -k -c "whoami"
RunAsHidden.exe -u=auto -p=auto -tn=tempuser. -d -c "whoami"
RunAsHidden.exe -tn=updater. -u=auto -p=auto -debug -c "dism.exe /english /online /get-packages"
RunAsHidden.exe -u user1 -p=. -v -d -debug -c "explorer.exe \\server\share" // Open folder \\server\shar in explorer window under user user1 session
RunAsHidden.exe -u user1 -p=. -v -d -debug -c "c:\Program Files\Microsoft Office\Office16\Outlook.exe" // Open Outlook under user user1 interactive session
RunAsHidden.exe -u=auto -p=auto -tn=tempuser. -d -k -c "whoami" // keep temporary user\n"
RunAsHidden.exe -u=auto -p=auto -tn=tempuser -c "whoami" // random suffix, user tempuser will be deleted after execution command\n";
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

