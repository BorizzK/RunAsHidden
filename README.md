# RunAsHidden

**Version:** 2.8.0.0  
**Author:** [BorizzK](https://github.com/BorizzK)  
**License:** MIT  
**Platform:** Windows x64 only

---

**RunAsHidden** is a command-line utility for Windows x64 that executes a command or process **under a different user account**, optionally hiding the window and redirecting output.
Useful for system administration, automation, service tasks, and privilege separation scenarios.
RanAs alternative for use in scripts.

---

## 🔧 Usage

```bash
RunAsHidden.exe -u <username> -p <password> [-debug] -c <command>
```

### Options

| Option | Description |
|--------|-------------|
| `-u`, `--username <username>` | Username (`user`, `domain\\user`, or `user@domain`) |
| `-p`, `--password <password>` | User password |
| `--debug` | Enables debug output (prints the command line and more) |
| `-n`, `--nowait` | Starts the process and exits; returns 0 if the process started successfully, otherwise 1 |
| `-d`, `--direct` | Runs the command directly without `cmd.exe /c`<br>Note: redirection operators like `>` won’t work in this mode |
| `-c`, `--command <command>` | Command line to run (**must be the last argument**) <br>Escape inner quotes using backslash (`\\`) |
| `-h`, `--help`, `-?` | Shows help information |

---

## 🧪 Examples

```bash
RunAsHidden.exe -u user -p pass -c "whoami"
RunAsHidden.exe --username="domain\\user" --password=pass --debug -c "dism.exe /online /get-packages"
RunAsHidden.exe --username="user@domain" --password=pass --debug -c "whoami >\"C:\\Temp\\whoami.log\""
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

- [ ] Create temporary user if password is omitted
- [ ] Logging to file
- [ ] GUI wrapper (optional)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file.
