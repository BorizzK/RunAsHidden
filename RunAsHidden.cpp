// RunAsHidden.cpp
// Version 2.8 (исправлена работа под SYSTEM, добавлен режим запуска без ожидания)
// mingw64
// Компилируется с /DUNICODE /D_UNICODE с линковкой advapi32.lib
// Compile command without res: 
// g++ RunAsHidden.cpp -o RunAsHidden.exe -municode -static -ladvapi32 -luserenv -lsecur32 -lversion
// Compile command with res:
// windres RunAsHidden.rc -O coff -o RunAsHidden.res & g++ RunAsHidden.cpp RunAsHidden.res -o RunAsHidden.exe -municode -static -ladvapi32 -luserenv -lsecur32 -lversion

	//#define UNICODE //Определил в команде компиляции -municode
	//#define _UNICODE
	#define SECURITY_WIN32
	#define _WIN32_WINNT 0x0601

	#include <windows.h>
	#include <winerror.h>
	#include <ntsecapi.h>
	#include <userenv.h>
	#include <secext.h>  // ← для GetUserNameExW
	#pragma comment(lib, "Secur32.lib") // ← обязателен линк #include <profileapi.h>
	#include <profileapi.h>
	#include <tlhelp32.h>
	#include <sddl.h>
	#include <iostream>
	#include <string>
	#include <vector>
	#include <sstream>

	#ifndef ERROR_USER_PROFILE_ALREADY_LOADED
	#define ERROR_USER_PROFILE_ALREADY_LOADED 1500
	#endif

	bool debug = false;

	auto SafeCloseHandle = [](HANDLE& h) {
		if (h && h != INVALID_HANDLE_VALUE) {
			CloseHandle(h);
			h = NULL;
		}
	};

	std::wstring GetFileVersion() {
		wchar_t filename[MAX_PATH];
		if (!GetModuleFileNameW(NULL, filename, MAX_PATH)) {
			return L"Unknown";
		}

		DWORD verHandle = 0;
		DWORD verSize = GetFileVersionInfoSizeW(filename, &verHandle);
		if (verSize == 0) {
			return L"Unknown";
		}

		std::vector<BYTE> verData(verSize);
		if (!GetFileVersionInfoW(filename, verHandle, verSize, verData.data())) {
			return L"Unknown";
		}

		VS_FIXEDFILEINFO* verInfo = nullptr;
		UINT size = 0;
		if (!VerQueryValueW(verData.data(), L"\\", (LPVOID*)&verInfo, &size)) {
			return L"Unknown";
		}

		if (size == 0) {
			return L"Unknown";
		}

		// Формат версии: major.minor.build.revision
		UINT64 ms = verInfo->dwFileVersionMS;
		UINT64 ls = verInfo->dwFileVersionLS;

		DWORD major = HIWORD(ms);
		DWORD minor = LOWORD(ms);
		DWORD build = HIWORD(ls);
		DWORD revision = LOWORD(ls);

		wchar_t buffer[64];
		swprintf(buffer, 64, L"%u.%u.%u.%u", major, minor, build, revision);
		return std::wstring(buffer);
	}

	void print_help() {
		std::wcout << L"RunAsHidden Version: " << GetFileVersion() << L"\n";
		std::wcout <<
		L"\n"
		L"Usage:\n"
		L"  RunAsHidden.exe -u <username> -p <password> [-debug] -c <command>\n\n"
		L"Options:\n"
		L"  -u, --username <username>       Username, can be 'user', 'domain\\\\user' or 'user@domain'\n"
		L"  -p, --password <password>       Password\n"
		L"  --debug                         Enable debug output (show command line)\n"
		L"  -n, --nowait                    Starts command or process and exits, checks if the process has started, returns 0, if not - 1\n"
		L"  -d, --direct                    Starts command or process directly without using cmd.exe /c\n"
		L"                                  In direct mode, output redirection operators like > are not parsed. To capture output, redirect RunAsHidden's own output instead.\n"
		L"  -c, --command <command>         Command line to run (must be last, rest args joined)\n"
		L"                                  Quotes inside command arguments must be escaped with a backslash (\\\\)\n"
		L"  -h, --help, -?                  Show this help\n\n"
		L"Examples:\n"
		L"  RunAsHidden.exe -u user -p pass -c \"whoami\"\n"
		L"  RunAsHidden.exe --username=\"domain\\\\user\" --password=pass --debug -c \"dism.exe /online /get-packages\"\n"
		L"  RunAsHidden.exe --username=\"user@domain\" --password=pass --debug -c \"whoami >\\\"C:\\\\Log Files\\\\whoami.log\\\"\"\n";
	}

	void print_error(const wchar_t* contextMessage) {
		DWORD err = GetLastError();
		switch (err) {
			case 0:
				std::wcerr << L"[ERROR]: " << contextMessage << L"\n";
				break;
			case ERROR_ACCESS_DENIED:
				std::wcerr << L"[ERROR]: Access denied.\n";
				break;
			case ERROR_LOGON_FAILURE:
				std::wcerr << L"[ERROR]: Incorrect username or password.\n";
				break;
			case ERROR_ACCOUNT_RESTRICTION:
				std::wcerr << L"[ERROR]: Account restrictions prevent login (e.g., time, workstation restrictions).\n";
				break;
			case ERROR_LOGON_TYPE_NOT_GRANTED:
				std::wcerr << L"[ERROR]: Logon type not granted (insufficient rights to logon interactively).\n";
				break;
			case ERROR_PRIVILEGE_NOT_HELD:
				std::wcerr << L"[ERROR]: The user does not have the required privilege.\n";
				break;
			default:
				std::wcerr << L"[ERROR]: " << contextMessage << L": error code: " << err << L"\n";
				break;
		}
	}

	void print_warning(const wchar_t* contextMessage) {
		DWORD werr = GetLastError();
		std::wcerr << L"[WARNING]: " << contextMessage << L": code: " << werr << L"\n";
	}

	void PrintTokenPrivileges(HANDLE hToken, const wchar_t* username) {
		if (!hToken) {
			std::wcout << L"[DEBUG]: [ERROR] Invalid token handle\n";
			return;
		}

		if (username)
			std::wcout << L"[DEBUG]: Token privileges for: " << username << L"\n";

		// Получаем SID пользователя (только для отладки)
		DWORD size = 0;
		GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			std::wcout << L"[DEBUG]: [ERROR] GetTokenInformation (TokenUser) sizing failed\n";
			return;
		}

		BYTE* buffer = new BYTE[size];
		TOKEN_USER* tokenUser = (TOKEN_USER*)buffer;

		if (GetTokenInformation(hToken, TokenUser, tokenUser, size, &size)) {
			LPWSTR stringSid = NULL;
			if (ConvertSidToStringSidW(tokenUser->User.Sid, &stringSid)) {
				std::wcout << L"[DEBUG]: User SID: " << stringSid << L"\n";
				LocalFree(stringSid);
			}
		}

		delete[] buffer;

		// Тип токена
		TOKEN_TYPE tokenType;
		if (GetTokenInformation(hToken, TokenType, &tokenType, sizeof(tokenType), &size)) {
			std::wcout << L"[DEBUG]: Token type: " << (tokenType == TokenPrimary ? L"Primary" : L"Impersonation") << L"\n";
		}

		// Привилегии
		DWORD len = 0;
		GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &len);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			std::wcout << L"[DEBUG]: [ERROR] GetTokenInformation (TokenPrivileges) sizing failed\n";
			return;
		}

		TOKEN_PRIVILEGES* privs = (TOKEN_PRIVILEGES*)new BYTE[len];
		if (!GetTokenInformation(hToken, TokenPrivileges, privs, len, &len)) {
			std::wcout << L"[DEBUG]: [ERROR] GetTokenInformation (TokenPrivileges) failed\n";
			delete[] privs;
			return;
		}

		for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
			LUID luid = privs->Privileges[i].Luid;
			DWORD nameLen = 0;
			LookupPrivilegeNameW(NULL, &luid, NULL, &nameLen); // получить размер
			std::wstring name(nameLen, L'\0');
			if (LookupPrivilegeNameW(NULL, &luid, &name[0], &nameLen)) {
				name.resize(nameLen); // убрать мусор
				std::wcout << L"    " << name;
				if (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
					std::wcout << L" [ENABLED]";
				std::wcout << L"\n";
			}
		}

		delete[] privs;
	}

	std::wstring GetHostname() {
		DWORD size = MAX_COMPUTERNAME_LENGTH + 1; // максимальная длина имени компьютера
		std::vector<wchar_t> buffer(size);
		if (GetComputerNameW(buffer.data(), &size)) {
			return std::wstring(buffer.data(), size);
		}
		std::wcerr << L"Failed to get computer name. Error: " << GetLastError() << L"\n";
		return L"";
	}

	std::wstring GetCurrentUserSamCompatible() {
		DWORD size = 0;
		GetUserNameExW(NameSamCompatible, NULL, &size);
		if (size == 0) {
			return L"";
		}
		std::vector<wchar_t> buffer(size);
		if (!GetUserNameExW(NameSamCompatible, buffer.data(), &size)) {
			return L"";
		}
		// size — длина без нуля, буфер нуль-терминирован
		return std::wstring(buffer.data(), size);
	}

	// Проверка, запущена ли программа под SYSTEM
	bool IsRunningAsSystem() {
		HANDLE token = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}

		DWORD size = 0;
		// First, get required size for TOKEN_USER
		GetTokenInformation(token, TokenUser, NULL, 0, &size);
		if (size == 0 || size > 1024) {
			SafeCloseHandle(token);
			return false;
		}

		BYTE buffer[1024]; // bigger buffer to be safe
		if (!GetTokenInformation(token, TokenUser, buffer, size, &size)) {
			SafeCloseHandle(token);
			return false;
		}

		SafeCloseHandle(token);

		TOKEN_USER* tokenUser = (TOKEN_USER*)buffer;

		SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
		PSID systemSid = NULL;
		if (!AllocateAndInitializeSid(&ntAuthority, 1,
									  SECURITY_LOCAL_SYSTEM_RID,
									  0,0,0,0,0,0,0,
									  &systemSid)) {
			return false;
		}

		BOOL isSystem = EqualSid(tokenUser->User.Sid, systemSid);
		FreeSid(systemSid);

		return isSystem == TRUE;
	}

	bool IsInteractiveSession() {
		DWORD sessionId = 0;
		if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
			return false;
		}
		return sessionId != 0;
	}

	bool AddLogonRight(const wchar_t* username, const wchar_t* rightName) { //AddLogonRight(L"UserName", L"SeInteractiveLogonRight");
		LSA_HANDLE policyHandle = nullptr;
		LSA_OBJECT_ATTRIBUTES objectAttributes = {};
		NTSTATUS status = LsaOpenPolicy(nullptr, &objectAttributes,
										POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT,
										&policyHandle);
		if (status != 0) {
			std::wcerr << L"Failed to open LSA policy. Error: " << LsaNtStatusToWinError(status) << std::endl;
			return false;
		}

		PSID pSid = nullptr;
		DWORD sidSize = 0, domainSize = 0;
		SID_NAME_USE sidType;

		// First call to get buffer sizes
		LookupAccountNameW(nullptr, username, nullptr, &sidSize, nullptr, &domainSize, &sidType);
		pSid = (PSID)malloc(sidSize);
		LPWSTR domainName = (LPWSTR)malloc(domainSize * sizeof(wchar_t));

		if (!LookupAccountNameW(nullptr, username, pSid, &sidSize, domainName, &domainSize, &sidType)) {
			std::wcerr << L"Failed to lookup account SID. Error: " << GetLastError() << std::endl;
			free(pSid);
			free(domainName);
			LsaClose(policyHandle);
			return false;
		}

		LSA_UNICODE_STRING userRight;
		userRight.Buffer = const_cast<wchar_t*>(rightName);
		userRight.Length = (USHORT)wcslen(rightName) * sizeof(wchar_t);
		userRight.MaximumLength = userRight.Length + sizeof(wchar_t);

		status = LsaAddAccountRights(policyHandle, pSid, &userRight, 1);
		if (status != 0) {
			std::wcerr << L"Failed to add account right. Error: " << LsaNtStatusToWinError(status) << std::endl;
			free(pSid);
			free(domainName);
			LsaClose(policyHandle);
			return false;
		}

		free(pSid);
		free(domainName);
		LsaClose(policyHandle);
		return true;
	}

	bool EnablePrivilege(LPCWSTR privName) {
		HANDLE hToken;
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
			print_error(L"OpenProcessToken failed");
			return false;
		}

		if (!LookupPrivilegeValueW(NULL, privName, &luid)) {
			print_error(L"LookupPrivilegeValue failed");
			SafeCloseHandle(hToken);
			return false;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
			print_error(L"AdjustTokenPrivileges failed");
			SafeCloseHandle(hToken);
			return false;
		}

		SafeCloseHandle(hToken);
		return GetLastError() == ERROR_SUCCESS;
	}


	bool EnableTokenPrivilege(HANDLE hToken, LPCWSTR privilegeName) {
		TOKEN_PRIVILEGES tp;
		LUID luid;
		if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
			print_error(L"LookupPrivilegeValueW failed");
			return FALSE;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL) &&
			   GetLastError() == ERROR_SUCCESS;
	}

	// FOR RUN UNDER SYSTEM
	bool RunUnderSystem(
		const std::wstring& userOnly,
		const std::wstring& domain,
		const std::wstring& password,
		wchar_t* cmdLine,
		STARTUPINFOW& si,
		PROCESS_INFORMATION& pi,
		DWORD creationFlags
	) {
		HANDLE hToken = NULL;
		HANDLE hPrimaryToken = NULL;
		LPVOID envBlock = NULL;
		PROFILEINFO up = {0};
		bool created = false;

		if (!EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME)) {
			print_error(L"RunUnderSystem: EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) failed");
		}

		if (!EnablePrivilege(SE_INCREASE_QUOTA_NAME)) {
			print_error(L"RunUnderSystem: EnablePrivilege(SE_INCREASE_QUOTA_NAME) failed");
		}

		if (!EnablePrivilege(SE_TCB_NAME)) {
			print_error(L"RunUnderSystem: EnablePrivilege(SE_TCB_NAME) failed");
		}

		if (!LogonUserW(userOnly.c_str(), domain.c_str(), password.c_str(),
						LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {
			print_error(L"RunUnderSystem: LogonUserW failed");
			return false;
		}

		if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
							  SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
			print_error(L"RunUnderSystem: DuplicateTokenEx failed");
			SafeCloseHandle(hToken);
			return false;
		}

		if (!EnableTokenPrivilege(hPrimaryToken, SE_ASSIGNPRIMARYTOKEN_NAME)) {
			if (debug) print_warning((std::wstring(L"RunUnderSystem: EnableTokenPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) failed for target user ") + userOnly).c_str());
		}
		if (!EnableTokenPrivilege(hPrimaryToken, SE_INCREASE_QUOTA_NAME)) {
			if (debug) print_warning((std::wstring(L"RunUnderSystem: EnableTokenPrivilege(SE_INCREASE_QUOTA_NAME) failed for user ") + userOnly).c_str());
		}
		if (!EnableTokenPrivilege(hPrimaryToken, SE_TCB_NAME)) {
			if (debug) print_warning((std::wstring(L"RunUnderSystem: EnableTokenPrivilege(SE_TCB_NAME) failed for target user ") + userOnly).c_str());
		}

		if (debug) {
			PrintTokenPrivileges(hToken,userOnly.c_str());
		}

		up.dwSize = sizeof(PROFILEINFO);
		up.lpUserName = const_cast<LPWSTR>(userOnly.c_str());
		if (!LoadUserProfileW(hPrimaryToken, &up)) {
			DWORD perr = GetLastError();
			if (perr == ERROR_USER_PROFILE_ALREADY_LOADED) {
				std::wcout << L"[WARNING]: RunUnderSystem: Profile already loaded: " << userOnly.c_str() << "\n";
			} else {
				std::wcerr << L"RunUnderSystem: LoadUserProfile failed. Error: " << perr << "\n";
				SafeCloseHandle(hPrimaryToken);
				SafeCloseHandle(hToken);
				return false;
			}
		}

		if (!CreateEnvironmentBlock(&envBlock, hPrimaryToken, TRUE)) {
			print_error(L"RunUnderSystem: CreateEnvironmentBlock failed");
			UnloadUserProfile(hPrimaryToken, up.hProfile);
			SafeCloseHandle(hPrimaryToken);
			SafeCloseHandle(hToken);
			return false;
		}

		WCHAR windowsDir[MAX_PATH];
		if (!GetWindowsDirectoryW(windowsDir, MAX_PATH)) {
			wcscpy(windowsDir, L"C:\\Windows");
		}

		created = CreateProcessAsUserW(
			hPrimaryToken,
			NULL,
			cmdLine,
			NULL,
			NULL,
			TRUE,
			creationFlags | CREATE_UNICODE_ENVIRONMENT,
			envBlock,
			windowsDir,
			&si,
			&pi
		);

		if (!created) {
			print_error(L"RunUnderSystem: CreateProcessAsUserW failed");
		}

		DestroyEnvironmentBlock(envBlock);
		UnloadUserProfile(hPrimaryToken, up.hProfile);
		SafeCloseHandle(hPrimaryToken);
		SafeCloseHandle(hToken);

		return created;
	}

	// FOR RUN UNDER USER
	bool RunUnderUser(
		const std::wstring& userOnly,
		const std::wstring& domain,
		const std::wstring& password,
		wchar_t* cmdLine,
		STARTUPINFOW& si,
		PROCESS_INFORMATION& pi,
		DWORD creationFlags
	) {
		bool created = false;

		WCHAR windowsDir[MAX_PATH];
		if (!GetWindowsDirectoryW(windowsDir, MAX_PATH)) {
			wcscpy(windowsDir, L"C:\\Windows");
		}

		created = CreateProcessWithLogonW(
			userOnly.c_str(),
			domain.c_str(),
			password.c_str(),
			LOGON_WITH_PROFILE,
			NULL,
			cmdLine,
			creationFlags,
			NULL,
			windowsDir,
			&si,
			&pi
		);

		if (!created) {
			print_error(L"RunUnderUser: CreateProcessWithLogonW failed");
		} else {
			if (debug) {
				HANDLE hProcessToken = NULL;
				if (OpenProcessToken(pi.hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hProcessToken)) {
					PrintTokenPrivileges(hProcessToken,userOnly.c_str());
					SafeCloseHandle(hProcessToken);
				} else {
					print_error(L"[DEBUG]: RunUnderUser: OpenProcessToken failed");
				}
			}
		}

		return created;
	}

	// Получить токен SYSTEM из процесса services.exe
	HANDLE GetSystemToken() {
		DWORD pid = 0;
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap == INVALID_HANDLE_VALUE) return NULL;

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(pe);

		if (!Process32First(hSnap, &pe)) {
			SafeCloseHandle(hSnap);
			return NULL;
		}

		do {
			if (_wcsicmp(pe.szExeFile, L"services.exe") == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnap, &pe));

		SafeCloseHandle(hSnap);

		if (pid == 0) return NULL;

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (!hProcess) return NULL;

		HANDLE hToken = NULL;
		if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
			SafeCloseHandle(hProcess);
			return NULL;
		}

		SafeCloseHandle(hProcess);

		HANDLE hTokenDup = NULL;
		if (!DuplicateTokenEx(
			hToken,
			TOKEN_ALL_ACCESS,
			NULL,
			SecurityImpersonation, // better than SecurityIdentification here
			TokenPrimary,
			&hTokenDup))
		{
			SafeCloseHandle(hToken);
			return NULL;
		}

		SafeCloseHandle(hToken);
		return hTokenDup;
	}

	// Глобальный PROCESS_INFORMATION для доступа из CtrlHandler
	PROCESS_INFORMATION g_pi = {0};

	// Удаляет только внешние кавычки, если они есть
	std::wstring trim_quotes(const std::wstring& str) {
		size_t start = 0;
		size_t end = str.length();

		if (end > 0 && str[0] == L'"') {
			start = 1;
		}

		if (end > start + 1 && str[end - 1] == L'"') {
			end--;
		}

		return str.substr(start, end - start);
	}

	static bool starts_with(const std::wstring& s, const std::wstring& prefix) {
		return s.compare(0, prefix.size(), prefix) == 0;
	}

	// Обработчик Ctrl+C/Break - посылает событие Ctrl+C дочернему процессу (группе)
	BOOL WINAPI CtrlHandler(DWORD ctrlType) {
		if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
			if (g_pi.hProcess != NULL) {
				if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, g_pi.dwProcessId)) {
					print_error(L"GenerateConsoleCtrlEvent failed");
				}
				Sleep(1000);
				DWORD exitCode = 0;
				if (GetExitCodeProcess(g_pi.hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
					std::wcerr << L"Child process still active, terminating forcibly...\n";
					TerminateProcess(g_pi.hProcess, 1);
				}
			}
			return TRUE;
		}
		return FALSE; // return FALSE for other signals to allow default handling
	}

	int wmain(int argc, wchar_t* argv[]) {
		if (argc < 2) {
			print_help();
			return 1;
		}

		std::wstring username, password, domain, command;
		debug = false; // GLOBAL
		bool nowait = false;
		bool direct = false;
		bool has_command = false;

		// Парсинг аргументов
		for (int i = 1; i < argc; ++i) {
			std::wstring arg = argv[i];

			if (arg == L"-h" || arg == L"--help" || arg == L"-?") {
				print_help();
				return 0;
			}

			if (arg == L"-debug" || arg == L"--debug") {
				debug = true;
				std::wcout << L"[DEBUG]: on\n";
				continue;
			}

			if (arg == L"-nowait" || arg == L"--nowait" || arg == L"-n") {
				nowait = true;
				continue;
			}

			if (arg == L"-direct" || arg == L"--direct") {
				direct = true;
				continue;
			}

			if (arg == L"-u" || arg == L"--username") {
				if (i + 1 >= argc) {
					std::wcerr << L"Error: " << arg << L" requires a value\n";
					return 1;
				}
				username = trim_quotes(argv[++i]);
				continue;
			}
			if (starts_with(arg, L"-u=")) {
				username = trim_quotes(arg.substr(3));
				continue;
			}
			if (starts_with(arg, L"--username=")) {
				username = trim_quotes(arg.substr(11));
				continue;
			}

			if (arg == L"-p" || arg == L"--password") {
				if (i + 1 >= argc) {
					std::wcerr << L"Error: " << arg << L" requires a value\n";
					return 1;
				}
				password = trim_quotes(argv[++i]);
				continue;
			}
			if (starts_with(arg, L"-p=")) {
				password = trim_quotes(arg.substr(3));
				continue;
			}
			if (starts_with(arg, L"--password=")) {
				password = trim_quotes(arg.substr(11));
				continue;
			}

			if (arg == L"-c" || arg == L"--command") {
				if (i + 1 >= argc) {
					std::wcerr << L"Error: " << arg << L" requires a command string\n";
					return 1;
				}
				std::wstring cmdline;
				for (int j = i + 1; j < argc; ++j) {
					if (j > i + 1) cmdline += L" ";
					cmdline += argv[j];
				}
				command = cmdline;
				has_command = true;
				break;
			}
			if (starts_with(arg, L"-c=")) {
				command = trim_quotes(arg.substr(3));
				has_command = true;
				break;
			}
			if (starts_with(arg, L"--command=")) {
				command = trim_quotes(arg.substr(10));
				has_command = true;
				break;
			}

			std::wcerr << L"Unknown or unexpected argument: " << arg << L"\n";
			print_help();
			return 1;
		}

		if (username.empty() || password.empty() || !has_command) {
			std::wcerr << L"Error: missing required parameters.\n";
			print_help();
			return 1;
		}

		// Определение domain и userOnly
		domain = L".";
		std::wstring userOnly = username;

		size_t pos = username.find(L'\\');
		if (pos != std::wstring::npos) {
			domain = username.substr(0, pos);
			userOnly = username.substr(pos + 1);
		} else {
			pos = username.find(L'@');
			if (pos != std::wstring::npos) {
				userOnly = username.substr(0, pos);
				domain = username.substr(pos + 1);
			}
		}

		if (debug) {
			std::wcout << L"RunAsHidden Version: " << GetFileVersion() << L"\n";
			std::wstring hostname = GetHostname();
			std::wcout << L"[DEBUG]: Computer name: " << hostname << L"\n";
			if (IsInteractiveSession()) {
				std::wcout << L"[DEBUG]: Interactive session\n";
			} else {
				std::wcout << L"[DEBUG]: Non Interactive session\n";
			}
			std::wstring currentuser = GetCurrentUserSamCompatible();
			if (!currentuser.empty()) {
				std::wcout << L"[DEBUG]: current user: " << currentuser << L"\n";
			} else {
				std::wcout << L"[DEBUG]: failed to get current user. Error: " << GetLastError() << L"\n";
			}
			std::wcout << L"[DEBUG]: username=\"" << username << L"\"\n";
			if (domain != L".") {
				std::wcout << L"[DEBUG]: domain=\"" << domain << L"\"\n";
			}
			std::wcout << L"[DEBUG]: user=\"" << userOnly << L"\"\n";
			std::wcout << L"[DEBUG]: command=\"" << command << L"\"\n";
			if (nowait) {
				std::wcout << L"[DEBUG]: NoWait\n";
			}
			if (direct) {
				std::wcout << L"[DEBUG]: Direct\n";
			}

		}

		if (debug) {
			HANDLE hToken = NULL;
			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
				std::wcout << L"[DEBUG]: Current Process token privileges:" << std::endl;
				DWORD len = 0;
				GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &len);
				std::vector<BYTE> buffer(len);
				TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)buffer.data();
				if (GetTokenInformation(hToken, TokenPrivileges, tp, len, &len)) {
					for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
						LUID_AND_ATTRIBUTES laa = tp->Privileges[i];
						WCHAR name[256];
						DWORD size = 256;
						if (LookupPrivilegeNameW(nullptr, &laa.Luid, name, &size)) {
							std::wcout << L"    " << name;
							if (laa.Attributes & SE_PRIVILEGE_ENABLED)
								std::wcout << L" [ENABLED]";
							std::wcout << std::endl;
						}
					}
				}
				SafeCloseHandle(hToken);
			} else {
				std::wcerr << L"[DEBUG]: Failed to open process token to enumerate privileges." << std::endl;
			}
		}

		// Pipe для вывода
		HANDLE hRead, hWrite;
		SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

		if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
			std::wcerr << L"CreatePipe failed.\n";
			return 1;
		}

		if (!SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0)) {
			std::wcerr << L"SetHandleInformation failed.\n";
		   if (hRead) {
				SafeCloseHandle(hRead);
				hRead = NULL;
				
			}
			if (hWrite) {
				SafeCloseHandle(hWrite);
				hWrite = NULL;
			}
			return 1;
		}

		// STARTUPINFO
		//STARTUPINFOW si = { sizeof(si) };
		//ZeroMemory(&g_pi, sizeof(g_pi));

		STARTUPINFOW si;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&g_pi, sizeof(g_pi));

		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		si.wShowWindow = SW_HIDE;
		si.hStdOutput = hWrite;
		si.hStdError = hWrite;

		// Ctrl+C - а надо ли это вообще? ну пусть будет
		if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
			print_error(L"SetConsoleCtrlHandler failed");
			if (hRead) {
				SafeCloseHandle(hRead);
				hRead = NULL;
				
			}
			if (hWrite) {
				SafeCloseHandle(hWrite);
				hWrite = NULL;
			}
			return 1;
		}

		std::wstring cmdLine;
		if (direct) {
			cmdLine = command; // Запускаем напрямую, без cmd.exe
		} else {
			cmdLine = L"cmd.exe /c " + command; // Через оболочку cmd.exe
		}
		std::vector<wchar_t> cmdLineBuf(cmdLine.begin(), cmdLine.end());
		cmdLineBuf.push_back(0); // null-terminator
	
		DWORD creationFlags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;

		BOOL created = FALSE;

		if (IsRunningAsSystem()) {
			created = RunUnderSystem(userOnly, domain, password, cmdLineBuf.data(), si, g_pi, creationFlags);
			if (!created) {
				print_error(L"RunUnderSystem failed");
				SafeCloseHandle(hWrite);
				SafeCloseHandle(hRead);
				SafeCloseHandle(g_pi.hProcess);
				SafeCloseHandle(g_pi.hThread);
				return 1;
			}
		} else {
			created = RunUnderUser(userOnly, domain, password, cmdLineBuf.data(), si, g_pi, creationFlags);
			if (!created) {
				print_error(L"RunUnderUser failed");
				SafeCloseHandle(hWrite);
				SafeCloseHandle(hRead);
				SafeCloseHandle(g_pi.hProcess);
				SafeCloseHandle(g_pi.hThread);
				return 1;
			}
		}

		SafeCloseHandle(hWrite);

		if (nowait) {
			if (debug) std::wcout << L"[DEBUG]: process started successfully [nowait mode], exiting.\n";
			SafeCloseHandle(hRead);
			SafeCloseHandle(g_pi.hProcess);
			SafeCloseHandle(g_pi.hThread);
			return 0;
		}

		if (debug) {
			std::wcout << L"\n[DEBUG]: COMMAND RESULTS:\n\n";
		}

		// Read output from process via pipe
		DWORD bytesRead;
		CHAR buffer[4096];
		std::string prev;

		while (true) {
			BOOL success = ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
			if (!success || bytesRead == 0) break;
			std::string current(buffer, bytesRead); // создаём строку из прочитанных байт
			if (current != prev) {
				std::cout.write(current.c_str(), current.size());
				std::cout.flush();
				prev = current;
			}
		}
		SafeCloseHandle(hRead);
	 
		// Ждем завершения дочернего процесса
		WaitForSingleObject(g_pi.hProcess, INFINITE);

		DWORD exitCode = 0;
		GetExitCodeProcess(g_pi.hProcess, &exitCode);

		SafeCloseHandle(g_pi.hProcess);
		SafeCloseHandle(g_pi.hThread);

		if (debug) std::wcout << L"\n[DEBUG]: process exited with code " << exitCode << L"\n";

		return static_cast<int>(exitCode);
	}

