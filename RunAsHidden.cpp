// RunAsHidden.cpp
// Version 4.5.4.0
// Author: [BorizzK](https://github.com/BorizzK / https://s-platoon.ru/profile/14721-borizzk / https://github.com/BorizzK )
// Forum: https://forum.ru-board.com/topic.cgi?forum=8&topic=82891#1
// GitHub: https://github.com/BorizzK/RunAsHidden
// License: MIT
// APi: https://learn.microsoft.com/ru-ru/windows/win32/api/ | https://learn.microsoft.com/en-us/windows/win32/api/
// mingw64 [https://winlibs.com/]
// Compile command without res: 
// g++ RunAsHidden.cpp -o RunAsHidden.exe -municode -static -ladvapi32 -luserenv -lsecur32 -lversion -lwtsapi32 -lnetapi32
// Compile command with res:
// windres RunAsHidden.rc -O coff -o RunAsHidden.res & g++ RunAsHidden.cpp RunAsHidden.res -o RunAsHidden.exe -municode -static -ladvapi32 -luserenv -lsecur32 -lversion -lwtsapi32 -lnetapi32

	#ifndef UNICODE
	#define UNICODE
	#endif 
	#define SECURITY_WIN32
	#define _WIN32_WINNT 0x0601
	#include <windows.h>
	#include <iomanip> // для setw
	//#include <bcrypt.h>
	#include <winerror.h>
	#include <tchar.h>
	#include <ntsecapi.h>
	#include <userenv.h>
	#include <secext.h> 
	#include <profileapi.h>
	#include <tlhelp32.h>
	#include <sddl.h>
	#include <iostream>
	#include <string>
	#include <random> //rand
	#include <vector>
	#include <sstream>
	#include <wtsapi32.h>
	#include <lm.h>			// NetUserAdd, NetUserSetInfo, etc.
	#include <aclapi.h>		// SetNamedSecurityInfo
	#include <accctrl.h>
	#include <dsrole.h>
	#include <io.h>			// для _setmode, _fileno
	#include <fcntl.h>		// для _O_U16TEXT
	#include <algorithm> 	// для std::transform
	#include <cstdlib>
	#include <ctime>
	//#include <Shlwapi.h> //PathFileExistsW
	//#pragma comment(lib, "Shlwapi.lib") //PathFileExistsW
	//#pragma comment(lib, "netapi32.lib") //NetUserModalsGet
	#ifndef ERROR_USER_PROFILE_ALREADY_LOADED
	#define ERROR_USER_PROFILE_ALREADY_LOADED 1500
	#endif

	//1. Доработка - вместо глобальных переменных - struct RahContext - в работе

	const DWORD WAIT_PROC_HOURS_DEFAULT = 12;

	const std::wstring g_userListKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList";
	const std::wstring g_profileRegKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
	const std::wstring g_RahRootDirName = L"\\RAH\\";
	const std::wstring g_RahTempRootDirPath = L"\\Temp" + g_RahRootDirName;
	const std::wstring g_tmpUserPrefix =  L"rah_tmp_";
	const std::wstring g_tmpUserPostfix = L"user";
	const std::wstring g_RahUserComment = L"Temporary user created by RunAsHidden administrative utility";
	const size_t g_DefaultPassLen = 12;
	const wchar_t CHARSET_PWD[129] = L"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789~`!@#$%^&*()_=+-'{}[];:,.?<>\\/abcdefghijklmnopqrstuvwxyz9876543210";
	const wchar_t CHARSET_PFX[129] = L"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789#$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz9876543210$#";

	bool debug = false;
	bool privdebug = false;
	bool isSystem = false;
	bool isImpersonated = false;
	std::wstring g_tempUserNameW;
	std::wstring g_tempUserW;
	std::wstring g_tempUserSidW;
	std::wstring g_tempUserProfileW;
	PSID g_tempUserPSid = nullptr;
	bool g_doUseExistingUserContext = false;
	bool g_tempUserCreated = false;
	bool g_keepTempUser = false; // -k / -keep
	bool g_tempuser_fallback = true;
	bool g_noWait = false; // -n / -nowait
	bool g_runFromGPO = false;
	bool g_cleanup_mode = false; // -cleanup
	bool g_cleanupall_mode = false; // -cleanup-all
	bool g_cl_on = false; // -cl
	bool g_cla_on = false; // -cla
	
	PROCESS_INFORMATION g_pi = {0};
	HANDLE g_hPrimaryToken = nullptr;
	LPVOID g_envBlock = nullptr;
	PROFILEINFO g_profileInfo = {0};
	bool g_profileLoaded = false;
	DWORD procPid;

	//----------------------------------------------------------------------------------------------------//

	auto SafeCloseHandle = [](HANDLE& h) {
		if (h && h != INVALID_HANDLE_VALUE) {
			CloseHandle(h);
			h = nullptr;
		}
	};

	std::wstring GetFileVersion() {
		wchar_t filename[MAX_PATH];
		if (!GetModuleFileNameW(nullptr, filename, MAX_PATH)) {
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

		// Version format major.minor.build.revision
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

	//----------------------------------------------------------------------------------------------------//

	void print_help() {
		std::wcout <<
		L"Usage:\n"
		L"\n"
		L"  RunAsHidden.exe -u <username> -p <password> [options] -c <command> [-params <parameters>]\n"
		L"\n"
		L"Options:\n"
		L"  -u, --username <username>       Target username. Formats:\n"
		L"                                  'user'           - local user\n"
		L"                                  'domain\\user'    - domain user\n"
		L"                                  'user@domain'    - domain user\n"
		L"                                  '.'              - current user (Use with the -p=. option)\n"
		L"                                  'auto'           - automatically create temporary hidden admin user\n"
		L"                                                     with isolated profile in %SystemRoot%\\Temp\\RAH\\ folder\n"
		L"                                                     By default, uses base name 'rah_tmp_user_' with 8\n"
		L"                                                     random characters appended (random suffix).\n"
		L"                                                     Example: rah_tmp_user_89nvDoQF\n"
		L"                                                     This user will always be removed after execution.\n"
		L"\n"
		L"  -p, --password <password>       Password for the user.\n"
		L"                                  Can be empty (-p=.) to use the current session.\n"
		L"                                  'auto' generates a strong random password for temporary hidden admin user.\n"
		L"\n"
		L"  -tn, --tempusername <username>  Used only with -u=auto option. Specifies the base name\n"
		L"                                  for the temporary hidden admin user.\n"
		L"                                  By default, 8 random characters are appended to ensure uniqueness:\n"
		L"                                  -tn=username (max 11 charecters) => username_89nvDoQF\n"
		L"                                  Using -tn with random suffix enabled automatically disables -k (--keep),\n"
		L"                                  so the temporary user and profile will always be removed.\n"
		L"                                  To disable random suffix generation, append a dot (.) to the name:\n"
		L"                                  -tn=username. (max 20 charecters without dot) => username\n"
		L"\n"
		L"  -k, --keep                      Keep the automatically created temporary hidden admin user\n"
		L"                                  for future use. Can only be used with -tn when random suffix is disabled\n"
		L"                                  (i.e., name ends with a dot).\n"
		L"\n"
		L"  -nofb, --nofb                   Disables automatic fallback to a new randomized username if the specified\n"
		L"                                  name (options -tn / -u ) is already taken by an existing non-temporary user.\n"
		L"                                  By default, if the utility cannot reuse an existing user (due to a name\n"
		L"                                  conflict or missing 'temporary' registry flag), it will create a new temporary\n"
		L"                                  hidden admin user with a random suffix (<username>_$random$) to ensure your\n"
		L"                                  scenario continues without interruption.\n"
		L"\n"
		L"                                  name (option -tn) is exists.\n"
		L"                                  (i.e., name ends with a dot).\n"
		L"\n"
		L"  -n, --nowait                    Do not wait for the command to finish.\n"
		L"                                  Returns 0 if process started successfully, otherwise 1.\n"
		L"                                  Incompatible with temporary admin user (options -u=auto, -tn).\n"
		L"\n"
		L"  -t, --timeout <seconds>         Wait the specified time before exiting and/or deleting temporary user.\n"
		L"                                  Maximum allowed: 60 seconds.\n"
		L"\n"
		L"  -d, --direct                    Run the command directly without 'cmd.exe /d /c'.\n"
		L"                                  Shell operators like >, |, & are not interpreted.\n"
		L"                                  Useful for direct execution or capturing output manually.\n"
		L"\n"
		L"  -v, --visible                   Run the command interactively (window visible) in the active session\n"
		L"                                  of the specified user. Use the -d option to run GUI applications directly.\n"
		L"\n"
		L"  -verb, --verbose                Enable small debug output of command details.\n"
		L"\n"
		L"  -debug, --debug                 Enable full debug output, diagnostics, and command details.\n"
		L"\n"
		L"  -c, --command <command>         Command line to execute. Can include full path.\n"
		L"                                  Quotes inside must be escaped with backslash (\\\\).\n"
		L"\n"
		L"  -params <parameters>            Optional parameters for the command. Passed exactly as-is.\n"
		L"                                  Use quotes if parameters contain spaces; escape internal quotes with \\\\.\n"
		L"\n"
		L"  -cleanup, --cleanup             Removes previously created temporary users\n"
		L"                                  (excluding those created with the -k option)\n"
		L"                                  that were not removed automatically. Cannot be\n"
		L"                                  use with other options.\n"
		L"\n"
		L"  -cleanup-all, --cleanup-all     Removes previously created temporary users\n"
		L"                                  (including those created with the -k option)\n"
		L"                                  that were not removed automatically. Cannot be\n"
		L"                                  use with other options.\n"
		L"\n"
		L"  -cl, --cl                       Can be use with other options. Removes previously\n"
		L"                                  created temporary users (excluding those created\n"
		L"                                  with the -k option) that were not removed automatically.\n"
		L"                                  Temorary users will be removed before execution command.\n"
		L"\n"
		L"  -cla, --cla                     Can be use with other options. Removes previously\n"
		L"                                  created temporary users (excluding those created \n"
		L"                                  with the -k option) that were not removed automatically.\n"
		L"                                  Temorary users will be removed before execution command.\n"
		L"\n"
		L"  -h, --help, -?                  Show this help message.\n"
		L"\n"
		L"Examples:\n"
		L"  RunAsHidden.exe -u user -p pass -c \"whoami\"\n"
		L"  RunAsHidden.exe -u=user -p=* -d -v -c \"mspaint.exe\" // Run mspaint.exe in existing user session\n"
		L"  RunAsHidden.exe -u=domain\\\\user -p=pass -c \"dism.exe /online /get-packages\"\n"
		L"  RunAsHidden.exe -u=auto -p=auto -c \"\\\"C:\\\\Program Files\\\\app.exe\\\" -arg1 -arg2\"\n"
		L"  RunAsHidden.exe -u=auto -p=auto -c \"\\\"script.cmd\\\" JJJ \\\"222\\\"\"\n"
		L"  RunAsHidden.exe -u=auto -p=auto -c \"\\\"script.cmd\\\"\" -params=\"\\\"222\\\" 333\"\n"
		L"      // Equivalent to: \"script.cmd\" \"222\" 333\n"
		L"  RunAsHidden.exe -u=auto -p=auto -c \"\\\"Updater.cmd\\\"\" -params=\"--file=\\\"C:\\\\Logs\\\\log.txt\\\" --mode=fast\"\n"
		L"  RunAsHidden.exe -u=auto -p=auto -d -c \"C:\\\\Windows\\\\System32\\\\whoami.exe\"\n"
		L"  RunAsHidden.exe -u=auto -p=auto -d -t 2 -k -c \"whoami\"\n"
		L"  RunAsHidden.exe -u=auto -p=auto -tn=tempuser. -d -k -c \"whoami\" // keep temporary user\n"
		L"  RunAsHidden.exe -u=auto -p=auto -tn=tempuser -c \"whoami\" // random suffix, user tempuser will be deleted after execution command\n";
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	void print_str(const std::wstring& msg) {
		std::wcout << msg << L"\n";
	}

	template<typename... Args>
	inline void print_warning(const Args&... args) {
		DWORD werr = GetLastError();
		std::wostringstream msg;
		msg << L"[WARNING]: ";
		(msg << ... << args);
		if (werr != 0) msg	<< L": code: " << werr;
		print_str(msg.str());
	}

	template<typename... Args>
	inline void print_debug(const Args&... args) {
		std::wostringstream msg;
		msg << L"[DEBUG]: ";
		(msg << ... << args);
		print_str(msg.str());
	}

	template<typename... Args>
	inline void print_error(const Args&... args) {
		DWORD err = GetLastError();
		std::wostringstream msg;
		std::wstring errorMessage;
		if constexpr (sizeof...(Args) > 0) {
			(msg << ... << args);
		}
		switch (err) {
			case ERROR_ACCESS_DENIED:
				errorMessage = L"Access denied";
				break;
			case ERROR_LOGON_FAILURE:
				errorMessage = L"Incorrect username or password";
				break;
			case ERROR_ACCOUNT_RESTRICTION:
				errorMessage = L"Account restrictions prevent login";
				break;
			case ERROR_LOGON_TYPE_NOT_GRANTED:
				errorMessage = L"Logon type not granted";
				break;
			case ERROR_PRIVILEGE_NOT_HELD:
				errorMessage = L"Required privilege not held";
				break;
			default:
				break;
		}
		if (!errorMessage.empty()) {
			msg << L": " << errorMessage;
		}
		if (err != 0) {
			msg << L" [error code: " << err << L"]";
		}

		print_str(L"[ERROR]: " + msg.str());
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	template<typename T>
	void SecureClear(std::basic_string<T>& str) {
		if (!str.empty()) {
			SecureZeroMemory(&str[0], str.size() * sizeof(T));
			str.clear();
			str.shrink_to_fit();
		}
	}

	void ClearSensitiveData(
		std::wstring& username,
		std::wstring& userOnly,
		std::wstring& domain,
		std::wstring& password,
		std::wstring& tempusername,
		std::wstring& temppassword,
		std::wstring& cmdLine,
		std::wstring& command,
		std::vector<wchar_t>& cmdLineBuf
	) {
		SecureClear(username);
		SecureClear(userOnly);
		SecureClear(domain);
		SecureClear(password);
		SecureClear(tempusername);
		SecureClear(temppassword);
		SecureClear(cmdLine);
		SecureClear(command);
		SecureZeroMemory(cmdLineBuf.data(), cmdLineBuf.size() * sizeof(wchar_t));
		cmdLineBuf.clear();
		cmdLineBuf.shrink_to_fit();
	}


	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	std::wstring GetHostname() {
		wchar_t name[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD size = ARRAYSIZE(name);
		if (!GetComputerNameW(name, &size)) 	{
			print_error(L"GetHostname: GetComputerNameW failed");
			return L"";
		}
		return std::wstring(name, size);
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	bool IsDirectoryExists(const std::wstring& path) {
		if (path.empty()) return false;
		DWORD dirAttrib = GetFileAttributesW(path.c_str());
		return (dirAttrib != INVALID_FILE_ATTRIBUTES && (dirAttrib & FILE_ATTRIBUTE_DIRECTORY));
	}

	bool IsFileExists(const std::wstring& path, const std::wstring& filename) {
		if (path.empty() || filename.empty()) return false;
		std::wstring fullPath = path + L"\\" + filename;
		DWORD fileAttrib = GetFileAttributesW(fullPath.c_str());
		return (fileAttrib != INVALID_FILE_ATTRIBUTES && !(fileAttrib & FILE_ATTRIBUTE_DIRECTORY));
	}

	bool CreateTagFile(const std::wstring& path, const std::wstring& filename) {
		if (path.empty() || filename.empty()) return false;
		std::wstring fullPath = path + L"\\" + filename;
		HANDLE hFile = CreateFileW(fullPath.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
		if (hFile == INVALID_HANDLE_VALUE) {
			return false; 
		}
		CloseHandle(hFile);
		return true;
	}


	LSTATUS DeleteRegistryKey(const std::wstring& RegKey) {
		if (RegKey.empty()) return ERROR_INVALID_PARAMETER;
		size_t pos = RegKey.find_last_of(L'\\');
		if (pos == std::wstring::npos) return ERROR_INVALID_PARAMETER;
		std::wstring parent = RegKey.substr(0, pos);
		std::wstring keyName = RegKey.substr(pos + 1);
		HKEY hParent = nullptr;
		LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,parent.c_str(),0,KEY_ALL_ACCESS,&hParent);
		if (status != ERROR_SUCCESS) return status;
		status = RegDeleteTreeW(hParent,keyName.c_str());
		RegCloseKey(hParent);
		if (debug) print_debug(L"DeleteRegistryKey: ", RegKey, L" - Status: ", status);
		return status;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	bool EnableDebugPrivilege() {
		HANDLE hToken = nullptr;
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
			print_error(L"EnableDebugPrivilege: OpenProcessToken failed");
			return false;
		}

		if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
			print_error(L"EnableDebugPrivilege: LookupPrivilegeValue failed");
			SafeCloseHandle(hToken);
			return false;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), nullptr, nullptr)) {
			print_error(L"EnableDebugPrivilege: AdjustTokenPrivileges failed");
			SafeCloseHandle(hToken);
			return false;
		}

		SafeCloseHandle(hToken);

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
			print_error(L"EnableDebugPrivilege: The token does not have the specified privilege");
			return false;
		}

		return true;
	}

	bool EnablePrivilege(LPCWSTR privName) {
		HANDLE hToken;
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
			print_error(L"EnablePrivilege: OpenProcessToken failed");
			return false;
		}

		if (!LookupPrivilegeValueW(nullptr, privName, &luid)) {
			print_error(L"EnablePrivilege: LookupPrivilegeValue failed");
			SafeCloseHandle(hToken);
			return false;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), nullptr, nullptr)) {
			print_error(L"EnablePrivilege: AdjustTokenPrivileges failed");
			SafeCloseHandle(hToken);
			return false;
		}

		SafeCloseHandle(hToken);
		return GetLastError() == ERROR_SUCCESS;
	}

	bool EnableThreadPrivilege(LPCWSTR privName) {
		HANDLE hToken = nullptr;;

		// Try to open the stream token (after ImpersonateLoggedOnUser it is there)
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, false, &hToken)) {
			// If thread token is missing, try to open the process token (fallback)
			if (GetLastError() == ERROR_NO_TOKEN) {
				if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
					print_error(L"EnableThreadPrivilege: OpenProcessToken failed");
					return false;
				}
			} else {
				print_error(L"EnableThreadPrivilege: OpenThreadToken failed");
				return false;
			}
		}

		LUID luid;
		if (!LookupPrivilegeValueW(nullptr, privName, &luid)) {
			print_error(L"EnableThreadPrivilege: LookupPrivilegeValue failed");
			SafeCloseHandle(hToken);
			return false;
		}

		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), nullptr, nullptr)) {
			print_error(L"EnableThreadPrivilege: AdjustTokenPrivileges failed");
			SafeCloseHandle(hToken);
			return false;
		}

		DWORD err = GetLastError();
		SafeCloseHandle(hToken);

		if (err == ERROR_NOT_ALL_ASSIGNED) {
			print_error(L"EnableThreadPrivilege: The token does not have the privilege: ", privName);
			return false;
		}

		return true;
	}

	bool EnableTokenPrivilege(HANDLE hToken, LPCWSTR privilegeName) {
		TOKEN_PRIVILEGES tp;
		LUID luid;
		if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
			print_error(L"EnableTokenPrivilege: LookupPrivilegeValueW failed");
			return false;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		return AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), nullptr, nullptr) &&
			   GetLastError() == ERROR_SUCCESS;
	}

	HANDLE GetSystemToken() {
		DWORD sessionId = WTSGetActiveConsoleSessionId(); // Current console gui session id
		if (debug) print_debug(L"Current Session ID: ", sessionId);

		EnablePrivilege(SE_DEBUG_NAME); //just in case

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap == INVALID_HANDLE_VALUE) {
			print_error(L"GetSystemToken: CreateToolhelp32Snapshot failed");
			return nullptr;
		}

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(pe);
		HANDLE hWinlogonToken = nullptr;;

		if (Process32First(hSnap, &pe)) {
			do {
				if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
					DWORD pid = pe.th32ProcessID;
					DWORD procSessionId = -1;
					if (!ProcessIdToSessionId(pid, &procSessionId)) continue;

					if (procSessionId != sessionId) continue;

					if (debug) print_debug(L"Found winlogon.exe PID=", pid);

					HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
					if (!hProc) {
						print_error(L"GetSystemToken: Cannot open winlogon.exe");
						continue;
					}

					HANDLE hToken = nullptr;;
					if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
						SafeCloseHandle(hProc);
						print_error(L"GetSystemToken: Cannot open token of winlogon.exe");
						continue;
					}

					if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &hWinlogonToken)) {
						print_error(L"GetSystemToken: DuplicateTokenEx failed");
						hWinlogonToken = nullptr;;
					}

					SafeCloseHandle(hToken);
					SafeCloseHandle(hProc);
					break;
				}
			} while (Process32Next(hSnap, &pe));
		}

		SafeCloseHandle(hSnap);

		if (!hWinlogonToken) {
			print_error(L"GetSystemToken: winlogon.exe not found or failed");
		}
		
		return hWinlogonToken;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	//****************************************************************************************************//

	size_t GetMinPasswordLengthPolicy() {
		size_t len = 8;
		USER_MODALS_INFO_0 *pBuf = nullptr;
		NET_API_STATUS nStatus = NetUserModalsGet(nullptr, 0, (LPBYTE *)&pBuf);
		if (nStatus == NERR_Success) {
			if (pBuf != nullptr) {
				len =  static_cast<size_t>(pBuf->usrmod0_min_passwd_len);
			}
		}
		if (pBuf != nullptr) {
			NetApiBufferFree(pBuf);
		}
		return len;
	}

	static std::mt19937& GetEngine() {
		static thread_local std::mt19937 engine(std::random_device{}() ^ (unsigned int)time(nullptr));
		return engine;
	}

	extern "C" BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);

	std::wstring GenerateRandom(size_t length, const wchar_t* charset) {
		std::wstring result;
		result.reserve(length);
		std::vector<BYTE> buf(length);
		if (RtlGenRandom(buf.data(), static_cast<ULONG>(buf.size()))) {
			for (size_t i = 0; i < length; ++i) {
				result += charset[buf[i] & 127];
			}
		} else {
			auto& engine = GetEngine();
			for (size_t i = 0; i < length; ++i) {
				result += charset[engine() & 127];
			}
		}
		SecureZeroMemory(buf.data(), buf.size()); 
		return result;
	}

	std::wstring GenerateUsernamePostfix(size_t length) {
		if (length < 8) length = 8;
		return GenerateRandom(length, CHARSET_PFX);
	}

	std::wstring GeneratePassword(size_t length) {
		size_t pollen = GetMinPasswordLengthPolicy();
		if (length < g_DefaultPassLen) length = g_DefaultPassLen;
		if (length < pollen) length = pollen;
		return GenerateRandom(length, CHARSET_PWD);
	}

	//****************************************************************************************************//

	//std::wstring GenerateRandomString_old(size_t length) {
	//	if (debug) print_debug(L"GenerateRandomString: Generate username postfix [random]");
	//	const wchar_t charset[] = L"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789#$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz9876543210$#";
	//	//const size_t charset_size = (sizeof(charset) / sizeof(charset[0])) - 1;
	//	if (length < 8) length = 8;
	//	std::wstring result;
	//	result.reserve(length);
	//	//std::uniform_int_distribution<size_t> distribution(0, charset_size - 1);
	//	auto& engine = GetEngine();
	//	for (size_t i = 0; i < length; ++i) {
	//		//result += charset[distribution(GetEngine())];
	//		result += charset[ engine() & 127 ];
	//	}
	//	return result;
	//}

	//void GeneratePassword_old(size_t length, std::wstring& genpassword) {
	//	const wchar_t charset[] = L"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789~`!@#$%^&*()_=+-'{}[];:,.?<>\\/abcdefghijklmnopqrstuvwxyz9876543210";
	//	//const size_t charset_size = (sizeof(charset) / sizeof(charset[0]) - 1);
	//	size_t pollen = GetMinPasswordLengthPolicy();
	//	if ( length < g_DefaultPassLen ) length = g_DefaultPassLen;
	//	if ( length < pollen) length = pollen;
	//	std::vector<BYTE> buf(length);
	//	bool crypto_ok = RtlGenRandom(buf.data(), (ULONG)buf.size()); //[SystemFunction036]
	//	crypto_ok = false;
	//	genpassword.clear();
	//	genpassword.reserve(length);
	//	if (crypto_ok) {
	//		if (debug) print_debug(L"GeneratePassword: Generate password [crypto]");
	//		for (size_t i = 0; i < length; ++i) {
	//			//genpassword += charset[ buf[i] % charset_size ];
	//			genpassword += charset[ buf[i] & 127 ]; 
	//		}
	//	} else {
	//		if (debug) print_debug(L"GeneratePassword: Generate password [random]");
	//		//std::uniform_int_distribution<size_t> distribution(0, charset_size - 1);
	//		auto& engine = GetEngine();
	//		for (size_t i = 0; i < length; ++i) {
	//			//genpassword += charset[distribution(GetEngine())];
	//			genpassword += charset[ engine() & 127 ];
	//		}
	//	}
	//}

	//****************************************************************************************************//

	//----------------------------------------------------------------------------------------------------//

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	void SetGlobalSid(PSID pSrcSid) {
		if (g_tempUserPSid) {
			LocalFree(g_tempUserPSid);
			g_tempUserPSid = nullptr;
		}
		if (pSrcSid && IsValidSid(pSrcSid)) {
			DWORD sidLen = GetLengthSid(pSrcSid);
			g_tempUserPSid = (PSID)LocalAlloc(LPTR, sidLen);
			if (g_tempUserPSid) {
				if (!CopySid(sidLen, g_tempUserPSid, pSrcSid)) {
					LocalFree(g_tempUserPSid);
					g_tempUserPSid = nullptr;
				}
			}
		}
	}

	std::wstring SidToString(PSID pSid) {
		if (!pSid) return L"";
		LPWSTR szSid = nullptr;
		std::wstring result = L"";
		if (ConvertSidToStringSidW(pSid, &szSid)) {
			result = szSid;
			LocalFree(szSid);
			szSid = nullptr;
		}
		return result;
	}
 
	bool GetSIDFromUsername(PSID* ppSid, const std::wstring& username, const std::wstring domain = L"") {
		if (!ppSid) return false;
		*ppSid = nullptr;
		LPCWSTR lpSystemName = domain.empty() ? nullptr : domain.c_str();

		BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
		DWORD sidSize = sizeof(sidBuffer);
		WCHAR domainBuffer[MAX_PATH];
		DWORD domainSize = MAX_PATH;
		SID_NAME_USE snu;

		if (LookupAccountNameW(lpSystemName, username.c_str(), (PSID)sidBuffer, &sidSize, domainBuffer, &domainSize, &snu)) {
			if (IsValidSid((PSID)sidBuffer)) {
				*ppSid = (PSID)LocalAlloc(LPTR, sidSize);
				if (*ppSid) {
					CopyMemory(*ppSid, sidBuffer, sidSize);
					if (debug) {
						std::wstring sidString = SidToString(*ppSid);
						print_debug(L"GetSIDFromUsername: LookupAccountNameW: Retrieved User SID: ", sidString);
					}
					return true;
				}
			} else {
				print_error(L"GetSIDFromUsername: LookupAccountNameW: Invalid SID");
			}
		}
		print_error(L"GetSIDFromUsername: LookupAccountNameW: failed to get SID for: ", username);
		return false;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	bool IsUserProcessRunning(PSID pTargetSid) {
		if (!pTargetSid) {
			print_error("IsUserProcessRunning: User SID is not specified.");
			return false;
		}
		PWTS_PROCESS_INFOW pProcInfo = nullptr;
		DWORD procCount = 0;
		bool found = false;
		if (WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pProcInfo, &procCount)) {
			for (DWORD i = 0; i < procCount; ++i) {
				if (pProcInfo[i].pUserSid && EqualSid(pProcInfo[i].pUserSid, pTargetSid)) {
					found = true;
					break;
				}
			}
			WTSFreeMemory(pProcInfo);
		}
		return found;
	}

	bool IsUserLoggedOn(const std::wstring& username) {
		if (username.empty()) {
			print_error("IsUserLoggedOn: Username is not specified.");
			return false;
		}
		bool success = false;
		PSID tSid = nullptr;
		bool tDebug = debug;
		debug = false;
		if (GetSIDFromUsername(&tSid,username)) {
			success = IsUserProcessRunning(tSid);
			LocalFree(tSid);
			tSid = nullptr;
		}
		debug = tDebug;
		return success;
	}

	//bool IsUserLoggedOnV2(const std::wstring& username) {
	//	if (username.empty()) {
	//		print_error("IsUserLoggedOn: Username is not specified.");
	//		return false;
	//	}
	//	bool found = false;
	//	BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
	//	DWORD sidSize = sizeof(sidBuffer);
	//	wchar_t domainName[MAX_PATH];
	//	DWORD domainSize = MAX_PATH;
	//	SID_NAME_USE snu;
	//	if (!LookupAccountNameW(nullptr, username.c_str(), (PSID)sidBuffer, &sidSize, domainName, &domainSize, &snu)) {
	//		return false; // No user in system
	//	}
	//	PWTS_PROCESS_INFOW pProcInfo = nullptr;
	//	DWORD procCount = 0;
	//	if (WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pProcInfo, &procCount)) {
	//		for (DWORD i = 0; i < procCount; ++i) {
	//			if (pProcInfo[i].pUserSid && EqualSid(pProcInfo[i].pUserSid, (PSID)sidBuffer)) {
	//				found = true;
	//				break;
	//			}
	//		}
	//		WTSFreeMemory(pProcInfo);
	//	}
	//	return found;
	//}

	//bool IsUserLoggedOnV1(const std::wstring& username) {
	//	if (username.empty()) {
	//		print_error("IsUserLoggedOn: Username is not specified.");
	//		return false;
	//	}
	//	bool found = false;
	//	PWTS_PROCESS_INFO pProcInfo = nullptr;
	//	DWORD procCount = 0;
	//	// Get procs list
	//	if (!WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pProcInfo, &procCount)) {
	//		return found; // Unable to get process list - assuming user is inactive
	//	}
	//	for (DWORD i = 0; i < procCount; ++i) {
	//		DWORD sessionId = pProcInfo[i].SessionId;
	//		LPWSTR procUser = nullptr;
	//		DWORD userLen = 0;
	//		// Get user from proc
	//		if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &procUser, &userLen)) {
	//			if (_wcsicmp(procUser, username.c_str()) == 0) {
	//				found = true; // Found proc
	//			}
	//			WTSFreeMemory(procUser);
	//		}
	//		if (found) break; // Proc found - terminating
	//	}
	//	WTSFreeMemory(pProcInfo);
	//	return found;
	//}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	HANDLE GetPrimaryTokenFromUserProcess(PSID pTargetSid) {
		if (!pTargetSid || !IsValidSid(pTargetSid)) return nullptr;
		PWTS_PROCESS_INFOW pProcInfo = nullptr;
		DWORD procCount = 0;
		HANDLE hPrimaryToken = nullptr;
		// 1. Get a list of all processes in the system
		if (WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pProcInfo, &procCount)) {
			for (DWORD i = 0; i < procCount; ++i) {
				// 2. We look for a process whose SID matches target SID.
				if (pProcInfo[i].pUserSid && EqualSid(pProcInfo[i].pUserSid, pTargetSid)) {
					// 3. We try to open a process to receive a token
					// We use PROCESS_QUERY_LIMITED_INFORMATION for maximum compatibility
					HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pProcInfo[i].ProcessId);
					if (hProcess) {
						HANDLE hProcessToken = nullptr;
						if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hProcessToken)) {
							// 4. Duplicate the token to obtain the Primary Token for CreateProcessAsUserW
							if (DuplicateTokenEx(hProcessToken, MAXIMUM_ALLOWED, nullptr,SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
								if (debug) {
									print_debug(L"GetPrimaryTokenFromUserProcess: Hijacked token from PID: ", pProcInfo[i].ProcessId);
								}
							}
							CloseHandle(hProcessToken);
						}
						CloseHandle(hProcess) ;
					}
					// If the token is successfully received, exit the loop
					if (hPrimaryToken) break;
				}
			}
			WTSFreeMemory(pProcInfo);
		}

		return hPrimaryToken;
	}

	DWORD GetSessionIdByUserName(const std::wstring& userOnly, const std::wstring& domain) {
		PWTS_SESSION_INFO pSessionInfo = nullptr;
		DWORD sessionCount = 0;
		if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount)) {
			return 0xFFFFFFFF;
		}
		struct SessionGuard { PWTS_SESSION_INFO p; ~SessionGuard(){ if(p) WTSFreeMemory(p); } } guard{ pSessionInfo };
		std::wstring targetDomain = domain;
		if (domain == L"." || domain.empty()) {
			WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
			DWORD size = ARRAYSIZE(computerName);
			if (!GetComputerNameW(computerName, &size)) {
				return 0xFFFFFFFF;
			}
			targetDomain = computerName; // check domain
		}
		for (DWORD i = 0; i < sessionCount; ++i) {
			DWORD sessionId = pSessionInfo[i].SessionId;
			struct WtsBuffer { LPWSTR ptr = nullptr; ~WtsBuffer(){ if(ptr) WTSFreeMemory(ptr); } } userBuf, domainBuf;
			DWORD bytes = 0;

			if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &userBuf.ptr, &bytes) || !userBuf.ptr || !*userBuf.ptr) {
				continue;
			}
			if (_wcsicmp(userBuf.ptr, userOnly.c_str()) != 0) {
				continue;
			}
			if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSDomainName, &domainBuf.ptr, &bytes) || !domainBuf.ptr || !*domainBuf.ptr) {
				continue;
			}
			if (_wcsicmp(domainBuf.ptr, targetDomain.c_str()) == 0) {
				return sessionId; // session id of target user
			}
		}
		return 0xFFFFFFFF;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	void PrintTokenInformation(HANDLE sToken) {

		if (!sToken || sToken == INVALID_HANDLE_VALUE) {
			print_error(L"PrintTokenInformation: Invalid token handle");
			return;
		}

		if (debug) print_debug(L"PrintTokenInformation, token: ", sToken);

		DWORD dwSize = 0;
		if (!GetTokenInformation(sToken, TokenUser, nullptr, 0, &dwSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			print_error(L"PrintTokenInformation: GetTokenInformation [TokenUser] size failed");
			return;
		}

		PTOKEN_USER pUser = (PTOKEN_USER)malloc(dwSize);
		if (!pUser) {
			print_error(L"PrintTokenInformation: Failed to allocate memory for TokenUser");
			return;
		}

		if (!GetTokenInformation(sToken, TokenUser, pUser, dwSize, &dwSize)) {
			print_error(L"PrintTokenInformation: GetTokenInformation [TokenUser] failed");
			free(pUser);
			return;
		}

		LPWSTR sidStr = nullptr;
		if (ConvertSidToStringSidW(pUser->User.Sid, &sidStr)) {
			if (debug) print_debug(L"SID: ", sidStr);
			LocalFree(sidStr);
			sidStr = nullptr;
		} else {
			print_error(L"PrintTokenInformation: ConvertSidToStringSidW failed");
		}
		free(pUser);
	}

	//----------------------------------------------------------------------------------------------------//

	void PrintTokenPrivileges(HANDLE hToken, const wchar_t* username) {
		if (!hToken) {
			print_error(L"PrintTokenPrivileges: Invalid token handle");
			return;
		}

		if (username) {
			if (debug) print_debug(L"Token privileges for: ", username);
		}

		// --- TokenUser ---
		DWORD size = 0;
		GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			print_error(L"PrintTokenPrivileges: GetTokenInformation [TokenUser] buffer size failed");
		} else {
			BYTE* buffer = new BYTE[size];
			TOKEN_USER* tokenUser = (TOKEN_USER*)buffer;

			if (GetTokenInformation(hToken, TokenUser, tokenUser, size, &size)) {
				LPWSTR stringSid = nullptr;
				if (ConvertSidToStringSidW(tokenUser->User.Sid, &stringSid)) {
					if (debug) print_debug(L"SID: ", stringSid);
					LocalFree(stringSid);
					stringSid = nullptr;
				} else {
					print_error(L"PrintTokenPrivileges: ConvertSidToStringSidW failed");
				}
			} else {
				print_error(L"PrintTokenPrivileges: GetTokenInformation [TokenUser] failed");
			}

			delete[] buffer;
		}

		// --- TokenType ---
		TOKEN_TYPE tokenType;
		if (GetTokenInformation(hToken, TokenType, &tokenType, sizeof(tokenType), &size)) {
			if (debug) print_debug(L"Token type: ", (tokenType == TokenPrimary ? L"Primary" : L"Impersonation"));
		} else {
			print_error(L"PrintTokenPrivileges: GetTokenInformation [TokenType] failed");
		}

		// --- TokenPrivileges ---
		DWORD len = 0;
		GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &len);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			print_error(L"PrintTokenPrivileges: GetTokenInformation [TokenPrivileges] buffer size failed");
			return;
		}

		TOKEN_PRIVILEGES* privs = (TOKEN_PRIVILEGES*)new BYTE[len];
		if (!GetTokenInformation(hToken, TokenPrivileges, privs, len, &len)) {
			print_error(L"PrintTokenPrivileges: GetTokenInformation [TokenPrivileges] failed");
			delete[] privs;
			return;
		}

		for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
			LUID luid = privs->Privileges[i].Luid;

			// Privilege name size
			DWORD nameLen = 0;
			LookupPrivilegeNameW(nullptr, &luid, nullptr, &nameLen);
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				print_error(L"PrintTokenPrivileges: LookupPrivilegeNameW failed to get size");
				continue;
			}

			nameLen++; // for finishing \0
			std::wstring name(nameLen, L'\0');

			if (LookupPrivilegeNameW(nullptr, &luid, &name[0], &nameLen)) {
				name.resize(nameLen); // remove unnecessary characters
				std::wcout << L"    " << name;

				// --- Full attributes output ---
				DWORD attrs = privs->Privileges[i].Attributes;
				if (attrs & SE_PRIVILEGE_ENABLED)
					std::wcout << L" [ENABLED]";
				if (attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
					std::wcout << L" [ENABLED_BY_DEFAULT]";
				if (attrs & SE_PRIVILEGE_REMOVED)
					std::wcout << L" [REMOVED]";
				if (attrs & SE_PRIVILEGE_USED_FOR_ACCESS)
					std::wcout << L" [USED_FOR_ACCESS]";

				std::wcout << L"\n";
			} else {
				print_error(L"PrintTokenPrivileges: LookupPrivilegeNameW failed");
			}
		}
		delete[] privs;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	std::wstring ToLower(const std::wstring& str) {
		std::wstring lower = str;
		std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
		return lower;
	}

	bool StartsWith(const std::wstring& str, const std::wstring& prefix) {
		std::wstring s1 = ToLower(str);
		std::wstring s2 = ToLower(prefix);
		return s1.compare(0, s2.length(), s2) == 0;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	std::wstring GetProfilePathBySid(const std::wstring& userSidW, HKEY hUserKey = nullptr) {
		std::wstring subKey = g_profileRegKey + L"\\" + userSidW;
		std::wstring profilePathW = L"";
		bool isOpened = false;
		LSTATUS status;
		if (hUserKey == nullptr) {
			status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ, &hUserKey);
			if (status == ERROR_SUCCESS) isOpened = true;
		} else {
			status = ERROR_SUCCESS;
		}
		if (status == ERROR_SUCCESS) {
			wchar_t profilePath[MAX_PATH] = {0};
			DWORD pathSize = sizeof(profilePath);
			if (RegQueryValueExW(hUserKey, L"ProfileImagePath", nullptr, nullptr,reinterpret_cast<BYTE*>(profilePath), &pathSize) == ERROR_SUCCESS) {
				wchar_t expandedPath[MAX_PATH];
				if (ExpandEnvironmentStringsW(profilePath, expandedPath, MAX_PATH) > 0) {
					profilePathW = expandedPath;
				} else {
					profilePathW = profilePath;
				}
			}
			if (isOpened) RegCloseKey(hUserKey);
		}
		return profilePathW;
	}

	void SetIsRahTemporaryUserSid(const std::wstring& userSidW, HKEY hKey = nullptr) {
		std::wstring regPath = g_profileRegKey + L"\\" + userSidW;
		LSTATUS res = ERROR_SUCCESS;
		bool isOpened = false;
		if (!hKey) {
			res = RegCreateKeyExW(HKEY_LOCAL_MACHINE,regPath.c_str(),0,nullptr,REG_OPTION_NON_VOLATILE,KEY_WRITE, nullptr, &hKey, nullptr);
			isOpened = true;
		}
		if (res == ERROR_SUCCESS && hKey) {
			DWORD val = 1;
			RegSetValueExW(hKey, L"IsRahTemporaryUser", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));
		}
		if (isOpened && hKey) RegCloseKey(hKey);
	}

	void SetIsRahTemporaryKeepedUserSid(const std::wstring& userSidW, HKEY hKey = nullptr) {
		std::wstring regPath = g_profileRegKey + L"\\" + userSidW;
		LSTATUS res = ERROR_SUCCESS;
		bool isOpened = false;
		if (!hKey) {
			res = RegCreateKeyExW(HKEY_LOCAL_MACHINE,regPath.c_str(),0,nullptr,REG_OPTION_NON_VOLATILE,KEY_WRITE, nullptr, &hKey, nullptr);
			isOpened = true;
		}
		if (res == ERROR_SUCCESS && hKey) {
			DWORD val = 1;
			RegSetValueExW(hKey, L"IsKeepedUser", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));
		}
		if (isOpened && hKey) RegCloseKey(hKey);
	}

	void UnSetIsRahTemporaryKeepedUserSid(const std::wstring& userSidW, HKEY hKey = nullptr) {
		std::wstring regPath = g_profileRegKey + L"\\" + userSidW;
		LSTATUS res = ERROR_SUCCESS;
		bool isOpened = false;
		if (!hKey) {
			res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_WRITE, &hKey);
			if (res == ERROR_SUCCESS) {
				isOpened = true;
			} else {
				hKey = nullptr;
			}
		}
		if (res == ERROR_SUCCESS && hKey) {
			RegDeleteValueW(hKey, L"IsKeepedUser");
		}
		if (isOpened && hKey) RegCloseKey(hKey);
	}

	bool IsRahTemporaryUserSid(const std::wstring& userSidW, HKEY hUserKey = nullptr) {
		bool success = false;
		bool isOpened = false;
		LSTATUS status;
		if (!hUserKey) {
			std::wstring subKey = g_profileRegKey + L"\\" + userSidW;
			status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ, &hUserKey);
			if (status == ERROR_SUCCESS) isOpened = true;
		} else {
			status = ERROR_SUCCESS;
		}
		if (status == ERROR_SUCCESS) {
			success	= (RegQueryValueExW(hUserKey,L"IsRahTemporaryUser",nullptr,nullptr,nullptr,nullptr) == ERROR_SUCCESS);
			if (isOpened) RegCloseKey(hUserKey);
		}
		return success;
	}

	bool IsRahTemporaryKeepedUserSid(const std::wstring& userSidW, HKEY hUserKey = nullptr) {
		bool success = false;
		bool isOpened = false;
		LSTATUS status;
		if (!hUserKey) {
			std::wstring subKey = g_profileRegKey + L"\\" + userSidW;
			status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ, &hUserKey);
			if (status == ERROR_SUCCESS) isOpened = true;
		} else {
			status = ERROR_SUCCESS;
		}
		if (status == ERROR_SUCCESS) {
			success	= (RegQueryValueExW(hUserKey,L"IsKeepedUser",nullptr,nullptr,nullptr,nullptr) == ERROR_SUCCESS);
			if (isOpened) RegCloseKey(hUserKey);
		}
		return success;
	}

	bool IsRahTemporaryUser(const std::wstring& username) {
		bool success = false;
		if (!username.empty()) {
			LPUSER_INFO_1 tmpInfo = nullptr;
			NET_API_STATUS nStatus = NetUserGetInfo(nullptr, username.c_str(), 1, (LPBYTE*)&tmpInfo);
			if (nStatus == NERR_Success) {
				if (tmpInfo) {
					if (tmpInfo->usri1_comment && std::wstring(tmpInfo->usri1_comment) == g_RahUserComment) {
						success = true; 
					}
				}
				if (!success) {
					PSID tSid = nullptr;		
					LPWSTR tSidString = nullptr;
					std::wstring tUserSid;
					bool tDebug = debug;
					debug = false;
					if (GetSIDFromUsername(&tSid,username)) {
						debug = tDebug;
						if (IsValidSid(tSid)) {
							if (ConvertSidToStringSidW(tSid, &tSidString)) {
								tUserSid = tSidString;
								LocalFree(tSidString);
								tSidString = nullptr;
							}
						}
						LocalFree(tSid);
						tSid = nullptr;	
					}
					if (!tUserSid.empty()) {
						success = IsRahTemporaryUserSid(tUserSid);
					}
					debug = tDebug;
				}
				NetApiBufferFree(tmpInfo);
				tmpInfo = nullptr;
			} else {
				if (nStatus != NERR_UserNotFound) {
					return false; //For future use
				}
			}
		}
		return success;
	}
	
	//void FindTemporaryUsers() { //As an example
	//	LPUSER_INFO_1 pBuf = nullptr;
	//	DWORD entriesRead = 0;
	//	DWORD totalEntries = 0;
	//	DWORD resumeHandle = 0;
	//	NET_API_STATUS nStatus;
	//	do {
	//		nStatus = NetUserEnum(nullptr,1,FILTER_NORMAL_ACCOUNT,(LPBYTE*)&pBuf,MAX_PREFERRED_LENGTH,&entriesRead,&totalEntries,&resumeHandle);
	//		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
	//			if (pBuf) {
	//				for (DWORD i = 0; i < entriesRead; i++) {
	//					// Check Comment
	//					if (pBuf[i].usri1_comment && pBuf[i].usri1_comment == g_RahUserComment) {
	//						if (debug) print_debug(L"FindTemporaryUsers: Found matching user: ", pBuf[i].usri1_name);
	//					}
	//				}
	//			}
	//		}
	//		if (pBuf) {
	//			NetApiBufferFree(pBuf);
	//			pBuf = nullptr;
	//		}
	//	} 
	//	while (nStatus == ERROR_MORE_DATA);
	//}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	bool TempUserAndProfileDebug(const std::wstring& usernameW, const std::wstring& userSidW, const std::wstring& profilePathW, const std::wstring& profileKeyW = L"" ) {

		bool success = true;

		std::wcout << L"[DEBUG]: User and profile:\n";
		std::wcout << L"  > Username: " << usernameW << L"\n";
		std::wcout << L"  > SID     : " << userSidW << L"\n";
		std::wcout << L"  > Profile : " << profilePathW << L"\n";

		// User exist?
		LPUSER_INFO_0 pInfo = nullptr;
		if (NetUserGetInfo(nullptr, usernameW.c_str(), 0, (LPBYTE*)&pInfo) == NERR_Success) {
			std::wcout << L"  > [OK] User exists.\n";
			NetApiBufferFree(pInfo);
		} else {
			std::wcout << L"  > [WARNING] User not found.\n";
			success = false;
		}

		// Check profile
		
		if (IsDirectoryExists(profilePathW)) {
			std::wcout << L"  > [OK] Profile directory exists.\n";
		} else {
			std::wcout << L"  > [WARNING] Profile path missing or not a directory.\n";
			success = false;
		}

		// Check SID
		if (userSidW.find(L"S-1-5-") == 0) {
			std::wcout << L"  > [OK] SID appears valid.\n";
		} else {
			std::wcout << L"  > [WARNING] SID may be invalid.\n";
			success = false;
		}

		// Check Profile rgistry key
		if (!profileKeyW.empty()) {
			std::wcout << L"  > [OK] Profile key: " << profileKeyW << "\n";
		}

		return success;
	}

	int g_R_UC = 0;
	LSTATUS RunRegUnload(const std::wstring& path) {
		if (path.empty()) return 0;
		DWORD exitCode = 0;
		std::wstring regLogName, regcommand;
		if (debug) {
			g_R_UC+=1;
			regLogName = L"reg_log_" + std::to_wstring(g_R_UC) + L".log";
			regcommand = L"cmd.exe /d /c \"chcp 437 >nul & ( reg.exe query \"HKEY_USERS\\" + path + L"\" >nul 2>&1 || (exit /b 0) ) && (reg.exe unload \"HKEY_USERS\\" + path + L"\" >\"%temp%\\" + regLogName + L"\" 2>&1)\"";
		} else {
			regcommand = L"cmd.exe /d /c \"chcp 437 >nul & ( reg.exe query \"HKEY_USERS\\" + path + L"\" >nul 2>&1 || (exit /b 0) ) && (reg.exe unload \"HKEY_USERS\\" + path + L"\" >nul 2>&1)\"";
		}
		STARTUPINFOW si = { sizeof(si) };
		PROCESS_INFORMATION pi = { 0 };
		if (CreateProcessW(nullptr, &regcommand[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
			WaitForSingleObject(pi.hProcess, 5000);
			GetExitCodeProcess(pi.hProcess, &exitCode);
			if (debug) print_debug(L"UnloadUserRegistry: Failover: reg unload ", path, L", ExitCode: ", exitCode);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		} else {
			print_error(L"UnloadUserRegistry: Failover: reg unload - fatal error");
			exitCode = 9009;
		}
		return exitCode;
	}

	void UnloadUserRegistry(const std::wstring& userSid) {
		if (userSid.empty()) {
			print_error("UnloadUserRegistry: User SID is not specified");
			return;
		}
		EnablePrivilege(SE_RESTORE_NAME);
		EnablePrivilege(SE_BACKUP_NAME);
		LSTATUS res = 0;
		res = RegUnLoadKeyW(HKEY_USERS, userSid.c_str());
		if (res == ERROR_SUCCESS || res == ERROR_FILE_NOT_FOUND) {
			if (debug) print_debug(L"UnloadUserRegistry: RegUnLoadKeyW: HKEY_USERS\\", userSid);
		} else {
			//failover to reg unload
			if (debug) print_debug(L"UnloadUserRegistry: RegUnLoadKeyW: Result: ", res);
			res = RunRegUnload(userSid);
		}
		if (debug) print_debug(L"UnloadUserRegistry: HKEY_USERS\\", userSid, L", Result: ", res);
		res = RegUnLoadKeyW(HKEY_USERS, (userSid + L"_Classes").c_str());
		if (res == ERROR_SUCCESS || res == ERROR_FILE_NOT_FOUND) {
			if (debug) print_debug(L"UnloadUserRegistry: RegUnLoadKeyW: HKEY_USERS\\", userSid);
		} else {
			//failover to reg unload
			if (debug) print_debug(L"UnloadUserRegistry: RegUnLoadKeyW: Result: ", res);
			res = RunRegUnload(userSid + L"_Classes");
		}
		if (debug) print_debug(L"UnloadUserRegistry: HKEY_USERS\\", userSid + L"_Classes", L", Result: ", res);
	}

	bool RemoveFromHiddenUserList(const std::wstring& username)	{
		if (username.empty()) return true;
		HKEY hKey = nullptr;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, g_userListKey.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
			return true;
		}
		LSTATUS res = RegDeleteValueW(hKey, username.c_str());
		if (res != ERROR_SUCCESS && res != ERROR_FILE_NOT_FOUND) {
			print_error(L"Failed to remove temporary user from UserList");
			RegCloseKey(hKey);
			return false;
		}
		RegCloseKey(hKey);
		return true;
	}

	void UnloadTempUserProfile(const std::wstring& usernameW, const std::wstring& userSidW) {
		
		// 1. Destroy environment
		//if (g_envBlock) {
		//	if (debug) print_debug(L"UnloadTempUserProfile: DestroyEnvironmentBlock: Temporary user: ", usernameW);
		//	DestroyEnvironmentBlock(g_envBlock);
		//	g_envBlock = nullptr;
		//}
		
		if (usernameW.empty()) {
			print_error("UnloadTempUserProfile: Username is not specified");
		}

		if (userSidW.empty()) {
			print_error("UnloadTempUserProfile: User SID is not specified");
		}

		// 2. Unload profile
		if (g_hPrimaryToken) {
			if (UnloadUserProfile(g_hPrimaryToken, g_profileInfo.hProfile)) {
				if (debug) print_debug(L"UnloadTempUserProfile: UnloadUserProfile: Temporary user: ", usernameW, L" - Success");
			} else {
				print_error(L"UnloadTempUserProfile: UnloadUserProfile: Temporary user: ", usernameW);
			}
			g_profileLoaded = false;
		}

		// 3. Erase token
		if (g_hPrimaryToken) {
			if (debug) print_debug(L"UnloadTempUserProfile: SafeCloseHandle: Temporary user: ", usernameW);
			SafeCloseHandle(g_hPrimaryToken);
			g_hPrimaryToken = nullptr;
		}

		// 4. Reg
		UnloadUserRegistry(userSidW);
	}
	
	bool DeleteTempUserProfile(const std::wstring& userSidW, const std::wstring& profilePathW) {
		bool success = false;
		if (!userSidW.empty()) {
			if (DeleteProfileW(userSidW.c_str(), nullptr, nullptr)) {
				success = true;
			}
		}
		if (!profilePathW.empty()) {
			if (IsDirectoryExists(profilePathW)) {
				if (!DeleteFileW((profilePathW + L"\\NTUSER.DAT").c_str())) {
					if (debug) print_warning(L"DeleteTempUserProfile: NTUSER.DAT could not be deleted (probably in use or not found)");
				}
				SHFILEOPSTRUCTW fileOp = {0};
				std::wstring fromPath = profilePathW + L'\0';
				fromPath.push_back(L'\0'); // double 0-term
					fileOp.wFunc = FO_DELETE;
				fileOp.pFrom = fromPath.c_str();
				fileOp.fFlags = FOF_NO_UI | FOF_SILENT | FOF_NOCONFIRMATION;
					DWORD shfres = SHFileOperationW(&fileOp);
				if (shfres != 0) {
					print_error(L"DeleteTempUserProfile: SHFileOperationW: failed to delete profile dir: ", profilePathW, L", code:", shfres);
				} else {
					if (debug) print_debug(L"DeleteTempUserProfile: SHFileOperationW: delete profile dir: ", profilePathW, L", result: ", shfres); 
					success = true;
				}
			} else {
				success = true;
			}
		}
		return success;
	}

	bool DeleteTempUserRegProfileKey(const std::wstring& userSidW) {
		bool success = false;
		LSTATUS res = 0;
		if (userSidW.empty()) return false;
		HKEY hKey = nullptr;
		std::wstring fullKey = g_profileRegKey + L"\\" + userSidW;
		std::wstring fullKeyBak = fullKey + L".bak" ;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,fullKeyBak.c_str(),0,KEY_ALL_ACCESS,&hKey) == ERROR_SUCCESS) {
			RegCloseKey(hKey);
			if (debug) print_debug(L"DeleteTempUserRegProfileKey: RegDeleteTreeW: for: ", userSidW, L".bak");
			res = DeleteRegistryKey(fullKeyBak);
			if (res == ERROR_SUCCESS || res == ERROR_FILE_NOT_FOUND) {
				if (debug) print_debug(L"DeleteTempUserRegProfileKey: RegDeleteTreeW: for: ", userSidW, L".bak, Result: ", res);
				success = true;
			} else {
				print_error(L"DeleteTempUserRegProfileKey: RegDeleteTreeW: failed for: ", userSidW, L".bak, Result: ", res);
			}
		} else {
			success = true;
		}
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,fullKey.c_str(),0,KEY_ALL_ACCESS,&hKey) == ERROR_SUCCESS) {
			RegCloseKey(hKey);
			if (debug) print_debug(L"DeleteTempUserRegProfileKey: RegDeleteTreeW: for: ", userSidW);
			res = DeleteRegistryKey(fullKey);
			if (res == ERROR_SUCCESS || res == ERROR_FILE_NOT_FOUND) {
				if (debug) print_debug(L"DeleteTempUserRegProfileKey: RegDeleteTreeW: for: ", userSidW, L", Result: ", res);
				success = true;
			} else {
				print_error(L"DeleteTempUserRegProfileKey: RegDeleteTreeW: failed for: ", userSidW, L", Result: ", res);
			}
		} else {
			success = true;
		}
		return success;
	}

	bool DeleteTempUser(const std::wstring& usernameW) {
		bool success = false;
		NET_API_STATUS status = NetUserDel(nullptr, usernameW.c_str());
		if (status != NERR_Success && status != NERR_UserNotFound) {
			std::wstring msg = std::wstring(L"DeleteTempUserAndProfile: NetUserDel failed: ") + std::to_wstring(status);
			print_error(L"DeleteTempUserAndProfile: NetUserDel failed: ", status);
			success = false;
		} else if (status == NERR_Success){
			success = true;
			if (debug) print_debug(L"DeleteTempUserAndProfile: NetUserDel user: ", usernameW, L", result: Success");
		} else if (status == NERR_UserNotFound){
			success = true;
			if (debug) print_debug(L"DeleteTempUserAndProfile: NetUserDel user: ", usernameW, L" not found");
		}
		return success;
	}

	bool DeleteTempUserAndProfile(const std::wstring& usernameW, const std::wstring& userSidW, const std::wstring& profilePathW, bool checkingUser = true, bool checkingProfile = true, bool checkSid = true) {
		bool success = true;
		int deleteUserFlag = 0;

		if (debug) {
			TempUserAndProfileDebug(usernameW, userSidW, profilePathW);
		}

		if (usernameW.empty()) {
			print_error(L"DeleteTempUserAndProfile: username is empty");
			return false;
		}

		if (checkSid) {
			if (userSidW.empty()) {
				print_error(L"DeleteTempUserAndProfile: SID is empty");
				return false;
			}
		}

		if (checkingProfile) {
			if (profilePathW.find(g_RahRootDirName) == std::wstring::npos) {
				print_error(L"DeleteTempUserAndProfile: Profile path is outside of expected RAH directory, aborting delete");
				return false;
			}
		}

		if (checkingUser) {
			if ( g_tempUserNameW.empty() ) {
				if (!StartsWith(usernameW, L"rah_")) {
					deleteUserFlag = 1;
				}
			} else {
				if ( usernameW != g_tempUserNameW ) {
					deleteUserFlag = 2;
				}
			}
		}

		if ( deleteUserFlag != 0 ) {
			std::wcout << L"[SECURITY]: DeleteTempUserAndProfile: Refusing to delete unknown account: " << usernameW << L" [" << deleteUserFlag << L"]\n";
			return false;
		}

		UnloadTempUserProfile(usernameW,userSidW);

		Sleep(1000);
		DeleteTempUserProfile(userSidW,profilePathW);
		
		DeleteTempUserRegProfileKey(userSidW);

		DeleteTempUser(usernameW);
		
		RemoveFromHiddenUserList(usernameW);

		return success;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	void CheckAndCleanupOrphanedTempUsers()	{

		bool tDebug = debug;
		HKEY hProfiles = nullptr;
		
		if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Begin.");

		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,g_profileRegKey.c_str(),0,KEY_READ,&hProfiles) != ERROR_SUCCESS) {
			print_error(L"CheckAndCleanupOrphanedTempUsers: Failed to open ProfileList key.");
			return;
		}

		if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: ProfileList key opened.");

		std::wstring hostname = GetHostname();

		DWORD subKeyIndex = 0;
		DWORD tempUserKeyIndex = 0;
		wchar_t subKeyName[256];
		DWORD subKeyNameSize = _countof(subKeyName);
		bool mTmpUsersFound = false;
		bool doIncrement = false;

		while (RegEnumKeyExW(hProfiles,subKeyIndex,subKeyName,&subKeyNameSize,nullptr,nullptr,nullptr,nullptr) == ERROR_SUCCESS) {

			doIncrement = true;
			subKeyNameSize = 256; //Reset
			HKEY hUserKey = nullptr;

			if (RegOpenKeyExW(hProfiles,subKeyName,0,KEY_READ,&hUserKey) == ERROR_SUCCESS) {

				bool isTemp = (RegQueryValueExW(hUserKey,L"IsRahTemporaryUser",nullptr,nullptr,nullptr,nullptr) == ERROR_SUCCESS);
				bool isKeeped =	(RegQueryValueExW(hUserKey,L"IsKeepedUser", nullptr,nullptr,nullptr,nullptr) == ERROR_SUCCESS);

				if (isTemp) {

					bool doDeleteOrphanedKey = false;
					if (!mTmpUsersFound) mTmpUsersFound = true;
					tempUserKeyIndex++;

					///// Temp user profile

						if (debug) {
							print_debug(L"CheckAndCleanupOrphanedTempUsers: Checking key: #",tempUserKeyIndex,L", Subkey: #",subKeyIndex);
							print_debug(L"CheckAndCleanupOrphanedTempUsers: Reg.Path: ",g_profileRegKey,L"\\",subKeyName);
						}

						std::wstring profilePathW;
						if (hUserKey) {
							profilePathW = GetProfilePathBySid(subKeyName, hUserKey);
						}
						if (profilePathW.empty()) {
							if (debug) print_error(L"CheckAndCleanupOrphanedTempUsers: GetProfilePathBySid: Get ProfileImagePath from registry failed");
						}

						bool isSidAssigned = false;
						DWORD sidSize = 0;
						PSID pSid  = nullptr;
						LPWSTR sidString = nullptr;

						std::wstring sidW;
						std::wstring usernameW;
						std::wstring domainW;
						wchar_t username[256] = { 0 };
						DWORD usernameSize = _countof(username);
						wchar_t domainName[256] = { 0 };
						DWORD domainNameSize = _countof(domainName);
						SID_NAME_USE sidType;

						if (RegQueryValueExW(hUserKey, L"Sid", nullptr, nullptr, nullptr, &sidSize) == ERROR_SUCCESS && sidSize > 0) {

							std::vector<BYTE> sidBuffer(sidSize);
							if (RegQueryValueExW(hUserKey, L"Sid", nullptr, nullptr, sidBuffer.data(), &sidSize) == ERROR_SUCCESS) {
								PSID tempSid = reinterpret_cast<PSID>(sidBuffer.data());
								DWORD sidLen = GetLengthSid(tempSid);
								pSid = (PSID)LocalAlloc(LPTR, sidLen);
								if (pSid) {
									if (CopySid(sidLen, pSid, tempSid)) {
										if (IsValidSid(pSid)) {
											isSidAssigned = true;
										}
									}
								}
								if (isSidAssigned) {
									if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: The SID from the reg key param 'sid' is assigned.");
								} else {
									print_error(L"CheckAndCleanupOrphanedTempUsers: The SID from the reg key param 'sid' is assign failed");
								}
							} else {
								print_error(L"CheckAndCleanupOrphanedTempUsers: Failed to read reg key param 'sid'");
							}
						}

						if (!isSidAssigned) {
							std::wstring tmpKey = subKeyName;
							if (tmpKey.size() > 4 && tmpKey.compare(tmpKey.size() - 4, 4, L".bak") == 0) {
								tmpKey.resize(tmpKey.size() - 4);
							}
							if (ConvertStringSidToSidW(tmpKey.c_str(), &pSid)) {
								if (IsValidSid(pSid)) {
									isSidAssigned = true;
									if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: The SID is assigned from the reg key: ", subKeyName );
								} else {
									sidW = tmpKey;
									if (LookupAccountSidW(nullptr, pSid, username, &usernameSize, domainName, &domainNameSize, &sidType)) {
										usernameW = username;
										domainW = domainName;
									}
									if (debug) print_warning(L"CheckAndCleanupOrphanedTempUsers: The SID is assigned from the reg key: ", subKeyName );
								}
							}
						}

						if (isSidAssigned) {

							if (ConvertSidToStringSidW(pSid, &sidString)) {
								sidW = sidString;
								LocalFree(sidString);
								sidString = nullptr;
								if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Found SID: '", sidW, L"'");
							}

							if (!sidW.empty()) {

								if (isKeeped) {
									if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Temporary keeped local user profile key found.");
								} else {
									if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Temporary non keeped local user profile key found.");
								}

								if (LookupAccountSidW(nullptr, pSid, username, &usernameSize, domainName, &domainNameSize, &sidType)) {

									usernameW = username;
									domainW = domainName;

									if (!usernameW.empty()) {
										if (hostname == domainW) {

											if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: LookupAccountSidW: Found local temorary user: '", usernameW, L"'");

											PSID tSid = nullptr;
											LPWSTR tSidString = nullptr;
											std::wstring tUserSid;

											debug = false;
											if (GetSIDFromUsername(&tSid,usernameW)) {
												debug = tDebug;
															
												if (IsValidSid(tSid)) {
													if (ConvertSidToStringSidW(tSid, &tSidString)) {
														tUserSid = tSidString;
														LocalFree(tSidString);
														tSidString = nullptr;
													}
												}

												if (debug) {
													print_debug(L"CheckAndCleanupOrphanedTempUsers: User debug:");
													TempUserAndProfileDebug(usernameW, sidW, profilePathW, subKeyName);
													print_debug(L"CheckAndCleanupOrphanedTempUsers: User debug end");
												}

												if (tUserSid == sidW) {
													if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Call.GetSIDFromUsername: User SID correct.");
													if (!profilePathW.empty()) {
														if (IsDirectoryExists(profilePathW)) {
															if (profilePathW.find(g_RahRootDirName) == std::wstring::npos) {
																print_warning(L"CheckAndCleanupOrphanedTempUsers: Profile Path is not in RAH: ", profilePathW);
															} else {
																if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Profile Path correct: ", profilePathW);
															}
														} else {
															print_warning(L"CheckAndCleanupOrphanedTempUsers: Profile Path is not exists: ", profilePathW);
														}
													} else {
														print_warning(L"CheckAndCleanupOrphanedTempUsers: Profile Path is not specified:");
													}

													if (g_cleanupall_mode) isKeeped = false;
													if (!isKeeped) {
														if (!IsUserProcessRunning(tSid)) {
															if (debug) {
																print_debug(L"CheckAndCleanupOrphanedTempUsers: Deleting local temorary user: ");
																print_debug(L"CheckAndCleanupOrphanedTempUsers: User name: ", usernameW);
																print_debug(L"CheckAndCleanupOrphanedTempUsers: User sid: ", sidW);
																if (!profilePathW.empty()) {
																	print_debug(L"CheckAndCleanupOrphanedTempUsers: Profile Path: ", profilePathW);
																} else {
																	print_warning(L"CheckAndCleanupOrphanedTempUsers: Profile Path is not specified:");
																}
															}
															if (DeleteTempUserAndProfile(usernameW, sidW, profilePathW, false)) { //false = do not check username
																if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Deleting local temorary user: Success");
																doIncrement = false; // no subKeyIndex++;
															} else {
																print_error(L"CheckAndCleanupOrphanedTempUsers: Deleting local temorary user Error");
															}
														} else {
															print_warning(L"CheckAndCleanupOrphanedTempUsers: Refused to delete logged in local temporary user: ", usernameW);
														}
													}
													if (!g_cleanupall_mode) {
														if (isKeeped) {
															if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Skip Deleting keeped local temorary user: ", usernameW);
														}
													}
												} else {
													print_error(L"CheckAndCleanupOrphanedTempUsers: Call.GetSIDFromUsername: User SID incorrect.");
													doDeleteOrphanedKey = true;
												}
											} else {
												print_error(L"CheckAndCleanupOrphanedTempUsers: Call.GetSIDFromUsername: failed.");
												doDeleteOrphanedKey = true;
											}
											if (tSid) {
												LocalFree(tSid);
												tSid = nullptr;
											}
											debug = tDebug;
										} else {
											if (debug) print_warning(L"CheckAndCleanupOrphanedTempUsers: LookupAccountSidW: Found non local temorary user: '", usernameW, L"', Skip.");
										}
									} else {
										print_error(L"CheckAndCleanupOrphanedTempUsers: LookupAccountSidW: Get UserName by SID failed.");
										doDeleteOrphanedKey = true;
									}
								} else {
									DWORD err = GetLastError();
									print_error(L"CheckAndCleanupOrphanedTempUsers: LookupAccountSidW: failed, error: ", err);
									doDeleteOrphanedKey = true;
								}
							} else {
								DWORD err = GetLastError();
								print_error(L"CheckAndCleanupOrphanedTempUsers: Convert SID: failed, error: ", err);
								doDeleteOrphanedKey = true;
							}

						} else {
							print_error(L"CheckAndCleanupOrphanedTempUsers: RegQueryValueExW: Get SID from registry failed.");
							doDeleteOrphanedKey = true;
						}

						if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Checking key: #",tempUserKeyIndex,L", Subkey: #",subKeyIndex,L" end.");

						if (doDeleteOrphanedKey) {
							TempUserAndProfileDebug(usernameW, sidW, profilePathW, subKeyName);
							if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Cleanup orphaned user profile");
							if (hUserKey != nullptr) {
								RegCloseKey(hUserKey);
								hUserKey = nullptr;
							}
							//Here Delete orphaned profile if exists
								if (!sidW.empty() || !profilePathW.empty()) {
									if (DeleteTempUserProfile(sidW,profilePathW)) {
										if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: DeleteTempUserProfile: Success.");
									}
								}
							//Here Delete orphaned profile key - SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\<SID> / <SID>.bak
								std::wstring fullKey = g_profileRegKey + L"\\" + subKeyName;
								LSTATUS res = DeleteRegistryKey(fullKey); //IsRahTemporaryUser
								if (res == ERROR_SUCCESS || res == ERROR_FILE_NOT_FOUND) {
									if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Cleanup orphaned user profile key: Success: ", res, ", Key: ", fullKey);
									doIncrement = false;
								} else {
									if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Cleanup orphaned user profile key: Result: ", res, ", Key: ", fullKey);
								}
								if (!usernameW.empty()) {
									DeleteTempUser(usernameW);
									RemoveFromHiddenUserList(usernameW);
								}
							if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Cleanup orphaned user profile end");
						}

					///// Temp user profile
					if (pSid) {
						LocalFree(pSid);
						pSid = nullptr;
					}

				}

				if (hUserKey != nullptr) {
					RegCloseKey(hUserKey);
					hUserKey = nullptr;
				}
		
			}
			if (doIncrement) subKeyIndex++;
		}

		RegCloseKey(hProfiles);

		if (!mTmpUsersFound) {
			if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: No any keys with profiles of local temporary users were found.");
		}
		if (debug) print_debug(L"CheckAndCleanupOrphanedTempUsers: Finish.");

	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	bool AddUserToAdminsLocalGroup(const std::wstring& username) {
		bool success = false;
		const wchar_t* adminGroupSidStr = L"S-1-5-32-544";
		PSID pAdminGroupSid = nullptr;
		if (!ConvertStringSidToSidW(adminGroupSidStr, &pAdminGroupSid)) {
			print_error(L"AddUserToAdminsLocalGroup: Failed to convert SID string: ", adminGroupSidStr);
			return false;
		}
		WCHAR groupName[256] = { 0 }, domainName[256] = { 0 };
		DWORD groupNameSize = ARRAYSIZE(groupName);
		DWORD domainNameSize = ARRAYSIZE(domainName);
		SID_NAME_USE sidUse;
		if (!LookupAccountSidW(nullptr, pAdminGroupSid, groupName, &groupNameSize, domainName, &domainNameSize, &sidUse)) {
			print_error(L"AddUserToAdminsLocalGroup: LookupAccountSidW: Administrators group failed");
		} else {
			if (pAdminGroupSid) {
				std::wstring fullGroupName = groupName;
				LOCALGROUP_MEMBERS_INFO_3 memberInfo;
				memberInfo.lgrmi3_domainandname = const_cast<LPWSTR>(username.c_str());
				NET_API_STATUS status = NetLocalGroupAddMembers(nullptr,fullGroupName.c_str(),3,(LPBYTE)&memberInfo,1);
				std::wstring statusText = std::to_wstring(status);
				if (debug) print_debug(L"NetLocalGroupAddMembers: Status ", statusText);
				if (status == NERR_Success) {
					if (debug) print_debug(L"Successfully added user ", username, L" to local administrators group");
					success = true;
				} else if ( status == ERROR_MEMBER_IN_ALIAS ) {
					if (debug) print_debug(L"User ", username, L" already in local administrators group");
					success = true;
				} else {
					print_error(L"AddUserToAdminsLocalGroup: NetLocalGroupAddMembers failed to add user ", username, L" to local administrators group");
				}
				LocalFree(pAdminGroupSid);
				pAdminGroupSid = nullptr;
			}
		}
		return success;
	}

	bool CreateLocalUser(const std::wstring& username, const std::wstring& password, const std::wstring& profileDir ) {
		bool userSuccess = false;
		NET_API_STATUS nStatus;
		LPBYTE pBuf = nullptr;
		nStatus = NetUserGetInfo(nullptr, username.c_str(), 1, &pBuf);
		if (nStatus == NERR_Success) {
			if (debug) print_debug(L"CreateLocalUser: ", username, L" already exists, updating user: ", username);
			USER_INFO_1* ui;
			ui = (USER_INFO_1*)pBuf;
			ui->usri1_password = const_cast<LPWSTR>(password.c_str());
			ui->usri1_comment  = const_cast<LPWSTR>(g_RahUserComment.c_str());
			ui->usri1_flags    = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
			nStatus = NetUserSetInfo(nullptr, username.c_str(), 1, (LPBYTE)ui, nullptr);
			if (nStatus == NERR_Success) {
				if (debug) print_debug(L"CreateLocalUser: User updated successfully: ", username);
				userSuccess = true;
			} else {
				print_error(L"CreateLocalUser: Failed to update user: ", username, L", Error: ", nStatus);
			}
			NetApiBufferFree(pBuf);
			ZeroMemory(&ui, sizeof(ui));
		} else if (nStatus == NERR_UserNotFound) {
			if (debug) print_debug(L"CreateLocalUser: User not exists, creating user: ", username);
			USER_INFO_1 ui;
			ZeroMemory(&ui, sizeof(ui));
			ui.usri1_name = const_cast<LPWSTR>(username.c_str());
			ui.usri1_password = const_cast<LPWSTR>(password.c_str());
			ui.usri1_priv = USER_PRIV_USER;
			ui.usri1_home_dir = const_cast<LPWSTR>(profileDir.c_str());
			ui.usri1_comment = const_cast<LPWSTR>(g_RahUserComment.c_str());
			ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
			ui.usri1_script_path = nullptr;
			nStatus = NetUserAdd(nullptr, 1, (LPBYTE)&ui, nullptr);
			if (nStatus == NERR_Success) {
				if (debug) print_debug(L"CreateLocalUser: User created successfully: ", username);
				userSuccess = true;
			} else {
				print_error(L"CreateLocalUser: Failed to create user: ", username, L" Error: ", nStatus);
			}
			ZeroMemory(&ui, sizeof(ui));
		} else {
			print_error(L"CreateLocalUser: Error: ", nStatus);
		}
		if (userSuccess) {
			if (AddUserToAdminsLocalGroup(username)) {
				if (debug) print_debug(L"CreateLocalUser: Successfully add user: ", username, L" to local administrators group");
			}
		}
		return userSuccess;
	}

	// PROFILE

		bool CopyDirectoryRecursive(const std::wstring& source, const std::wstring& dest) {

			WIN32_FIND_DATAW findData{};
			HANDLE hFind = INVALID_HANDLE_VALUE; // init

			DWORD attr = GetFileAttributesW(dest.c_str());
			if (attr == INVALID_FILE_ATTRIBUTES) {
				if (!CreateDirectoryW(dest.c_str(), nullptr)) {
					if (GetLastError() != ERROR_ALREADY_EXISTS) {
						print_error(L"CopyDirectoryRecursive: Failed to create directory");
						return false;
					}
				}
			}

			std::wstring searchPath = source + L"\\*";

			hFind = FindFirstFileW(searchPath.c_str(), &findData);
			if (hFind == INVALID_HANDLE_VALUE) {
				print_error(L"CopyDirectoryRecursive: FindFirstFile failed");

				return false;
			}

			do {
				const std::wstring itemName = findData.cFileName;

				if (itemName == L"." || itemName == L"..") continue;

				std::wstring sourcePath = source + L"\\" + itemName;
				std::wstring destPath = dest + L"\\" + itemName;

				if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					if (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
						continue;
					}
					//Recursion
					if (!CopyDirectoryRecursive(sourcePath, destPath)) {
						if (hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
						return false;
					}
				} else {
					if (!CopyFileW(sourcePath.c_str(), destPath.c_str(), false)) {
						print_error((L"CopyDirectoryRecursive: Failed to copy file: " + sourcePath + L" to " + destPath).c_str());
						if (hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
						return false;
					}
				}
			} while (FindNextFileW(hFind, &findData) != 0);

			DWORD err = GetLastError();
			if (hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
				if (err != ERROR_NO_MORE_FILES) {
				  SetLastError(err);
				  return false;
			}
			return true;
		}

		bool CreateProfileTemplate(const std::wstring& destProfilePath) {

			if (IsFileExists(destProfilePath, L"NTUSER.DAT")) {
				if (debug) print_debug(L"CreateProfileTemplate: File NTUSER.DAT already exist in profile");
				return true;
			} else {
				if (debug) print_debug(L"CreateProfileTemplate: File NTUSER.DAT not exist in profile ", destProfilePath);
			}

			wchar_t systemDrive[MAX_PATH] = {0};
			DWORD len = GetEnvironmentVariableW(L"SystemDrive", systemDrive, MAX_PATH);
			if (len == 0 || len >= MAX_PATH) {
				wcscpy_s(systemDrive, L"C:");
			}
			std::wstring defaultProfile = std::wstring(systemDrive) + L"\\Users\\Default";

			if (!IsDirectoryExists(defaultProfile)) {
				print_error(L"CreateProfileTemplate: Default profile does not exist");
				return false;
			}

			if (!IsDirectoryExists(destProfilePath)) {
				if (!CreateDirectoryW(destProfilePath.c_str(), nullptr)) {
					print_error(L"CreateProfileTemplate: Failed to create profile directory");
					return false;
				}
			}

			bool defregcopyed = false;
			std::wstring srcDat = defaultProfile + L"\\NTUSER.DAT";
			std::wstring dstDat = destProfilePath + L"\\NTUSER.DAT";
			std::wstring srcLog = defaultProfile + L"\\NTUSER.DAT.LOG";
			std::wstring dstLog = destProfilePath + L"\\NTUSER.DAT.LOG";
			if (CopyFileW(srcDat.c_str(), dstDat.c_str(), false)) {
				if (debug) print_debug(L"CreateProfileTemplate: Copyed default reg NTUSER.DAT from ", defaultProfile, L" to ", destProfilePath);
				CopyFileW(srcLog.c_str(), dstLog.c_str(), false);
				defregcopyed = true;
			}

			if (!defregcopyed) {
				if (debug) print_debug(L"Copy default profile recursively from ", defaultProfile, L" to ", destProfilePath);
				if (!CopyDirectoryRecursive(defaultProfile, destProfilePath)) {
					print_error(L"CreateProfileTemplate: Failed to copy default profile recursively");
					return false;
				}
			}

			CreateTagFile(destProfilePath, L"$temporary_user$");
			return true;
		}

		bool CreateProfileRegistryKey(const std::wstring& userSidW, const std::wstring& profilePath) {

			HKEY hKey = nullptr;
			std::wstring regPath = g_profileRegKey + L"\\" + userSidW;

			LSTATUS res = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,KEY_WRITE, nullptr, &hKey, nullptr);
			if (res != ERROR_SUCCESS) {
				print_error(L"CreateProfileRegistryKey: Failed to create/open registry key");
				return false;
			}

			res = RegSetValueExW(hKey, L"ProfileImagePath", 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(profilePath.c_str()), (DWORD)((profilePath.length() + 1) * sizeof(wchar_t)));
			if (res != ERROR_SUCCESS) {
				print_error(L"CreateProfileRegistryKey: Failed to set ProfileImagePath");
				RegCloseKey(hKey);
				return false;
			}

			DWORD flags = 0;
			RegSetValueExW(hKey, L"Flags", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&flags), sizeof(flags));
			RegSetValueExW(hKey, L"State", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&flags), sizeof(flags));
			DWORD val = 1;
			RegSetValueExW(hKey, L"IsRahTemporaryUser", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));
			if (g_keepTempUser) {
				RegSetValueExW(hKey, L"IsKeepedUser", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));
			} else {
				RegDeleteValueW(hKey, L"IsKeepedUser");
			}
			RegCloseKey(hKey);

			return true;

		}
		
	// PROFILE

	bool AddToHiddenUserList(const std::wstring& username) {
		if (username.empty()) return true;
		HKEY hKey = nullptr;
		if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, g_userListKey.c_str(), 0, nullptr,REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
			print_error(L"AddToHiddenUserList: Failed to open or create UserList registry key");
			return false;
		}
		DWORD val = 0; // 0 = hidden
		if (RegSetValueExW(hKey, username.c_str(), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val)) != ERROR_SUCCESS) {
			print_error(L"AddToHiddenUserList: Failed to add temporary user to UserList");
			RegCloseKey(hKey);
			return false;
		}
		RegCloseKey(hKey);
		return true;
	}

	// NOTE: Fixed username intentionally — parallel execution with same names not supported.

	bool CreateAndInitializeAutoUser(std::wstring& outUsername, std::wstring& outPassword, bool recursive_fallback = false) {

		std::wstring username, password, profilePath;
		const std::wstring profileRoot = std::wstring(_wgetenv(L"SystemRoot")) + g_RahTempRootDirPath; //path
		WCHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD dwSize = ARRAYSIZE(szComputerName);
		DWORD err;
		bool doContinueCreateUser = false;
		bool doUseExistingUser = false;
		g_doUseExistingUserContext = false; //For the future - for DuplicateTokenEx (injection into the user session).

		if (g_tempUserNameW.empty()) {
			username = g_tmpUserPrefix + g_tmpUserPostfix; //Default: g_tmpUserPrefix=L"rah_tmp_", g_tmpUserPostfix=L"user"; 
			g_keepTempUser = false;
			g_noWait = false;
		} else {
			username = g_tempUserNameW;
		}

		profilePath = profileRoot + username;
		std::wstring userSid;

		LPUSER_INFO_1 tmpInfo = nullptr;
		if (NetUserGetInfo(nullptr, username.c_str(), 1, (LPBYTE*)&tmpInfo) == NERR_Success) {

			// Get existing user SID
			PSID tSid = nullptr;
			LPWSTR tSidString = nullptr;
			std::wstring tUserSid;
			if (GetSIDFromUsername(&tSid,username)) {
				if (ConvertSidToStringSidW(tSid, &tSidString)) {
					tUserSid = tSidString;
					LocalFree(tSidString);
					tSidString = nullptr;
				}
			}
			NetApiBufferFree(tmpInfo);

			// Check registry key value - IsRahTemporaryUser
			if (!tUserSid.empty()) {
				if (IsRahTemporaryUser(username)) {
					AddToHiddenUserList(username);
					doUseExistingUser = true;
					userSid = tUserSid;
				}
			}

			
			if (tSid) {
				if (!IsUserProcessRunning(tSid)) {
					doUseExistingUser = true;
				} else {
					print_error(L"CreateAndInitializeAutoUser: Temporary user already active: ", username);
					HANDLE uToken = GetPrimaryTokenFromUserProcess(tSid);
					if (uToken) {
						if (debug) print_debug(L"CreateAndInitializeAutoUser: Active temporary user: ", username, ", token: ", uToken);
						g_hPrimaryToken = uToken; //Global
						g_doUseExistingUserContext = true;
					}
					SetGlobalSid(tSid);
					LocalFree(tSid);
					tSid = nullptr;
					if (g_doUseExistingUserContext) {
						doUseExistingUser = true;
						outUsername 		= username;
						g_tempUserW			= username;
						g_tempUserSidW		= userSid;
						g_tempUserProfileW	= profilePath;
						if (g_keepTempUser) {
							SetIsRahTemporaryKeepedUserSid(userSid);
						} else {
							UnSetIsRahTemporaryKeepedUserSid(userSid);
						}
						return true;
					} else {
						doUseExistingUser = true;
					}
				}
			}

			if (!doUseExistingUser) {
				if (g_tempuser_fallback) {
					print_warning(L"CreateAndInitializeAutoUser: User already exists: ", username);
					//A recursive fallback 
					if (!recursive_fallback) {
						g_tempUserNameW = username + L"_" + GenerateUsernamePostfix(8);
						print_warning(L"CreateAndInitializeAutoUser: A fallback is to create a temporary user: ", g_tempUserNameW);
						if (g_keepTempUser) {
							print_warning(L"CreateAndInitializeAutoUser: Temporary user keeping is enabled; The fallback mode disables keeping the temporary user for later use");
							g_keepTempUser = false;
						}
						bool rfb = CreateAndInitializeAutoUser(outUsername, outPassword, true);
						return rfb;
					}
				}
				print_error(L"CreateAndInitializeAutoUser: Failed to create Temporary user because user already exists: ", username);
				return false;
			}

			if (debug) print_debug(L"CreateAndInitializeAutoUser: Using an existing Temporary user: ", username);
			
		}

		password = GeneratePassword(dwSize);

		if (debug) {
			std::wstring first3 = password.substr(0, 3);         
			std::wstring last3  = password.substr(password.length() - 3); 
			if (debug) print_debug(L"CreateAndInitializeAutoUser: Temporary user: ", username, L", password: ", first3, L"***", last3);
			SecureClear(first3);
			SecureClear(last3);
		}

		if (doUseExistingUser) {
			AddToHiddenUserList(username);
			if (!CreateLocalUser(username, password, profilePath)) {
				print_error(L"CreateAndInitializeAutoUser: Failed to update existing local user");
				RemoveFromHiddenUserList(username);
			} else {
				if (debug) print_debug(L"CreateAndInitializeAutoUser: Update existing local user: Success");
				g_tempUserCreated	= true;
			}
			bool doProfileReCreate = false;
			if (g_tempUserCreated) {
				if (!IsDirectoryExists(profilePath)) doProfileReCreate = true;
				if (!doProfileReCreate) if (!IsDirectoryExists(profilePath + L"\\AppData")) doProfileReCreate = true;
				if (!doProfileReCreate) if (!IsFileExists(profilePath, L"\\NTUSER.DAT")) doProfileReCreate = true;
				if (!doProfileReCreate) if (!IsFileExists(profilePath, L"\\ntuser.ini")) doProfileReCreate = true;
				if (!doProfileReCreate) if (!IsFileExists(profilePath, L"\\$temporary_user$")) doProfileReCreate = true;
				if (!doProfileReCreate) if (!IsFileExists(profilePath, L"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat")) doProfileReCreate = true;
				if (doProfileReCreate) {
					if (CreateProfileTemplate(profilePath)) {
						if (debug) print_debug(L"CreateAndInitializeAutoUser: Update existing local user profile: Success");
					} else {
						if (debug) print_debug(L"CreateAndInitializeAutoUser: Failed to update existing local user profile");
						g_tempUserCreated	= false;
					}
				} else {
					if (debug) print_debug(L"CreateAndInitializeAutoUser: Using an existing Temporary user profile");
				}
			}
			if (g_keepTempUser) {
				SetIsRahTemporaryKeepedUserSid(userSid);
			} else {
				UnSetIsRahTemporaryKeepedUserSid(userSid);
			}
		} else {
			if (!CreateDirectoryW(profileRoot.c_str(), nullptr)) {
				err = GetLastError();
				if (err != ERROR_ALREADY_EXISTS) {
					print_error(L"CreateAndInitializeAutoUser: Failed to create Temporary user profile root dir: ", profileRoot);
					doContinueCreateUser = false;
				} else if (err == ERROR_ALREADY_EXISTS) {
					if (debug) print_debug(L"CreateAndInitializeAutoUser: Temporary user profile root dir already exists: ", profileRoot);
					doContinueCreateUser = true;
				}
			} else {
				doContinueCreateUser = true;
			}

			if (doContinueCreateUser) {

				if (doContinueCreateUser) {
					AddToHiddenUserList(username);
					if (!CreateLocalUser(username, password, profilePath)) {
						print_error(L"CreateAndInitializeAutoUser: Failed to create local user");
						RemoveFromHiddenUserList(username);
						doContinueCreateUser = false;
					} else {
						if (debug) print_debug(L"CreateAndInitializeAutoUser: Temporary user profile dir: ", profilePath);
						doContinueCreateUser = true;
					}
				}

				if (doContinueCreateUser) {
					PSID pSid = nullptr;
					LPWSTR sidString = nullptr;
					if (GetSIDFromUsername(&pSid,username)) {
						if (ConvertSidToStringSidW(pSid, &sidString)) {
							userSid = sidString;
							LocalFree(sidString);
							sidString = nullptr;
							if (debug) print_debug(L"CreateAndInitializeAutoUser: User SID: ", userSid);
							doContinueCreateUser = true;
							SetGlobalSid(pSid);
						} else {
							print_error(L"CreateAndInitializeAutoUser: ConvertSidToStringSid failed");
							doContinueCreateUser = false;
						}
						if (pSid) {
							LocalFree(pSid);
							pSid = nullptr;
						}
					} else {
						print_error(L"CreateAndInitializeAutoUser: Failed to get SID for user");
						doContinueCreateUser = false;
					}
				}

				if (doContinueCreateUser) {
					if (!CreateDirectoryW(profilePath.c_str(), nullptr)) {
						err = GetLastError();
						if (err != ERROR_ALREADY_EXISTS) {
							print_error((L"CreateAndInitializeAutoUser: Failed to create Temporary user profile dir: " + profilePath).c_str());
							doContinueCreateUser = false;
						} else if (err == ERROR_ALREADY_EXISTS) {
							if (debug) print_debug(L"CreateAndInitializeAutoUser: Temporary user profile dir already exists: ", profilePath);
							doContinueCreateUser = true;
						}
					} else {
						doContinueCreateUser = true;
					}
				}

				if (doContinueCreateUser) {
					if (debug) print_debug(L"CreateAndInitializeAutoUser: Preparing profile SID: ", userSid);
					if (!CreateProfileTemplate(profilePath)) {
						print_error(L"CreateAndInitializeAutoUser: Failed to create profile template");
						doContinueCreateUser = false;
					} else {
						doContinueCreateUser = true;
					}
				}
				
				if (doContinueCreateUser) {
					if (!CreateProfileRegistryKey(userSid, profilePath)) {
						print_error(L"CreateAndInitializeAutoUser: Failed to create profile registry key");
						doContinueCreateUser = false;
					} else {
						doContinueCreateUser = true;
					}
				}

				if (doContinueCreateUser) {
					g_tempUserCreated	= true;
				}
				
				if (!g_tempUserCreated) {
					print_error(L"CreateAndInitializeAutoUser: Failed to create temporary user. Performing Cleanup...");
					DeleteTempUserAndProfile(username, userSid, profilePath,false,false,false);
				}

			}
		}

		if (g_tempUserCreated) {
			outUsername			= username;
			outPassword			= password;
			g_tempUserW			= username;
			g_tempUserSidW		= userSid;
			g_tempUserProfileW	= profilePath;
		}

		SecureClear(username);
		SecureClear(password);
		SecureClear(profilePath);
		return g_tempUserCreated;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	std::wstring GetCurrentUserSamCompatible() {
		DWORD size = 0;
		GetUserNameExW(NameSamCompatible, nullptr, &size);
		if (size == 0) {
			print_error(L"GetCurrentUserSamCompatible: GetUserNameExW size failed");
			return L"";
		}
		std::vector<wchar_t> buffer(size);
		if (!GetUserNameExW(NameSamCompatible, buffer.data(), &size)) {
			print_error(L"GetCurrentUserSamCompatible: GetUserNameExW failed");
			return L"";
		}
		return std::wstring(buffer.data(), size);
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	bool IsDomainController() {
		DSROLE_PRIMARY_DOMAIN_INFO_BASIC* pInfo = nullptr;
		if (DsRoleGetPrimaryDomainInformation( nullptr,DsRolePrimaryDomainInfoBasic,(PBYTE*)&pInfo) != ERROR_SUCCESS || !pInfo) {
			return false;
		}
		bool isDC = (pInfo->MachineRole == DsRole_RolePrimaryDomainController || pInfo->MachineRole == DsRole_RoleBackupDomainController);
		bool isDsRunning = (pInfo->Flags & DSROLE_PRIMARY_DS_RUNNING) != 0;
		DsRoleFreeMemory(pInfo);
		return isDC && isDsRunning;
	}

	bool IsDomainControllerReg() {
		HKEY hKey;
		wchar_t productType[64];
		DWORD size = sizeof(productType); // размер буфера в байтах
		bool result = false;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions",0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) {
			return false;
		}
		if (RegQueryValueExW(hKey, L"ProductType", nullptr, nullptr,reinterpret_cast<BYTE*>(productType), &size) == ERROR_SUCCESS) {
			size_t charsRead = size / sizeof(wchar_t);
			if (charsRead >= _countof(productType)) {
				charsRead = _countof(productType) - 1;
			}
			productType[charsRead] = L'\0';
			result = (_wcsicmp(productType, L"LanmanNT") == 0);
		}
		RegCloseKey(hKey);
		return result;
	}

	bool IsRunningAsAdmin() {
		BOOL imisAdmin = false;
		HANDLE token = nullptr;

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			TOKEN_ELEVATION elevation;
			DWORD size = sizeof(TOKEN_ELEVATION);
			if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
				imisAdmin = elevation.TokenIsElevated;
			}
			SafeCloseHandle(token);
		}

		return imisAdmin == true;
	}

	bool IsRunningAsSystem() {
		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}

		DWORD size = 0;
		GetTokenInformation(token, TokenUser, nullptr, 0, &size);
		if (size == 0 || size > 1024) {
			SafeCloseHandle(token);
			return false;
		}

		BYTE buffer[1024];
		if (!GetTokenInformation(token, TokenUser, buffer, size, &size)) {
			SafeCloseHandle(token);
			return false;
		}

		SafeCloseHandle(token);

		TOKEN_USER* tokenUser = (TOKEN_USER*)buffer;

		SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
		PSID systemSid = nullptr;
		if (!AllocateAndInitializeSid(&ntAuthority, 1,
									  SECURITY_LOCAL_SYSTEM_RID,
									  0,0,0,0,0,0,0,
									  &systemSid)) {
			
			FreeSid(systemSid);
			return false;
		}

		BOOL imisSystem = EqualSid(tokenUser->User.Sid, systemSid);
		FreeSid(systemSid);

		memset(buffer, 0, sizeof(buffer));

		return imisSystem == true;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	bool IsInteractiveSession() {
		DWORD sessionId = 0;
		if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
			return false;
		}
		return sessionId != 0;
	}

	bool IsUserInteractiveSession(DWORD sessionId) {
		LPWSTR winStationName = nullptr;
		DWORD bytesReturned = 0;

		if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSWinStationName, &winStationName, &bytesReturned)) {
			bool interactive = (_wcsicmp(winStationName, L"Console") == 0 || _wcsnicmp(winStationName, L"RDP", 3) == 0);
			if (debug) print_debug(L"winStationName for ", sessionId, L": ", winStationName);
			WTSFreeMemory(winStationName);
			return interactive;
		}
		return false;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	//Run in existing user session in visible mode
	bool RunAsInteractive(
		const std::wstring& userOnly,
		const std::wstring& domain,
		const std::wstring& password,
		wchar_t* cmdLine,
		STARTUPINFOW& si,
		PROCESS_INFORMATION& pi,
		DWORD creationFlags
	) {

		BOOL created = false;
		si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

		if (debug) {
			if (isSystem) {
				if (debug) print_debug(L"RunAsInteractive: System context");
			} else {
				if (debug) print_debug(L"RunAsInteractive: User context");
			}
			if (debug) print_debug(L"Desktop: ", si.lpDesktop);
		}

		WCHAR homeDir[MAX_PATH];
		PSID pSid = nullptr;
		if (GetSIDFromUsername(&pSid,userOnly,domain)) {
			std::wstring sidString = SidToString(pSid);
			if (!sidString.empty()) {
				std::wstring path = GetProfilePathBySid(sidString);
				if (!path.empty() && IsDirectoryExists(path.c_str())) {
					wcsncpy(homeDir, path.c_str(), MAX_PATH - 1);
				}
			}
			FreeSid(pSid);
			pSid = nullptr;
		}
		if (homeDir[0] == L'\0') {
			if (!GetWindowsDirectoryW(homeDir, MAX_PATH)) {
				wcscpy(homeDir, L"C:\\Windows");
			}
		}

		DWORD userSessionId = 0xFFFFFFFF;
		std::wstring fullUserName = domain + L"\\" + userOnly;
		userSessionId = GetSessionIdByUserName(userOnly,domain);
		if (userSessionId == 0xFFFFFFFF) {
			print_error(L"RunAsInteractive: Unable to get session ID for user ", fullUserName);
			return false;
		}

		if (!IsUserInteractiveSession(userSessionId)) {
			if (debug) print_warning(L"RunAsInteractive: User: ", fullUserName, L", session: ", userSessionId, L" is not interactive");
			//return false; // Process always start in logged user session
		}

		std::wstring cmdLineStr(cmdLine);
		std::wstring exeName;
		size_t spacePos = cmdLineStr.find(L' ');
		if (spacePos != std::wstring::npos) {
			exeName = cmdLineStr.substr(0, spacePos);
		} else {
			exeName = cmdLineStr;
		}

		if (_wcsicmp(exeName.c_str(), L"cmd.exe") == 0) {
			if (debug) print_debug(L"RunAsInteractive: Exe: ", exeName);
			creationFlags |= CREATE_NEW_CONSOLE;
		}

		if (debug) print_debug(L"RunAsInteractive: Home dir: ", homeDir);

		if (isSystem) {

			HANDLE hUserToken = nullptr;

			if (!WTSQueryUserToken(userSessionId, &hUserToken)) {
				print_error(L"RunAsInteractive: WTSQueryUserToken failed for session: ", userSessionId);
				SafeCloseHandle(hUserToken);
				return false;
			}

			if (debug) print_debug(L"RunAsInteractive [SYSTEM]: CreateProcessAsUserW: User: ", fullUserName, L", Session ID: ", userSessionId);

			LPVOID lpEnvironment = nullptr;

			if (!CreateEnvironmentBlock(&lpEnvironment, hUserToken, true)) {
				print_error(L"RunAsInteractive: CreateEnvironmentBlock failed");
				lpEnvironment = nullptr; // fallback to nullptr
			}

			created = CreateProcessAsUserW(
				hUserToken,
				nullptr,
				cmdLine,
				nullptr,
				nullptr,
				false,
				creationFlags | CREATE_UNICODE_ENVIRONMENT,
				lpEnvironment,
				homeDir,
				&si,
				&pi
			);

			if (!created) {
				print_error(L"RunAsInteractive: CreateProcessAsUserW failed");
			} else {
				procPid = pi.dwProcessId;
				if (debug) {
					print_debug(L"RunAsInteractive: CreateProcessAsUserW Success. Pid: ", procPid, ", Token: ", hUserToken);
				}
			}

			if (lpEnvironment) {
				if (debug) print_debug(L"RunAsInteractive [SYSTEM]: DestroyEnvironmentBlock: ", lpEnvironment);
				DestroyEnvironmentBlock(lpEnvironment);
			}

			SafeCloseHandle(hUserToken);

		} else {

			if (debug) print_debug(L"RunAsInteractive: CreateProcessWithLogonW: User: ", fullUserName, L", Session ID: ", userSessionId);

			created = CreateProcessWithLogonW(
				userOnly.c_str(),
				domain.c_str(),
				password.c_str(),
				LOGON_WITH_PROFILE,
				nullptr,
				cmdLine,
				creationFlags | CREATE_UNICODE_ENVIRONMENT,
				nullptr,
				homeDir,
				&si,
				&pi
			);

			if (!created) {
				print_error(L"RunAsInteractive: CreateProcessWithLogonW failed");
			} else {
				procPid = pi.dwProcessId;
				if (debug) {
					print_debug("RunAsInteractive: CreateProcessWithLogonW Success. Pid: ", procPid);
				}
			}
		}

		return created;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	// FOR HIDDEN RUN FROM SYSTEM/Administrator - STANDARD - with login if not active

	bool RunUnderSystem(
		const std::wstring& userOnly,
		const std::wstring& domain,
		const std::wstring& password,
		wchar_t* cmdLine,
		STARTUPINFOW& si,
		PROCESS_INFORMATION& pi,
		DWORD creationFlags
	) {
		HANDLE hToken = nullptr;
		HANDLE hPrimaryToken = nullptr;
		LPVOID envBlock = nullptr;
		PROFILEINFO up = {0};
		bool created = false;
		bool profileloaded = false;

		if (debug) print_debug(L"RunUnderSystem:");

		// 1. If an active user process EXISTS and runs under the system, no re-login, password, or profile loading is required to run the program.
		if (g_doUseExistingUserContext && g_hPrimaryToken) {
			DWORD tokenType;
			DWORD len;
			// Checking token handle
			if (!GetTokenInformation(g_hPrimaryToken, TokenType, &tokenType, sizeof(tokenType), &len)) {
				if (debug) print_warning(L"RunUnderSystem: Obtained token from existing context is dead. Terminating.");
				SafeCloseHandle(g_hPrimaryToken);
				g_hPrimaryToken = nullptr;
				g_doUseExistingUserContext = false;
				return false;
			} else {
				hPrimaryToken = g_hPrimaryToken;
				if (debug) print_debug(L"RunUnderSystem: Using obtained token from existing context");
			}
		}

		
		// 2. If an active user session EXISTS and runs under the system, no re-login, password, or profile loading is required to run the program.
		// if (!hPrimaryToken) {	
		// 	DWORD userSessionId = 0xFFFFFFFF;
		// 	std::wstring fullUserName = domain + L"\\" + userOnly;
		// 	userSessionId = GetSessionIdByUserName(userOnly,domain);
		// 	if (userSessionId != 0xFFFFFFFF) {
		// 		// The session exists - we get the user token
		// 		if (!WTSQueryUserToken(userSessionId, &hPrimaryToken)) {
		// 			if (debug) print_debug(L"RunUnderSystem: WTSQueryUserToken failed, fallback to LogonUserW");
		// 		} else {
		// 			if (debug) print_debug(L"RunUnderSystem: Using obtained token from existing session ", userSessionId);
		// 		}
		// 	}
		// }
		//

		if (!hPrimaryToken) { // USER IS NOT LOGGED IN
			if (!LogonUserW(userOnly.c_str(), domain.c_str(), password.c_str(),LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {
				print_error(L"RunUnderSystem: LogonUserW failed");
				return false;
			} else {
				if (debug) print_debug(L"RunUnderSystem: LogonUserW: Token OK: ", hToken);
			}
			if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
				print_error(L"RunUnderSystem: DuplicateTokenEx failed");
				SafeCloseHandle(hToken);
				return false;
			} else {
				if (debug) print_debug(L"RunUnderSystem: DuplicateTokenEx: PrimaryToken OK: ", hPrimaryToken);
			}
			if (!EnableTokenPrivilege(hPrimaryToken, SE_ASSIGNPRIMARYTOKEN_NAME)) {
				if (debug) {
					print_warning(L"RunUnderSystem: EnableTokenPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) for target user: ", userOnly);
				}
			}
			if (!EnableTokenPrivilege(hPrimaryToken, SE_INCREASE_QUOTA_NAME)) {
				if (debug) {
					print_warning(L"RunUnderSystem: EnableTokenPrivilege(SE_INCREASE_QUOTA_NAME) for user: ", userOnly);
				}
			}
			if (!EnableTokenPrivilege(hPrimaryToken, SE_TCB_NAME)) {
				if (debug) {
					print_warning(L"RunUnderSystem: EnableTokenPrivilege(SE_TCB_NAME) for target user: ", userOnly);
				}
			}
			if (privdebug) {
				print_str(L"------------------------------------------");
				PrintTokenPrivileges(hToken,userOnly.c_str());
				print_str(L"------------------------------------------");
			}
		} else {
			//Run under existing session/context (1.,2.)
			if (debug) print_debug(L"RunUnderSystem: LoadUserProfileW: Skip. Using existing user context.");
		}

		up.dwSize = sizeof(PROFILEINFO);
		up.lpUserName = const_cast<LPWSTR>(userOnly.c_str());
		if (!LoadUserProfileW(hPrimaryToken, &up)) {
			DWORD perr = GetLastError();
			if (perr == ERROR_USER_PROFILE_ALREADY_LOADED) {
				if (debug) {
					print_warning(L"RunUnderSystem: Profile already loaded for user: ", userOnly);
				}
				profileloaded = true;
			} 
			else if (perr == 299 /* ERROR_PARTIAL_COPY */) {
				print_warning(L"RunUnderSystem: Profile not loaded for user: ", userOnly);
				SafeCloseHandle(hPrimaryToken);
				SafeCloseHandle(hToken);
				return false;
			} else {
				print_warning(L"RunUnderSystem: LoadUserProfile failed for user: ", userOnly);
				SafeCloseHandle(hPrimaryToken);
				SafeCloseHandle(hToken);
				return false;
			}
		} else {
			if (debug) print_debug(L"RunUnderSystem: LoadUserProfileW: Profile OK: ", up.hProfile);
			profileloaded = true;
		}

		if (!CreateEnvironmentBlock(&envBlock, hPrimaryToken, true)) {
			print_error(L"RunUnderSystem: CreateEnvironmentBlock failed");
			if (profileloaded) UnloadUserProfile(hPrimaryToken, up.hProfile);
			SafeCloseHandle(hPrimaryToken);
			SafeCloseHandle(hToken);
			return false;
		} else {
			if (debug) print_debug(L"RunUnderSystem: LoadUserProfileW: Environment OK: ", envBlock);
		}

		WCHAR windowsDir[MAX_PATH];
		if (!GetWindowsDirectoryW(windowsDir, MAX_PATH)) {
			wcscpy(windowsDir, L"C:\\Windows");
		}

		if (debug) {
			print_debug(L"RunUnderSystem: CreateProcess Parameters");
			std::wcout << L"    runFromGPO flag: " << g_runFromGPO << L"\n";
			std::wcout << L"    hPrimaryToken: " << hPrimaryToken << L"\n";
			std::wcout << L"    lpApplicationName: " << (LPCVOID)nullptr << L"\n";
			std::wcout << L"    lpCommandLine: " << cmdLine << L"\n";
			std::wcout << L"    bInheritHandles: " << TRUE << L"\n";
			std::wcout << L"    creationFlags: 0x" << std::hex << (creationFlags | CREATE_UNICODE_ENVIRONMENT) << L"\n";
			std::wcout << L"    envBlock: " << (LPVOID)envBlock << L"\n";
			std::wcout << L"    lpCurrentDirectory: " << windowsDir << L"\n";
			std::wcout << L"    si.cb: " << si.cb << L"\n";
			std::wcout << L"    si.dwFlags: 0x" << std::hex << si.dwFlags << L"\n";
			std::wcout << L"    si.lpDesktop: " << (si.lpDesktop ? si.lpDesktop : L"(NULL)") << L"\n";
			std::wcout << L"    si.hStdInput: " << si.hStdInput << L"\n";
			std::wcout << L"    si.hStdOutput: " << si.hStdOutput << L"\n";
			std::wcout << L"    si.hStdError: " << si.hStdError << L"\n";
			print_debug(L"End of parameters");
		}

		if (debug) print_debug(L"RunUnderSystem: CreateProcessAsUserW");
		created = CreateProcessAsUserW(
			hPrimaryToken,
			nullptr,
			cmdLine,
			nullptr,
			nullptr,
			true,
			creationFlags | CREATE_UNICODE_ENVIRONMENT,
			envBlock,
			windowsDir,
			&si,
			&pi
		);

		if (!created) {
			print_error(L"RunUnderSystem: CreateProcessAsUserW failed");
			if (profileloaded) UnloadUserProfile(hPrimaryToken, up.hProfile);
			SafeCloseHandle(hPrimaryToken);
			SafeCloseHandle(hToken);
			hPrimaryToken = nullptr;
			hToken = nullptr;
		} else {
			procPid = pi.dwProcessId;
			if (debug) print_debug(L"RunUnderSystem: CreateProcessAsUserW Success. Pid: ", procPid, ", Token: ", hPrimaryToken);
		}

		if (envBlock) DestroyEnvironmentBlock(envBlock);
		envBlock = nullptr;

		g_hPrimaryToken = hPrimaryToken;
		g_profileInfo = up;
		g_profileLoaded = profileloaded;

		return created;
	}

	// FOR HIDDEN RUN FROM ADMIN USER // DEPRICATED
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

		if (debug) print_debug(L"RunUnderUser:");

		WCHAR windowsDir[MAX_PATH];
		if (!GetWindowsDirectoryW(windowsDir, MAX_PATH)) {
			wcscpy(windowsDir, L"C:\\Windows");
		}

		created = CreateProcessWithLogonW(
			userOnly.c_str(),
			domain.c_str(),
			password.c_str(),
			LOGON_WITH_PROFILE,
			nullptr,
			cmdLine,
			creationFlags,
			nullptr,
			windowsDir,
			&si,
			&pi
		);

		if (!created) {
			print_error(L"RunUnderUser: CreateProcessWithLogonW failed");
		} else {
			procPid = pi.dwProcessId;
			if (debug) {
				print_debug(L"RunUnderUser: CreateProcessWithLogonW Success. Pid: ", procPid);
				HANDLE hProcessToken = nullptr;
				if (OpenProcessToken(pi.hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hProcessToken)) {
					if (privdebug) {
						print_str(L"------------------------------------------");
						PrintTokenPrivileges(hProcessToken,userOnly.c_str());
						print_str(L"------------------------------------------");
					}
					SafeCloseHandle(hProcessToken);
				} else {
					print_error(L"RunUnderUser: OpenProcessToken failed");
				}
			}
		}

		return created;
	}

	bool RunUnderCurrentUser(
		wchar_t* cmdLine,
		STARTUPINFOW& si,
		PROCESS_INFORMATION& pi,
		DWORD creationFlags
	) {
		HANDLE hToken = nullptr;
		HANDLE hPrimaryToken = nullptr;
		LPVOID envBlock = nullptr;

		if (!OpenProcessToken(
				GetCurrentProcess(),
				TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
				&hToken)) {
			print_error(L"RunUnderCurrentUser: OpenProcessToken failed");
			return false;
		}

		if (!DuplicateTokenEx(
				hToken,
				MAXIMUM_ALLOWED,
				nullptr,
				SecurityImpersonation,
				TokenPrimary,
				&hPrimaryToken)) {
			print_error(L"RunUnderCurrentUser: DuplicateTokenEx failed");
			SafeCloseHandle(hToken);
			return false;
		}

		if (!CreateEnvironmentBlock(&envBlock, hPrimaryToken, true)) {
			print_error(L"RunUnderCurrentUser: CreateEnvironmentBlock failed");
			envBlock = nullptr; // fallback
		}

		WCHAR windowsDir[MAX_PATH];
		GetWindowsDirectoryW(windowsDir, MAX_PATH);

		BOOL created = CreateProcessAsUserW(
			hPrimaryToken,
			nullptr,
			cmdLine,
			nullptr,
			nullptr,
			TRUE,
			creationFlags | CREATE_UNICODE_ENVIRONMENT,
			envBlock,
			windowsDir,
			&si,
			&pi
		);

		if (!created) {
			print_error(L"RunUnderCurrentUser: CreateProcessAsUserW failed");
		} else {
			procPid = pi.dwProcessId;
			if (debug) print_debug(L"RunUnderCurrentUser: CreateProcessAsUserW Success. Pid: ", procPid);
		}

		if (envBlock) DestroyEnvironmentBlock(envBlock);
		SafeCloseHandle(hPrimaryToken);
		SafeCloseHandle(hToken);

		return created;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

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

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	// Ctrl+C/Break - send Ctrl+C to process/process group

	//BOOL WINAPI CtrlHandlerV1(DWORD ctrlType) {
	//	if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
	//		if (g_pi.hProcess) {
	//			if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, g_pi.dwProcessId)) {
	//				print_error(L"GenerateConsoleCtrlEvent failed");
	//			}
	//			Sleep(1000);
	//			DWORD exitCode = 0;
	//			if (GetExitCodeProcess(g_pi.hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
	//				std::wcout << L"[INFO]: Child process still active, terminating forcibly...\n";
	//				TerminateProcess(g_pi.hProcess, 1);
	//			}
	//		}
	//		return true;
	//	}
	//	return false; // return false for other signals to allow default handling
	//}

	BOOL WINAPI CtrlHandler(DWORD ctrlType) {
		if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
			if (g_pi.hProcess) {
				if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, g_pi.dwProcessId)) {
					print_error(L"GenerateConsoleCtrlEvent failed");
				}
				DWORD wait = WaitForSingleObject(g_pi.hProcess, 1000);
				if (wait == WAIT_TIMEOUT) {
					std::wcout << L"[INFO]: Child process still active, terminating forcibly...\n";
					TerminateProcess(g_pi.hProcess, 1);
				}
			}
			return true;
		}
		return false;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

		//#include <cstdio>

		struct ProcInfo {
			std::wstring processName;
			DWORD pid;
			std::wstring windowTitle;
		};

		std::vector<ProcInfo> EnumAllUserProcesses(const std::wstring& username) {
			std::vector<ProcInfo> result;

			std::wstring cmd = L"tasklist /v /fo csv /nh /fi \"username eq " + username + L"\"";
			FILE* pipe = _wpopen(cmd.c_str(), L"r");
			if (!pipe) return result;

			wchar_t buffer[1024];
			while (fgetws(buffer, 1024, pipe)) {
				std::wstring line(buffer);
				line.erase(std::remove(line.begin(), line.end(), L'\n'), line.end());

				ProcInfo pi;
				size_t pos = 0;
				std::vector<std::wstring> fields;
				while ((pos = line.find(L'"')) != std::wstring::npos) {
					size_t end = line.find(L'"', pos + 1);
					fields.push_back(line.substr(pos + 1, end - pos - 1));
					line = line.substr(end + 1);
					if (!line.empty() && line[0] == L',') line.erase(0,1);
				}

				if (fields.size() >= 3) {
					pi.processName = fields[0];
					pi.pid = std::stoul(fields[1]);
					std::wstring wTitle = fields.back();

						//std::wstring s = wTitle;
						//std::wcout << L"Window title codes: ";
						//for (wchar_t c : s) {
						//	std::wcout << std::hex << std::showbase << (int)c << L" ";
						//}
						//std::wcout << L"\n";

					// check OEM-codes for "N/A" (0x8D/0x2F/0x84)
					if (wTitle.size() == 3 && 
						wTitle[0] == 0x8D && 
						wTitle[1] == 0x2F && 
						wTitle[2] == 0x84) {
						wTitle = L"N/A";
					}

					pi.windowTitle = wTitle;

				} else {
					pi.windowTitle = L"N/A";
				}

				result.push_back(std::move(pi));
			}

			_pclose(pipe);
			return result;
		}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

		bool IsCmdScript(const std::wstring& path)
		{
			if (path.empty()) return false;

			std::wstring image;

			if (path[0] == L'"') {
				auto pos = path.find(L'"', 1);
				if (pos == std::wstring::npos) return false;
				image = path.substr(1, pos - 1);
			} else {
				auto pos = path.find(L' ');
				image = (pos == std::wstring::npos) ? path : path.substr(0, pos);
			}

			auto dot = image.rfind(L'.');
			if (dot == std::wstring::npos) return false;

			std::wstring ext = image.substr(dot);
			return _wcsicmp(ext.c_str(), L".cmd") == 0 || _wcsicmp(ext.c_str(), L".bat") == 0;
		}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

		bool IsInvalidUsername(const std::wstring& username) {
			if (username.empty()) return true;
			const std::wstring illegalChars = L"@/\\!?*=^&<>|'`,;:.\"+[]() 	";
			if (username.find_first_of(illegalChars) != std::wstring::npos) {
				return true;
			}
			return false;
		}

		bool IsInvalidDomain(const std::wstring& domain) {
			if (domain.empty()) return true;
			const std::wstring illegalChars = L"@/\\!?*=^&<>|'`,;:\"+[]() 	";
			if (domain.find_first_of(illegalChars) != std::wstring::npos) {
				return true;
			}
			return false;
		}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	int wmain(int argc, wchar_t* argv[]) {

		setvbuf(stdout, nullptr, _IONBF, 0);
		//std::wcout << std::unitbuf;

		if (argc < 2) {
			print_str(std::wstring(L"RunAsHidden Version: ") + GetFileVersion() + std::wstring(L"\n"));
			print_help();
			return 1;
		}

		if (!IsRunningAsSystem() && !IsRunningAsAdmin()) {
			print_str(std::wstring(L"RunAsHidden Version: ") + GetFileVersion());
			print_error(L"Must be run as administrator or SYSTEM. Terminating.");
			return 1;
		}

		if (IsRunningAsSystem()) isSystem = true;

		std::wstring username, userOnly, password, domain, tempusername, temppassword, commandPath, command, cmdparams, timeoutS;
		int timeoutMs = 0;
		debug = false; // GLOBAL
		bool readPipe = true;
		bool verb = false;
		bool visible = false;
		bool direct = false;
		bool silent = false;
		bool autouser = false;
		bool has_command = false;
		bool queryUserProcs = false;
		bool RunAsCurrentUser = false;
		size_t pos;

		std::wstring cmdLine;
		std::vector<wchar_t> cmdLineBuf;

		STARTUPINFOW si;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&g_pi, sizeof(g_pi));

		// Pipe for read output if available
		HANDLE hRead, hWrite;
		HANDLE hSystemToken;
		HANDLE hAutoUserToken;

		SECURITY_ATTRIBUTES sa;

		DWORD creationFlags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
		BOOL created = false;

		DWORD bytesRead;
		CHAR buffer[4096];
		std::string prev;
		
		const DWORD WAIT_PROC_HOURS = WAIT_PROC_HOURS_DEFAULT * 60 * 60 * 1000;
		DWORD waitResult;
		DWORD exitCode = 0;

		// Parsing args
		for (int i = 1; i < argc; ++i) {
			std::wstring arg = argv[i];

			// helpers extract vals
				auto extract_value = [&](const std::wstring &a, int &idx, std::wstring &out) -> bool {
					size_t pos = a.find(L'=');
					if (pos != std::wstring::npos) {
						out = trim_quotes(a.substr(pos + 1));
						return true;
					}
					if (idx + 1 >= argc) return false;
					std::wstring next = argv[idx + 1];
					if (!next.empty() && next[0] == L'-') return false; // protect: capture another opt
					out = trim_quotes(argv[++idx]);
					return true;
				};
				auto extract_value_raw = [&](const std::wstring &a, int &idx, std::wstring &out) -> bool {
					size_t pos = a.find(L'=');
					if (pos != std::wstring::npos) {
						out = a.substr(pos + 1);
						return true;
					}
					if (idx + 1 >= argc) return false;
					std::wstring next = argv[idx + 1];
					if (!next.empty() && next[0] == L'-') return false; // skip next option
					out = argv[++idx];
					return true;
				};
			// helpers extract vals end

			if (arg == L"-h" || arg == L"--help" || arg == L"-?") {
				print_str(std::wstring(L"RunAsHidden Version: ") + GetFileVersion() + std::wstring(L"\n"));
				print_help();
				goto exitmainproc;
			}

			if (arg == L"-silent" || arg == L"--silent" || arg == L"-s") {
				silent = true;
				continue;
			}

			if (arg == L"-debug" || arg == L"--debug") {
				debug = true;
				continue;
			}
			if (arg == L"-privdebug" || arg == L"--privdebug") {
				privdebug = true;
				continue;
			}

			if (arg == L"-verb" || arg == L"--verb" || arg == L"-verbose" || arg == L"--verbose") {
				verb = true;
				continue;
			}

			if (arg == L"-query-procs" || arg == L"--query-procs") {
				queryUserProcs = true;
				has_command = true;
				continue;
			}

			if (arg == L"-cleanup" || arg == L"--cleanup") {
				g_cleanup_mode = true;
				has_command = true;
				continue;
			}

			if (arg == L"-cleanup-all" || arg == L"--cleanup-all") {
				g_cleanup_mode = true;
				g_cleanupall_mode = true;
				has_command = true;
				continue;
			}
			
			if (arg == L"-cl" || arg == L"--cl") {
				g_cl_on = true;
				continue;
			}

			if (arg == L"-cla" || arg == L"--cla") {
				g_cl_on = true;
				g_cla_on = true;
				continue;
			}

			if (arg == L"-nowait" || arg == L"--nowait" || arg == L"-n") {
				g_noWait = true;
				continue;
			}

			if (arg == L"-no-output" || arg == L"--no-output") {
				readPipe = false;
				continue;
			}

			if (arg == L"-gpo" || arg == L"--gpo") {
				g_runFromGPO = true;
				continue;
			}

			// timeout
			if (arg == L"-t" || arg == L"-timeout" || arg == L"--timeout" ||
				starts_with(arg, L"-t=") || starts_with(arg, L"-timeout=") || starts_with(arg, L"--timeout=")) {
				if (!extract_value(arg, i, timeoutS)) {
					print_error(arg, L" requires a value");
					SetLastError(2);
					exitCode = 2;
					goto exitmainproc;
				}
				continue;
			}

			if (arg == L"-direct" || arg == L"--direct" || arg == L"-d") {
				direct = true;
				continue;
			}

			if (arg == L"-visible" || arg == L"--visible" || arg == L"-v") {
				visible = true;
				continue;
			}

			if (arg == L"-keep" || arg == L"--keep" || arg == L"-k") {
				g_keepTempUser = true;
				continue;
			}

			if (arg == L"-nofb" || arg == L"--nofb" || arg == L"-nofallback" || arg == L"--nofallback") {
				g_tempuser_fallback = false;
				continue;
			}

			// custom temporary username
			if (arg == L"-tn" || arg == L"--tn" || arg == L"-tempusername" || arg == L"--tempusername" ||
				starts_with(arg, L"-tn=") || starts_with(arg, L"--tn=") || starts_with(arg, L"-tempusername=") || starts_with(arg, L"--tempusername=")) {
				if (!extract_value(arg, i, tempusername)) {
					print_error(arg, L" requires a value");
					SetLastError(2);
					exitCode = 2;
					goto exitmainproc;
				}
				continue;
			}

			// username
			if (arg == L"-u" || arg == L"--username" || arg == L"-username" ||
				starts_with(arg, L"-u=") || starts_with(arg, L"--username=") || starts_with(arg, L"-username=")) {
				if (!extract_value(arg, i, username)) {
					print_error(arg, L" requires a value");
					SetLastError(2);
					exitCode = 2;
					goto exitmainproc;
				}
				continue;
			}

			// password
			if (arg == L"-p" || arg == L"--password" || arg == L"-password" ||
				starts_with(arg, L"-p=") || starts_with(arg, L"--password=") || starts_with(arg, L"-password=")) {
				if (!extract_value(arg, i, password)) {
					print_error(arg, L" requires a value");
					SetLastError(2);
					exitCode = 2;
					goto exitmainproc;
				}
				continue;
			}

			// command
			if (arg == L"-c" || arg == L"--command" ||
				starts_with(arg, L"-c=") || starts_with(arg, L"--command=")) {

				if (!extract_value_raw(arg, i, command)) {  // trim quotes
					print_error(arg, L" requires a command string");
					exitCode = 2;
					goto exitmainproc;
				}
				has_command = true;
				continue;
			}

			// command params
			if (arg == L"-params" || arg == L"--params" ||
				starts_with(arg, L"-params=") || starts_with(arg, L"--params=")) {
				if (!extract_value_raw(arg, i, cmdparams)) {  // RAW
					print_error(arg, L" requires a value");
					exitCode = 2;
					goto exitmainproc;
				}
				continue;
			}

			print_error(L"Unknown or unexpected argument");
			SetLastError(1);
			exitCode = 2;
			goto exitmainproc;
		}

		//1.

		if (!has_command) {
			print_error(L"Missing required parameters");
			SetLastError(1);
			exitCode = 2;
			goto exitmainproc;
		}

		//2.

		if (g_cleanup_mode || g_cl_on) {
			if (IsDomainController()) {
				print_error(L"Any cleanup mode is incompatible with domain controllers.");
				SetLastError(1);
				goto exitmainproc;
			}
		}

		if (g_cleanup_mode) {
			if (!g_cleanupall_mode) {
				print_str(L"Cleanup mode.");
			} else {
				print_str(L"Cleanup all mode.");
			}
			CheckAndCleanupOrphanedTempUsers();
			goto exitmainproc;
		}

		//3.

		if (!tempusername.empty()) {
			if (username != L"auto") {
				print_error(L"Incompatible parameter: -tn can only be used with -u=auto");
				SetLastError(1);
				exitCode = 3;
				goto exitmainproc;
			}
			if (tempusername.back() != L'.') {
				if (tempusername.length() > (size_t)11) {
					print_error(L"The specified temporary username cannot be longer than 11 characters");
					SetLastError(1);
					exitCode = 3;
					goto exitmainproc;
				}
				if (g_keepTempUser) {
					print_error(L"Incompatible parameter: -k / --keep");
					SetLastError(1);
					exitCode = 3;
					goto exitmainproc;
				}
				if (username == L"auto") {
					if (g_noWait) {
						print_error(L"Incompatible parameter: -n / -nowait");
						SetLastError(1);
						exitCode = 3;
						goto exitmainproc;
					}
				}
			} else {
				
				if (tempusername.length() > (size_t)21) {
					print_error(L"The specified temporary username cannot be longer than 20 characters");
					SetLastError(1);
					exitCode = 3;
					goto exitmainproc;
				}
			}
		} else {
			if (username == L"auto") {
				if (g_noWait) {
					print_error(L"Incompatible parameter: -n / -nowait");
					SetLastError(1);
					exitCode = 3;
					goto exitmainproc;
				}
			}
			if (g_keepTempUser) {
				print_error(L"Incompatible parameter: -k / --keep");
				SetLastError(1);
				exitCode = 3;
				goto exitmainproc;
			}
		}

		//4.

		// Domain / userOnly
		domain = L".";
		userOnly = username;
		pos = username.find(L'\\');
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

		//5.

		if ( userOnly == L"auto" || userOnly == L"*" ) {
			if ( password == L"auto" || password == L"*" ) {
				autouser = true;
				if ( !tempusername.empty() ) {
					if (tempusername.back() == L'.') {
						tempusername.pop_back();
					} else {
						tempusername = tempusername + L"_" + GenerateUsernamePostfix(8);
						g_keepTempUser = false;
						g_noWait = false;
					}
					username = tempusername;
					g_tempUserNameW = username;
					userOnly = username;
				}
			} else {
				print_error(L"Invalid password parameter");
				SetLastError(1);
				exitCode = 3;
				goto exitmainproc;
			}
		}

		//6.

		if (IsInvalidUsername(userOnly)) {
			print_error(L"Invalid user name: contains illegal characters: ", userOnly);
			SetLastError(1);
			exitCode = 3;
			goto exitmainproc;
		}
		if (!domain.empty()) {
			if (IsInvalidDomain(domain)) {
				print_error(L"Invalid domain name: contains illegal characters: ", domain);
				SetLastError(1);
				exitCode = 3;
				goto exitmainproc;
			}
		}

		//7.

		if (IsDomainController()) {
			if (autouser || visible) {
				print_error(L"Can not be run on a domain controller in this mode [autouser or visible]");
				SetLastError(1);
				exitCode = 3;
				goto exitmainproc;
			}
		}

		//8.

		if (autouser && visible) {
			print_error(L"Can not be run in this mode [autouser and visible]");
			SetLastError(1);
			exitCode = 3;
			goto exitmainproc;
		}


		if (direct && IsCmdScript(command)) {
			print_error(L"Direct mode is not allowed for .cmd/.bat");
			SetLastError(1);
			exitCode = 3;
			goto exitmainproc;
		}

		if (debug) {
			print_str(std::wstring(L"RunAsHidden Version: ") + GetFileVersion());
			print_str(L"------------------------------------------");
		}

		if (debug) print_debug(L"Target user to execute: '" + username + L"', Domain: '" + domain + L"', Auto: '" + (autouser ? L"true" : L"false"));

		if (g_cl_on) { //UNDER CONSTRUCTION
			g_cleanup_mode = true;
			if (g_cla_on) {
				g_cleanupall_mode = true;
				if (debug) print_str(L"-- Cleanup all before execution command --");
			} else {
				if (debug) print_str(L"---- Cleanup before execution command ----");
			}
			//CheckAndCleanupOrphanedTempUsers();
			print_str(L"------------------------------------------");
		}

		if (username.empty() || username == L"." ) {
			username = L".";   // current user
			password = L"";   // current user
			RunAsCurrentUser = true;
		}

		if (!debug && verb) {
			std::wcout << L"Command: " << command << L"\n";
			if (!cmdparams.empty()) {
				std::wcout << L"Params: " << cmdparams << L"\n";
			}
			std::wcout << L"Direct run: " << direct << L"\n";
			std::wcout << L"Is cmd script: " << IsCmdScript(command) << L"\n";
		}

		if (debug) {
			if ( autouser ) {
				if ( !tempusername.empty() ) {
					print_debug(L"User [Spec.tmp]: ", username);
				} else {
					print_debug(L"User [Def.tmp]: ", username);
				}
			} else {
				print_debug(L"User: ", username);
			}
			print_debug(L"Command: ", command);
			print_debug(L"Params: ", cmdparams);
			print_debug(L"Direct run: ", direct);
			print_debug(L"Is cmd script: ", IsCmdScript(command));
			print_str(L"------------------------------------------");
		}

		if (!timeoutS.empty()) {
			try {
				int t = std::stoi(timeoutS);
				timeoutMs = static_cast<DWORD>(std::max(0, t)) * 1000;
			}
			catch (const std::exception& e) {
				print_error(L"Incorrect timeout param: ", timeoutS, L", will be reset to 1 sec");
				timeoutMs = 1000;
			}
			if (timeoutMs > 60000) {
				print_error(L"Incorrect timeout: ", timeoutS, L", will be reset to 1 sec");
				timeoutMs = 1000;
			}
		}

		// get user procs
			if (queryUserProcs) {
				PSID pSid = nullptr;
				if (GetSIDFromUsername(&pSid,username)) {
					auto procs = EnumAllUserProcesses(username);

					// Table header
					std::wcout << std::left
							   << std::setw(32) << L"Process Name"
							   << std::setw(10) << L"PID"
							   << L"Window Title\n";
					std::wcout << std::wstring(60, L'-') << L"\n";

					for (auto& p : procs) {
						std::wcout << std::left
								   << std::setw(25) << p.processName
								   << std::setw(10) << p.pid
								   << p.windowTitle << L"\n";
					}

					LocalFree(pSid);
					pSid = nullptr;
				} else {
					print_error(L"Error GET SID for user.");
				}
				exitCode = 0;
				goto exitmainproc;
			}
		// get user procs end

		if (autouser) {
			if (debug) print_debug(L"Auto user mode");
			if (!CreateAndInitializeAutoUser(username, password)) {
				print_error(L"Initialize temporary user failed");
				exitCode = 1;
				goto exitmainproc;
			} else {
				userOnly = username;
				if (debug) print_debug(L"Using automatically created temporary user: ", userOnly, L" [", username, L"]");
			}
			
			if (debug) print_str(L"------------------------------------------");
		} else {
			if (debug) print_debug(L"Default mode");
		}

		if (debug) {
			std::wstring hostname = GetHostname();
			print_debug(L"Computer name: ", hostname);
			if (IsInteractiveSession()) {
				print_debug(L"Interactive session");
			} else {
				print_debug(L"Non Interactive session");
			}
			std::wstring currentuser = GetCurrentUserSamCompatible();
			if (!currentuser.empty()) {
				print_debug(L"Current user: ", currentuser);
			} else {
				print_debug(L"Failed to get current user. Error: ", GetLastError());
			}
			if (!isSystem) {
				print_debug(L"User context");
			} else {
				print_debug(L"System context");
			}
			print_debug(L"Target username='", username, L"'");
			if (domain != L".") {
				print_debug(L"Target domain='", domain, L"'");
			}
			print_debug(L"Target user='", userOnly, L"'");
			print_debug(L"Visible=", (visible ? L"true" : L"false"));
			print_debug(L"Command='", command, L"'");
			if (g_noWait) {
				print_debug(L"NoWait=", g_noWait);
			}
			if (timeoutMs > 0)	{
				print_debug(L"Timeout: ", timeoutS);
			}
			if (direct) {
				print_debug(L"Direct");
			}
			if (silent) {
				print_debug(L"Silent");
			}
			if (queryUserProcs) {
				print_debug(L"Query user processes: ", username);
			}
			print_str(L"------------------------------------------");
		}

		if (!EnablePrivilege(SE_INCREASE_QUOTA_NAME)) {
			print_error(L"EnablePrivilege(SE_INCREASE_QUOTA_NAME) failed");
		}

		if (!isSystem) {
			if (EnableDebugPrivilege()) {
				if (debug) print_debug(L"SeDebugPrivilege enabled");
				hSystemToken = GetSystemToken();
				if (hSystemToken) {
					if (debug) PrintTokenInformation(hSystemToken);
					if (ImpersonateLoggedOnUser(hSystemToken)) {
						if (debug) print_debug(L"Successfully impersonated SYSTEM");
						isSystem = true;
						isImpersonated = true;
					} else {
						print_error(L"ImpersonateLoggedOnUser failed");
						SafeCloseHandle(hSystemToken);
					}
				} else {
					print_error(L"Failed to get SYSTEM token");
				}
				EnablePrivilege(SE_RESTORE_NAME);
				EnablePrivilege(SE_BACKUP_NAME);
			} else {
				print_error(L"Failed to enable SeDebugPrivilege");
			}
		} else {
			if (!EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME)) {
				print_error(L"EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) failed");
			}
			if (!EnablePrivilege(SE_TCB_NAME)) {
				print_error(L"EnablePrivilege(SE_TCB_NAME) failed");
			}
		}

		if (isSystem) {
			if (debug) print_debug(L"[Call] EnableThreadPrivilege");
			if (!EnableThreadPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME)) {
				print_error(L"EnableThreadPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) failed");
			}
			if (!EnableThreadPrivilege(SE_INCREASE_QUOTA_NAME)) {
				print_error(L"EnableThreadPrivilege(SE_INCREASE_QUOTA_NAME) failed");
			}
			if (!EnableThreadPrivilege(SE_TCB_NAME)) {
				print_error(L"EnableThreadPrivilege(SE_TCB_NAME) failed");
			}
		}

		if (debug) {
			if (privdebug) {
				HANDLE hToken = nullptr;
				if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
						print_str(L"------------------------------------------");
						print_debug(L"Current Process token privileges:");
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
									std::wcout << L"\n";
								}
							}
						}
						print_str(L"------------------------------------------");
					SafeCloseHandle(hToken);
				} else {
					print_error(L"Failed to open process token to enumerate privileges");
				}
			}

			if (isImpersonated) {
				if (privdebug) {
					HANDLE hThreadToken = nullptr;
					if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, &hThreadToken)) {
						print_str(L"------------------------------------------");
						print_debug(L"Current Tread token privileges:");
						PrintTokenPrivileges(hThreadToken, L"CurrentThread");
						print_str(L"------------------------------------------");
						SafeCloseHandle(hThreadToken);
					} else {
						print_error(L"OpenThreadToken failed for PrintTokenPrivileges");
					}
				}
			}

		}

		if (direct) {
			// direct run
			cmdLine = command;
			if (!cmdparams.empty())
				cmdLine += L" " + cmdparams;
		} else {
			// cmd.exe /d /c
			cmdLine = L"cmd.exe /d /c \"" + command;
			if (!cmdparams.empty())
				cmdLine += L" " + cmdparams;
			cmdLine += L"\"";
		}

		if (debug) {
			print_debug(L"Execute command line: ", cmdLine);
		} 
		else if (verb) {
			std::wcout << L"Execute command line: " << cmdLine << L"\n";
		}

		cmdLineBuf.assign(cmdLine.begin(), cmdLine.end());
		cmdLineBuf.push_back(L'\0');

		if (visible) {
			si.dwFlags = STARTF_USESHOWWINDOW;
			si.wShowWindow = SW_SHOW;
			DWORD creationflagsVisible = CREATE_NEW_PROCESS_GROUP;
			bool creationvisible = RunAsInteractive(userOnly,domain,password,cmdLineBuf.data(),si,g_pi,creationflagsVisible);
			exitCode = creationvisible ? 0 : 1;
			goto exitmain;
		}

		sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, true };

		if (readPipe) {
			if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
				print_error(L"CreatePipe failed");
				exitCode = 1;
				goto exitmain;
			}
			if (!SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0)) {
				print_error(L"SetHandleInformation failed");
				SafeCloseHandle(hRead);
				SafeCloseHandle(hWrite);
				exitCode = 1;
				goto exitmain;
			}
			si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
			si.hStdOutput = hWrite;
			si.hStdError = hWrite;
		}
		si.wShowWindow = SW_HIDE;

		// Ctrl+C - Is this even necessary? Well, let it be.
		if (!SetConsoleCtrlHandler(CtrlHandler, true)) {
			print_error(L"SetConsoleCtrlHandler failed");
			SafeCloseHandle(hRead);
			SafeCloseHandle(hWrite);
			exitCode = 1;
			goto exitmain;
		}

		if (RunAsCurrentUser) {
			created = RunUnderCurrentUser(
				cmdLineBuf.data(),
				si,
				g_pi,
				creationFlags
			);
			if (!created) {
				print_error(L"RunUnderCurrentUser failed");
				exitCode = 1;
				goto exitmain;
			}
		} else {
			if (isSystem) {
				created = RunUnderSystem(userOnly, domain, password, cmdLineBuf.data(), si, g_pi, creationFlags);
				if (!created) {
					print_error(L"RunUnderSystem failed");
					SafeCloseHandle(hWrite);
					SafeCloseHandle(hRead);
					SafeCloseHandle(g_pi.hProcess);
					SafeCloseHandle(g_pi.hThread);
					exitCode = 1;
					goto exitmain;
				}
			} else {
				created = RunUnderUser(userOnly, domain, password, cmdLineBuf.data(), si, g_pi, creationFlags);
				if (!created) {
					print_error(L"RunUnderUser failed");
					SafeCloseHandle(hWrite);
					SafeCloseHandle(hRead);
					SafeCloseHandle(g_pi.hProcess);
					SafeCloseHandle(g_pi.hThread);
					exitCode = 1;
					goto exitmain;
				}
			}
		}

		SafeCloseHandle(hWrite);

		if (g_noWait) {
			if (debug) print_debug(L"Process started successfully [nowait mode], exiting.");
			SafeCloseHandle(hRead);
			SafeCloseHandle(g_pi.hProcess);
			SafeCloseHandle(g_pi.hThread);
			exitCode = 0;
			goto exitmain;
		}

		// Read output from process via pipe
		if (readPipe) {
			if (debug) {
				print_str(L"\nCOMMAND OUTPUT:\n");
			}
			while (true) {
				BOOL success = ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
				if (!success || bytesRead == 0) break;
				std::string current(buffer, bytesRead);
				if (current != prev) {
					std::cout.write(current.c_str(), current.size());
					prev = current;
				}
			}
			if (debug) {
				print_str(L"\nCOMMAND OUTPUT END.\n");
			}
		}
		SafeCloseHandle(hRead);
	 
		waitResult = WaitForSingleObject(g_pi.hProcess, WAIT_PROC_HOURS);
		if (waitResult == WAIT_OBJECT_0) {
			if (!GetExitCodeProcess(g_pi.hProcess, &exitCode)) {
				print_error(L"GetExitCodeProcess failed, error: ", GetLastError());
			}
		} else {
			if (waitResult == WAIT_TIMEOUT) {
				print_error(L"Process execution exceeded ", WAIT_PROC_HOURS_DEFAULT, L" hours limit.");
			} else {
				print_error(L"WaitForSingleObject failed, error: ", GetLastError());
			}
		}

		SafeCloseHandle(g_pi.hProcess);
		SafeCloseHandle(g_pi.hThread);
		
		if (debug) {
			if (debug) print_debug(L"COMMAND EXIT CODE: ", exitCode);			
		}

		goto exitmain;

		exitmain:

				if (timeoutMs > 0) {
					Sleep(timeoutMs);
				}

				std::wcout << L"\n";

				if (!g_noWait) {

					if (autouser) {

						if (!IsRahTemporaryKeepedUserSid(g_tempUserSidW)) {

							if (g_tempUserCreated || g_doUseExistingUserContext) {
								if (IsUserLoggedOn(g_tempUserW)) {
									if (debug) print_debug(L"Temporary user processes are still active. Temporary user preserved.");
								} else {
									if (timeoutMs <= 1000) Sleep(1000);
									DeleteTempUserAndProfile(g_tempUserW, g_tempUserSidW, g_tempUserProfileW);
								}
							}

						} else {
							if (debug) print_debug(L"Temporary user preserved as requested");
						}

						if (g_hPrimaryToken) {
							if (!IsUserLoggedOn(g_tempUserW)) {
								UnloadTempUserProfile(g_tempUserW, g_tempUserSidW);
							}
						}
					} 

				} else {

					if (autouser) {
						if (debug) print_debug(L"Temporary user processes are still active. Temporary user preserved in NoWait mode.");
					}

				}

		exitmainproc:

				SecureClear(g_tempUserW);
				SecureClear(g_tempUserSidW);
				SecureClear(g_tempUserProfileW);

				if (g_tempUserPSid) {
					LocalFree(g_tempUserPSid);
					g_tempUserPSid = nullptr;
				}
				ClearSensitiveData(username, userOnly, domain, password, tempusername, temppassword, cmdLine, command, cmdLineBuf);
				if (debug) print_debug("Process exited with code ", exitCode);
				return static_cast<int>(exitCode);
	}
