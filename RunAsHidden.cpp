// RunAsHidden.cpp
// Version 4.0.7.2
// Author: [BorizzK](https://github.com/BorizzK / https://s-platoon.ru/profile/14721-borizzk / https://github.com/BorizzK )
// Forum: https://forum.ru-board.com/topic.cgi?forum=8&topic=82891#1
// GitHub: https://github.com/BorizzK/RunAsHidden
// License: MIT
// APi: https://learn.microsoft.com/ru-ru/windows/win32/api/ | https://learn.microsoft.com/en-us/windows/win32/api/
// mingw64 [https://winlibs.com/]
// Compile command without res: 
// g++ RunAsHidden.cpp -o RunAsHidden.exe -municode -static -ladvapi32 -luserenv -lsecur32 -lversion -lwtsapi32 -lnetapi32
// Compile command with res:
// windres RunAsHidden.rc -O coff -o RunAsHidden.res & g++ RunAsHidden.cpp RunAsHidden.res -o RunAsHidden.exe -municode -static -ladvapi32 -luserenv -lsecur32 -lversion -lwtsapi32 -lnetapi32 -lbcrypt

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
	#ifndef ERROR_USER_PROFILE_ALREADY_LOADED
	#define ERROR_USER_PROFILE_ALREADY_LOADED 1500
	#endif

	bool debug = false;
	bool isSystem = false;
	bool isImpersonated = false;
	std::wstring tempUserW;
	std::wstring tempUserSidW;
	std::wstring tempUserProfileW;
	bool tempUserCreated = false;
	bool keepTempUser = false;
	bool runFromGPO = false;
	
	PROCESS_INFORMATION g_pi = {0};

	HANDLE g_hPrimaryToken = NULL;
	LPVOID g_envBlock = NULL;
	PROFILEINFO g_profileInfo = {0};
	bool g_profileLoaded = false;

	DWORD procPid;

	//----------------------------------------------------------------------------------------------------//

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
		std::wcout << L"RunAsHidden Version: " << GetFileVersion() << L"\n\n";

		std::wcout <<
		L"Usage:\n"
		L"  RunAsHidden.exe -u <username> -p <password> [options] -c <command> [-params <parameters>]\n\n"

		L"Options:\n"
		L"  -u, --username <username>       Target username. Formats:\n"
		L"                                  'user'             - local user\n"
		L"                                  'domain\\\\user'    - domain user\n"
		L"                                  'user@domain'      - domain user\n"
		L"                                  'auto'             - automatically create temporary hidden admin user\n"
		L"                                                      with isolated profile in %SystemRoot%\\Temp\\RAH\\\n"
		L"\n"
		L"  -p, --password <password>       Password for the user.\n"
		L"                                  Can be empty (-p=.) for logged-in session.\n"
		L"                                  'auto' generates a strong random password for temporary user.\n"
		L"\n"
		L"  -k, --keep                      Keep the automatically created temporary user for future use.\n"
		L"\n"
		L"  -n, --nowait                    Do not wait for the command to finish.\n"
		L"                                  Returns 0 if process started successfully, otherwise 1.\n"
		L"\n"
		L"  -t, --timeout <seconds>         Wait the specified time before exiting and/or deleting temporary user.\n"
		L"                                  Maximum allowed: 60 seconds.\n"
		L"\n"
		L"  -d, --direct                    Run the command directly without 'cmd.exe /c'.\n"
		L"                                  Shell operators like >, |, & are not interpreted.\n"
		L"                                  Useful for direct execution or capturing output manually.\n"
		L"\n"
		L"  -v, --visible                   Run the command interactively (window visible) in the active session.\n"
		L"\n"
		L"  -verb, --verbose                Enable small debug output of command details.\n"
		L"\n"
		L"  -debug, --debug                 Enable debug output, diagnostics, and command details.\n"
		L"\n"
		L"  -c, --command <command>         Command line to execute. Can include full path.\n"
		L"                                  Quotes inside must be escaped with backslash (\\\\).\n"
		L"\n"
		L"  -params <parameters>            Optional parameters for the command. Passed exactly as-is.\n"
		L"                                  Use quotes if parameters contain spaces, escape internal quotes with \\\\.\n"
		L"\n"
		L"  -h, --help, -?                  Show this help message.\n\n"

		L"Examples:\n"
		L"  RunAsHidden.exe -u user -p pass -c \"whoami\"\n"
		L"  RunAsHidden.exe -u=domain\\\\user -p=pass -c \"dism.exe /online /get-packages\"\n"
		L"  RunAsHidden.exe -u=auto -p=auto -c \"\\\"C:\\\\Program Files\\\\app.exe\\\" -arg1 -arg2\"\n"
		L"  RunAsHidden.exe -u=auto -p=auto -c \"\\\"script.cmd\\\" JJJ \\\"222\\\"\"\n"
		L"  RunAsHidden.exe -u=auto -p=auto -c \"\\\"script.cmd\\\"\" -params=\"\\\"222\\\" 333\"\n"
		L"      // Equivalent to: \"script.cmd\" \"222\" 333\n"
		L"  RunAsHidden.exe -u=auto -p=auto -c \"\\\"Updater.cmd\\\"\" -params=\"--file=\\\"C:\\\\Logs\\\\log.txt\\\" --mode=fast\"\n"
		L"  RunAsHidden.exe -u auto -p auto -d -c \"C:\\\\Windows\\\\System32\\\\whoami.exe\"\n"
		L"  RunAsHidden.exe -u auto -p auto -d -t 2 -k -c \"whoami\"\n";
		std::wcout.flush();
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	void print_str(const std::wstring& msg) {
		std::wcout << msg << L"\n";
		std::wcout.flush();
	}

	void print_err(const std::wstring& msg) {
		std::wcerr << msg << L'\n';
		std::wcerr.flush();
	}

	void print_warning(const std::wstring& warningMessage) {
		DWORD werr = GetLastError();
		std::wostringstream msg;
		msg << L"[WARNING]: " << warningMessage
			<< L": code: " << werr;
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
		if (err != 0) {
			msg << L" (error code: " << err << L")";
		}
		switch (err) {
			case 0:
				errorMessage = msg.str();
				break;

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
				errorMessage = msg.str();
				break;
		}
		if (!errorMessage.empty()) {
			print_err(L"[ERROR]: " + errorMessage);
		}
	}

	void print_net_error(const std::wstring& neterrorMessage, NET_API_STATUS status) {
		std::wstring errorMessage;

		switch (status) {
			case NERR_InvalidComputer:
				errorMessage = L"Invalid computer name";
				break;
			case NERR_NotPrimary:
				errorMessage = L"Operation allowed only on the primary domain controller";
				break;
			case NERR_UserExists:
				errorMessage = L"User account already exists";
				break;
			case NERR_PasswordTooShort:
				errorMessage = L"Password is too short";
				break;
			case NERR_PasswordTooRecent:
				errorMessage = L"Password was changed recently";
				break;
			case NERR_GroupNotFound:
				errorMessage = L"Specified group not found";
				break;
			default: {
				std::wostringstream msg;
				msg << neterrorMessage << L": Code: " << status;
				errorMessage = msg.str();
				break;
			}
		}

		if (!errorMessage.empty()) {
			print_err(L"[ERROR]: " + errorMessage);
		}
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
		DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
		std::vector<wchar_t> buffer(size);
		if (GetComputerNameW(buffer.data(), &size)) {
			return std::wstring(buffer.data(), size);
		}
		print_error(L"GetHostname: Failed to get computer name");
		return L"";
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	//****************************************************************************************************//

	std::wstring GenerateRandomString(size_t length) {
		const wchar_t charset[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		std::wstring result;
		result.reserve(length);
		srand((unsigned)time(NULL) ^ GetTickCount());
		for (size_t i = 0; i < length; ++i) {
			result += charset[rand() % (sizeof(charset)/sizeof(wchar_t) - 1)];
		}
		return result;
	}

	//****************************************************************************************************//

	// RtlGenRandom [SystemFunction036]
	extern "C" BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
	void GenerateRandomPassword(size_t length, std::wstring& genpassword) {
		const wchar_t charset[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
		const size_t charset_size = sizeof(charset) / sizeof(wchar_t) - 1;

		std::vector<BYTE> buf(length);
		bool crypto_ok = RtlGenRandom(buf.data(), (ULONG)buf.size()) != false;

		genpassword.clear();
		genpassword.reserve(length);

		if (crypto_ok) {
			// Криптоустойчивый способ
			for (size_t i = 0; i < length; ++i) {
				genpassword += charset[ buf[i] % charset_size ];
			}
		} else {
			// Fallback на rand()
			srand((unsigned)time(NULL) ^ GetTickCount());
			for (size_t i = 0; i < length; ++i) {
				genpassword += charset[rand() % charset_size];
			}
		}
	}

	//****************************************************************************************************//

	//----------------------------------------------------------------------------------------------------//

	bool GetSIDFromUsername(const std::wstring& username, PSID* ppSid) {
		if (!ppSid) return false;
		*ppSid = nullptr; //Reset

		DWORD sidSize = 0, domainSize = 0;
		SID_NAME_USE use;

		// Get buffer sizes
		LookupAccountNameW(NULL, username.c_str(), NULL, &sidSize, NULL, &domainSize, &use);
		DWORD err = GetLastError();
		if (err != ERROR_INSUFFICIENT_BUFFER) {
			print_error(L"GetSIDFromUsername: Initial LookupAccountNameW failed [not buffer error]");
			return false;
		}

		std::vector<BYTE> sidBuffer(sidSize);
		std::vector<wchar_t> domainBuffer(domainSize);

		// Get SID
		if (!LookupAccountNameW(NULL, username.c_str(),
			sidBuffer.data(), &sidSize,
			domainBuffer.data(), &domainSize, &use)) {
			print_error(L"GetSIDFromUsername: LookupAccountNameW failed");
			return false;
		}

		// Copy sid to mem
		*ppSid = (PSID)LocalAlloc(LPTR, sidSize);
		if (!*ppSid) {
			print_error(L"GetSIDFromUsername: LocalAlloc failed");
			return false;
		}
		CopyMemory(*ppSid, sidBuffer.data(), sidSize);

		LPWSTR sidString = NULL;
		if (ConvertSidToStringSidW(*ppSid, &sidString)) {
			if (debug) print_debug(L"Retrieved User SID: ", sidString);
			LocalFree(sidString);
			return true;
		}
		LocalFree(sidString);
		LocalFree(*ppSid); //reset
		*ppSid = nullptr; //reset
 		print_error(L"GetSIDFromUsername: FAILED");
		return false;
	}

	bool AddUserToAdminsLocalGroup(const std::wstring& username) {

		const wchar_t* adminGroupSidStr = L"S-1-5-32-544";
		PSID pAdminGroupSid = nullptr;

		if (!ConvertStringSidToSidW(adminGroupSidStr, &pAdminGroupSid)) {
			std::wstring msg = std::wstring(L"AddUserToAdminsLocalGroup: Failed to convert SID string: ") + adminGroupSidStr;
			print_error(msg.c_str());
			return false;
		}

		WCHAR groupName[256], domainName[256];
		DWORD groupNameSize = ARRAYSIZE(groupName);
		DWORD domainNameSize = ARRAYSIZE(domainName);
		SID_NAME_USE sidUse;
		if (!LookupAccountSidW(nullptr, pAdminGroupSid, groupName, &groupNameSize, domainName, &domainNameSize, &sidUse)) {
			print_error(L"AddUserToAdminsLocalGroup: LookupAccountSidW failed");
			LocalFree(pAdminGroupSid);
			return false;
		}

		std::wstring fullGroupName = groupName;
		LOCALGROUP_MEMBERS_INFO_3 memberInfo;
		memberInfo.lgrmi3_domainandname = const_cast<LPWSTR>(username.c_str());
		NET_API_STATUS status = NetLocalGroupAddMembers(
			nullptr,                     // local computer
			fullGroupName.c_str(),       // group
			3,                           // level struct
			(LPBYTE)&memberInfo,         // data
			1                            // element
		);
		std::wstring statusText = std::to_wstring(status);
		if (debug) print_debug(L"NetLocalGroupAddMembers status ", statusText);
		if (status == NERR_Success) {
			if (debug) print_debug(L"Successfully added user ", username, L" to local administrators group");
		} else if ( status == ERROR_MEMBER_IN_ALIAS ) {
			if (debug) print_debug(L"User ", username, L" already in local administrators group");
		} else {
			print_error(L"AddUserToAdminsLocalGroup: NetLocalGroupAddMembers failed to add user ", username, L" to local administrators group");
			LocalFree(pAdminGroupSid);
			return false;
		}
		LocalFree(pAdminGroupSid);
		return true;
	}

	bool CreateLocalUser(const std::wstring& username, const std::wstring& password, const std::wstring& profileDir ) {
		
		USER_INFO_1 ui;
		NET_API_STATUS nStatus;

		ZeroMemory(&ui, sizeof(ui));
		ui.usri1_name = const_cast<LPWSTR>(username.c_str());
		ui.usri1_password = const_cast<LPWSTR>(password.c_str());
		ui.usri1_priv = USER_PRIV_USER;
		//ui.usri1_home_dir = NULL;
		ui.usri1_home_dir = const_cast<LPWSTR>(profileDir.c_str());
		ui.usri1_comment = const_cast<LPWSTR>(L"Temporary user created by RunAsHidden");
		ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
		ui.usri1_script_path = NULL;

		nStatus = NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);

		if (nStatus == NERR_Success) {
			if (debug) print_debug(L"", username, L" created successfully");
		} else if (nStatus == NERR_UserExists) {
			if (debug) print_debug(L"User: ", username, L" already exists, changing password");
			USER_INFO_1003 uiPwd;
			uiPwd.usri1003_password = const_cast<LPWSTR>(password.c_str());
			NET_API_STATUS pwdStatus = NetUserSetInfo(NULL, username.c_str(), 1003, (LPBYTE)&uiPwd, NULL);
			if (pwdStatus == NERR_Success) {
				if (debug) print_debug(L"Password changed successfully for user: ", username);
			} else {
				std::wstring msg = std::wstring(L"Failed to change password for user: ") + username;
				print_error(msg.c_str());
				return false;
			}
		} else {
			std::wstring msg = std::wstring(L"CreateLocalUser: Failed to create user: ") + username;
			print_error(msg.c_str());
			return false;
		}
		
		if (!AddUserToAdminsLocalGroup(username)) {
			return false;
		}
		if (debug) print_debug(L"Successfully add user: ", username, L" to local administrators group");

		return true;
	}

	// PROFILE

		bool CopyDirectoryRecursive(const std::wstring& source, const std::wstring& dest) {

			WIN32_FIND_DATAW findData{};
			HANDLE hFind = INVALID_HANDLE_VALUE; // init

			DWORD attr = GetFileAttributesW(dest.c_str());
			if (attr == INVALID_FILE_ATTRIBUTES) {
				if (!CreateDirectoryW(dest.c_str(), NULL)) {
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
						print_error((L"CreateAndInitializeAutoUser: Failed to copy file: " + sourcePath + L" to " + destPath).c_str());
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

		bool FileExistsInProfile(const std::wstring& destProfilePath, const std::wstring& fileName) {
			std::wstring fullPath = destProfilePath + L'\\' + fileName;
			DWORD attrs = GetFileAttributesW(fullPath.c_str());
			if (debug) {
				std::wstringstream atrstr;
				atrstr << L"0x" << std::hex << attrs;
				print_debug(L"FileExistsInProfile: File ", fileName, L" attributes = ", atrstr.str());
			}
			return (attrs != INVALID_FILE_ATTRIBUTES); //FILE_ATTRIBUTE_DIRECTORY
		}

		bool CreateProfileTemplate(const std::wstring& destProfilePath) {

			if (FileExistsInProfile(destProfilePath, L"NTUSER.DAT") && FileExistsInProfile(destProfilePath, L"NTUSER.DAT.LOG")) {
				if (debug) print_debug(L"Files NTUSER exist in profile");
				return true;
			} else {
				if (debug) print_debug(L"Files NTUSER not exist in profile ", destProfilePath);
			}

			wchar_t systemDrive[MAX_PATH] = {0};
			DWORD len = GetEnvironmentVariableW(L"SystemDrive", systemDrive, MAX_PATH);
			if (len == 0 || len >= MAX_PATH) {
				wcscpy_s(systemDrive, L"C:");
			}
			std::wstring defaultProfile = std::wstring(systemDrive) + L"\\Users\\Default";

			DWORD attr = GetFileAttributesW(defaultProfile.c_str());
			if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
				print_error(L"CreateProfileTemplate: Default profile folder does not exist");
				return false;
			}

			attr = GetFileAttributesW(destProfilePath.c_str());
			if (attr == INVALID_FILE_ATTRIBUTES) {
				if (!CreateDirectoryW(destProfilePath.c_str(), NULL)) {
					if (GetLastError() != ERROR_ALREADY_EXISTS) {
						print_error(L"CreateProfileTemplate: Failed to create destination directory");
						return false;
					}
				}
			}

			bool defregcopyed = false;
			std::wstring srcDat = defaultProfile + L"\\NTUSER.DAT";
			std::wstring dstDat = destProfilePath + L"\\NTUSER.DAT";
			std::wstring srcLog = defaultProfile + L"\\NTUSER.DAT.LOG";
			std::wstring dstLog = destProfilePath + L"\\NTUSER.DAT.LOG";
			if (CopyFileW(srcDat.c_str(), dstDat.c_str(), false)) {
				if (debug) print_debug(L"Copyed default reg NTUSER.DAT from ", defaultProfile, L" to ", destProfilePath);
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

			return true;
		}

		bool CreateProfileRegistryKey(const std::wstring& userSid, const std::wstring& profilePath) {

			HKEY hKey = NULL;
			std::wstring regPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + userSid;

			LONG res = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, NULL,
									  REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
			if (res != ERROR_SUCCESS) {
				print_error(L"CreateProfileRegistryKey: Failed to create/open registry key");
				return false;
			}

			res = RegSetValueExW(hKey, L"ProfileImagePath", 0, REG_EXPAND_SZ,
								(const BYTE*)profilePath.c_str(),
								(DWORD)((profilePath.length() + 1) * sizeof(wchar_t)));
			if (res != ERROR_SUCCESS) {
				print_error(L"CreateProfileRegistryKey: Failed to set ProfileImagePath");
				RegCloseKey(hKey);
				return false;
			}

			DWORD flags = 0;
			RegSetValueExW(hKey, L"Flags", 0, REG_DWORD, (const BYTE*)&flags, sizeof(flags));
			RegSetValueExW(hKey, L"State", 0, REG_DWORD, (const BYTE*)&flags, sizeof(flags));

			RegCloseKey(hKey);
			return true;

		}
	// PROFILE

	// NOTE: Fixed username intentionally — parallel execution not supported.
	// For concurrent runs, uncomment random suffix generation below:
	// username = userPrefix + GenerateRandomString(6);
	// And comment fixed
	// username = userPrefix + userPostfix;

	bool CreateAndInitializeAutoUser(std::wstring& outUsername, std::wstring& outPassword) {

		std::wstring username, password, profilePath;
		const std::wstring userPrefix = L"rah_tmp_";
		const std::wstring userPostfix = L"user"; //temporary
		const std::wstring profileRoot = std::wstring(_wgetenv(L"SystemRoot")) + L"\\Temp\\RAH\\";
		WCHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD dwSize = ARRAYSIZE(szComputerName);
		DWORD err;

		//username = userPrefix + GenerateRandomString(6); //temporary disabled
		username = userPrefix + userPostfix;
		GenerateRandomPassword(dwSize,password);

		if (debug) {
				std::wstring first3 = password.substr(0, 3);         
				std::wstring last3  = password.substr(password.length() - 3); 
				if (debug) print_debug(L"Temporary user: ", username, L", password: ", first3, L"*", last3);
				SecureClear(first3);
				SecureClear(last3);
		}

		if (!CreateDirectoryW(profileRoot.c_str(), NULL)) {
			err = GetLastError();
			if (err != ERROR_ALREADY_EXISTS) {
				//print_error((L"CreateAndInitializeAutoUser: Failed to create Temporary user profile root dir: " + profileRoot + L", error code: " + std::to_wstring(err)).c_str());
				print_error((L"CreateAndInitializeAutoUser: Failed to create Temporary user profile root dir: " + profileRoot).c_str());
				SecureClear(username);
				SecureClear(password);
				return false;
			} else if (err == ERROR_ALREADY_EXISTS) {
				if (debug) print_debug(L"Temporary user profile root dir already exists: ", profileRoot);
			}
		}

		profilePath = profileRoot + username;
		if (!CreateDirectoryW(profilePath.c_str(), NULL)) {
			err = GetLastError();
			if (err != ERROR_ALREADY_EXISTS) {
				print_error((L"CreateAndInitializeAutoUser: Failed to create Temporary user profile dir: " + profilePath).c_str());
				SecureClear(username);
				SecureClear(password);
				return false;
			} else if (err == ERROR_ALREADY_EXISTS) {
				if (debug) print_debug(L"Temporary user profile dir already exists: ", profilePath);
			}
		}
		
		if (debug) print_debug(L"Temporary user profile dir: ", profilePath);

		if (!CreateLocalUser(username, password, profilePath)) {
			print_error(L"CreateAndInitializeAutoUser: Failed to create local user");
			SecureClear(username);
			SecureClear(password);
			return false;
		}

		PSID pSid = nullptr;
		LPWSTR sidString = nullptr;
		std::wstring userSid;
		if (GetSIDFromUsername(username, &pSid)) {
			if (ConvertSidToStringSidW(pSid, &sidString)) {
				userSid = sidString;
				LocalFree(pSid);
				LocalFree(sidString);
				if (debug) print_debug(L"User SID: ", userSid);
			} else {
				print_error(L"CreateAndInitializeAutoUser: ConvertSidToStringSid failed");
				if (pSid) LocalFree(pSid);
				SecureClear(username);
				SecureClear(password);
				return false;
			}
		} else {
			print_error(L"CreateAndInitializeAutoUser: Failed to get SID for user");
			SecureClear(username);
			SecureClear(password);
			return false;
		}

		if (debug) print_debug(L"Preparing profile SID: ", userSid);

		if (!CreateProfileTemplate(profilePath)) {
			print_error(L"CreateAndInitializeAutoUser: Failed to create profile template");
			SecureClear(username);
			SecureClear(password);
			return false;
		}

		if (!CreateProfileRegistryKey(userSid, profilePath)) {
			print_error(L"CreateAndInitializeAutoUser: Failed to create profile registry key");
			SecureClear(username);
			SecureClear(password);
			return false;
		}		
	
		outUsername			= username;
		outPassword			= password;
		tempUserW			= username;
		tempUserSidW		= userSid;
		tempUserProfileW	= profilePath;
		tempUserCreated		= true;

		SecureClear(username);
		SecureClear(password);
		SecureClear(profilePath);
		//SecureClear(profileRoot); // const
		//SecureClear(userPrefix); // const
		//SecureClear(userPostfix); // const
		return true;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	bool DeleteUserAndProfileDebug(const std::wstring& usernameW, const std::wstring& userSidW, const std::wstring& profilePathW) {

		bool success = true;

		std::wcout << L"[TEST]: DeleteUserAndProfile\n";
		std::wcout << L"  > Username: " << usernameW << L"\n";
		std::wcout << L"  > SID     : " << userSidW << L"\n";
		std::wcout << L"  > Profile : " << profilePathW << L"\n";

		// User exist?
		LPUSER_INFO_0 pInfo = nullptr;
		if (NetUserGetInfo(NULL, usernameW.c_str(), 0, (LPBYTE*)&pInfo) == NERR_Success) {
			std::wcout << L"  > [OK] User exists.\n";
			NetApiBufferFree(pInfo);
		} else {
			std::wcerr << L"  > [WARNING] User not found.\n";
			success = false;
		}

		// Check profile
		DWORD attrib = GetFileAttributesW(profilePathW.c_str());
		if (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY)) {
			std::wcout << L"  > [OK] Profile directory exists.\n";
		} else {
			std::wcerr << L"  > [WARNING] Profile path missing or not a directory.\n";
			success = false;
		}

		// Check SID
		if (userSidW.find(L"S-1-5-") == 0) {
			std::wcout << L"  > [OK] SID appears valid.\n";
		} else {
			std::wcerr << L"  > [WARNING] SID may be invalid.\n";
			success = false;
		}

		return success;
	}

	// Template DeleteUserAndProfile - Under construction
	// exec: DeleteUserAndProfile(L"RAH_tmp_user", L"S-1-5-21-...-1001", L"C:\\Windows\\Temp\\RAH\\RAH_tmp_user");
	// exec: DeleteUserAndProfile(username, userSID, profilePath);

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

	bool DeleteUserAndProfile(const std::wstring& usernameW, const std::wstring& userSidW, const std::wstring& profilePathW) {
		bool success = true;

		if (debug) {
			DeleteUserAndProfileDebug(usernameW, userSidW, profilePathW);
		}

		if (usernameW.empty() || userSidW.empty()) {
			print_error(L"DeleteUserAndProfile: username or SID is empty");
			return false;
		}

		if (profilePathW.find(L"\\RAH\\") == std::wstring::npos) {
			print_error(L"Profile path is outside of expected RAH directory, aborting delete");
			return false;
		}

		if (!StartsWith(usernameW, L"RAH_")) {
			std::wcerr << L"[SECURITY]: Refusing to delete unknown account: " << usernameW << L"\n";
			return false;
		}

		// 1. Destroy environment
		if (g_envBlock) {
			DestroyEnvironmentBlock(g_envBlock);
			g_envBlock = NULL;
		}

		// 2. Unload profile
		if (g_profileLoaded) {
			UnloadUserProfile(g_hPrimaryToken, g_profileInfo.hProfile);
			g_profileLoaded = false;
		}

		// 3. Erase token
		if (g_hPrimaryToken) {
			SafeCloseHandle(g_hPrimaryToken);
			g_hPrimaryToken = NULL;
		}

		// 4. Delete user
		NET_API_STATUS status = NetUserDel(NULL, usernameW.c_str());
		if (status != NERR_Success && status != NERR_UserNotFound) {
			std::wstring msg = std::wstring(L"DeleteUserAndProfile: NetUserDel failed: ") + std::to_wstring(status);
			print_error(msg.c_str());
			success = false;
		} else if (status == NERR_Success){
			if (debug) print_debug(L"NetUserDel user: ", usernameW, L", result: Success");
		} else if (status == NERR_UserNotFound){
			if (debug) print_debug(L"NetUserDel user: ", usernameW, L" not found");
		}

		// 5. Delete from profilelist
		HKEY hKey = NULL;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
						  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
						  0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
			LONG regDelRes = RegDeleteTreeW(hKey, userSidW.c_str());
			if (regDelRes != ERROR_SUCCESS) {
				std::wstring msg = std::wstring(L"DeleteUserAndProfile: RegDeleteTreeW failed for SID: ") + userSidW;
				print_error(msg.c_str());
				success = false;
			} else {
				if (debug) print_debug(L"RegDeleteTreeW for SID: ", userSidW, L", result: ", regDelRes);
			}
			RegCloseKey(hKey);
		} else {
			print_error(L"DeleteUserAndProfile: RegOpenKeyExW Failed to open ProfileList key");
			success = false;
		}

		// 6. Delete profile directory
		if (!profilePathW.empty()) {
			if (!DeleteFileW((profilePathW + L"\\NTUSER.DAT").c_str())) {
				if (debug) print_warning(L"DeleteUserAndProfile: NTUSER.DAT could not be deleted (probably in use or not found)");
			}

			SHFILEOPSTRUCTW fileOp = {0};
			std::wstring fromPath = profilePathW + L'\0';
			fromPath.push_back(L'\0'); // double 0-term

			fileOp.wFunc = FO_DELETE;
			fileOp.pFrom = fromPath.c_str();
			fileOp.fFlags = FOF_NO_UI | FOF_SILENT | FOF_NOCONFIRMATION;

			DWORD shfres = SHFileOperationW(&fileOp);
			if (shfres != 0) {
				std::wstring msg = std::wstring(L"DeleteUserAndProfile: SHFileOperationW failed to delete profile dir: ") + profilePathW + std::wstring(L", code:") + std::to_wstring(shfres);
				print_error(msg.c_str());
				success = false;
			}
			if (debug) print_debug(L"SHFileOperationW delete profile dir: ", profilePathW, L", result: ", shfres); 
		} else {
			if (debug) print_debug(L"Profile dir empty: ", profilePathW); 
		}

		return success;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	bool EnableDebugPrivilege() {
		HANDLE hToken = NULL;
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
			print_error(L"EnableDebugPrivilege: OpenProcessToken failed");
			return false;
		}

		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
			print_error(L"EnableDebugPrivilege: LookupPrivilegeValue failed");
			SafeCloseHandle(hToken);
			return false;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL)) {
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

		if (!LookupPrivilegeValueW(NULL, privName, &luid)) {
			print_error(L"EnablePrivilege: LookupPrivilegeValue failed");
			SafeCloseHandle(hToken);
			return false;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL)) {
			print_error(L"EnablePrivilege: AdjustTokenPrivileges failed");
			SafeCloseHandle(hToken);
			return false;
		}

		SafeCloseHandle(hToken);
		return GetLastError() == ERROR_SUCCESS;
	}

	bool EnableThreadPrivilege(LPCWSTR privName) {
		HANDLE hToken = NULL;

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
		if (!LookupPrivilegeValueW(NULL, privName, &luid)) {
			print_error(L"EnableThreadPrivilege: LookupPrivilegeValue failed");
			SafeCloseHandle(hToken);
			return false;
		}

		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL)) {
			print_error(L"EnableThreadPrivilege: AdjustTokenPrivileges failed");
			SafeCloseHandle(hToken);
			return false;
		}

		DWORD err = GetLastError();
		SafeCloseHandle(hToken);

		if (err == ERROR_NOT_ALL_ASSIGNED) {
			std::wstring msg = std::wstring(L"EnableThreadPrivilege: The token does not have the privilege: ") + privName;
			print_error(msg.c_str());
			return false;
		}

		return true;
	}

	bool EnableTokenPrivilege(HANDLE hToken, LPCWSTR privilegeName) {
		TOKEN_PRIVILEGES tp;
		LUID luid;
		if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
			print_error(L"EnableTokenPrivilege: LookupPrivilegeValueW failed");
			return false;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		return AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL) &&
			   GetLastError() == ERROR_SUCCESS;
	}

	HANDLE GetSystemToken() {
		DWORD sessionId = WTSGetActiveConsoleSessionId(); // Current console gui session id
		if (debug) print_debug(L"Current Session ID: ", sessionId);

		EnablePrivilege(SE_DEBUG_NAME); //на всякий случай

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap == INVALID_HANDLE_VALUE) {
			print_error(L"GetSystemToken: CreateToolhelp32Snapshot failed");
			return NULL;
		}

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(pe);
		HANDLE hWinlogonToken = NULL;

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

					HANDLE hToken = NULL;
					if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
						SafeCloseHandle(hProc);
						print_error(L"GetSystemToken: Cannot open token of winlogon.exe");
						continue;
					}

					if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hWinlogonToken)) {
						print_error(L"GetSystemToken: DuplicateTokenEx failed");
						hWinlogonToken = NULL;
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

	void PrintTokenInformation(HANDLE sToken) {

		if (!sToken || sToken == INVALID_HANDLE_VALUE) {
			print_error(L"PrintTokenInformation: Invalid token handle");
			return;
		}

		if (debug) print_debug(L"PrintTokenInformation, token: ", sToken);

		DWORD dwSize = 0;
		if (!GetTokenInformation(sToken, TokenUser, nullptr, 0, &dwSize) &&
			GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
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
		GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			print_error(L"PrintTokenPrivileges: GetTokenInformation [TokenUser] buffer size failed");
		} else {
			BYTE* buffer = new BYTE[size];
			TOKEN_USER* tokenUser = (TOKEN_USER*)buffer;

			if (GetTokenInformation(hToken, TokenUser, tokenUser, size, &size)) {
				LPWSTR stringSid = NULL;
				if (ConvertSidToStringSidW(tokenUser->User.Sid, &stringSid)) {
					if (debug) print_debug(L"SID: ", stringSid);
					LocalFree(stringSid);
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
		GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &len);
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
			LookupPrivilegeNameW(NULL, &luid, NULL, &nameLen);
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				print_error(L"PrintTokenPrivileges: LookupPrivilegeNameW failed to get size");
				continue;
			}

			nameLen++; // for finishing \0
			std::wstring name(nameLen, L'\0');

			if (LookupPrivilegeNameW(NULL, &luid, &name[0], &nameLen)) {
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

	std::wstring GetCurrentUserSamCompatible() {
		DWORD size = 0;
		GetUserNameExW(NameSamCompatible, NULL, &size);
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
		if (DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE*)&pInfo) == ERROR_SUCCESS) {
			bool isDC = (pInfo->MachineRole == DsRole_RolePrimaryDomainController ||
						 pInfo->MachineRole == DsRole_RoleBackupDomainController);
			DsRoleFreeMemory(pInfo);
			return isDC;
		}
		return false;
	}

	bool IsRunningAsAdmin() {
		BOOL imisAdmin = false;
		HANDLE token = NULL;

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
		HANDLE token = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}

		DWORD size = 0;
		GetTokenInformation(token, TokenUser, NULL, 0, &size);
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
		PSID systemSid = NULL;
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
		LPWSTR winStationName = NULL;
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

	//Not used
	bool AddLogonRight(const wchar_t* username, const wchar_t* rightName) {
		LSA_HANDLE policyHandle = nullptr;
		LSA_OBJECT_ATTRIBUTES objectAttributes = {};
		NTSTATUS status = LsaOpenPolicy(nullptr, &objectAttributes,
										POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT,
										&policyHandle);
		if (status != 0) {
			print_error(L"AddLogonRight: LsaOpenPolicy failed");
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
			print_error(L"AddLogonRight: LookupAccountNameW: Failed to lookup account SID");
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
			print_error(L"AddLogonRight: LsaAddAccountRights failed");
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
	//Not used

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

	//SESSION (visible mode)
	DWORD GetSessionIdByUserName(const std::wstring& userOnly, const std::wstring& domain) {
		DWORD sessionCount = 0;
		WTS_SESSION_INFO* pSessionInfo = nullptr;

		// . -> ComputerName
		std::wstring targetUserName;
		if (domain == L"." || domain.empty()) {
			WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
			DWORD size = ARRAYSIZE(computerName);
			if (GetComputerNameW(computerName, &size)) {
				targetUserName = std::wstring(computerName) + L"\\" + userOnly;
			} else {
				print_error(L"GetSessionIdByUserName: GetComputerNameW failed");
				return 0xFFFFFFFF;
			}
		} else {
			targetUserName = domain + L"\\" + userOnly;
		}

		if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount)) {
			if (debug) print_debug(L"No sessions found");
			return 0xFFFFFFFF;
		}

		for (DWORD i = 0; i < sessionCount; ++i) {
			DWORD sessionId = pSessionInfo[i].SessionId;

			LPWSTR pUserName = nullptr;
			DWORD userNameLen = 0;
			if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &pUserName, &userNameLen) || !pUserName || !*pUserName) {
				if (pUserName) WTSFreeMemory(pUserName);
				continue;
			}

			LPWSTR pDomainName = nullptr;
			DWORD domainNameLen = 0;
			if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSDomainName, &pDomainName, &domainNameLen) || !pDomainName || !*pDomainName) {
				WTSFreeMemory(pUserName);
				if (pDomainName) WTSFreeMemory(pDomainName);
				continue;
			}

			std::wstring candidate = std::wstring(pDomainName) + L"\\" + std::wstring(pUserName);

			std::wstring stateStr;
			switch (pSessionInfo[i].State) {
				case WTSActive: stateStr = L"Active"; break;
				case WTSConnected: stateStr = L"Connected"; break;
				case WTSDisconnected: stateStr = L"Disconnected"; break;
				default: stateStr = L"Other"; break;
			}

			if (debug) print_debug(L"Session ", sessionId, L" [", stateStr, L"]: ", candidate);

			if (_wcsicmp(candidate.c_str(), targetUserName.c_str()) == 0 ||
				_wcsicmp(pUserName, userOnly.c_str()) == 0) // fallback
			{
				WTSFreeMemory(pUserName);
				WTSFreeMemory(pDomainName);
				WTSFreeMemory(pSessionInfo);
				return sessionId;
			}

			WTSFreeMemory(pUserName);
			WTSFreeMemory(pDomainName);
		}

		WTSFreeMemory(pSessionInfo);
		return 0xFFFFFFFF;
	}

	//=================================================================================================================================================================//
	//=================================================================================================================================================================//

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

		WCHAR windowsDir[MAX_PATH];
		if (!GetWindowsDirectoryW(windowsDir, MAX_PATH)) {
			wcscpy(windowsDir, L"C:\\Windows");
		}

		DWORD userSessionId = 0xFFFFFFFF;
		std::wstring fullUserName = domain + L"\\" + userOnly;
		userSessionId = GetSessionIdByUserName(userOnly,domain);
		if (userSessionId == 0xFFFFFFFF) {
			std::wstring msg = std::wstring(L"RunAsInteractive: Unable to get session ID for user ") + fullUserName;
			print_error(msg.c_str());
			return false;
		}

		if (!IsUserInteractiveSession(userSessionId)) {
			std::wstring msg = std::wstring(L"RunAsInteractive: User ") + fullUserName + L" session " + std::to_wstring(userSessionId) + L" is not interactive";
			if (debug) print_warning(msg.c_str());
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

		if (isSystem) {

			HANDLE hUserToken = NULL;

			if (!WTSQueryUserToken(userSessionId, &hUserToken)) {
				std::wstring msg = std::wstring(L"RunAsInteractive: WTSQueryUserToken failed for session ") + std::to_wstring(userSessionId);
				print_error(msg.c_str());
				SafeCloseHandle(hUserToken);
				return false;
			}

			if (debug) print_debug(L"RunAsInteractive [SYSTEM]: CreateProcessAsUserW: User: ", fullUserName, L", Session ID: ", userSessionId);

			LPVOID lpEnvironment = NULL;

			if (!CreateEnvironmentBlock(&lpEnvironment, hUserToken, true)) {
				print_error(L"RunAsInteractive: CreateEnvironmentBlock failed");
				lpEnvironment = NULL; // fallback to NULL
			}

			created = CreateProcessAsUserW(
				hUserToken,
				NULL,
				cmdLine,
				NULL,
				NULL,
				false,
				creationFlags | CREATE_UNICODE_ENVIRONMENT,
				lpEnvironment,
				windowsDir,
				&si,
				&pi
			);

			if (!created) {
				print_error(L"RunAsInteractive: CreateProcessAsUserW failed");
			} else {
				procPid = pi.dwProcessId;
				if (debug) {
					print_debug(L"RunAsInteractive: CreateProcessAsUserW Success. Pid: ", procPid);
				}
			}

			if (lpEnvironment) {
				if (debug) print_debug(L"RunAsInteractive [SYSTEM]: DestroyEnvironmentBlock(lpEnvironment)");
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
				NULL,
				cmdLine,
				creationFlags | CREATE_UNICODE_ENVIRONMENT,
				NULL,
				windowsDir,
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

	// FOR HIDDEN RUN FROM SYSTEM V1 - STANDARD with login

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
		bool profileloaded = false;

		if (debug) print_debug(L"RunUnderSystem:");

		// Если сессия СУЩЕСТВУЕТ и запуск из под системы - для запуска программы в фоне НЕ НУЖЕН ПАРОЛЬ, ЛОГИН, ЗАГРУЗКА ПРОФИЛЯ...
			DWORD userSessionId = 0xFFFFFFFF;
			std::wstring fullUserName = domain + L"\\" + userOnly;
			userSessionId = GetSessionIdByUserName(userOnly,domain);
			if (userSessionId != 0xFFFFFFFF) {
				// Сессия существует — получаем токен пользователя
				if (!WTSQueryUserToken(userSessionId, &hPrimaryToken)) {
					if (debug) print_debug(L"RunUnderSystem: WTSQueryUserToken failed, fallback to LogonUserW");
				} else {
					if (debug) print_debug(L"RunUnderSystem: Obtained token from existing session ", userSessionId);
				}
			}
		//

		if (!hPrimaryToken) { // USER IS NOT LOGGED IN
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
				if (debug) {
					std::wstring msg = std::wstring(L"RunUnderSystem: EnableTokenPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) failed for target user ") + userOnly;
					print_warning(msg.c_str());
				}
			}
			if (!EnableTokenPrivilege(hPrimaryToken, SE_INCREASE_QUOTA_NAME)) {
				if (debug) {
					std::wstring msg = std::wstring(L"RunUnderSystem: EnableTokenPrivilege(SE_INCREASE_QUOTA_NAME) failed for user ") + userOnly;
					print_warning(msg.c_str());
				}
			}
			if (!EnableTokenPrivilege(hPrimaryToken, SE_TCB_NAME)) {
				if (debug) {
					std::wstring msg = std::wstring(L"RunUnderSystem: EnableTokenPrivilege(SE_TCB_NAME) failed for target user ") + userOnly;
					print_warning(msg.c_str());
				}
			}
			if (debug) {
				print_str(L"------------------------------------------");
				PrintTokenPrivileges(hToken,userOnly.c_str());
				print_str(L"------------------------------------------");
			}

			up.dwSize = sizeof(PROFILEINFO);
			up.lpUserName = const_cast<LPWSTR>(userOnly.c_str());
			if (!LoadUserProfileW(hPrimaryToken, &up)) {
				DWORD perr = GetLastError();
				if (perr == ERROR_USER_PROFILE_ALREADY_LOADED) {
					if (debug) {
						std::wstring msg = std::wstring(L"RunUnderSystem: Profile already loaded or user: ") + userOnly;
						print_warning(msg.c_str());
					}
				} 
				else if (perr == 299 /* ERROR_PARTIAL_COPY */) {
					if (debug) {
						std::wstring msg = std::wstring(L"RunUnderSystem: Profile not loaded for user: ") + userOnly;
						print_warning(msg.c_str());
					}
					return false;
				} else {
					std::wstring msg = std::wstring(L"RunUnderSystem: LoadUserProfile failed for user: ") + userOnly;
					print_warning(msg.c_str());
					SafeCloseHandle(hPrimaryToken);
					SafeCloseHandle(hToken);
					return false;
				}
			} else {
				profileloaded = true;
			}

			if (!CreateEnvironmentBlock(&envBlock, hPrimaryToken, true)) {
				print_error(L"RunUnderSystem: CreateEnvironmentBlock failed");
				if (profileloaded) UnloadUserProfile(hPrimaryToken, up.hProfile);
				SafeCloseHandle(hPrimaryToken);
				SafeCloseHandle(hToken);
				return false;
			}
		}

		WCHAR windowsDir[MAX_PATH];
		if (!GetWindowsDirectoryW(windowsDir, MAX_PATH)) {
			wcscpy(windowsDir, L"C:\\Windows");
		}

		if (debug) {
			print_debug(L"RunUnderSystem: CreateProcess Parameters");
			std::wcout << L"    runFromGPO flag: " << runFromGPO << L"\n";
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
			NULL,
			cmdLine,
			NULL,
			NULL,
			true,
			creationFlags | CREATE_UNICODE_ENVIRONMENT,
			envBlock,
			windowsDir,
			&si,
			&pi
		);

		if (!created) {
			print_error(L"RunUnderSystem: CreateProcessAsUserW failed");
			DestroyEnvironmentBlock(envBlock);
			if (profileloaded) UnloadUserProfile(hPrimaryToken, up.hProfile);
			SafeCloseHandle(hPrimaryToken);
			SafeCloseHandle(hToken);
			return false;
		} else {
			procPid = pi.dwProcessId;
			if (debug) print_debug(L"RunUnderSystem: CreateProcessAsUserW Success. Pid: ", procPid);
		}

		g_hPrimaryToken = hPrimaryToken;
		g_envBlock = envBlock;
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
			procPid = pi.dwProcessId;
			if (debug) {
				print_debug(L"RunUnderUser: CreateProcessWithLogonW Success. Pid: ", procPid);
				HANDLE hProcessToken = NULL;
				if (OpenProcessToken(pi.hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hProcessToken)) {
					print_str(L"------------------------------------------");
					PrintTokenPrivileges(hProcessToken,userOnly.c_str());
					print_str(L"------------------------------------------");
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
		HANDLE hToken = NULL;
		HANDLE hPrimaryToken = NULL;
		LPVOID envBlock = NULL;

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
				NULL,
				SecurityImpersonation,
				TokenPrimary,
				&hPrimaryToken)) {
			print_error(L"RunUnderCurrentUser: DuplicateTokenEx failed");
			SafeCloseHandle(hToken);
			return false;
		}

		if (!CreateEnvironmentBlock(&envBlock, hPrimaryToken, true)) {
			print_error(L"RunUnderCurrentUser: CreateEnvironmentBlock failed");
			envBlock = NULL; // fallback
		}

		WCHAR windowsDir[MAX_PATH];
		GetWindowsDirectoryW(windowsDir, MAX_PATH);

		BOOL created = CreateProcessAsUserW(
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

	BOOL WINAPI CtrlHandlerV1(DWORD ctrlType) {
		if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
			if (g_pi.hProcess != NULL) {
				if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, g_pi.dwProcessId)) {
					print_error(L"GenerateConsoleCtrlEvent failed");
				}
				Sleep(1000);
				DWORD exitCode = 0;
				if (GetExitCodeProcess(g_pi.hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
					std::wcout << L"[INFO]: Child process still active, terminating forcibly...\n";
					std::wcout.flush();
					TerminateProcess(g_pi.hProcess, 1);
				}
			}
			return true;
		}
		return false; // return false for other signals to allow default handling
	}

	BOOL WINAPI CtrlHandler(DWORD ctrlType) {
		if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
			if (g_pi.hProcess != NULL) {
				if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, g_pi.dwProcessId)) {
					print_error(L"GenerateConsoleCtrlEvent failed");
				}
				DWORD wait = WaitForSingleObject(g_pi.hProcess, 5000);
				if (wait == WAIT_TIMEOUT) {
					std::wcout << L"[INFO]: Child process still active, terminating forcibly...\n";
					std::wcout.flush();
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
						//std::wcout.flush();

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

	int wmain(int argc, wchar_t* argv[]) {

		if (argc < 3) {
			print_help();
			return 2;
		}

		if (!IsRunningAsSystem() && !IsRunningAsAdmin()) {
			print_error(L"Must be run as administrator or SYSTEM. Terminating.");
			return 3;
		}

		if (IsRunningAsSystem()) isSystem = true;

		std::wstring username, userOnly, password, domain, tempusername, temppassword, commandPath, command, cmdparams, timeoutS;
		int timeoutMs = 0;
		debug = false; // GLOBAL
		bool readPipe = true;
		bool verb = false;
		bool visible = false;
		bool nowait = false;
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
				print_help();
				goto exitmain;
			}

			if (arg == L"-query-procs" || arg == L"--query-procs") {
				queryUserProcs = true;
				has_command = true;
				break;
			}

			if (arg == L"-silent" || arg == L"--silent" || arg == L"-s") {
				silent = true;
				continue;
			}

			if (arg == L"-debug" || arg == L"--debug") {
				debug = true;
				continue;
			}

			if (arg == L"-nowait" || arg == L"--nowait" || arg == L"-n") {
				nowait = true;
				continue;
			}

			if (arg == L"-verb" || arg == L"--verb" || arg == L"-verbose" || arg == L"--verbose") {
				verb = true;
				continue;
			}

			if (arg == L"-no-output" || arg == L"--no-output") {
				readPipe = false;
				continue;
			}

			if (arg == L"-gpo" || arg == L"--gpo") {
				runFromGPO = true;
				continue;
			}

			// timeout
			if (arg == L"-t" || arg == L"-timeout" || arg == L"--timeout" ||
				starts_with(arg, L"-t=") || starts_with(arg, L"-timeout=") || starts_with(arg, L"--timeout=")) {
				if (!extract_value(arg, i, timeoutS)) {
					print_error(arg, L" requires a value");
					SetLastError(2);
					exitCode = 2;
					goto exitmain;
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
				keepTempUser = true;
				continue;
			}

			// username
			if (arg == L"-u" || arg == L"--username" || arg == L"-username" ||
				starts_with(arg, L"-u=") || starts_with(arg, L"--username=") || starts_with(arg, L"-username=")) {
				if (!extract_value(arg, i, username)) {
					print_error(arg, L" requires a value");
					SetLastError(2);
					exitCode = 2;
					goto exitmain;
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
					goto exitmain;
				}
				continue;
			}

			// command
			if (arg == L"-c" || arg == L"--command" ||
				starts_with(arg, L"-c=") || starts_with(arg, L"--command=")) {

				if (!extract_value_raw(arg, i, command)) {  // trim quotes
					print_error(arg, L" requires a command string");
					exitCode = 2;
					goto exitmain;
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
					goto exitmain;
				}
				continue;
			}

			print_error(L"Unknown or unexpected argument");
			print_help();
			SetLastError(1);
			exitCode = 2;
			goto exitmain;
		}

		if (debug) {
			print_str(std::wstring(L"RunAsHidden Version: ") + GetFileVersion());
			print_str(L"------------------------------------------");
		}

		if (!has_command) {
			print_error(L"Missing required parameters");
			print_help();
			SetLastError(1);
			exitCode = 2;
			goto exitmain;
		}

		if (debug) {
			print_debug(L"User: ", username);
			print_debug(L"Pass: ***"); // pass not printing
			print_debug(L"Command: ", command);
			print_debug(L"Params: ", cmdparams);
			print_debug(L"Direct run: ", direct);
			print_debug(L"Is cmd script: ", IsCmdScript(command));
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
			std::wcout.flush();
		}

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
		
		if ( userOnly == L"auto" || userOnly == L"*" ) {
			if ( password == L"auto" || password == L"*" ) {
				autouser = true;
			}
		}

		if (IsDomainController()) {
			if (autouser || visible) {
				print_error(L"RunAsHidden must not be run on a domain controller in this mode. Terminating.");
				SetLastError(2);
				exitCode = 2;
				goto exitmain;
			}
		}

		if (autouser && visible) {
			print_error(L"RunAsHidden must not be run in this mode. Terminating.");
			SetLastError(2);
			exitCode = 2;
			goto exitmain;
		}

		if (!timeoutS.empty()) {
			try {
				int t = std::stoi(timeoutS);
				timeoutMs = static_cast<DWORD>(std::max(0, t)) * 1000;
			}
			catch (const std::exception& e) {
				print_error(L"Incorrect timeout param: ", timeoutS, L", will be reset to 0");
				timeoutMs = 0;
			}
			if (timeoutMs > 60000) {
				print_error(L"Incorrect timeout: ", timeoutS, L", will be reset to 0");
				timeoutMs = 0;
			}
		}

		// get user procs
			if (queryUserProcs) {
				PSID pSid = nullptr;
				if (GetSIDFromUsername(username, &pSid)) {
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
					std::wcout.flush();

					LocalFree(pSid);
				} else {
					print_error(L"Error GET SID for user.");
				}
				exitCode = 0;
				goto exitmain;
			}
		// get user procs end

		//Under Construction
		srand((unsigned int)time(NULL));
		if (autouser) {
			if (debug) print_debug(L"Auto user mode");
			if (!CreateAndInitializeAutoUser(username, password)) {
				print_error(L"Automatic create user failed");
				exitCode = 1;
				goto exitmain;
			} else {
				userOnly = username;
				if (debug) print_debug(L"Using automatically created temporary user: ", userOnly, L" [", username, L"] with tremporary password");
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
			if (nowait) {
				print_debug(L"NoWait");
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
						if (debug) print_error(L"ImpersonateLoggedOnUser failed");
						SafeCloseHandle(hSystemToken);
					}
				} else {
					if (debug) print_error(L"Failed to get SYSTEM token");
				}
			} else {
				if (debug) print_error(L"Failed to enable SeDebugPrivilege");
			}
		} else {
			if (!EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME)) {
				if (debug) print_error(L"EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) failed");
			}
			if (!EnablePrivilege(SE_TCB_NAME)) {
				if (debug) print_error(L"EnablePrivilege(SE_TCB_NAME) failed");
			}
		}

		//Temporary break
		//goto exitmain;

		if (isSystem) {
			if (debug) print_debug(L"[Call EnableThreadPrivilege]");
			if (!EnableThreadPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME)) {
				if (debug) print_error(L"EnableThreadPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) failed");
			}
			if (!EnableThreadPrivilege(SE_INCREASE_QUOTA_NAME)) {
				if (debug) print_error(L"EnableThreadPrivilege(SE_INCREASE_QUOTA_NAME) failed");
			}
			if (!EnableThreadPrivilege(SE_TCB_NAME)) {
				if (debug) print_error(L"EnableThreadPrivilege(SE_TCB_NAME) failed");
			}
		}

		if (debug) {
			HANDLE hToken = NULL;
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

			if (isImpersonated) {
				HANDLE hThreadToken = NULL;
				if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, &hThreadToken)) {
					print_str(L"------------------------------------------");
					print_debug(L"Current Tread token privileges:");
					PrintTokenPrivileges(hThreadToken, L"CurrentThread");
					SafeCloseHandle(hThreadToken);
					print_str(L"------------------------------------------");
				} else {
					print_error(L"OpenThreadToken failed for PrintTokenPrivileges");
				}
			}

		}

		if (direct && IsCmdScript(command)) {
			print_error(L"Direct mode is not allowed for .cmd/.bat");
			SetLastError(ERROR_INVALID_PARAMETER);
			exitCode = 2;
			goto exitmain;
		}

		if (direct) {
			// direct run
			cmdLine = command;
			if (!cmdparams.empty())
				cmdLine += L" " + cmdparams;
		} else {
			// cmd.exe /c
			cmdLine = L"cmd.exe /c \"" + command;
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

		sa = { sizeof(SECURITY_ATTRIBUTES), NULL, true };

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

		// Ctrl+C - а надо ли это вообще? ну пусть будет
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

		if (nowait) {
			if (debug) print_debug(L"process started successfully [nowait mode], exiting");
			SafeCloseHandle(hRead);
			SafeCloseHandle(g_pi.hProcess);
			SafeCloseHandle(g_pi.hThread);
			exitCode = 0;
			goto exitmain;
		}

		// Read output from process via pipe
		if (readPipe) {
			if (debug) {
				print_str(L"\nCOMMAND RESULTS:\n");
			}
			while (true) {
				BOOL success = ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
				if (!success || bytesRead == 0) break;
				std::string current(buffer, bytesRead);
				if (current != prev) {
					std::cout.write(current.c_str(), current.size());
					std::cout.flush();
					prev = current;
				}
			}
			if (debug) {
				print_str(L"\nCOMMAND RESULTS END.\n");
			}
		}
		SafeCloseHandle(hRead);
	 
		WaitForSingleObject(g_pi.hProcess, INFINITE);

		GetExitCodeProcess(g_pi.hProcess, &exitCode);

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

				if (!nowait) {
					if (autouser) {
						if (!keepTempUser) {
							if (tempUserCreated) {
								std::wcout << L"\n";
								if (timeoutMs <= 0) Sleep(2500);
								DeleteUserAndProfile(tempUserW, tempUserSidW, tempUserProfileW);
								SecureClear(tempUserW);
								SecureClear(tempUserSidW);
								SecureClear(tempUserProfileW);
							}
						} else {
							std::wcout << L"\n";
							if (debug) print_debug(L"Temporary user preserved as requested");
						}
					}
				}
			ClearSensitiveData(username, userOnly, domain, password, tempusername, temppassword, cmdLine, command, cmdLineBuf);
			if (debug) print_debug("Process exited with code ", exitCode);
			return static_cast<int>(exitCode);
	}

