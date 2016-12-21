// Injecter.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include <Dbghelp.h>
#include <shlwapi.h>

#pragma comment(lib, "Dbghelp.lib")

#define  x86FILE		1
#define  x64FILE		2
#define  x86PS			3
#define  x64PS			4
#define  x86OS			5
#define  x64OS			6

// 判断文件是否存在，存在则返回TRUE，否则返回FALSE
// 
BOOL WINAPI IsFileExist(PWCHAR pfile)
{
	HANDLE hfile;
	BOOL bIsFileExist = TRUE;
	hfile = CreateFileW(pfile, FILE_ALL_ACCESS, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hfile)
	{
		if (ERROR_FILE_NOT_FOUND == GetLastError())
		{
			bIsFileExist = FALSE;
		}
	}
	else
	{
		CloseHandle(hfile);
	}
	return bIsFileExist;
}

// 根据进程名获取进程ID
//
DWORD WINAPI GetProcessIDbyName(PWCHAR pName)
{
	DWORD dwPID = 0;
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 stPE;

	__try
	{
		// 进程名转化为unicode

		ZeroMemory(&stPE, sizeof(PROCESSENTRY32));
		stPE.dwSize = sizeof(PROCESSENTRY32);

		// 找到对应进程
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (INVALID_HANDLE_VALUE == hSnapshot)
		{
			printf("[GetProcessIDbyName]获取进程快照失败！\n");
			__leave;
		}

		if (Process32FirstW(hSnapshot, &stPE))
		{
			do 
			{
				if (lstrcmpiW(stPE.szExeFile, pName) == 0)
				{
					dwPID = stPE.th32ProcessID;
					break;
				}
			} while (Process32NextW(hSnapshot, &stPE));
		}
		else
		{
			printf("[GetProcessIDbyName]Process32FirstW failed, error code = %d\n", GetLastError());
		}
	}

	__finally
	{
		if (hSnapshot)
		{
			CloseHandle(hSnapshot);
			hSnapshot = NULL;
		}
	}

	return dwPID;
}

// 32位dll注入32位进程
//
BOOL WINAPI Inject32Dll_32Process(__in  DWORD dwProcessId, __in PWCHAR pDllpath)
{
	BOOL bOk = FALSE; // Assume that the function fails
	HANDLE hProcess = NULL, hThread = NULL;
	PVOID pszLibFileRemote = NULL;

	__try 
	{
		// Get a handle for the target process.
		hProcess = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE, FALSE, dwProcessId);
		if (hProcess == NULL) 
		{
			printf("[Inject32Dll_32Process]打开进程失败...错误码：%d\n", GetLastError());
			__leave;
		}

		// Calculate the number of bytes needed for the DLL's pathname
		int cch = 1 + lstrlenW(pDllpath);
		int cb  = cch * sizeof(WCHAR);

		// Allocate space in the remote process for the pathname
		pszLibFileRemote = (PVOID) VirtualAllocEx(hProcess, NULL, cb+2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pszLibFileRemote == NULL) 
		{
			printf("[Inject32Dll_32Process]申请内存失败...错误码：%d\n", GetLastError());
			__leave;
		}

		// Copy the DLL's pathname to the remote process' address space
		if (!WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID) pDllpath, cb, NULL)) 
		{
			printf("[Inject32Dll_32Process]写目标进程内存失败...错误码：%d\n", GetLastError());
			__leave;
		}

		// Get the real address of LoadLibraryW in Kernel32.dll
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"Kernel32"), "LoadLibraryW");
		if (pfnThreadRtn == NULL) 
		{
			printf("[Inject32Dll_32Process]获取LoadLibraryW地址失败...错误码：%d\n", GetLastError());
			__leave;
		}

		// Create a remote thread that calls LoadLibraryW(DLLPathname)
		hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
		if (hThread == NULL)
		{
			printf("[Inject32Dll_32Process]创建远程线程失败...错误码：%d\n", GetLastError());
			__leave;
		}
		// 等待远线程结束  
		WaitForSingleObject(hThread, INFINITE);  
		// 取DLL在目标进程的句柄  
		DWORD remoteModule;  
		GetExitCodeThread(hThread, &remoteModule);  

		bOk = TRUE; // Everything executed successfully
	}

	__finally 
	{ 
		// Free the remote memory that contained the DLL's pathname
		if (pszLibFileRemote != NULL)
			VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_DECOMMIT);

		if (hThread  != NULL) 
			CloseHandle(hThread);

		if (hProcess != NULL) 
			CloseHandle(hProcess);
	}

	return(bOk);
}

// 判断文件是32位还是64位
// 
DWORD WINAPI CheckPEFileMachine(PWCHAR pFileName)
{
	DWORD dwRet = 0;
	HANDLE hPEFileMap = 0;
	LPVOID pFileMap = 0;
	PIMAGE_NT_HEADERS stNTheader;
	HANDLE hPEfile = 0;

	__try
	{
		// 检查参数
		if (pFileName == 0					||
			lstrlenW(pFileName) == 0		||
			IsFileExist(pFileName) == FALSE	)
		{
			printf("[CheckFileMachine]参数错误...\n");
			__leave;
		}

		// 打开文件 
		hPEfile = CreateFileW(pFileName, FILE_ALL_ACCESS, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hPEfile)
		{
			printf("[CheckFileMachine]打开文件失败...错误码：%d\n", GetLastError());
			__leave;
		}

		// 创建文件映射
		hPEFileMap = CreateFileMappingW(hPEfile, NULL, PAGE_READWRITE, 0, 0, 0);
		if (NULL == hPEFileMap)
		{
			printf("[CheckFileMachine]创建文件映射失败...错误码：%d\n", GetLastError());
			__leave;
		}

		// 映射文件
		pFileMap = MapViewOfFile(hPEFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (NULL == pFileMap)
		{
			printf("[CheckFileMachine]映射文件失败...错误码：%d\n", GetLastError());
			__leave;
		}

		// 获取PE文件NT_HEADER
		stNTheader = ImageNtHeader(pFileMap);

		// 判断Machine位以确定是x86文件还是x64文件
		switch (stNTheader->FileHeader.Machine)
		{
		case IMAGE_FILE_MACHINE_I386:
			dwRet = x86FILE;
			__leave;

		case IMAGE_FILE_MACHINE_AMD64:
			dwRet = x64FILE;

		default:
			__leave;
		}
	}
	__finally
	{
		if (hPEfile)
		{
			CloseHandle(hPEfile);
			hPEfile = NULL;
		}

		if (hPEFileMap)
		{
			CloseHandle(hPEFileMap);
			hPEFileMap = NULL;
		}
	}

	return (dwRet);
}

// 判断系统是x86还是x64
//
DWORD WINAPI CheckOS()
{
	DWORD dwOSType = 0;
	SYSTEM_INFO si;
	typedef VOID(__stdcall*GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

	GETNATIVESYSTEMINFO fnGetNativeSystemInfo;
	fnGetNativeSystemInfo = (GETNATIVESYSTEMINFO)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
	if (fnGetNativeSystemInfo != NULL)
	{
		fnGetNativeSystemInfo(&si);

		if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
			si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)

		{
			dwOSType = x64OS;
		}
		else
		{
			dwOSType = x86OS;
		}
	}

	return dwOSType;
}

// 判断进程是x86还是x64，函数失败的话返回0
//
DWORD WINAPI CheckPS(PWCHAR pPsName)
{
	DWORD dwRet = 0;
	DWORD PID = 0;
	HANDLE hProcess = 0;

	typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	BOOL bIsWow64 = FALSE;
	BOOL bRet;
	DWORD nError;

	__try
	{
		// 获取进程句柄
		PID = GetProcessIDbyName(pPsName);
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

		// 获取IsWow64Process地址
		fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
		if (NULL != fnIsWow64Process)
		{
			bRet = fnIsWow64Process(hProcess, &bIsWow64);
			if (bRet == 0)
			{
				nError = GetLastError();
				__leave;
			}
			else
			{
				if (CheckOS() == x64OS)
				{
					// x64系统下判断bIsWow64
					if (bIsWow64)
					{
						dwRet = x86PS;
					}
					else
					{
						dwRet = x64PS;
					}
				}
				else
				{
					// x86系统肯定是32位进程
					dwRet = x86PS;
				}
			}
		}
	}
	__finally
	{
		CloseHandle(hProcess);
		hProcess = 0;
	}

	return (dwRet);
}

//提权  
//
int EnablePrivilege(bool isStart)  
{          
	//1. 得到令牌句柄  
	HANDLE  hToken = NULL;      //令牌句柄    
	if (!OpenProcessToken( GetCurrentProcess(),   
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ,   
		&hToken))  
	{     
		return FALSE;  
	}  

	//2. 得到特权值  
	LUID    luid = {0};         //特权值  
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))  
	{  
		return FALSE;  
	}  
	//3. 提升令牌句柄权限  
	TOKEN_PRIVILEGES tp = {0};  //令牌新权限  
	tp.PrivilegeCount = 1;   
	tp.Privileges[0].Luid = luid;  
	tp.Privileges[0].Attributes = isStart ? SE_PRIVILEGE_ENABLED : 0;  
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL))  
	{  
		return FALSE;  
	}  
	//4. 关闭令牌句柄  
	CloseHandle(hToken);  
	return 0;  
}  

int _tmain(int argc, _TCHAR* argv[])
{
	WCHAR wzDstProcess[MAX_PATH];
	WCHAR wzDll[MAX_PATH];
	DWORD dwProcessID = 0;
	DWORD dwDllBit = 0;
	DWORD dwProcBit = 0;

	__try
	{
		// 判断参数个数
		if (argc != 3)
		{
			printf("[_tmain]参数个数错误...\n");
			__leave;
		}
		lstrcpyW(wzDstProcess, argv[1]);
		lstrcpyW(wzDll, argv[2]);
		
		// 判断dll是否存在
		if (FALSE == IsFileExist(wzDll))
		{
			printf("[_tmain]%s文件不存在...\n", wzDll);
			__leave;
		}

		// 获取进程PID
		dwProcessID = GetProcessIDbyName(wzDstProcess);
		if (dwProcessID == 0)
		{
			printf("[_tmain]获取进程ID失败...\n");
			__leave;
		}

		// 判断dll是32位还是64位
		dwDllBit = CheckPEFileMachine(wzDll);
		if (dwDllBit == 0)
		{
			printf("[_tmain]检查PE文件位数失败...\n");
			__leave;
		}

		// 判断进程是32位还是64位
		dwProcBit = CheckPS(wzDstProcess);
		if (dwProcBit == 0)
		{
			printf("[_tmain]检查进程位数失败...\n");
			__leave;
		}

		switch (dwDllBit)
		{
		case x86FILE:
			{
				switch (dwProcBit)
				{
				case x86PS:
					EnablePrivilege(TRUE);
					if (Inject32Dll_32Process(dwProcessID, wzDll) == 0)
					{
						printf("[_tmain]远程线程注入失败...\n");
					}
					else
					{
						OutputDebugStringW(L"DONE!");
					}
					__leave;
				case x64PS:

				default:
					__leave;
				}
			}
		case x64FILE:
			{
				switch (dwProcBit)
				{
				case x86PS:

					__leave;
				case x64PS:

				default:
					__leave;
				}
			}

		default:
			__leave;
		}
	}
	__finally
	{

	}

	return 0;
}