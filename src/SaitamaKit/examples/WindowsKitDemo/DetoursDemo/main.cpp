#include <Windows.h>
#include <stdio.h>
#if 0
int APIENTRY _tWinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPTSTR    lpCmdLine,
	int       nCmdShow)
#endif

#include <Dependences\Detours\include\detours.h>
#pragma comment(lib, "detours.lib")

static int (WINAPI* OLD_MessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) = MessageBoxW;
int WINAPI NEW_MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	int ret = OLD_MessageBoxW(hWnd, L"no more hello world", L"[unknown]", uType);
	return ret;
}

VOID DetoursHookMessageBox()
{
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourAttach(&(PVOID&)OLD_MessageBoxW, NEW_MessageBoxW);

	DetourTransactionCommit();
}

VOID DetoursUnHookMessageBox()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourDetach(&(PVOID&)OLD_MessageBoxW, NEW_MessageBoxW);

	DetourTransactionCommit();

}

VOID TestDetoursBasicHookDemo() {
	MessageBoxW(0, L"hello world", L"unknown", 0);
	DetoursHookMessageBox();
	MessageBoxW(0, L"hello world again", L"unknown", 0);
	DetoursUnHookMessageBox();
}

VOID TestDetourCreateProcess() {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);
	char* DirPath = new char[MAX_PATH];
	char* DLLPath = new char[MAX_PATH]; //testdll.dll    
	char* DetourPath = new char[MAX_PATH]; //detoured.dll  

	GetCurrentDirectory(MAX_PATH, DirPath);
	sprintf_s(DLLPath, MAX_PATH, "%s\\testdll.dll", DirPath);
	sprintf_s(DetourPath, MAX_PATH, "%s\\detoured.dll", DirPath);
	DetourCreateProcessWithDll(NULL, "C:\\windows\\notepad.exe",
		NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi, DetourPath, DLLPath, NULL);
	delete[] DirPath;
	delete[] DLLPath;
	delete[] DetourPath;
}
int main(int argc, char *argv[]) {
	return 0;
}