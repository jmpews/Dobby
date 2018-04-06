#include <Windows.h>

extern "C" __declspec(dllexport) VOID NullExport() {
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) {
	switch (Reason) {
	case DLL_THREAD_ATTACH: {
		MessageBoxW(0, L"dll attach.", L"dll main", 0);
		break;
	}
	case DLL_THREAD_DETACH: {
		MessageBoxW(0, L"dll detach", L"dll main", 0);
		break;
	}
	case DLL_PROCESS_ATTACH:
	}
}