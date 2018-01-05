#include <iostream>
#include <vector>
#include <Windows.h>
#include <algorithm>

#include <HotKeyAbstractInterface/HotKey.h>

using namespace KeyBoardKit::HotKeyKit;
using namespace std;


HotKey::HotKey(UINT fsModifiers, UINT vk, void(*func)()) :
	m_fsModifiers(fsModifiers),
	m_vk(vk),
	m_func(func) {
}

HotKey *HotKey::CreateHotKeyByKeyString(std::string hotkey_str, void(*func)()) {
	int curr_pos = 0, t;
	UINT fsModifiers = MOD_NOREPEAT;
	UINT vk = 0;

	// vector<string, string> fsModifiersCache;


	transform(hotkey_str.begin(), hotkey_str.end(), hotkey_str.begin(), ::toupper);

	while (1) {
		t = hotkey_str.find('+', curr_pos);

		if (t == string::npos) {
			t = hotkey_str.length();
		}

		if (!hotkey_str.compare(curr_pos, t - curr_pos, "CTRL")) {
			fsModifiers = fsModifiers | MOD_CONTROL;
		}
		else if (!hotkey_str.compare(curr_pos, t - curr_pos, "SHIFT")) {
			fsModifiers = fsModifiers | MOD_SHIFT;
		}
		else if (1 == (t - curr_pos)) {
			char c = hotkey_str[curr_pos];
			vk = vk | int(c);
		}

		if (t == hotkey_str.length())
			break;

		curr_pos = t + 1;
	}

	return (new HotKey(fsModifiers, vk, func));
}