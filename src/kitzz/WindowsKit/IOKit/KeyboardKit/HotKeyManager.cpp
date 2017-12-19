#include <iostream>
#include <Windows.h>

#include <HotKeyAbstractInterface/HotKeyManager.h>

using KeyBoardKit::HotKeyKit::HotKeyManager;
using KeyBoardKit::HotKeyKit::HotKeyIndentifier;


HotKeyManager::HotKeyManager(HWND associatedWindow) :
	m_associatedWindow(associatedWindow),
	m_nextHotKeyIdentifier(1) {
}

HotKeyManager::~HotKeyManager() {
	// TODO: release all hotkeys
	std::cout << "remember to release all hotkeys." << std::endl;
}

HotKeyIndentifier HotKeyManager::registerHotKey(const HotKey &hotkey) {
	m_nextHotKeyIdentifier += 1;
	HotKeyIndentifier hotkey_id = m_nextHotKeyIdentifier;

	if (RegisterHotKey(m_associatedWindow, hotkey_id, hotkey.m_fsModifiers, hotkey.m_vk) == 0) {
		// TODO: handle failure
		std::cout << "remember to handle failure." << std::endl;
	}

	m_hotkeys.insert(std::make_pair(hotkey_id, hotkey));

	return hotkey_id;

}

void HotKeyManager::unregisterHotKey(HotKeyIndentifier hotkey_id) {

	if (m_hotkeys.find(hotkey_id) == m_hotkeys.end()) {
		std::cout << "Hotkey is not set." << std::endl;
		return;
	}

	if (UnregisterHotKey(m_associatedWindow, hotkey_id) == 0) {
		std::cout << "release hotkey failed." << std::endl;
		return;
	}

	m_hotkeys.erase(m_hotkeys.find(hotkey_id));
}

void *HotKeyManager::findActionByHotKeyId(HotKeyIndentifier hotkey_id) {
	auto hotkeyIter = m_hotkeys.find(hotkey_id);

	if (hotkeyIter == m_hotkeys.end()) {
		return nullptr;
	}

	return hotkeyIter->second.m_func;
}

void HotKeyManager::unregisterAllHotkeys() {
	auto hotkeyIter = m_hotkeys.begin(), hotkeyIterLast = m_hotkeys.end();

	while (hotkeyIter != hotkeyIterLast) {
		HotKeyIndentifier hotkeyId = hotkeyIter->first;


		if (UnregisterHotKey(m_associatedWindow, hotkeyId) == 0) {
			std::cout << "release hotkey failed." << std::endl;
		}

		hotkeyIter = m_hotkeys.erase(hotkeyIter);
	}
}