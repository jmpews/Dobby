#pragma once

#include<iostream>

namespace KeyBoardKit {
	namespace HotKeyKit {
		typedef int HotKeyIndentifier;

		class HotKeyAction {
			// TODO: need this?
		};

		class HotKey {
		public:
			HotKey(UINT fsModifiers, UINT vk, void(*func)());

			static HotKey *CreateHotKeyByKeyString(std::string , void(*func)());

			std::string hotkey_str;
			UINT m_fsModifiers;
			UINT m_vk;
			void(*m_func)();
		};
	}
}