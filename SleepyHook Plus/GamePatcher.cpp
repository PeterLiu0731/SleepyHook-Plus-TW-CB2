#include <Windows.h>
#include "Main.h"
#include "MetaHook.h"
#include "Utils.h"

DWORD WINAPI GameUI_Patcher();

unsigned long m_iHostIPAddress;
unsigned short m_iHostPort;

void WriteBytes(PVOID address, void* val, int bytes) {
	DWORD d, ds;
	VirtualProtect(address, bytes, PAGE_EXECUTE_READWRITE, &d);
	memcpy(address, val, bytes);
	VirtualProtect(address, bytes, d, &ds);
}

namespace GameGuard
{
	int (__cdecl* oGetStateCode)();
	int __cdecl GetStateCode() {
		return 1877;
	}
}

namespace HookFuncs
{
	int(__thiscall* oIpRedirector)(void* pThis, unsigned long ip, u_short port, char a4);
	int __fastcall IpRedirector(void* pThis, void* edx, unsigned long ip, u_short port, char a4) {
		return oIpRedirector(pThis, m_iHostIPAddress, m_iHostPort, a4);
	}

	int(__cdecl* oIpRedirector2)(unsigned long ip, u_short port);
	int __cdecl IpRedirector2(unsigned long ip, u_short port) {
		return oIpRedirector2(m_iHostIPAddress, m_iHostPort);
	}

	char(__thiscall* oPacketTransfer)(void* pThis, void* packetBuffer, int packetSize);
	char __fastcall PacketTransfer(void* pThis, void* edx, void* packetBuffer, int packetSize) {
		m_iHostIPAddress = *((unsigned long*)((char*)packetBuffer));
		m_iHostPort = htons(*((unsigned short*)((char*)packetBuffer + 4)));
		return oPacketTransfer(pThis, packetBuffer, packetSize);
	}

	int(__thiscall* oSharedDictCheck)(int* thisptr, char* a2);
	int __fastcall SharedDictCheck_Hook(int* thisptr, void* edx, char* a2) {
		return 0;
	}

	int(__thiscall* oIV_DecryptPacket)(void* pNetworkHandler, char* buffer, int maxBufferSize, int* bufferLen, BOOL bWaitHandshake);
	int __fastcall IV_DecryptPacket_hook(void* pNetworkHandler, void* edx, char* outBuffer, int maxBufferSize, int* outBufferLength, BOOL bWaitHandshake) {
		// pNetworkHandler: g_SocketManager->m_pNetworkHandler (Offset 0x04)
		int errorCode = oIV_DecryptPacket(pNetworkHandler, outBuffer, maxBufferSize, outBufferLength, bWaitHandshake);
		if (bWaitHandshake) // ~SERVERCONNECTED\n\0
			return errorCode;
		short packetId = reinterpret_cast<short*>(outBuffer)[0];
		unsigned char* buffer = reinterpret_cast<unsigned char*>(outBuffer);
		Utils::ConsolePrint("[PacketID: %02d] Data: ", packetId);
		for (int i = 0; i < *outBufferLength; i++) {
			Utils::ConsolePrint("%02X ", buffer[i]);
		}
		Utils::ConsolePrint("\n");
		return errorCode;
	}
}

void GamePatcher() {

	DWORD dwHardWare = (DWORD)GetModuleHandleA("hw.dll");
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)GameUI_Patcher, 0, 0, 0);
	if (CommandLine()->CheckParm("-dbg") != NULL) {
		Utils::AttachConsole();
		MH_InlineHook((void*)(dwHardWare + 0x244BF0), HookFuncs::IV_DecryptPacket_hook, (void*&)HookFuncs::oIV_DecryptPacket);
	}

	std::string sIpAddr = CommandLine()->GetParmValue("-ip");
	unsigned short nPort = CommandLine()->GetParmValue("-port", 0);
	m_iHostIPAddress = inet_addr(sIpAddr.c_str());
	m_iHostPort = htons(nPort);

	//Ip Redirector
	MH_InlineHook((void*)(dwHardWare + 0x242840), HookFuncs::IpRedirector, (void*&)HookFuncs::oIpRedirector);
	MH_InlineHook((void*)(dwHardWare + 0xE0A40), HookFuncs::IpRedirector2, (void*&)HookFuncs::oIpRedirector2);

	// Packet_Transfer
	MH_InlineHook((void*)(dwHardWare + 0x14DE10), HookFuncs::PacketTransfer, (void*&)HookFuncs::oPacketTransfer);

	//GameGuard Bypass
	MH_InlineHook((void*)(dwHardWare + 0x248070), GameGuard::GetStateCode, (void*&)GameGuard::oGetStateCode);
	WriteBytes((void*)(dwHardWare + 0xDA544), (void*)"\xEB", 1);

	if (CommandLine()->CheckParm("-nossl") != NULL)
	{
		//Disable SSL Certificate Init
		WriteBytes((void*)(dwHardWare + 0x244297), (void*)"\x90\x90\x90\x90\x90", 5);
		WriteBytes((void*)(dwHardWare + 0x2429E9), (void*)"\x90\x90\x90\x90\x90\x90\x90\xEB", 8);
		WriteBytes((void*)(dwHardWare + 0x2429D9), (void*)"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x8B\x4E\x04\x90\x90\x90", 16); //Disable SSL Connect Log write
	}

	// Clear Reply Error Code
	// Fixed the bug that you have to restart the game to login again after entering the wrong account or password
	WriteBytes((void*)(dwHardWare + 0xF7EB2), (void*)"\x90\x90\x90\x90\x90\x90", 6);

	//Patch SharedDict Check
	//MH_InlineHook((void*)(dwHardWare + 0xC0D0D8), HookFuncs::SharedDictCheck_Hook, (void*&)HookFuncs::oSharedDictCheck);
}

DWORD WINAPI GameUI_Patcher() {
	DWORD dwGameUI = NULL;
	while (true) {
		dwGameUI = (DWORD)GetModuleHandleA("GameUI.dll");
		if (dwGameUI)
			break;
		Sleep(0);
	}
	/*
	CSOTaskbar::CSOTaskbar checks the Lang command, and if it is 'tw' or 'chn', it will disable some UI. Ex: Shop, Inventory, Clan etc.
	This method is very simple and straightforward. You can also directly modify the binary file of GameUI.dll, but here we choose not to alter the clean official files.
	*/
	WriteBytes((void*)(dwGameUI + 0x1213FC), (void*)"\x00\x00\x00", 3); //tw
	WriteBytes((void*)(dwGameUI + 0x121400), (void*)"\x00\x00\x00", 3); //chn
	return 1;
}