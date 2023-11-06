// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#pragma comment(linker,"/export:auxGetDevCapsA=winmm_orig.auxGetDevCapsA,@15")
#pragma comment(linker,"/export:auxGetDevCapsW=winmm_orig.auxGetDevCapsW,@16")
#pragma comment(linker,"/export:auxGetNumDevs=winmm_orig.auxGetNumDevs,@17")
#pragma comment(linker,"/export:auxGetVolume=winmm_orig.auxGetVolume,@18")
#pragma comment(linker,"/export:auxOutMessage=winmm_orig.auxOutMessage,@19")
#pragma comment(linker,"/export:auxSetVolume=winmm_orig.auxSetVolume,@20")
#pragma comment(linker,"/export:CloseDriver=winmm_orig.CloseDriver,@4")
#pragma comment(linker,"/export:DefDriverProc=winmm_orig.DefDriverProc,@5")
#pragma comment(linker,"/export:DriverCallback=winmm_orig.DriverCallback,@6")
#pragma comment(linker,"/export:DrvGetModuleHandle=winmm_orig.DrvGetModuleHandle,@7")
#pragma comment(linker,"/export:GetDriverModuleHandle=winmm_orig.GetDriverModuleHandle,@8")
#pragma comment(linker,"/export:joyConfigChanged=winmm_orig.joyConfigChanged,@21")
#pragma comment(linker,"/export:joyGetDevCapsA=winmm_orig.joyGetDevCapsA,@22")
#pragma comment(linker,"/export:joyGetDevCapsW=winmm_orig.joyGetDevCapsW,@23")
#pragma comment(linker,"/export:joyGetNumDevs=winmm_orig.joyGetNumDevs,@24")
#pragma comment(linker,"/export:joyGetPos=winmm_orig.joyGetPos,@25")
#pragma comment(linker,"/export:joyGetPosEx=winmm_orig.joyGetPosEx,@26")
#pragma comment(linker,"/export:joyGetThreshold=winmm_orig.joyGetThreshold,@27")
#pragma comment(linker,"/export:joyReleaseCapture=winmm_orig.joyReleaseCapture,@28")
#pragma comment(linker,"/export:joySetCapture=winmm_orig.joySetCapture,@29")
#pragma comment(linker,"/export:joySetThreshold=winmm_orig.joySetThreshold,@30")
#pragma comment(linker,"/export:mciDriverNotify=winmm_orig.mciDriverNotify,@31")
#pragma comment(linker,"/export:mciDriverYield=winmm_orig.mciDriverYield,@32")
#pragma comment(linker,"/export:mciExecute=winmm_orig.mciExecute,@3")
#pragma comment(linker,"/export:mciFreeCommandResource=winmm_orig.mciFreeCommandResource,@33")
#pragma comment(linker,"/export:mciGetCreatorTask=winmm_orig.mciGetCreatorTask,@34")
#pragma comment(linker,"/export:mciGetDeviceIDA=winmm_orig.mciGetDeviceIDA,@35")
#pragma comment(linker,"/export:mciGetDeviceIDFromElementIDA=winmm_orig.mciGetDeviceIDFromElementIDA,@36")
#pragma comment(linker,"/export:mciGetDeviceIDFromElementIDW=winmm_orig.mciGetDeviceIDFromElementIDW,@37")
#pragma comment(linker,"/export:mciGetDeviceIDW=winmm_orig.mciGetDeviceIDW,@38")
#pragma comment(linker,"/export:mciGetDriverData=winmm_orig.mciGetDriverData,@39")
#pragma comment(linker,"/export:mciGetErrorStringA=winmm_orig.mciGetErrorStringA,@40")
#pragma comment(linker,"/export:mciGetErrorStringW=winmm_orig.mciGetErrorStringW,@41")
#pragma comment(linker,"/export:mciGetYieldProc=winmm_orig.mciGetYieldProc,@42")
#pragma comment(linker,"/export:mciLoadCommandResource=winmm_orig.mciLoadCommandResource,@43")
#pragma comment(linker,"/export:mciSendCommandA=winmm_orig.mciSendCommandA,@44")
#pragma comment(linker,"/export:mciSendCommandW=winmm_orig.mciSendCommandW,@45")
#pragma comment(linker,"/export:mciSendStringA=winmm_orig.mciSendStringA,@46")
#pragma comment(linker,"/export:mciSendStringW=winmm_orig.mciSendStringW,@47")
#pragma comment(linker,"/export:mciSetDriverData=winmm_orig.mciSetDriverData,@48")
#pragma comment(linker,"/export:mciSetYieldProc=winmm_orig.mciSetYieldProc,@49")
#pragma comment(linker,"/export:midiConnect=winmm_orig.midiConnect,@50")
#pragma comment(linker,"/export:midiDisconnect=winmm_orig.midiDisconnect,@51")
#pragma comment(linker,"/export:midiInAddBuffer=winmm_orig.midiInAddBuffer,@52")
#pragma comment(linker,"/export:midiInClose=winmm_orig.midiInClose,@53")
#pragma comment(linker,"/export:midiInGetDevCapsA=winmm_orig.midiInGetDevCapsA,@54")
#pragma comment(linker,"/export:midiInGetDevCapsW=winmm_orig.midiInGetDevCapsW,@55")
#pragma comment(linker,"/export:midiInGetErrorTextA=winmm_orig.midiInGetErrorTextA,@56")
#pragma comment(linker,"/export:midiInGetErrorTextW=winmm_orig.midiInGetErrorTextW,@57")
#pragma comment(linker,"/export:midiInGetID=winmm_orig.midiInGetID,@58")
#pragma comment(linker,"/export:midiInGetNumDevs=winmm_orig.midiInGetNumDevs,@59")
#pragma comment(linker,"/export:midiInMessage=winmm_orig.midiInMessage,@60")
#pragma comment(linker,"/export:midiInOpen=winmm_orig.midiInOpen,@61")
#pragma comment(linker,"/export:midiInPrepareHeader=winmm_orig.midiInPrepareHeader,@62")
#pragma comment(linker,"/export:midiInReset=winmm_orig.midiInReset,@63")
#pragma comment(linker,"/export:midiInStart=winmm_orig.midiInStart,@64")
#pragma comment(linker,"/export:midiInStop=winmm_orig.midiInStop,@65")
#pragma comment(linker,"/export:midiInUnprepareHeader=winmm_orig.midiInUnprepareHeader,@66")
#pragma comment(linker,"/export:midiOutCacheDrumPatches=winmm_orig.midiOutCacheDrumPatches,@67")
#pragma comment(linker,"/export:midiOutCachePatches=winmm_orig.midiOutCachePatches,@68")
#pragma comment(linker,"/export:midiOutClose=winmm_orig.midiOutClose,@69")
#pragma comment(linker,"/export:midiOutGetDevCapsA=winmm_orig.midiOutGetDevCapsA,@70")
#pragma comment(linker,"/export:midiOutGetDevCapsW=winmm_orig.midiOutGetDevCapsW,@71")
#pragma comment(linker,"/export:midiOutGetErrorTextA=winmm_orig.midiOutGetErrorTextA,@72")
#pragma comment(linker,"/export:midiOutGetErrorTextW=winmm_orig.midiOutGetErrorTextW,@73")
#pragma comment(linker,"/export:midiOutGetID=winmm_orig.midiOutGetID,@74")
#pragma comment(linker,"/export:midiOutGetNumDevs=winmm_orig.midiOutGetNumDevs,@75")
#pragma comment(linker,"/export:midiOutGetVolume=winmm_orig.midiOutGetVolume,@76")
#pragma comment(linker,"/export:midiOutLongMsg=winmm_orig.midiOutLongMsg,@77")
#pragma comment(linker,"/export:midiOutMessage=winmm_orig.midiOutMessage,@78")
#pragma comment(linker,"/export:midiOutOpen=winmm_orig.midiOutOpen,@79")
#pragma comment(linker,"/export:midiOutPrepareHeader=winmm_orig.midiOutPrepareHeader,@80")
#pragma comment(linker,"/export:midiOutReset=winmm_orig.midiOutReset,@81")
#pragma comment(linker,"/export:midiOutSetVolume=winmm_orig.midiOutSetVolume,@82")
#pragma comment(linker,"/export:midiOutShortMsg=winmm_orig.midiOutShortMsg,@83")
#pragma comment(linker,"/export:midiOutUnprepareHeader=winmm_orig.midiOutUnprepareHeader,@84")
#pragma comment(linker,"/export:midiStreamClose=winmm_orig.midiStreamClose,@85")
#pragma comment(linker,"/export:midiStreamOpen=winmm_orig.midiStreamOpen,@86")
#pragma comment(linker,"/export:midiStreamOut=winmm_orig.midiStreamOut,@87")
#pragma comment(linker,"/export:midiStreamPause=winmm_orig.midiStreamPause,@88")
#pragma comment(linker,"/export:midiStreamPosition=winmm_orig.midiStreamPosition,@89")
#pragma comment(linker,"/export:midiStreamProperty=winmm_orig.midiStreamProperty,@90")
#pragma comment(linker,"/export:midiStreamRestart=winmm_orig.midiStreamRestart,@91")
#pragma comment(linker,"/export:midiStreamStop=winmm_orig.midiStreamStop,@92")
#pragma comment(linker,"/export:mixerClose=winmm_orig.mixerClose,@93")
#pragma comment(linker,"/export:mixerGetControlDetailsA=winmm_orig.mixerGetControlDetailsA,@94")
#pragma comment(linker,"/export:mixerGetControlDetailsW=winmm_orig.mixerGetControlDetailsW,@95")
#pragma comment(linker,"/export:mixerGetDevCapsA=winmm_orig.mixerGetDevCapsA,@96")
#pragma comment(linker,"/export:mixerGetDevCapsW=winmm_orig.mixerGetDevCapsW,@97")
#pragma comment(linker,"/export:mixerGetID=winmm_orig.mixerGetID,@98")
#pragma comment(linker,"/export:mixerGetLineControlsA=winmm_orig.mixerGetLineControlsA,@99")
#pragma comment(linker,"/export:mixerGetLineControlsW=winmm_orig.mixerGetLineControlsW,@100")
#pragma comment(linker,"/export:mixerGetLineInfoA=winmm_orig.mixerGetLineInfoA,@101")
#pragma comment(linker,"/export:mixerGetLineInfoW=winmm_orig.mixerGetLineInfoW,@102")
#pragma comment(linker,"/export:mixerGetNumDevs=winmm_orig.mixerGetNumDevs,@103")
#pragma comment(linker,"/export:mixerMessage=winmm_orig.mixerMessage,@104")
#pragma comment(linker,"/export:mixerOpen=winmm_orig.mixerOpen,@105")
#pragma comment(linker,"/export:mixerSetControlDetails=winmm_orig.mixerSetControlDetails,@106")
#pragma comment(linker,"/export:mmDrvInstall=winmm_orig.mmDrvInstall,@107")
#pragma comment(linker,"/export:mmGetCurrentTask=winmm_orig.mmGetCurrentTask,@108")
#pragma comment(linker,"/export:mmioAdvance=winmm_orig.mmioAdvance,@113")
#pragma comment(linker,"/export:mmioAscend=winmm_orig.mmioAscend,@114")
#pragma comment(linker,"/export:mmioClose=winmm_orig.mmioClose,@115")
#pragma comment(linker,"/export:mmioCreateChunk=winmm_orig.mmioCreateChunk,@116")
#pragma comment(linker,"/export:mmioDescend=winmm_orig.mmioDescend,@117")
#pragma comment(linker,"/export:mmioFlush=winmm_orig.mmioFlush,@118")
#pragma comment(linker,"/export:mmioGetInfo=winmm_orig.mmioGetInfo,@119")
#pragma comment(linker,"/export:mmioInstallIOProcA=winmm_orig.mmioInstallIOProcA,@120")
#pragma comment(linker,"/export:mmioInstallIOProcW=winmm_orig.mmioInstallIOProcW,@121")
#pragma comment(linker,"/export:mmioOpenA=winmm_orig.mmioOpenA,@122")
#pragma comment(linker,"/export:mmioOpenW=winmm_orig.mmioOpenW,@123")
#pragma comment(linker,"/export:mmioRead=winmm_orig.mmioRead,@124")
#pragma comment(linker,"/export:mmioRenameA=winmm_orig.mmioRenameA,@125")
#pragma comment(linker,"/export:mmioRenameW=winmm_orig.mmioRenameW,@126")
#pragma comment(linker,"/export:mmioSeek=winmm_orig.mmioSeek,@127")
#pragma comment(linker,"/export:mmioSendMessage=winmm_orig.mmioSendMessage,@128")
#pragma comment(linker,"/export:mmioSetBuffer=winmm_orig.mmioSetBuffer,@129")
#pragma comment(linker,"/export:mmioSetInfo=winmm_orig.mmioSetInfo,@130")
#pragma comment(linker,"/export:mmioStringToFOURCCA=winmm_orig.mmioStringToFOURCCA,@131")
#pragma comment(linker,"/export:mmioStringToFOURCCW=winmm_orig.mmioStringToFOURCCW,@132")
#pragma comment(linker,"/export:mmioWrite=winmm_orig.mmioWrite,@133")
#pragma comment(linker,"/export:mmsystemGetVersion=winmm_orig.mmsystemGetVersion,@134")
#pragma comment(linker,"/export:mmTaskBlock=winmm_orig.mmTaskBlock,@109")
#pragma comment(linker,"/export:mmTaskCreate=winmm_orig.mmTaskCreate,@110")
#pragma comment(linker,"/export:mmTaskSignal=winmm_orig.mmTaskSignal,@111")
#pragma comment(linker,"/export:mmTaskYield=winmm_orig.mmTaskYield,@112")
#pragma comment(linker,"/export:OpenDriver=winmm_orig.OpenDriver,@9")
#pragma comment(linker,"/export:PlaySound=winmm_orig.PlaySound,@10")
#pragma comment(linker,"/export:PlaySoundA=winmm_orig.PlaySoundA,@11")
#pragma comment(linker,"/export:PlaySoundW=winmm_orig.PlaySoundW,@12")
#pragma comment(linker,"/export:SendDriverMessage=winmm_orig.SendDriverMessage,@13")
#pragma comment(linker,"/export:sndPlaySoundA=winmm_orig.sndPlaySoundA,@135")
#pragma comment(linker,"/export:sndPlaySoundW=winmm_orig.sndPlaySoundW,@136")
#pragma comment(linker,"/export:timeBeginPeriod=winmm_orig.timeBeginPeriod,@137")
#pragma comment(linker,"/export:timeEndPeriod=winmm_orig.timeEndPeriod,@138")
#pragma comment(linker,"/export:timeGetDevCaps=winmm_orig.timeGetDevCaps,@139")
#pragma comment(linker,"/export:timeGetSystemTime=winmm_orig.timeGetSystemTime,@140")
#pragma comment(linker,"/export:timeGetTime=winmm_orig.timeGetTime,@141")
#pragma comment(linker,"/export:timeKillEvent=winmm_orig.timeKillEvent,@142")
#pragma comment(linker,"/export:timeSetEvent=winmm_orig.timeSetEvent,@143")
#pragma comment(linker,"/export:waveInAddBuffer=winmm_orig.waveInAddBuffer,@144")
#pragma comment(linker,"/export:waveInClose=winmm_orig.waveInClose,@145")
#pragma comment(linker,"/export:waveInGetDevCapsA=winmm_orig.waveInGetDevCapsA,@146")
#pragma comment(linker,"/export:waveInGetDevCapsW=winmm_orig.waveInGetDevCapsW,@147")
#pragma comment(linker,"/export:waveInGetErrorTextA=winmm_orig.waveInGetErrorTextA,@148")
#pragma comment(linker,"/export:waveInGetErrorTextW=winmm_orig.waveInGetErrorTextW,@149")
#pragma comment(linker,"/export:waveInGetID=winmm_orig.waveInGetID,@150")
#pragma comment(linker,"/export:waveInGetNumDevs=winmm_orig.waveInGetNumDevs,@151")
#pragma comment(linker,"/export:waveInGetPosition=winmm_orig.waveInGetPosition,@152")
#pragma comment(linker,"/export:waveInMessage=winmm_orig.waveInMessage,@153")
#pragma comment(linker,"/export:waveInOpen=winmm_orig.waveInOpen,@154")
#pragma comment(linker,"/export:waveInPrepareHeader=winmm_orig.waveInPrepareHeader,@155")
#pragma comment(linker,"/export:waveInReset=winmm_orig.waveInReset,@156")
#pragma comment(linker,"/export:waveInStart=winmm_orig.waveInStart,@157")
#pragma comment(linker,"/export:waveInStop=winmm_orig.waveInStop,@158")
#pragma comment(linker,"/export:waveInUnprepareHeader=winmm_orig.waveInUnprepareHeader,@159")
#pragma comment(linker,"/export:waveOutBreakLoop=winmm_orig.waveOutBreakLoop,@160")
#pragma comment(linker,"/export:waveOutClose=winmm_orig.waveOutClose,@161")
#pragma comment(linker,"/export:waveOutGetDevCapsA=winmm_orig.waveOutGetDevCapsA,@162")
#pragma comment(linker,"/export:waveOutGetDevCapsW=winmm_orig.waveOutGetDevCapsW,@163")
#pragma comment(linker,"/export:waveOutGetErrorTextA=winmm_orig.waveOutGetErrorTextA,@164")
#pragma comment(linker,"/export:waveOutGetErrorTextW=winmm_orig.waveOutGetErrorTextW,@165")
#pragma comment(linker,"/export:waveOutGetID=winmm_orig.waveOutGetID,@166")
#pragma comment(linker,"/export:waveOutGetNumDevs=winmm_orig.waveOutGetNumDevs,@167")
#pragma comment(linker,"/export:waveOutGetPitch=winmm_orig.waveOutGetPitch,@168")
#pragma comment(linker,"/export:waveOutGetPlaybackRate=winmm_orig.waveOutGetPlaybackRate,@169")
#pragma comment(linker,"/export:waveOutGetPosition=winmm_orig.waveOutGetPosition,@170")
#pragma comment(linker,"/export:waveOutGetVolume=winmm_orig.waveOutGetVolume,@171")
#pragma comment(linker,"/export:waveOutMessage=winmm_orig.waveOutMessage,@172")
#pragma comment(linker,"/export:waveOutOpen=winmm_orig.waveOutOpen,@173")
#pragma comment(linker,"/export:waveOutPause=winmm_orig.waveOutPause,@174")
#pragma comment(linker,"/export:waveOutPrepareHeader=winmm_orig.waveOutPrepareHeader,@175")
#pragma comment(linker,"/export:waveOutReset=winmm_orig.waveOutReset,@176")
#pragma comment(linker,"/export:waveOutRestart=winmm_orig.waveOutRestart,@177")
#pragma comment(linker,"/export:waveOutSetPitch=winmm_orig.waveOutSetPitch,@178")
#pragma comment(linker,"/export:waveOutSetPlaybackRate=winmm_orig.waveOutSetPlaybackRate,@179")
#pragma comment(linker,"/export:waveOutSetVolume=winmm_orig.waveOutSetVolume,@180")
#pragma comment(linker,"/export:waveOutUnprepareHeader=winmm_orig.waveOutUnprepareHeader,@181")
#pragma comment(linker,"/export:waveOutWrite=winmm_orig.waveOutWrite,@182")
#pragma comment(linker,"/export:WOWAppExit=winmm_orig.WOWAppExit,@14")




INT _EntryCode() {
    //获取KERNELBASE!GetSystemTimeAsFileTime函数的地址
    HMODULE _module_handle = GetModuleHandleA("C:\\Windows\\System32\\KERNELBASE.dll");
    if (0 == _module_handle) {
        OutputDebugStringA("[-] failed to get handle of module 'KERNELBASE.dll'\n");
        return 1;
    }
    PVOID _func_addr = GetProcAddress(_module_handle, "GetSystemTimeAsFileTime");
    if (0 == _func_addr) {
        OutputDebugStringA("[-] failed to get function (GetSystemTimeAsFileTime) address from KNELBASE32.dll\n");
        return 1;
    }
    // 修改内存保护权限为可写
    DWORD _out = 0;
    if (!VirtualProtect(_func_addr, 0xE, PAGE_EXECUTE_READWRITE, &_out)) {
        OutputDebugStringA("[-] failed to modify function memory protection\n");
        return 1;
    }


    PBYTE _byte_func_addr = (PBYTE)_func_addr;
    *(PWORD)(_byte_func_addr + 0) = 0xB848;
    *(PDWORD64)(_byte_func_addr + 2) = 0x1DA336E4FA8CC18;
    *(PDWORD)(_byte_func_addr + 10) = 0xC3018948;

    PVOID _func_addr_of_getsystemtime = GetProcAddress(_module_handle, "GetSystemTime");
    if (0 == _func_addr_of_getsystemtime) {
        OutputDebugStringA("[-] failed to get function (GetSystemTime) address from KNELBASE32.dll\n");
        return 1;
    }
    // 修改内存保护权限为可写
    if (!VirtualProtect(_func_addr_of_getsystemtime, 0x20, PAGE_EXECUTE_READWRITE, &_out)) {
        OutputDebugStringA("[-] failed to modify function memory protection\n");
        return 1;
    }

    _byte_func_addr = (PBYTE)_func_addr_of_getsystemtime;
    *(PWORD)(_byte_func_addr + 0) = 0xB848;
    *(PDWORD64)(_byte_func_addr + 2) = 0x1122334455667788;
    *(PWORD)(_byte_func_addr + 10) = 0x8948;
    *(PBYTE)(_byte_func_addr + 12) = 0x01;
    *(PWORD)(_byte_func_addr + 13) = 0xB848;
    *(PDWORD64)(_byte_func_addr + 15) = 0x99887766554433;
    *(PDWORD)(_byte_func_addr + 23) = 0x08418948;
    *(PBYTE)(_byte_func_addr + 27) = 0xC3;


    OutputDebugStringA("[+] fucntion modification is done!\n");

    return 0;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        _EntryCode();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
