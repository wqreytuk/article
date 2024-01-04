0:000> pa 76984387     
Breakpoint 0 hit
eax=00000000 ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=76984245 esp=010ff7e0 ebp=010ff7f4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile:
76984245 8bff            mov     edi,edi
0:000> pa 76984387     
eax=00000000 ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=76984247 esp=010ff7e0 ebp=010ff7f4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x2:
76984247 55              push    ebp
eax=00000000 ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=76984248 esp=010ff7dc ebp=010ff7f4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x3:
76984248 8bec            mov     ebp,esp
eax=00000000 ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=7698424a esp=010ff7dc ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x5:
7698424a 83ec1c          sub     esp,1Ch
eax=00000000 ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=7698424d esp=010ff7c0 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x8:
7698424d a1e0709b76      mov     eax,dword ptr [coml2!__security_cookie (769b70e0)] ds:0023:769b70e0=539149a7
eax=539149a7 ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=76984252 esp=010ff7c0 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xd:
76984252 33c5            xor     eax,ebp
eax=529ebe7b ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=76984254 esp=010ff7c0 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xf:
76984254 8945fc          mov     dword ptr [ebp-4],eax ss:0023:010ff7d8={ole32!_imp__StgCreateDocfile (774e8094)}
eax=529ebe7b ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=76984257 esp=010ff7c0 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x12:
76984257 53              push    ebx
eax=529ebe7b ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=76984258 esp=010ff7bc ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x13:
76984258 56              push    esi
eax=529ebe7b ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=76984259 esp=010ff7b8 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x14:
76984259 8bc1            mov     eax,ecx
eax=0122f6e0 ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=01205380 edi=012056b8
eip=7698425b esp=010ff7b8 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x16:
7698425b 33f6            xor     esi,esi
eax=0122f6e0 ebx=00e19000 ecx=0122f6e0 edx=00001012 esi=00000000 edi=012056b8
eip=7698425d esp=010ff7b8 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x18:
7698425d 8b4d14          mov     ecx,dword ptr [ebp+14h] ss:0023:010ff7f0=010ff830
eax=0122f6e0 ebx=00e19000 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=76984260 esp=010ff7b8 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x1b:
76984260 8bda            mov     ebx,edx
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=76984262 esp=010ff7b8 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x1d:
76984262 8945f0          mov     dword ptr [ebp-10h],eax ss:0023:010ff7cc={ole32!_DELAY_IMPORT_DESCRIPTOR_api_ms_win_core_com_l2_1_1_dll (774d6394)}
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=76984265 esp=010ff7b8 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x20:
76984265 8975ec          mov     dword ptr [ebp-14h],esi ss:0023:010ff7c8={ole32!std::nothrow (77410000)}
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=76984268 esp=010ff7b8 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x23:
76984268 8975f8          mov     dword ptr [ebp-8],esi ss:0023:010ff7d4={KERNELBASE!DelayLoadFailureHook (754e0050)}
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=7698426b esp=010ff7b8 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x26:
7698426b 57              push    edi
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=7698426c esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x27:
7698426c 85c9            test    ecx,ecx
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=7698426e esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x29:
7698426e 0f84bd490100    je      coml2!DfCreateDocfile+0x149ec (76998c31) [br=0]
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=76984274 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x2f:
76984274 8931            mov     dword ptr [ecx],esi  ds:0023:010ff830=00000000
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=76984276 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x31:
76984276 85c0            test    eax,eax
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=76984278 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
coml2!DfCreateDocfile+0x33:
76984278 741c            je      coml2!DfCreateDocfile+0x51 (76984296)   [br=0]
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00001012 esi=00000000 edi=012056b8
eip=7698427a esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
coml2!DfCreateDocfile+0x35:
7698427a ba04010000      mov     edx,104h
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00000104 esi=00000000 edi=012056b8
eip=7698427f esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
coml2!DfCreateDocfile+0x3a:
7698427f 8bc8            mov     ecx,eax
eax=0122f6e0 ebx=00001012 ecx=0122f6e0 edx=00000104 esi=00000000 edi=012056b8
eip=76984281 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
coml2!DfCreateDocfile+0x3c:
76984281 e8093ffeff      call    coml2!ValidateNameW (7696818f)
eax=00000000 ebx=00001012 ecx=00000000 edx=000000de esi=00000000 edi=012056b8
eip=76984286 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x41:
76984286 8bf8            mov     edi,eax
eax=00000000 ebx=00001012 ecx=00000000 edx=000000de esi=00000000 edi=00000000
eip=76984288 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x43:
76984288 85ff            test    edi,edi
eax=00000000 ebx=00001012 ecx=00000000 edx=000000de esi=00000000 edi=00000000
eip=7698428a esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x45:
7698428a 0f880a010000    js      coml2!DfCreateDocfile+0x155 (7698439a)  [br=0]
eax=00000000 ebx=00001012 ecx=00000000 edx=000000de esi=00000000 edi=00000000
eip=76984290 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x4b:
76984290 8b45f0          mov     eax,dword ptr [ebp-10h] ss:0023:010ff7cc=0122f6e0
eax=0122f6e0 ebx=00001012 ecx=00000000 edx=000000de esi=00000000 edi=00000000
eip=76984293 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x4e:
76984293 8b4d14          mov     ecx,dword ptr [ebp+14h] ss:0023:010ff7f0=010ff830
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=000000de esi=00000000 edi=00000000
eip=76984296 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x51:
76984296 f7c300000008    test    ebx,8000000h
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=000000de esi=00000000 edi=00000000
eip=7698429c esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x57:
7698429c 0f8599490100    jne     coml2!DfCreateDocfile+0x149f6 (76998c3b) [br=0]
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=000000de esi=00000000 edi=00000000
eip=769842a2 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x5d:
769842a2 33d2            xor     edx,edx
eax=0122f6e0 ebx=00001012 ecx=010ff830 edx=00000000 esi=00000000 edi=00000000
eip=769842a4 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x5f:
769842a4 8bcb            mov     ecx,ebx
eax=0122f6e0 ebx=00001012 ecx=00001012 edx=00000000 esi=00000000 edi=00000000
eip=769842a6 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x61:
769842a6 42              inc     edx
eax=0122f6e0 ebx=00001012 ecx=00001012 edx=00000001 esi=00000000 edi=00000000
eip=769842a7 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
coml2!DfCreateDocfile+0x62:
769842a7 e82469feff      call    coml2!VerifyPerms (7696abd0)
eax=00000000 ebx=00001012 ecx=00001012 edx=00000001 esi=00000000 edi=00000000
eip=769842ac esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x67:
769842ac 8bf8            mov     edi,eax
eax=00000000 ebx=00001012 ecx=00001012 edx=00000001 esi=00000000 edi=00000000
eip=769842ae esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x69:
769842ae 85ff            test    edi,edi
eax=00000000 ebx=00001012 ecx=00001012 edx=00000001 esi=00000000 edi=00000000
eip=769842b0 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x6b:
769842b0 0f88e4000000    js      coml2!DfCreateDocfile+0x155 (7698439a)  [br=0]
eax=00000000 ebx=00001012 ecx=00001012 edx=00000001 esi=00000000 edi=00000000
eip=769842b6 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x71:
769842b6 b900000204      mov     ecx,4020000h
eax=00000000 ebx=00001012 ecx=04020000 edx=00000001 esi=00000000 edi=00000000
eip=769842bb esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x76:
769842bb 8bc3            mov     eax,ebx
eax=00001012 ebx=00001012 ecx=04020000 edx=00000001 esi=00000000 edi=00000000
eip=769842bd esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x78:
769842bd 23c1            and     eax,ecx
eax=00000000 ebx=00001012 ecx=04020000 edx=00000001 esi=00000000 edi=00000000
eip=769842bf esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x7a:
769842bf 3bc1            cmp     eax,ecx
eax=00000000 ebx=00001012 ecx=04020000 edx=00000001 esi=00000000 edi=00000000
eip=769842c1 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
coml2!DfCreateDocfile+0x7c:
769842c1 0f95c1          setne   cl
eax=00000000 ebx=00001012 ecx=04020001 edx=00000001 esi=00000000 edi=00000000
eip=769842c4 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
coml2!DfCreateDocfile+0x7f:
769842c4 f6c303          test    bl,3
eax=00000000 ebx=00001012 ecx=04020001 edx=00000001 esi=00000000 edi=00000000
eip=769842c7 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
coml2!DfCreateDocfile+0x82:
769842c7 0f95c0          setne   al
eax=00000001 ebx=00001012 ecx=04020001 edx=00000001 esi=00000000 edi=00000000
eip=769842ca esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
coml2!DfCreateDocfile+0x85:
769842ca 84c8            test    al,cl
eax=00000001 ebx=00001012 ecx=04020001 edx=00000001 esi=00000000 edi=00000000
eip=769842cc esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
coml2!DfCreateDocfile+0x87:
769842cc 0f841f4a0100    je      coml2!DfCreateDocfile+0x14aac (76998cf1) [br=0]
eax=00000001 ebx=00001012 ecx=04020001 edx=00000001 esi=00000000 edi=00000000
eip=769842d2 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
coml2!DfCreateDocfile+0x8d:
769842d2 8bcb            mov     ecx,ebx
eax=00000001 ebx=00001012 ecx=00001012 edx=00000001 esi=00000000 edi=00000000
eip=769842d4 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
coml2!DfCreateDocfile+0x8f:
769842d4 e81963feff      call    coml2!ModeToDFlags (7696a5f2)
eax=000003c0 ebx=00001012 ecx=00001012 edx=000003c0 esi=00000000 edi=00000000
eip=769842d9 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x94:
769842d9 8bd0            mov     edx,eax
eax=000003c0 ebx=00001012 ecx=00001012 edx=000003c0 esi=00000000 edi=00000000
eip=769842db esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x96:
769842db 8945f4          mov     dword ptr [ebp-0Ch],eax ss:0023:010ff7d0=00000000
eax=000003c0 ebx=00001012 ecx=00001012 edx=000003c0 esi=00000000 edi=00000000
eip=769842de esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x99:
769842de b800000300      mov     eax,30000h
eax=00030000 ebx=00001012 ecx=00001012 edx=000003c0 esi=00000000 edi=00000000
eip=769842e3 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x9e:
769842e3 23c8            and     ecx,eax
eax=00030000 ebx=00001012 ecx=00000000 edx=000003c0 esi=00000000 edi=00000000
eip=769842e5 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0xa0:
769842e5 3bc8            cmp     ecx,eax
eax=00030000 ebx=00001012 ecx=00000000 edx=000003c0 esi=00000000 edi=00000000
eip=769842e7 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
coml2!DfCreateDocfile+0xa2:
769842e7 0f847e490100    je      coml2!DfCreateDocfile+0x14a26 (76998c6b) [br=0]
eax=00030000 ebx=00001012 ecx=00000000 edx=000003c0 esi=00000000 edi=00000000
eip=769842ed esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
coml2!DfCreateDocfile+0xa8:
769842ed 8b450c          mov     eax,dword ptr [ebp+0Ch] ss:0023:010ff7e8=00000000
eax=00000000 ebx=00001012 ecx=00000000 edx=000003c0 esi=00000000 edi=00000000
eip=769842f0 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
coml2!DfCreateDocfile+0xab:
769842f0 b900020000      mov     ecx,200h
eax=00000000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00000000
eip=769842f5 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
coml2!DfCreateDocfile+0xb0:
769842f5 bf00100000      mov     edi,1000h
eax=00000000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=769842fa esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
coml2!DfCreateDocfile+0xb5:
769842fa 3bc1            cmp     eax,ecx
eax=00000000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=769842fc esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
coml2!DfCreateDocfile+0xb7:
769842fc 0f87ad000000    ja      coml2!DfCreateDocfile+0x16a (769843af)  [br=0]
eax=00000000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=76984302 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
coml2!DfCreateDocfile+0xbd:
76984302 85c0            test    eax,eax
eax=00000000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=76984304 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0xbf:
76984304 7408            je      coml2!DfCreateDocfile+0xc9 (7698430e)   [br=1]
eax=00000000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=7698430e esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0xc9:
7698430e 8bc3            mov     eax,ebx
eax=00001012 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=76984310 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0xcb:
76984310 23c7            and     eax,edi
eax=00001000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=76984312 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xcd:
76984312 8945e4          mov     dword ptr [ebp-1Ch],eax ss:0023:010ff7c0=77da62d6
eax=00001000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=76984315 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xd0:
76984315 0f85b1000000    jne     coml2!DfCreateDocfile+0x187 (769843cc)  [br=1]
eax=00001000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=769843cc esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x187:
769843cc f7451000400000  test    dword ptr [ebp+10h],4000h ss:0023:010ff7ec=00000000
eax=00001000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=769843d3 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x18e:
769843d3 0f8542ffffff    jne     coml2!DfCreateDocfile+0xd6 (7698431b)   [br=0]
eax=00001000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=00001000
eip=769843d9 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x194:
769843d9 8b7df0          mov     edi,dword ptr [ebp-10h] ss:0023:010ff7cc=0122f6e0
eax=00001000 ebx=00001012 ecx=00000200 edx=000003c0 esi=00000000 edi=0122f6e0
eip=769843dc esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x197:
769843dc 8bcf            mov     ecx,edi
eax=00001000 ebx=00001012 ecx=0122f6e0 edx=000003c0 esi=00000000 edi=0122f6e0
eip=769843de esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x199:
769843de e846f7ffff      call    coml2!CNtfsStorage::IsNffAppropriate (76983b29)
eax=80030002 ebx=00001012 ecx=01200000 edx=01200000 esi=00000000 edi=0122f6e0
eip=769843e3 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x19e:
769843e3 85c0            test    eax,eax
eax=80030002 ebx=00001012 ecx=01200000 edx=01200000 esi=00000000 edi=0122f6e0
eip=769843e5 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
coml2!DfCreateDocfile+0x1a0:
769843e5 0f8830ffffff    js      coml2!DfCreateDocfile+0xd6 (7698431b)   [br=1]
eax=80030002 ebx=00001012 ecx=01200000 edx=01200000 esi=00000000 edi=0122f6e0
eip=7698431b esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
coml2!DfCreateDocfile+0xd6:
7698431b 64a118000000    mov     eax,dword ptr fs:[00000018h] fs:003b:00000018=00e1a000
eax=00e1a000 ebx=00001012 ecx=01200000 edx=01200000 esi=00000000 edi=0122f6e0
eip=76984321 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
coml2!DfCreateDocfile+0xdc:
76984321 8b80800f0000    mov     eax,dword ptr [eax+0F80h] ds:0023:00e1af80=0121c150
eax=0121c150 ebx=00001012 ecx=01200000 edx=01200000 esi=00000000 edi=0122f6e0
eip=76984327 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
coml2!DfCreateDocfile+0xe2:
76984327 8945e8          mov     dword ptr [ebp-18h],eax ss:0023:010ff7c4=7743d4ef
eax=0121c150 ebx=00001012 ecx=01200000 edx=01200000 esi=00000000 edi=0122f6e0
eip=7698432a esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
coml2!DfCreateDocfile+0xe5:
7698432a 85c0            test    eax,eax
eax=0121c150 ebx=00001012 ecx=01200000 edx=01200000 esi=00000000 edi=0122f6e0
eip=7698432c esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xe7:
7698432c 0f84a6490100    je      coml2!DfCreateDocfile+0x14a93 (76998cd8) [br=0]
eax=0121c150 ebx=00001012 ecx=01200000 edx=01200000 esi=00000000 edi=0122f6e0
eip=76984332 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xed:
76984332 8b5510          mov     edx,dword ptr [ebp+10h] ss:0023:010ff7ec=00000000    // ebp+0x10就是a5  即0
eax=0121c150 ebx=00001012 ecx=01200000 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984335 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xf0:
76984335 8d45ec          lea     eax,[ebp-14h]
eax=010ff7c8 ebx=00001012 ecx=01200000 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984338 esp=010ff7b4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xf3:
76984338 51              push    ecx
eax=010ff7c8 ebx=00001012 ecx=01200000 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984339 esp=010ff7b0 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xf4:
76984339 ff7508          push    dword ptr [ebp+8]    ss:0023:010ff7e4=00000000	// 由于coml2!DfCreateDocfile是fastcall，前两个参数在寄存器里，因此ebp+8取出的是第一个栈参数，即coml2!DfCreateDocfile的a3  就是0
eax=010ff7c8 ebx=00001012 ecx=01200000 edx=00000000 esi=00000000 edi=0122f6e0
eip=7698433c esp=010ff7ac ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xf7:
7698433c 8bcb            mov     ecx,ebx
eax=010ff7c8 ebx=00001012 ecx=00001012 edx=00000000 esi=00000000 edi=0122f6e0
eip=7698433e esp=010ff7ac ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0xf9:
7698433e 81e300000200    and     ebx,20000h
eax=010ff7c8 ebx=00000000 ecx=00001012 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984344 esp=010ff7ac ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0xff:
76984344 c1e902          shr     ecx,2
eax=010ff7c8 ebx=00000000 ecx=00000404 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984347 esp=010ff7ac ebp=010ff7dc iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
coml2!DfCreateDocfile+0x102:
76984347 81e100000001    and     ecx,1000000h
eax=010ff7c8 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=7698434d esp=010ff7ac ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x108:
7698434d 56              push    esi
eax=010ff7c8 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=7698434e esp=010ff7a8 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x109:
7698434e 50              push    eax
eax=010ff7c8 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=7698434f esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x10a:
7698434f 8bc2            mov     eax,edx
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984351 esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x10c:
76984351 81e200400000    and     edx,4000h
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984357 esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x112:
76984357 2500000020      and     eax,20000000h
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=7698435c esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x117:
7698435c 0bc8            or      ecx,eax
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=7698435e esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x119:
7698435e 33c0            xor     eax,eax
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984360 esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x11b:
76984360 c1e903          shr     ecx,3
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984363 esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x11e:
76984363 0bcb            or      ecx,ebx
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984365 esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x120:
76984365 c1e90d          shr     ecx,0Dh
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=76984368 esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x123:
76984368 0bca            or      ecx,edx
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=0122f6e0
eip=7698436a esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x125:
7698436a 8b55f4          mov     edx,dword ptr [ebp-0Ch] ss:0023:010ff7d0=000003c0
eax=00000000 ebx=00000000 ecx=00000000 edx=000003c0 esi=00000000 edi=0122f6e0
eip=7698436d esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x128:
7698436d c1e904          shr     ecx,4
eax=00000000 ebx=00000000 ecx=00000000 edx=000003c0 esi=00000000 edi=0122f6e0
eip=76984370 esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
coml2!DfCreateDocfile+0x12b:
76984370 3945e4          cmp     dword ptr [ebp-1Ch],eax ss:0023:010ff7c0=00001000
eax=00000000 ebx=00000000 ecx=00000000 edx=000003c0 esi=00000000 edi=0122f6e0
eip=76984373 esp=010ff7a4 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x12e:
76984373 56              push    esi
eax=00000000 ebx=00000000 ecx=00000000 edx=000003c0 esi=00000000 edi=0122f6e0
eip=76984374 esp=010ff7a0 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x12f:
76984374 0f95c0          setne   al
eax=00000001 ebx=00000000 ecx=00000000 edx=000003c0 esi=00000000 edi=0122f6e0
eip=76984377 esp=010ff7a0 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x132:
76984377 8d044504000000  lea     eax,[eax*2+4]   // 6就是从这里来的  也就是说   a5控制了coml2!DfFromName的第一个参数   当然，只有a5还是不够的，因为ecx也会对该函数的a1产生影响，而ecx的值又来自于grfMode，因此coml2!DfFromName的a1由coml2!DfCreateDocfile.asm的a5和StgCreateDocfile的a2（grfmode）共同决定
eax=00000006 ebx=00000000 ecx=00000000 edx=000003c0 esi=00000000 edi=0122f6e0
eip=7698437e esp=010ff7a0 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x139:
7698437e 0bc8            or      ecx,eax
eax=00000006 ebx=00000000 ecx=00000006 edx=000003c0 esi=00000000 edi=0122f6e0
eip=76984380 esp=010ff7a0 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x13b:
76984380 0b4df8          or      ecx,dword ptr [ebp-8] ss:0023:010ff7d4=00000000
eax=00000006 ebx=00000000 ecx=00000006 edx=000003c0 esi=00000000 edi=0122f6e0
eip=76984383 esp=010ff7a0 ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x13e:
76984383 51              push    ecx
eax=00000006 ebx=00000000 ecx=00000006 edx=000003c0 esi=00000000 edi=0122f6e0
eip=76984384 esp=010ff79c ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x13f:
76984384 8b4df0          mov     ecx,dword ptr [ebp-10h] ss:0023:010ff7cc=0122f6e0
eax=00000006 ebx=00000000 ecx=0122f6e0 edx=000003c0 esi=00000000 edi=0122f6e0
eip=76984387 esp=010ff79c ebp=010ff7dc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
coml2!DfCreateDocfile+0x142:
76984387 e88442feff      call    coml2!DfFromName (76968610)
