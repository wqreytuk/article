kd> .thread
Implicit thread is now ffffd0823e0a5080
kd> g
CB - CBAllocateBlock - Allocating block: start 0XFFFFF804835EA380, length (not counting hdr) 0x30 bytes
CB - CBAllocateBlock - Bytes remaining: 0xfc8
CB - CBAllocateBlock - Allocating block: start 0XFFFFF804835EA3B8, length (not counting hdr) 0x38 bytes
CB - CBAllocateBlock - Bytes remaining: 0xf88
CB - CBAllocateBlock - Allocating block: start 0XFFFFF804835EA3F8, length (not counting hdr) 0x30 bytes
CB - CBAllocateBlock - Bytes remaining: 0xf50
CB - CBAllocateBlock - Allocating block: start 0XFFFFF804835EA430, length (not counting hdr) 0x30 bytes
CB - CBAllocateBlock - Bytes remaining: 0xf18
CB - CBAllocateBlock - Allocating block: start 0XFFFFF804835EA468, length (not counting hdr) 0x30 bytes
CB - CBAllocateBlock - Bytes remaining: 0xee0
CB - CBAllocateBlock - Allocating block: start 0XFFFFF804835EA4A0, length (not counting hdr) 0x38 bytes
CB - CBAllocateBlock - Bytes remaining: 0xea0
CB - CBAllocateBlock - Allocating block: start 0XFFFFF804835EA4E0, length (not counting hdr) 0x18 bytes
CB - CBAllocateBlock - Bytes remaining: 0xe80
Break instruction exception - code 80000003 (first chance)
driver!ApcSpuriousIntTest+0x25a:
fffff804`835e192a cc              int     3
kd> p
driver!ApcSpuriousIntTest+0x25b:
fffff804`835e192b c744246803000000 mov     dword ptr [rsp+68h],3
kd> 
driver!ApcSpuriousIntTest+0x263:
fffff804`835e1933 c744246c00000000 mov     dword ptr [rsp+6Ch],0
kd> 
driver!ApcSpuriousIntTest+0x26b:
fffff804`835e193b e8c0f6ffff      call    driver!cli_asm_func (fffff804`835e1000)
kd> 
driver!ApcSpuriousIntTest+0x270:
fffff804`835e1940 ba08000000      mov     edx,8
kd> 
CB - CBAllocateBlock - Allocating block: start 0XFFFFF804835EA500, length (not counting hdr) 0x8 bytes
CB - CBAllocateBlock - Bytes remaining: 0xe70
driver!ApcSpuriousIntTest+0x285:
fffff804`835e1955 817c2458010000a0 cmp     dword ptr [rsp+58h],0A0000001h
kd> 
driver!ApcSpuriousIntTest+0x2b2:
fffff804`835e1982 488d442468      lea     rax,[rsp+68h]
kd> 
driver!ApcSpuriousIntTest+0x2bf:
fffff804`835e198f 48c784249800000008000000 mov qword ptr [rsp+98h],8
kd> 
driver!ApcSpuriousIntTest+0x2cb:
fffff804`835e199b 48c784249000000000000000 mov qword ptr [rsp+90h],0
kd> 
driver!ApcSpuriousIntTest+0x2d7:
fffff804`835e19a7 48c744242000000000 mov   qword ptr [rsp+20h],0
kd> 
driver!ApcSpuriousIntTest+0x304:
fffff804`835e19d4 e829f6ffff      call    driver!sti_asm_func (fffff804`835e1002)
kd> 
driver!ApcSpuriousIntTest+0x309:
fffff804`835e19d9 488b442448      mov     rax,qword ptr [rsp+48h]
kd> 
driver!ApcSpuriousIntTest+0x334:
fffff804`835e1a04 e8f7f5ffff      call    driver!cli_asm_func (fffff804`835e1000)
kd> 
driver!ApcSpuriousIntTest+0x339:
fffff804`835e1a09 e822280000      call    driver!RemoveHooks (fffff804`835e4230)
kd> 


execute these commands in kernel debugger
	eb 0xFFFFF804ECCA5CD0 0x48
	eb 0xFFFFF804ECCA5CD1 0x55
	eb 0xFFFFF804ECCA5CD2 0x48
	eb 0xFFFFF804ECCA5CD3 0x83
	eb 0xFFFFF804ECCA5CD4 0xec
	eb 0xFFFFF804ECCA5CD5 0x30
	eb 0xFFFFF804EC84A2B0 0x48
	eb 0xFFFFF804EC84A2B1 0x55
	eb 0xFFFFF804EC84A2B2 0x48
	eb 0xFFFFF804EC84A2B3 0x83
	eb 0xFFFFF804EC84A2B4 0xec
	eb 0xFFFFF804EC84A2B5 0x30


WARNING: This break is not a step/trace completion.
The last command has been cleared to prevent
accidental continuation of this unrelated event.
Check the event, location and thread before resuming.
Break instruction exception - code 80000003 (first chance)
driver!RemoveHooks+0xfc:
fffff804`835e432c cc              int     3
kd>  eb 0xFFFFF804ECCA5CD0 0x48
kd>  eb 0xFFFFF804ECCA5CD1 0x55
kd>  eb 0xFFFFF804ECCA5CD2 0x48
kd>  eb 0xFFFFF804ECCA5CD3 0x83
kd>  eb 0xFFFFF804ECCA5CD4 0xec
kd>  eb 0xFFFFF804ECCA5CD5 0x30
kd>  eb 0xFFFFF804EC84A2B0 0x48
kd>  eb 0xFFFFF804EC84A2B1 0x55
kd>  eb 0xFFFFF804EC84A2B2 0x48
kd>  eb 0xFFFFF804EC84A2B3 0x83
kd>  eb 0xFFFFF804EC84A2B4 0xec
kd>  eb 0xFFFFF804EC84A2B5 0x30
kd> p
driver!RemoveHooks+0xfd:
fffff804`835e432d 4883c448        add     rsp,48h
kd> 
driver!ApcSpuriousIntTest+0x33e:
fffff804`835e1a0e e8eff5ffff      call    driver!sti_asm_func (fffff804`835e1002)
kd> 
driver!ApcSpuriousIntTest+0x343:
fffff804`835e1a13 e888150000      call    driver!DumpTrace (fffff804`835e2fa0)
kd>  ffffd0823e0a5080
CB - CBXtractFromStart - Xtracting.
    current block start:       0XFFFFF804835EA380
    length (not counting hdr): 0x30
    source:                    0XFFFFF804835EA388
    dest:                      0XFFFFE1049E5B6540
    len:                       0x30


APCTEST - SWAP CONTEXT trace


APCTEST -		Current IRQL:                    0x2
APCTEST -		Current thread:                  0XFFFFD0823E0A5080
APCTEST -		Current thread K APC pending:    1
APCTEST -		Current thread K APC list empty: 0
APCTEST -		Current thread U APC pending:    0
APCTEST -		Current thread U APC list empty: 0

APCTEST -		New thread:                      0XFFFFD082387B4080
APCTEST -		New thread K APC pending:        0
APCTEST -		New thread K APC list empty:     1
APCTEST -		New thread U APC pending:        0
APCTEST -		New thread U APC list empty:     0

APCTEST -		APC INT:                         0CB - CBFreeOldestDataBlock - Avail bytes before: 0xe70
CB - CBFreeOldestDataBlock - Discarding block: start 0XFFFFF804835EA380, length (not counting hdr) 0x30 bytes
CB - CBFreeOldestDataBlock - Avail bytes after:  0xea8
CB - CBXtractFromStart - Xtracting.
    current block start:       0XFFFFF804835EA3B8
    length (not counting hdr): 0x38
    source:                    0XFFFFF804835EA3C0
    dest:                      0XFFFFE1049E5B6540
    len:                       0x38


APCTEST - DELIVER APC trace


APCTEST -		Current IRQL:                    0x1
APCTEST -		Caller address:                  0XFFFFF804ECCA267B
APCTEST -		Trap frame:                      0XFFFFE1049A100750
APCTEST -		Reserved:                        0000000000000000
APCTEST -		PreviousMode:                    0

APCTEST -		Thread:                          0XFFFFD082387B4080
APCTEST -		Thread K APC pending:            0
APCTEST -		Thread K APC list empty:         1
APCTEST -		Thread U APC pending:            0
APCTEST -		Thread U APC list empty:         0CB - CBFreeOldestDataBlock - Avail bytes before: 0xea8
CB - CBFreeOldestDataBlock - Discarding block: start 0XFFFFF804835EA3B8, length (not counting hdr) 0x38 bytes
CB - CBFreeOldestDataBlock - Avail bytes after:  0xee8
CB - CBXtractFromStart - Xtracting.
    current block start:       0XFFFFF804835EA3F8
    length (not counting hdr): 0x30
    source:                    0XFFFFF804835EA400
    dest:                      0XFFFFE1049E5B6540
    len:                       0x30

ffffd0823e0a5080
APCTEST - SWAP CONTEXT trace


APCTEST -		Current IRQL:                    0x2
APCTEST -		Current thread:                  0XFFFFD082387B4080
APCTEST -		Current thread K APC pending:    0
APCTEST -		Current thread K APC list empty: 1
APCTEST -		Current thread U APC pending:    0
APCTEST -		Current thread U APC list empty: 0

APCTEST -		New thread:                      0XFFFFD0823A1DE080
APCTEST -		New thread K APC pending:        0
APCTEST -		New thread K APC list empty:     1
APCTEST -		New thread U APC pending:        0
APCTEST -		New thread U APC list empty:     0

APCTEST -		APC INT:                         0CB - CBFreeOldestDataBlock - Avail bytes before: 0xee8
CB - CBFreeOldestDataBlock - Discarding block: start 0XFFFFF804835EA3F8, length (not counting hdr) 0x30 bytes
CB - CBFreeOldestDataBlock - Avail bytes after:  0xf20
CB - CBXtractFromStart - Xtracting.
    current block start:       0XFFFFF804835EA430
    length (not counting hdr): 0x30
    source:                    0XFFFFF804835EA438
    dest:                      0XFFFFE1049E5B6540
    len:                       0x30


APCTEST - SWAP CONTEXT trace

ffffd0823e0a5080
APCTEST -		Current IRQL:                    0x2
APCTEST -		Current thread:                  0XFFFFD0823A1DE080
APCTEST -		Current thread K APC pending:    0
APCTEST -		Current thread K APC list empty: 1
APCTEST -		Current thread U APC pending:    0
APCTEST -		Current thread U APC list empty: 0

APCTEST -		New thread:                      0XFFFFD0823F34E080
APCTEST -		New thread K APC pending:        0
APCTEST -		New thread K APC list empty:     1
APCTEST -		New thread U APC pending:        0
APCTEST -		New thread U APC list empty:     0

APCTEST -		APC INT:                         0CB - CBFreeOldestDataBlock - Avail bytes before: 0xf20
CB - CBFreeOldestDataBlock - Discarding block: start 0XFFFFF804835EA430, length (not counting hdr) 0x30 bytes
CB - CBFreeOldestDataBlock - Avail bytes after:  0xf58
CB - CBXtractFromStart - Xtracting.
    current block start:       0XFFFFF804835EA468
    length (not counting hdr): 0x30
    source:                    0XFFFFF804835EA470
    dest:                      0XFFFFE1049E5B6540
    len:                       0x30


APCTEST - SWAP CONTEXT trace

ffffd0823e0a5080
APCTEST -		Current IRQL:                    0x2
APCTEST -		Current thread:                  0XFFFFD0823F34E080
APCTEST -		Current thread K APC pending:    0
APCTEST -		Current thread K APC list empty: 1
APCTEST -		Current thread U APC pending:    0
APCTEST -		Current thread U APC list empty: 0

APCTEST -		New thread:                      0XFFFFD0823E0A5080
APCTEST -		New thread K APC pending:        1
APCTEST -		New thread K APC list empty:     0
APCTEST -		New thread U APC pending:        0
APCTEST -		New thread U APC list empty:     0

APCTEST -		APC INT:                         0CB - CBFreeOldestDataBlock - Avail bytes before: 0xf58
CB - CBFreeOldestDataBlock - Discarding block: start 0XFFFFF804835EA468, length (not counting hdr) 0x30 bytes
CB - CBFreeOldestDataBlock - Avail bytes after:  0xf90
CB - CBXtractFromStart - Xtracting.
    current block start:       0XFFFFF804835EA4A0
    length (not counting hdr): 0x38
    source:                    0XFFFFF804835EA4A8
    dest:                      0XFFFFE1049E5B6540
    len:                       0x38


APCTEST - DELIVER APC trace
ffffd0823e0a5080

APCTEST -		Current IRQL:                    0x1
APCTEST -		Caller address:                  0XFFFFF804ECCA267B
APCTEST -		Trap frame:                      0XFFFFE1049E5B63D0
APCTEST -		Reserved:                        0000000000000000
APCTEST -		PreviousMode:                    0

APCTEST -		Thread:                          0XFFFFD0823E0A5080
APCTEST -		Thread K APC pending:            1
APCTEST -		Thread K APC list empty:         0
APCTEST -		Thread U APC pending:            0
APCTEST -		Thread U APC list empty:         0CB - CBFreeOldestDataBlock - Avail bytes before: 0xf90
CB - CBFreeOldestDataBlock - Discarding block: start 0XFFFFF804835EA4A0, length (not counting hdr) 0x38 bytes
CB - CBFreeOldestDataBlock - Avail bytes after:  0xfd0
CB - CBXtractFromStart - Xtracting.
    current block start:       0XFFFFF804835EA4E0
    length (not counting hdr): 0x18
    source:                    0XFFFFF804835EA4E8
    dest:                      0XFFFFE1049E5B6540
    len:                       0x18


APCTEST - KERNEL ROUTINE trace

ffffd0823e0a5080

APCTEST -		Thread:                          0XFFFFD0823E0A5080
APCTEST -		Thread K APC pending:            0
APCTEST -		Thread K APC list empty:         1
APCTEST -		Thread U APC pending:            0
APCTEST -		Thread U APC list empty:         0CB - CBFreeOldestDataBlock - Avail bytes before: 0xfd0
CB - CBFreeOldestDataBlock - Discarding block: start 0XFFFFF804835EA4E0, length (not counting hdr) 0x18 bytes
CB - CBFreeOldestDataBlock - Avail bytes after:  0xff0
CB - CBXtractFromStart - Xtracting.
    current block start:       0XFFFFF804835EA500
    length (not counting hdr): 0x8
    source:                    0XFFFFF804835EA508
    dest:                      0XFFFFE1049E5B6540
    len:                       0x8

APCTEST - TRACE MESSAGE: Returned from KeLowerIrqlCB - CBFreeOldestDataBlock - Avail bytes before: 0xff0
CB - CBFreeOldestDataBlock - Discarding block: start 0XFFFFF804835EA500, length (not counting hdr) 0x8 bytes
CB - CBFreeOldestDataBlock - Avail bytes after:  0x1000
driver!ApcSpuriousIntTest+0x348:
fffff804`835e1a18 8b442444        mov     eax,dword ptr [rsp+44h]
