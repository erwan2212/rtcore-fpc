unit untdll;

{$mode delphi}    {$H+}

interface

uses
  windows, SysUtils;

type NTSTATUS = integer;


  OBJECT_INFORMATION_CLASS = (ObjectBasicInformation,ObjectNameInformation,ObjectTypeInformation,ObjectAllTypesInformation,ObjectHandleInformation );

  UNICODE_STRING=packed record
           Length       :Word;
           MaximumLength:Word;
           Buffer       :PWideChar;
        end;

        OBJECT_NAME_INFORMATION=UNICODE_STRING;

        OBJECT_BASIC_INFORMATION = record
                 Attributes:ULONG;
                 GrantedAccess:ACCESS_MASK;
                 HandleCount:ULONG;
                 PointerCount:ULONG;
                 PagedPoolUsage: ULONG;
                     NonPagedPoolUsage: ULONG;
                     Reserved: array[0..2] of ULONG;
                     NameInformationLength: ULONG;
                     TypeInformationLength: ULONG;
                     SecurityDescriptorLength: ULONG;
                     CreateTime: LARGE_INTEGER;
                   end;


function NtSuspendProcess(ProcessID:Dword):DWORD; stdcall;external 'ntdll.dll';
function NtGetNextThread(
        ProcessHandle:thandle;
        ThreadHandle:thandle;
        DesiredAccess:ACCESS_MASK;
        HandleAttributes:ulong;
        Flags:ulong;
        var NewThreadHandle:thandle
       ):NTSTATUS;stdcall;external 'ntdll.dll';
function NtGetNextProcess(
        ProcessHandle:thandle;
        DesiredAccess:ACCESS_MASK;
        HandleAttributes:ulong;
        Flags:ulong;
        var NewProcessHandle:thandle
       ):NTSTATUS;stdcall;external 'ntdll.dll';
function NtQueryObject(ObjectHandle:cardinal; ObjectInformationClass:OBJECT_INFORMATION_CLASS; ObjectInformation:pointer; Length:ULONG;ResultLength:PDWORD):THandle;stdcall;external 'ntdll.dll';

function QueryFullProcessImageNameA(hProcess: HANDLE; dwFlags: DWORD;  lpExeName: LPTSTR;
 var dwsize: DWORD): BOOL; stdcall; external 'KERNEL32.dll';
//
function GetNextThread(process_handle:thandle):boolean;
function GetNextProcess():boolean;

implementation

function GetNextThread(process_handle:thandle):boolean;
type
 TGetThreadId=function(thread:thandle):NTSTATUS;stdcall;//external 'kernel32.dll';

var
newth,th:thandle;
ret:NTSTATUS;
start,teb:dword;
tid:dword;
GetThreadId:TGetThreadId;
begin
newth:=thandle(-1);
result:=false;
//https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms686769(v=vs.85).aspx
//THREAD_ALL_ACCESS
ret:=NtGetNextThread(process_handle ,0,MAXIMUM_ALLOWED,0,0,newth); //THREAD_ALL_ACCESS  THREAD_QUERY_INFORMATION
//if ret<>0 then writeln(inttohex(ret,sizeof(ret)));
if ret<>0 then exit;
GetThreadId :=GetProcAddress (loadlibrary('kernel32.dll'),'GetThreadId');
//0x8000001A STATUS_NO_MORE_ENTRIES
while ret=0 do
begin
tid :=GetThreadId(newth);
//GetThreadInfo(process_handle,newth,start,teb);
writeln('tid:'+inttostr(tid));
th:=newth;
ret:=ntGetNextThread(
                   process_handle,
                   th,
                   MAXIMUM_ALLOWED, //THREAD_ALL_ACCESS THREAD_QUERY_INFORMATION
                   0,
                   0,
                   newth  //newth
                   );
closehandle(th); //avoid handle leaking
end;
result:=true;
end;

//not working
function GetNextProcess():boolean;
type
 TGetProcessId=function(ph:thandle):NTSTATUS;stdcall;//external 'kernel32.dll';

var
newth,th:thandle;
ret:NTSTATUS;
start,teb:dword;
tid:dword;
GetProcessId:TGetProcessId;
exename:array[0..MAX_PATH-1] of char;
size:dword=0;
begin
newth:=thandle(-1);
th:=0 ;
result:=false;
ret:=NtGetNextProcess(th ,MAXIMUM_ALLOWED ,0,0,newth); //THREAD_ALL_ACCESS  THREAD_QUERY_INFORMATION MAXIMUM_ALLOWED
//if ret<>0 then writeln(inttohex(ret,sizeof(ret)));
if ret<>0 then exit;
GetProcessId :=GetProcAddress (loadlibrary('kernel32.dll'),'GetProcessId');
//0x8000001A STATUS_NO_MORE_ENTRIES
while ret=0 do
begin
tid :=GetProcessId(newth);
//if GetModuleFileNameEx(newth, 0, Buffer, MAX_PATH) then writeln(buffer);
size:=max_path;
QueryFullProcessImageNameA(newth,0,@exename[0],size);
writeln(inttostr(tid)+';'+strpas(exename));
th:=newth;
ret:=NtGetNextProcess(
                   th,
                   MAXIMUM_ALLOWED,
                   0,
                   0,
                   newth  //newth
                   );
closehandle(th); //avoid handle leaking
end; //while
result:=true;
end;

end.

