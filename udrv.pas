unit udrv;

{$mode delphi} {$H+}

interface

uses
  windows,sysutils;

function LoadDriver(szDriverPath:string;szDriverSvc  :string= '_driver'):boolean;
function UnloadDriver(szDriverSvc  :string= '_driver'):boolean;
function OpenHandle(filename:string):thandle;

implementation

function LoadDriver(szDriverPath:string;szDriverSvc  :string= '_driver'):boolean;
var
  ServiceMan   :SC_HANDLE= thandle(-1);
  ServicePtr  :SC_HANDLE= thandle(-1);
  boolRetVal  :BOOL = FALSE;

begin
  writeln('LoadDriver');
  if szDriverPath='' then exit;
  //szDriverSvc = ExtractService(szDriverPath);
  ServiceMan  := OpenSCManager(nil, nil, SC_MANAGER_CREATE_SERVICE);
  if ServiceMan <> thandle(-1) then
    begin
    ServicePtr := CreateServiceA(ServiceMan, pchar(szDriverSvc), pchar(szDriverSvc),
		    SERVICE_START or SERVICE_DELETE or SERVICE_STOP,
		    SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
		    SERVICE_ERROR_IGNORE, pchar(szDriverPath), nil,nil, nil, nil, nil);
    if ServicePtr <>thandle(-1) then
      begin
	writeln('registered service successfully: '+szDriverSvc);
	if  StartService(ServicePtr, 0, nil) = TRUE then
          begin
		writeln('started service successfully');
		boolRetVal := TRUE;
          end //StartService
          else writeln('LoadDriver(StartService): GetLastError() -> '+ inttostr(GetLastError));
	CloseServiceHandle(ServicePtr);
      end //if ServicePtr <>thandle(-1) then
     else writeln('LoadDriver(CreateServiceA): GetLastError() ->  '+ inttostr(GetLastError));
    CloseServiceHandle(ServiceMan);
  end; //if ServiceMan <> thandle(-1) then
  result:= boolRetVal;
end;

function UnloadDriver(szDriverSvc  :string= '_driver'):boolean;
var
  //szDriverSvc  :string= 'zam';
  ServiceMan   :SC_HANDLE= thandle(-1);
  ServicePtr  :SC_HANDLE= thandle(-1);
  boolRetVal  :BOOL = FALSE;
  ServiceStat  :SERVICE_STATUS ;

begin
  if szDriverSvc='' then exit;
  fillchar(ServiceStat,sizeof(ServiceStat),0);
  ServiceMan  := OpenSCManager(nil, nil, SC_MANAGER_CREATE_SERVICE);
  if ServiceMan <> thandle(-1) then
    begin
	ServicePtr := OpenServiceA(ServiceMan, pchar(szDriverSvc), SERVICE_STOP or SERVICE_DELETE);
	if ( ServicePtr <> thandle(-1) ) then
        begin
		ControlService(ServicePtr, SERVICE_CONTROL_STOP, @ServiceStat);
		if  DeleteService(ServicePtr) <> TRUE
                    then  writeln('failed to delete service, cleanup manually!')
		    else  writeln('deleted service successfully: '+szDriverSvc);
		CloseServiceHandle(ServicePtr);
		boolRetVal := TRUE;

        end;//if ( ServicePtr <> thandle(-1) ) then
	CloseServiceHandle(ServiceMan);

 end; //if ServiceMan <> thandle(-1) then
  result:= boolRetVal;
end;

function OpenHandle(filename:string):thandle;
begin
	result:= CreateFileA(pchar(filename),GENERIC_READ or GENERIC_WRITE,
		0, nil, OPEN_EXISTING,	FILE_ATTRIBUTE_NORMAL, 0);
end;

end.

