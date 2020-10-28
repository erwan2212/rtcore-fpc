unit uutils;

{$mode delphi}

interface

uses
  windows, SysUtils;

type toffsets=record
      nextFlink:word; //aka activeprocesslinks
      Token:word;
      SignatureProtect:word;
      ImageFileName:word;
end;

  var
  offsets:toffsets;
  ReleaseID:string;

  function SetOffsets:boolean;
  function ReadRegEntry(strSubKey,strValueName: string): string;

implementation

function ReadRegEntry(strSubKey,strValueName: string): string;
 var
  Key: HKey;
  Buffer: array[0..255] of char;
  Size: cardinal;
 begin
  Result := '';
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
 //writeln('SetOffsets');
 result:=true;
 with offsets do
 begin
 fillchar(offsets,sizeof(offsets),0);
 case strtoint(releaseid) of
 7600:begin    nextFlink :=$0188;SignatureProtect :=$000; Token :=$208;ImageFileName :=$2e0; end; //7
 7601:begin    nextFlink :=$0188;SignatureProtect :=$000; Token :=$208;ImageFileName :=$2e0; end; //7sp1
 9200:begin    nextFlink :=$02e8;SignatureProtect :=$0648; Token :=$348;ImageFileName :=$438; end; //8.0
 9600:begin    nextFlink :=$02e8;SignatureProtect :=$0678; Token :=$348;ImageFileName :=$438; end; //8.1
 //
 1703:begin    nextFlink :=$02e8;SignatureProtect :=$06c8; Token :=$358;ImageFileName :=$450; end;
 1709:begin    nextFlink :=$02e8;SignatureProtect :=$06c8; Token :=$358; ImageFileName :=$450; end;
 1803:begin    nextFlink :=$02e8;SignatureProtect :=$06c8; Token :=$358; ImageFileName :=$450; end;
 1809:begin    nextFlink :=$02e8;SignatureProtect :=$06c8; Token :=$358; ImageFileName :=$450; end;
 1903:begin    nextFlink :=$02f0;SignatureProtect :=$06f8; Token :=$360; ImageFileName :=$450; end;
 1909:begin    nextFlink :=$02f0;SignatureProtect :=$06f8; Token :=$360; ImageFileName :=$450; end;
 2004:begin    nextFlink :=$0448;SignatureProtect :=$0878; Token :=$4b8; ImageFileName :=$5a8; end;
 //20H2:begin    EprocessNext :=$0448;SignatureProtect :=$0878; Token :=$4b8; end;
 //21H1:begin    EprocessNext :=$0448;SignatureProtect :=$0878; Token :=$4b8; end;
 else result:=false;
 end; //case
 end;//with offsets do
end;

end.

