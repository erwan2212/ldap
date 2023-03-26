program certfpc;

uses windows,sysutils,registry,classes,
  wcrypt2,schannel,
  rcmdline in '..\rcmdline-master\rcmdline.pas',
  cryptutils,
  ddetours;

{$ifdef CPU64}
const POINTER_MASK =$E35A172CD96214A0;
{$endif}
{$ifdef CPU32}
const POINTER_MASK =$E35A172C;
{$endif}

type

UInt32_t = UInt32;

_KEY =record
    pUnknown:pvoid;
    dwUnknow:dword;
    dwFlags:dword;
end;
_pkey=^_key;
_ppkey=^_pkey;

key_data_s=record
 unknown:pvoid;  //xor'ed
 alg:uint32_t;
 flags:uint32_t;
 key_size:uint32_t;
 key_bytes:pvoid;
end;
 pkey_data_s=^key_data_s;

 magic_s=record
 key_data:pkey_data_s;
end;
 pmagic_s=^magic_s;

HCRYPTKEY_=record

 CPGenKey:pointer;       //4
 CPDeriveKey:pointer;    //8
 CPDestroyKey:pointer;   //12
 CPSetKeyParam:pointer;  //16
 CPGetKeyParam:pointer;  //20
 CPExportKey:pointer;    //24
 CPImportKey:pointer;    //28
 CPEncrypt:pointer;      //32
 CPDecrypt:pointer;      //36
 CPDuplicateKey:pointer; //40
 hCryptProv_:HCRYPTPROV;  //44
 magic:pmagic_s; //is XOR-ed with a constant value, 0xE35A172C.
end;
PHCRYPTKEY_=^HCRYPTKEY_;


  //
var
  cmd: TCommandLineReader;

  nCPExportKey:function(
    hProv:HCRYPTPROV;hKey:HCRYPTKEY;hExpKey:HCRYPTKEY;dwBlobType:DWORD;
    dwFlags:DWORD;pbData:PBYTE;pdwDataLen:PDWORD):boolean; stdcall=nil;


  {
  Const SIMPLEBLOB                = 1
  Const PUBLICKEYBLOB             = 6
  Const PRIVATEKEYBLOB            = 7
  Const PLAINTEXTKEYBLOB          = 8
  }
  //see https://github.com/iSECPartners/jailbreak
  function MyCPExportKey(
    hProv:HCRYPTPROV;hKey:HCRYPTKEY;hExpKey:HCRYPTKEY;dwBlobType:DWORD;
    dwFlags:DWORD;pbData:PBYTE;pdwDataLen:PDWORD):boolean; stdcall;
  var
    magic:nativeuint;
    key_data_s:nativeuint;
    p:pointer=nil;
    d:dword=1234;
    ppKey:_ppkey = nil;
    dwFlags_:dword=0;
  begin
    //p:=@d;
    //will display the address of the iptrValue variable,
    //then the address stored in that variable,
    //and then the value stored at that address
    //0148F9A4 -> 0148F9A0 -> 1234
    //writeln(Format('%p -> %p -> %d', [@p, p, dword(p^)]));
    //writeln(inttohex(nativeuint(pointer(p)),8)); //address stored in p aka 0148F9A0
    //writeln(inttohex(nativeuint(pointer(@p)),8)); //address of p aka 0148F9A4
    //writeln('MyCPExportKey');
    //writeln('dwBlobType:'+inttostr(dwBlobType));
    //
    ppKey := _ppkey(hKey xor POINTER_MASK );
    dwFlags_:= ppkey^.dwFlags ;
    //writeln('dwFlags_:'+inttostr(dwFlags_));
    ppkey^.dwFlags:=$4001;
    //*(DWORD*)(*(DWORD*)(*(DWORD*)(hKey +0x2C) ^ 0xE35A172C) + 8)
    //writeln('pointer(hkey):'+inttohex(nativeuint(pointer(@hkey)),8));
    result:=nCPExportKey(hProv,hKey,hExpKey,dwBlobType,dwFlags,pbData,pdwDataLen);
    ppkey^.dwFlags:=dwflags;
  end;

//certutil -v blob.bin
function SaveBlob(RootKey: HKEY; const Key: string):boolean;
const
  marker:array [0..7] of byte=($20,00,00,00,01,00,00,00);
var
  Registry: TRegistry;
  Bytes: TBytes;
  hFile:thandle=thandle(-1);
  size:dword=0;
  pos:dword=0;
  i:word;
begin
  result:=false;
  writeln(key);
  Registry := TRegistry.Create;
  Try
    Registry.RootKey := RootKey;
    if Registry.OpenKeyReadOnly(Key)=true then
       begin
       SetLength(Bytes, Registry.GetDataSize('blob'));
       writeln(length(bytes));
       size:= registry.ReadBinaryData('blob',bytes[0],length(bytes)); //Pointer(Bytes)^
       if size>0 then
          begin
          writeln(size);
          for i:=0 to size -1 do
            begin
              if comparemem(@bytes[i],@marker[0],sizeof(marker))= true then pos:=i+sizeof(marker)+4;
            end;
          writeln(pos);
          //https://blog.nviso.eu/2019/08/28/extracting-certificates-from-the-windows-registry/
          //locate 20 00 00 00 01 00 00 00 xx xx xx xx and truncate to start with 30 xx
          hFile := CreateFile(PChar('blob.cer'), GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, nil, CREATE_ALWAYS , FILE_ATTRIBUTE_NORMAL, 0);
          if hfile<>thandle(-1) then
             begin
             if WriteFile(hfile, bytes[pos], length(bytes)-pos, size, nil) then result:=true;
             CloseHandle(hfile);
             end;
          end;
       end;
  Finally
    Registry.Free;
  End;
end;

procedure EnumSubKeys(RootKey: HKEY; const Key: string);
var
  Registry: TRegistry;
  SubKeyNames: TStringList;
  Name: string;
begin
  writeln(key);
  Registry := TRegistry.Create;
  Try
    Registry.RootKey := RootKey;
    Registry.OpenKeyReadOnly(Key);
    SubKeyNames := TStringList.Create;
    Try
      Registry.GetKeyNames(SubKeyNames);
      for Name in SubKeyNames do
        Writeln(Name);
    Finally
      SubKeyNames.Free;
    End;
  Finally
    Registry.Free;
  End;
end;

begin

    cmd := TCommandLineReader.create;
    cmd.declareflag ('export','export to a pfx file');
    cmd.declareFlag ('force','will hook cpexportkey to export non exportable pvk');
    cmd.declareflag ('dumpcert','dump from registry to a cer file');
    //cmd.declareflag ('import','');
    cmd.declareflag ('mkcert','');
    cmd.declareflag ('enumcerts','enumerate certificates');
    cmd.declareflag ('enumstores','enumerate stores');
    cmd.declareflag ('delete','');
    cmd.declareString('store', 'certificate store','MY');
    cmd.declareString('subject', 'subject used when exporting or deleting');
    cmd.declareString('hash', 'sha1 used when exporting or deleting');
    cmd.declarestring('profile', 'user or machine','user' );
    cmd.declarestring('password', 'cert password' );
    cmd.declarestring('filename', 'cert filename' );

    cmd.parse(cmdline);

    if cmd.readstring('profile')='machine' then CERT_SYSTEM_STORE:=CERT_SYSTEM_STORE_LOCAL_MACHINE;
 //
 if cmd.existsProperty('enumstores') then
 begin
   //EnumSubKeys(HKEY_CURRENT_USER ,'software\microsoft\systemcertificates');
   if enumstore =true then writeln('ok') else writeln('nok');
 end;

 if cmd.existsProperty('dumpcert') then
 begin
    if saveblob(HKEY_CURRENT_USER ,'software\microsoft\systemcertificates\'+cmd.readstring('store')+'\certificates\'+cmd.readstring('hash'))=true
       then writeln('ok') else writeln('not ok');
 end;

 if (cmd.existsProperty('export')) and (cmd.existsProperty('subject'))
    then
    begin
    if cmd.existsProperty('force') then
       begin
       LoadLibrary ('rsaenh.dll'); //or else intercept may/will fail
       @nCPExportKey    :=ddetours.InterceptCreate(GetProcAddress(GetModuleHandle('rsaenh.dll'), 'CPExportKey') , @myCPExportKey);
       end;
       if ExportCert(widestring(cmd.readstring('store')),cmd.readstring('subject'),'')=true
         then writeln('ok') else writeln('nok');
    end;

  if (cmd.existsProperty('export')) and (cmd.existsProperty('hash'))
    then
    begin
       if cmd.existsProperty('force') then
          begin
          LoadLibrary ('rsaenh.dll'); //or else intercept may/will fail
          @nCPExportKey    :=ddetours.InterceptCreate(GetProcAddress(GetModuleHandle('rsaenh.dll'), 'CPExportKey') , @myCPExportKey);
          end;
       if ExportCert(widestring(cmd.readstring('store')),'',cmd.readstring('hash'))=true
         then writeln('ok') else writeln('nok');
    end;

  if cmd.existsProperty('enumcerts')
     then EnumCertificates(cmd.readstring('store'));

  if (cmd.existsProperty('delete')) and (cmd.existsProperty('subject'))
     then if DeleteCertificate(widestring(cmd.readstring('store')),cmd.readstring('subject'))=true
          then writeln('ok') else writeln('nok');

   if (cmd.existsProperty('delete')) and (cmd.existsProperty('hash'))
     then if DeleteCertificate(widestring(cmd.readstring('store')),'',cmd.readstring('hash'))=true
          then writeln('ok') else writeln('nok');
   {
   if cmd.existsProperty('import')
      then if ImportCert(widestring(cmd.readstring('store')),cmd.readstring('filename'),widestring(cmd.readstring('password')))=true
           then writeln('ok') else writeln('nok');
   }

     //use cmd.readstring('subject')
     if cmd.existsProperty('mkcert')
       then DoCreateCertificate (cmd.readstring('store'),'_Root Authority','CN=Toto8,E=toto@example.com');

end.

