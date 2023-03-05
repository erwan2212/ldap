program certfpc;

uses windows,sysutils,registry,classes,
  wcrypt2,schannel,
  rcmdline in '..\rcmdline-master\rcmdline.pas', cryptutils ;




  //
var
  cmd: TCommandLineReader;

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
    then if ExportCert(widestring(cmd.readstring('store')),cmd.readstring('subject'),'')=true
         then writeln('ok') else writeln('nok');

  if (cmd.existsProperty('export')) and (cmd.existsProperty('hash'))
    then if ExportCert(widestring(cmd.readstring('store')),'',cmd.readstring('hash'))=true
         then writeln('ok') else writeln('nok');

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

     if cmd.existsProperty('mkcert')
       then DoCreateCertificate (cmd.readstring('store'),'_Root Authority','CN=Toto8,E=toto@example.com');

end.

