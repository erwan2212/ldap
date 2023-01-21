program certfpc;

uses windows,sysutils,schannel,
  rcmdline in '..\rcmdline-master\rcmdline.pas', advapi32;

const
  CERT_STORE_PROV_MEMORY = (LPCSTR(2));
  CERT_STORE_ADD_REPLACE_EXISTING                    = 3;
  CERT_STORE_PROV_SYSTEM_A = (LPCSTR(9));
  CERT_STORE_PROV_SYSTEM_W =  (LPCSTR(10));
  CERT_STORE_PROV_SYSTEM = CERT_STORE_PROV_SYSTEM_W;
  CERT_SYSTEM_STORE_CURRENT_USER  = $00010000;
  CERT_SYSTEM_STORE_LOCAL_MACHINE = $00020000;
  //
const
  CERT_KEY_PROV_HANDLE_PROP_ID        = 1;
  CERT_KEY_PROV_INFO_PROP_ID          = 2;
  CERT_SHA1_HASH_PROP_ID              = 3;
  CERT_MD5_HASH_PROP_ID               = 4;
  CERT_HASH_PROP_ID                   = CERT_SHA1_HASH_PROP_ID;
  CERT_KEY_CONTEXT_PROP_ID            = 5;
  CERT_KEY_SPEC_PROP_ID               = 6;
  CERT_IE30_RESERVED_PROP_ID          = 7;
  CERT_PUBKEY_HASH_RESERVED_PROP_ID   = 8;
  CERT_ENHKEY_USAGE_PROP_ID           = 9;
  CERT_CTL_USAGE_PROP_ID              = CERT_ENHKEY_USAGE_PROP_ID;
  CERT_NEXT_UPDATE_LOCATION_PROP_ID   = 10;
  CERT_FRIENDLY_NAME_PROP_ID          = 11;
  CERT_PVK_FILE_PROP_ID               = 12;
// Note, 32 - 34 are reserved for the CERT, CRL and CTL file element IDs.
  CERT_FIRST_RESERVED_PROP_ID         = 13;
  CERT_SIGNATURE_HASH_PROP_ID=15;
  CERT_KEY_IDENTIFIER_PROP_ID = 20;
  CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID     = 24;
  CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID    = 25;
 const
  CERT_NAME_SIMPLE_DISPLAY_TYPE=4;
  CERT_NAME_ISSUER_FLAG=$1;
 const
  SHA1_HASH_STRING_LENGTH=40;
  CRYPT_STRING_HEXRAW=$0000000c;

  type
    PPCCERT_CONTEXT = ^PCCERT_CONTEXT;

const
  REPORT_NO_PRIVATE_KEY                 = $0001;
  REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY = $0002;
  EXPORT_PRIVATE_KEYS                   = $0004;
  PKCS12_INCLUDE_EXTENDED_PROPERTIES    = $0010;

  // Password to protect PFX file
  WidePass: WideString = '';

  //
  function CertGetNameStringA(pCertContext: PCCERT_CONTEXT;
                           dwType: DWORD;
                           dwFlags: DWORD;
                           pvTypePara: Pointer;
                           pszNameString: LPTSTR;
                           cchNameString: DWORD): DWORD; stdcall;external 'crypt32.dll';

  function CertGetCertificateContextProperty(pCertContext :PCCERT_CONTEXT;
                                           dwPropId :DWORD;
                                           pvData :PVOID;
                                           pcbData :PDWORD):BOOL ; stdcall;external 'crypt32.dll';

  function CertEnumCertificateContextProperties(pCertContext :PCCERT_CONTEXT;
                                                dwPropId :DWORD):DWORD ; stdcall;external 'crypt32.dll';

  function CertEnumCertificatesInStore(hCertStore :HCERTSTORE;
                                     pPrevCertContext :PCCERT_CONTEXT
                                     ):PCCERT_CONTEXT ; stdcall;external 'crypt32.dll';
  //

function CertOpenStore(lpszStoreProvider: LPCSTR;
  dwEncodingType: DWORD;
  hCryptProv: HCRYPTPROV;
  dwFlags: DWORD;
  const pvPara: PVOID): HCERTSTORE; stdcall;external 'crypt32.dll';

 function CertAddCertificateLinkToStore(hCertStore: HCERTSTORE;
   pCertContext: PCCERT_CONTEXT; dwAddDisposition: DWORD;
   ppStoreContext: PPCCERT_CONTEXT): BOOL; stdcall;external 'crypt32.dll';

 function CertFindCertificateInStore(hCertStore :HCERTSTORE;
                                    dwCertEncodingType :DWORD;
                                    dwFindFlags :DWORD;
                                    dwFindType :DWORD;
                                    pvFindPara :pointer;
                                    pPrevCertContext :PCCERT_CONTEXT
                                    ):PCCERT_CONTEXT ; stdcall; external 'crypt32.dll';

 function PFXExportCertStoreEx(hStore: HCERTSTORE;
                              var pPFX: CRYPT_DATA_BLOB;
                              szPassword: LPCWSTR;
                              pvPra: Pointer;
                              dwFlags: DWORD): BOOL; stdcall; external 'Crypt32.dll';
var
  cmd: TCommandLineReader;

 procedure EnumCertificates(storename:string);
 var
   hStore: HCERTSTORE=thandle(-1);
   CertContext: PCCERT_CONTEXT;
   CertPropId: DWORD;
   Data: array[0..511] of Char;
   DataLen: DWORD;
   i: Integer;
   p:pwidechar;
 begin
   try

     hStore := CertOpenSystemStorew(0, pwidechar(widestring(StoreName)));
     if hStore = thandle(-1) then
       RaiseLastWin32Error;
     try
       CertContext := CertEnumCertificatesInStore(hStore, nil);
       while CertContext <> nil do
       begin
         writeln('*********************************************');
         if CertGetNameStringA(CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil,data, 512) <> 0
            then Writeln('SUBJECT_CERT_NAME: ', data);
         if CertGetNameStringA(CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nil,data, 512) <> 0
            then Writeln('ISSUER_CERT_NAME: ', data);
         //p:=getmem(CertContext.pCertInfo.Subject.cbData);
         //copymemory(p,CertContext.pCertInfo.Subject.pbData,CertContext.pCertInfo.Subject.cbData );
         //writeln(strpas(p));
         //DisplayCertContext(CertContext);
         CertPropId := CertEnumCertificateContextProperties(CertContext, 0);
         while CertPropId <> 0 do
         begin
           DataLen := 512;
           //Writeln(Format('CertPropId: %d', [CertPropId]));
           case CertPropId of
           CERT_KEY_PROV_HANDLE_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Writeln(Format('KEY_PROV_HANDLE: $%.8x', [PDWORD(@Data[0])^]));
           end;
           {
           CERT_KEY_PROV_INFO_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             with PCRYPT_KEY_PROV_INFO(@Data[0])^ do
             begin
               Writeln(Format('pwszContainerName = %s', [pwszContainerName]));
               Writeln(Format('pwszProvName = %s', [pwszProvName]));
               Writeln(Format('dwFlags = %d', [dwFlags]));
               Writeln(Format('cProvParams = %d', [cProvParam]));
               //Writeln(Format('rgProvParam', [rgProvParam]));
               Writeln(Format('dwKeySpec = %d', [dwKeySpec]));
             end;
             //Writeln(Format('KEY_PROV_INFO: %d', [@Data[0]])); //[EConvertError]
           end;
           }
           CERT_FRIENDLY_NAME_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Writeln(Format('FRIENDLY_NAME: %s', [PwideChar(@Data[0])]));
           end;
           CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('SUBJECT_PUBLIC_KEY_MD5_HASH: ');
             for i := 1 to DataLen do
               Write(Format('%.2x ', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('ISSUER_PUBLIC_KEY_MD5_HASH: ');
             for i := 1 to DataLen do
               Write(Format('%.2x ', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           CERT_SIGNATURE_HASH_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('SIGNATURE_HASH: ');
             for i := 1 to DataLen do
               Write(Format('%.2x ', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           CERT_KEY_IDENTIFIER_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('KEY_IDENTIFIER: ');
             for i := 1 to DataLen do
               Write(Format('%.2x ', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           CERT_SHA1_HASH_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('SHA1_HASH: ');
             for i := 1 to DataLen do
               Write(Format('%.2x ', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           CERT_MD5_HASH_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('MD5_HASH: ');
             for i := 1 to DataLen do
               Write(Format('%.2x ', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           else
           end;
           CertPropId := CertEnumCertificateContextProperties(CertContext,
             CertPropId);
         end;
         CertContext := CertEnumCertificatesInStore(hStore, CertContext);
       end;
 //      if GetLastError <> CRYPT_E_NOT_FOUND then
 //        RaiseLastWin32Error;
     finally
       CertCloseStore(hStore, 0);
     end;
   except
     on E: Exception do
     begin
       ExitCode := 1;
       Writeln(Format('[%s] %s', [E.ClassName, E.Message]));
     end;
   end;

 end;

function ExportCert(store:widestring;subject:string;sha1:string=''):boolean;
var
  pStore, pStoreTmp: HCERTSTORE;
  pCert: PCCERT_CONTEXT;
  PFX,
  Hash: CRYPT_INTEGER_BLOB;

  ChainPara: CERT_CHAIN_PARA;
  EnhkeyUsage: CERT_ENHKEY_USAGE;
  CertUsage: CERT_USAGE_MATCH;
  pChainContext: PCCERT_CHAIN_CONTEXT;
  ppCertSimpleChain: ^PCERT_SIMPLE_CHAIN;
  ppCertChainElement: ^PCERT_CHAIN_ELEMENT;

  i, j: Integer;
  Buffer: array of char; //RawByteString;
  str:string;
  junk:dword=0;
  dest:thandle;
  dwHashDataLength:dword=0;
begin
  writeln('store:'+store);
  writeln('subject:'+subject);
  result:=false;
  pStore := thandle(-1);
  pStoreTmp := thandle(-1);
  pCert := nil;

  PFX.pbData := nil;
  PFX.cbData := 0;

  // Open system certificate store
  pStore := CertOpenSystemStoreW(0, pwidechar(store));
  {
  pStore := CertOpenStore(
       CERT_STORE_PROV_SYSTEM,
       0,                      // Encoding type not needed
                               // with this PROV.
       0,                   // Accept the default HCRYPTPROV.
       CERT_SYSTEM_STORE_CURRENT_USER,
                               // Set the system store location in
                               // the registry.
       pchar(store));                 // Could have used other predefined
                               // system stores
                               // including Trust, CA, or Root.
  }
  // Open in-mem temporal certificate store
  pStoreTmp := CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nil);

  // HEX SHA1 Hash of the certificate to find
  if sha1<>'' then
    begin
      sha1:=stringreplace(sha1,' ','',[rfReplaceAll, rfIgnoreCase]);
      //sha1 := '001AA5081EDA97805B4D6A9B6730CDBEE39761C3';
      if CryptStringToBinaryA(pchar(sha1), SHA1_HASH_STRING_LENGTH,  CRYPT_STRING_HEXRAW,    nil, @dwHashDataLength, nil,nil) then
         begin
           setlength(buffer,dwHashDataLength);
           if CryptStringToBinaryA(pchar(sha1),SHA1_HASH_STRING_LENGTH,CRYPT_STRING_HEXRAW,@buffer[0],@dwHashDataLength,nil, nil) then
              begin
              Hash.cbData := Length(Buffer);
              Hash.pbData := pbyte(@Buffer[0]);
              end;
         end;

  pCert := CertFindCertificateInStore(pStore,
                                      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                                      0,
                                      CERT_FIND_SHA1_HASH,
                                      @Hash,
                                      nil);

  end;

    if subject<>'' then
    begin
    setlength(buffer,255);
    str:=subject; //'mycomputer';
    copymemory(@buffer[0],@str[1],length(str));
    pCert := CertFindCertificateInStore(pStore,
                                      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                                      0,
                                      CERT_FIND_SUBJECT_STR_A ,//CERT_FIND_SUBJECT_STR CERT_FIND_SUBJECT_NAME
                                      @Buffer[0],
                                      nil);
    end;

    if pcert=nil then
     begin
       writeln('CertFindCertificateInStore failed');
       exit;
     end;

  // Now let's get the certificate's chain context
  EnhkeyUsage.cUsageIdentifier := 0;
  EnhkeyUsage.rgpszUsageIdentifier := nil;
  CertUsage.dwType := USAGE_MATCH_TYPE_AND;
  CertUsage.Usage := EnhkeyUsage;
  ChainPara.cbSize := SizeOf(CERT_CHAIN_PARA);
  ChainPara.RequestedUsage := CertUsage;

  if CertGetCertificateChain(0, pCert, nil, 0,
                          ChainPara, 0, nil, pChainContext)=false then
                          begin
                            writeln('CertGetCertificateChain failed');
                            exit;
                          end;

  // Iterate the chain context and add every certificate to mem-store
  ppCertSimpleChain := Pointer(pChainContext^.rgpChain);
  for i := 1 to pChainContext^.cChain do
  begin
    ppCertChainElement := pointer(ppCertSimpleChain^.rgpElement);
    for j := 1 to ppCertSimpleChain^.cElement do
    begin
      if CertAddCertificateLinkToStore(pStoreTmp,
                                    ppCertChainElement^.pCertContext,
                                    CERT_STORE_ADD_REPLACE_EXISTING,
                                    nil)=false then
                                    begin
                                      writeln('CertAddCertificateLinkToStore failed');
                                      exit;
                                    end;
      Inc(ppCertChainElement);
    end;
    Inc(ppCertSimpleChain);
  end;

  // Save to PFX ...
  PFX.pbData := nil;
  PFX.cbData := 0;
  // First a call with an empty BLOB to get the space needed
  if PFXExportCertStoreEx(pStoreTmp,
                       PFX,
                       PWideChar(WidePass),
                       nil,
                       EXPORT_PRIVATE_KEYS +
                       //REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY +
                       //REPORT_NO_PRIVATE_KEY +
                       PKCS12_INCLUDE_EXTENDED_PROPERTIES)=false then
                       begin
                         //0x8009000B (NTE_BAD_KEY_STATE)
                         writeln('1.PFXExportCertStoreEx failed:'+inttohex(getlasterror,8));
                         exit;
                       end;

  // OK, reserve the needed memory
  GetMem(PFX.pbData, PFX.cbData);

  // Fill data
  if PFXExportCertStoreEx(pStoreTmp,
                       PFX,
                       PWideChar(WidePass),
                       nil,
                       EXPORT_PRIVATE_KEYS +
                       //REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY +
                       //REPORT_NO_PRIVATE_KEY +
                       PKCS12_INCLUDE_EXTENDED_PROPERTIES)=false then
                       begin
                         writeln('2.PFXExportCertStoreEx failed:'+inttohex(getlasterror,8));
                         exit;
                       end;

  // Now PFX.pbData points to PFX information of length PFX.cbData
  // Write it to a temporary file that replaces your PEM files.
 if subject='' then subject:=sha1;
 Dest:=CreateFileA(PChar(subject+'.pfx'), GENERIC_WRITE, 0, nil, CREATE_ALWAYS, 0, 0);
 //writeln(PFX.cbData);
 WriteFile(Dest, PFX.pbData^, PFX.cbData, junk, nil);
 if junk=0 then writeln('WriteFile failed');
 CloseHandle(dest);

  // Free memory used
  // I deliberately did not check whether
  // previous API calls returned an error.
  // You should check.
  // Take a look to Microsoft's documentation for functions results
  // and GetLastError function for error code
  CertFreeCertificateChain(pChainContext);
  CertFreeCertificateContext(pCert);
  CertCloseStore(pStoreTmp, 0);
  CertCloseStore(pStore, 0);
  FreeMem(PFX.pbData);
  result:=true;
end;

begin
 //
  cmd := TCommandLineReader.create;
    cmd.declareflag ('export','');
    cmd.declareflag ('enum','');
    cmd.declareString('store', 'MY');
    cmd.declareString('subject', '');
    cmd.declareString('hash', '');

    cmd.parse(cmdline);
 //
 if (cmd.existsProperty('export')) and (cmd.existsProperty('subject'))
    then if ExportCert(widestring(cmd.readstring('store')),cmd.readstring('subject'))=true
         then writeln('ok') else writeln('nok');

  if (cmd.existsProperty('export')) and (cmd.existsProperty('hash'))
    then if ExportCert(widestring(cmd.readstring('store')),'',cmd.readstring('hash'))=true
         then writeln('ok') else writeln('nok');

  if cmd.existsProperty('enum')
     then EnumCertificates(cmd.readstring('store'));
end.

