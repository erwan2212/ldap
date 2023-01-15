program exportcert;

uses windows,sysutils,schannel;

const
  CERT_STORE_PROV_MEMORY = (LPCSTR(2));
  CERT_STORE_ADD_REPLACE_EXISTING                    = 3;

  type
    PPCCERT_CONTEXT = ^PCCERT_CONTEXT;

const
  REPORT_NO_PRIVATE_KEY                 = $0001;
  REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY = $0002;
  EXPORT_PRIVATE_KEYS                   = $0004;
  PKCS12_INCLUDE_EXTENDED_PROPERTIES    = $0010;

  // Password to protect PFX file
  WidePass: WideString = '';

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


function ExportCert(store:widestring;subject:string):boolean;
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
begin
  result:=false;
  pStore := thandle(-1);
  pStoreTmp := thandle(-1);
  pCert := nil;

  PFX.pbData := nil;
  PFX.cbData := 0;

  // Open system certificate store
  pStore := CertOpenSystemStore(0, pwidechar(store));

  // Open in-mem temporal certificate store
  pStoreTmp := CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nil);

  // HEX SHA1 Hash of the certificate to find
  setlength(buffer,255);
  str:=subject; //'mycomputer';
  copymemory(@buffer[0],@str[1],length(str));
  //Buffer := 'CN = erwan'; //'001AA5081EDA97805B4D6A9B6730CDBEE39761C3';
  Hash.cbData := Length(Buffer);
  Hash.pbData := @Buffer[0];
  // Find it
  {
  pCert := CertFindCertificateInStore(pStore,
                                      X509_ASN_ENCODING,
                                      0,
                                      CERT_FIND_SHA1_HASH,
                                      @Hash,
                                      nil);
  }
    pCert := CertFindCertificateInStore(pStore,
                                      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                                      0,
                                      CERT_FIND_SUBJECT_STR_A ,//CERT_FIND_SUBJECT_STR CERT_FIND_SUBJECT_NAME
                                      @Buffer[0],
                                      nil);
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
  if ExportCert(widestring(paramstr(1)),paramstr(2))=true then writeln('ok') else writeln('nok');
end.

