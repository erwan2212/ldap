unit crypt32;

{$mode delphi}

interface

uses windows,schannel;


    type
    PPCCERT_CONTEXT = ^PCCERT_CONTEXT;

//
function CryptAcquireCertificatePrivateKey(
             pCert:PCCERT_CONTEXT;
             dwFlags:DWORD;
             pvParameters:pvoid;
             var phCryptProvOrNCryptKey:thandle;
             pdwKeySpec:PDWORD;
             pfCallerFreeProvOrNCryptKey:PBOOL): BOOL; stdcall;external 'crypt32.dll';

   function CertDeleteCertificateFromStore(pCertContext: PCCERT_CONTEXT): BOOL; stdcall;external 'crypt32.dll';

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

 function PFXImportCertStore(pPFX:PCRYPT_DATA_BLOB;szPassword:LPCWSTR;
                              dwFlags:DWORD):HCERTSTORE; stdcall; external 'Crypt32.dll';

//

function CryptStringToBinary(pszString: PChar; cchString: dword; dwFlags: dword;
         pbBinary: pointer; pcbBinary: pdword; pdwSkip: pdword;
         pdwFlags: pdword): boolean; stdcall;external 'crypt32.dll';

function CryptBinaryToString(pbBinary: pointer; cbBinary: dword; dwFlags: dword;
         pszString: PChar; pcchString: pdword): boolean; stdcall;external 'crypt32.dll';

function CryptStringToBinaryA(pszString: PChar; cchString: dword; dwFlags: dword;
         pbBinary: pointer;  pcbBinary: pdword; pdwSkip: pdword;
         pdwFlags: pdword): boolean; stdcall;external 'crypt32.dll';

function CryptBinaryToStringA(pbBinary: pointer; cbBinary: dword; dwFlags: dword;
         pszString: PChar; pcchString: pdword): boolean; stdcall;external 'crypt32.dll';

function CryptStringToBinaryW(pszString: PWideChar; cchString: dword; dwFlags: dword;
         pbBinary: pointer; pcbBinary: pdword; pdwSkip: pdword;
         pdwFlags: pdword): boolean; stdcall;external 'crypt32.dll';

function CryptBinaryToStringW(pbBinary: pointer; cbBinary: dword; dwFlags: dword;
         pszString: PWideChar; pcchString: pdword): boolean; stdcall;external 'crypt32.dll';

implementation

end.

