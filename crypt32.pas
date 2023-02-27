unit crypt32;

{$mode delphi}

interface

uses windows,schannel;

const
  MS_ENHANCED_PROV   = 'Microsoft Enhanced Cryptographic Provider v1.0';
  PROV_RSA_FULL          = 1;
  CRYPT_NEWKEYSET      = $00000008;
  AT_KEYEXCHANGE    = 1;

    type
    PPCCERT_CONTEXT = ^PCCERT_CONTEXT;
    HCRYPTKEY = ULONG_PTR;
    PHCRYPTPROV = ^HCRYPTPROV;
    PHCRYPTKEY  = ^HCRYPTKEY;

    CRYPT_KEY_PROV_PARAM = record
   dwParam:DWORD;
    pbData:pBYTE;
   cbData:DWORD;
  dwFlags:DWORD;
  end;
PCRYPT_KEY_PROV_PARAM=^CRYPT_KEY_PROV_PARAM;

    CRYPT_KEY_PROV_INFO =record
                  pwszContainerName:LPWSTR;
                  pwszProvName:LPWSTR;
                  dwProvType:DWORD;
                  dwFlags:DWORD;
                  cProvParam:DWORD;
                  rgProvParam:PCRYPT_KEY_PROV_PARAM;
                  dwKeySpec:DWORD;
                  end;
    PCRYPT_KEY_PROV_INFO=^CRYPT_KEY_PROV_INFO;

    type
    PCERT_PUBLIC_KEY_INFO = ^CERT_PUBLIC_KEY_INFO;
    CERT_PUBLIC_KEY_INFO = record
    Algorithm :CRYPT_ALGORITHM_IDENTIFIER;
    PublicKey :CRYPT_BIT_BLOB;
  end;

//

function CertGetIntendedKeyUsage(dwCertEncodingType :DWORD;
                                 pCertInfo :PCERT_INFO;
                                 pbKeyUsage :PBYTE;
                                 cbKeyUsage :DWORD):BOOL ; stdcall; external 'crypt32.dll' name 'CertGetIntendedKeyUsage';

function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: LongWord): LongBool; stdcall; external 'advapi32.dll' name 'CryptReleaseContext';

function CryptAcquireContextW(Prov: PHCRYPTPROV; Container: PwideChar; Provider: PwideChar;
         ProvType: LongWord; Flags: LongWord): LongBool; stdcall; external 'advapi32.dll' name 'CryptAcquireContextW';

function CryptAcquireContextA(phProv       :PHCRYPTPROV;
                              pszContainer :PAnsiChar;
                              pszProvider  :PAnsiChar;
                              dwProvType   :DWORD;
                              dwFlags      :DWORD) :BOOL;stdcall; external 'advapi32.dll' name 'CryptAcquireContextA';

function CryptGetUserKey(hProv: HCRYPTPROV; dwKeySpec: DWORD;
         phUserKey: PHCRYPTKEY): BOOL; stdcall;external 'advapi32.dll';

function CryptExportKey(hKey, hExpKey: HCRYPTKEY; dwBlobType, dwFlags: DWORD;
  pbData: LPBYTE; pdwDataLen: PDWORD): BOOL; stdcall;external 'advapi32.dll';

function CryptGenKey(hProv   :HCRYPTPROV;
                     Algid   :ALG_ID;
                     dwFlags :DWORD;
                     phKey   :PHCRYPTKEY) :BOOL;stdcall ;external 'advapi32.dll';


function CryptAcquireCertificatePrivateKey(
             pCert:PCCERT_CONTEXT;
             dwFlags:DWORD;
             pvParameters:pvoid;
             var phCryptProvOrNCryptKey:thandle;
             pdwKeySpec:PDWORD;
             pfCallerFreeProvOrNCryptKey:PBOOL): BOOL; stdcall;external 'crypt32.dll';

   function CertDeleteCertificateFromStore(pCertContext: PCCERT_CONTEXT): BOOL; stdcall;external 'crypt32.dll';

  function CertGetNameString(pCertContext: PCCERT_CONTEXT;
                           dwType: DWORD;
                           dwFlags: DWORD;
                           pvTypePara: Pointer;
                           pszNameString: LPTSTR;
                           cchNameString: DWORD): DWORD; stdcall;external 'crypt32.dll' name 'CertGetNameStringA';;

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

   function CertAddCertificateContextToStore(hCertStore: HCERTSTORE;
     pCertContext: PCCERT_CONTEXT; dwAddDisposition: DWORD;
     ppStoreContext: PPCCERT_CONTEXT): BOOL; stdcall;external 'crypt32.dll';

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

