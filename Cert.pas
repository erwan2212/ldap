unit Cert;

{$mode delphi}

interface

uses WinLdap, wcrypt2, Windows,sysutils,dialogs,constant;

function  VerifyCert(Connection: PLDAP; pServerCert: PCCERT_CONTEXT): BOOLEAN; cdecl ;


var
  CertServerName:widestring;
  certdebug:boolean=false;
  CertUserAbort:boolean=true;

implementation

const
  CERT_NAME_EMAIL_TYPE=1;
  CERT_NAME_RDN_TYPE=2;
  CERT_NAME_ATTR_TYPE=3;
  CERT_NAME_SIMPLE_DISPLAY_TYPE=4;
  CERT_NAME_FRIENDLY_DISPLAY_TYPE=5;
  CERT_NAME_DNS_TYPE=6;
  CERT_NAME_URL_TYPE=7;
  CERT_NAME_UPN_TYPE=8;
  CERT_NAME_ISSUER_FLAG=$1;

  CERT_KEY_IDENTIFIER_PROP_ID = 20;

procedure ShowMessageFmt(const Formatting :string; const Data :array of const);
begin
  messageboxa(0,pchar(format(Formatting,data)),'ldap',0);
end;

procedure DisplayCertContext(CertContext: PCCERT_CONTEXT);
var
  CertName: array[0..255] of Char;
begin
  {
  if CertGetNameString(CertContext, CERT_NAME_EMAIL_TYPE, 0, nil,
    CertName, 256) = 0 then RaiseLastWin32Error;
  Writeln('Subject CERT_NAME_EMAIL_TYPE: ', CertName);
  }
  {if CertGetNameString(CertContext, CERT_NAME_RDN_TYPE, 0, nil,
    CertName, 256) = 0 then RaiseLastWin32Error;
  Writeln('Subject CERT_NAME_RDN_TYPE: ', CertName);
  }
  if CertGetNameString(CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil,
    CertName, 256) = 0 then RaiseLastWin32Error;
  Writeln('Subject CERT_NAME_SIMPLE_DISPLAY_TYPE: ', CertName);
  {
  if CertGetNameString(CertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, nil,
    CertName, 256) = 0 then RaiseLastWin32Error;
  Writeln('Subject CERT_NAME_FRIENDLY_DISPLAY_TYPE: ', CertName);
  }
  {
  if CertGetNameString(CertContext, CERT_NAME_EMAIL_TYPE, CERT_NAME_ISSUER_FLAG, nil,
    CertName, 256) = 0 then RaiseLastWin32Error;
  Writeln('Issuer CERT_NAME_EMAIL_TYPE: ', CertName);
  }
  if CertGetNameString(CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nil,
    CertName, 256) = 0 then RaiseLastWin32Error;
  Writeln('Issuer CERT_NAME_SIMPLE_DISPLAY_TYPE: ', CertName);
  {
  if CertGetNameString(CertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nil,
    CertName, 256) = 0 then RaiseLastWin32Error;
  Writeln('Issuer CERT_NAME_FRIENDLY_DISPLAY_TYPE: ', CertName);
  }
  {
  if CertGetNameString(CertContext, CERT_NAME_ATTR_TYPE, 0, PAnsiChar(szOID_COMMON_NAME),
                       CertName, 256)=0 then RaiseLastWin32Error;
  Writeln('COMMON_NAME: ', CertName);
  }
end;



procedure EnumCertificates(storename:string);
var
  hStore: HCERTSTORE;
  CertContext: PCCERT_CONTEXT;
  CertPropId: DWORD;
  Data: array[0..511] of Char;
  DataLen: DWORD;
  i: Integer;
  p:pwidechar;
begin
  try

    hStore := CertOpenSystemStore(0, pchar(StoreName));
    if hStore = nil then
      RaiseLastWin32Error;
    try
      CertContext := CertEnumCertificatesInStore(hStore, nil);
      while CertContext <> nil do
      begin
        writeln('*********************************************');
        //p:=getmem(CertContext.pCertInfo.Subject.cbData);
        //copymemory(p,CertContext.pCertInfo.Subject.pbData,CertContext.pCertInfo.Subject.cbData );
        //writeln(strpas(p));
        DisplayCertContext(CertContext);
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
          CERT_FRIENDLY_NAME_PROP_ID:
          begin
            CertGetCertificateContextProperty(CertContext, CertPropId,
              @Data[0], @DataLen);
            Writeln(Format('FRIENDLY_NAME: %s', [PwideChar(@Data[0])]));
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

function VerifyCertHostName(pCertContext: PCCERT_CONTEXT; HostName: string): boolean;
type
  PCERT_ALT_NAME_ENTRY = array of CERT_ALT_NAME_ENTRY;
var
  cbStructInfo, dwCommonNameLength, i: Cardinal;
  szOID: LPSTR;
  pvStructInfo: Cardinal;
  CommonName, DNSName: string;
  pExtension: PCERT_EXTENSION;
  pNameInfo: PCERT_ALT_NAME_INFO;
begin

  Result := false;

  if hostname = '' then Exit;

  // Try SUBJECT_ALT_NAME2 first - it supercedes SUBJECT_ALT_NAME
  szOID := szOID_SUBJECT_ALT_NAME2;
  pExtension := CertFindExtension(szOID, pCertContext^.pCertInfo^.cExtension,
                                  pCertContext^.pCertInfo^.rgExtension);
  if not Assigned(pExtension) then
  begin
    szOID := szOID_SUBJECT_ALT_NAME;
    pExtension := CertFindExtension(szOID, pCertContext^.pCertInfo^.cExtension,
                                    pCertContext^.pCertInfo^.rgExtension);
  end;

  if (Assigned(pExtension) and CryptDecodeObject(X509_ASN_ENCODING, szOID,
      pExtension^.Value.pbData, pExtension^.Value.cbData, 0, nil, @cbStructInfo)) then
  begin
    pvStructInfo := LocalAlloc(LMEM_FIXED, cbStructInfo);
    if pvStructInfo <> 0 then
    begin
      CryptDecodeObject(X509_ASN_ENCODING, szOID, pExtension^.Value.pbData,
                        pExtension^.Value.cbData, 0, Pointer(pvStructInfo), @cbStructInfo);
      pNameInfo := PCERT_ALT_NAME_INFO(pvStructInfo);
      i := 0;
      while (not Result and (i < pNameInfo^.cAltEntry)) do
      begin
        if (PCERT_ALT_NAME_ENTRY(pNameInfo^.rgAltEntry)[i].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME) then
        begin
          {$IFDEF UNICODE}
          DNSName := PCERT_ALT_NAME_ENTRY(pNameInfo^.rgAltEntry)[i].pwszDNSName;
          {$ELSE}
          DNSName := WideCharToString(PCERT_ALT_NAME_ENTRY(pNameInfo^.rgAltEntry)[i].pwszDNSName);
          {$ENDIF}
          if (CompareText(HostName, DNSName) = 0) then
          begin
            Result := true;
            break;
          end;
        end;
        inc(i);
      end;
      LocalFree(pvStructInfo);
      if Result then
        Exit;
    end;
  end;

  // No subjectAltName extension -- check commonName

  dwCommonNameLength := CertGetNameString(pCertContext, {CERT_NAME_ATTR_TYPE}3, 0,
                                          PAnsiChar(szOID_COMMON_NAME), nil, 0);
  if (dwCommonNameLength <> 0) then
  begin

    SetLength(CommonName, dwCommonNameLength);

    CertGetNameString(pCertContext, {CERT_NAME_ATTR_TYPE}3, 0, PAnsiChar(szOID_COMMON_NAME),
                       PChar(CommonName), dwCommonNameLength);
    if AnsiCompareStr(HostName, CommonName) = 0 then // compare null terminated
      Result := true;
  end;

end;

function AddStore(Collection: HCERTSTORE; pvSystemStore: PChar): Boolean;
var
  Store: HCERTSTORE;
begin
  Result := false;
  Store := CertOpenSystemStore(0, pvSystemStore);
  if Store <> nil then
  begin
    Result := CertAddStoreToCollection(Collection, Store, 0, 0);
    CertCloseStore(Store, 0);
  end
end;

{ Enumerate calback function }

function EnumSysCallback(pvSystemStore: Pointer; dwFlags: DWORD; pStoreInfo: PCERT_SYSTEM_STORE_INFO;
                         pvReserved: Pointer; pvArg: Pointer): BOOL; stdcall;
{$IFNDEF UNICODE}
var
  s: string;
{$ENDIF}
begin
  {$IFNDEF UNICODE}
   s := WideCharToString(pvSystemStore);
   pvSystemStore := PChar(s);
  {$ENDIF}
  if not AddStore(HCERTSTORE(pvArg), pvSystemStore) then
    ShowMessageFmt(stCertOpenStoreErr, [WideCharToString(pvSystemStore), SysErrorMessage(GetLastError)]);
  Result := true;
end;


{ VERIFYSERVERCERT callback function }

function VerifyCert(Connection: PLDAP; pServerCert: PCCERT_CONTEXT): BOOLEAN; cdecl ;
var
  Collect: HCERTSTORE;
  flags: DWORD;
  iCert, pSub: PCCERT_CONTEXT;
  err: Cardinal;
  errStr, cap: string;
  //uidlg: TUIDlg;
begin
  Result := false;
  psub := PCCERT_CONTEXT(Pointer(pServerCert)^);
  Collect := CertOpenStore ({CERT_STORE_PROV_COLLECTION}LPCSTR(11), 0, 0, 0, nil);
  if Collect = nil then  RaiseLastOSError;
  if not CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, nil, Collect, EnumSysCallback) then
  begin
    AddStore(Collect, 'MY');
    AddStore(Collect, 'CA');
    AddStore(Collect, 'ROOT');
    AddStore(Collect, 'SPC');
    AddStore(Collect, 'TRUST');
  end;
  if certdebug=true then DisplayCertContext(psub ); //test !!!
  //writeln(pchar(psub^.pCertInfo^.Subject.pbData)) ;
  flags:= CERT_STORE_SIGNATURE_FLAG or CERT_STORE_TIME_VALIDITY_FLAG;
  iCert:= CertGetIssuerCertificateFromStore(collect, pSub, nil, @flags);
  if icert = nil then
  begin
    err := GetLastError;
    case err of
       {CRYPT_E_NOT_FOUND} $80092004: errStr := #9 + '- ' + stCertNotFound + #10#13;
       {CRYPT_E_SELF_SIGNED} $80092007: errStr := #9 + '- ' + stCertSelfSigned + #10#13;
    else
      errStr := #9 + '- ' + SysErrorMessage(err);
    end;
    raise exception.Create (errStr );
  end
  else
  begin
    //CertGetNameString(pSub, {CERT_NAME_SIMPLE_DISPLAY_TYPE}4, 0, nil, pszNameString, 128);
    if flags and CERT_STORE_SIGNATURE_FLAG <> 0 then
      errStr := #9 + '- ' + stCertInvalidSig + #10#13;
    if flags and CERT_STORE_TIME_VALIDITY_FLAG <> 0 then
      errStr := errStr + #9 + '- ' + stCertInvalidTime + #10#13;
    if not VerifyCertHostName(pSub, CertServerName) then
      errStr := errStr + #9 + '- ' + stCertInvalidName + #10#13;
    CertFreeCertificateContext(iCert);
  end;
  if errStr = '' then
    Result := true
  else
  begin
    {
    uiDlg := TUIDlg.Create(pSub, CERT_STORE_CERTIFICATE_CONTEXT, cCert);
    if Assigned(UIDlg.OnClickProc) then
      cap := cView
    else
      cap := '';
    if MessageDlgEx(Format(stCertConfirmConn, [errStr]), mtWarning, [mbYes, mbNo, mbHelp], ['','',cap], [nil,nil,uiDlg.OnClickProc]) = mrYes then
      Result := true
    else
      CertUserAbort := true;
    uiDlg.Free;
    }
    if CertUserAbort=false then result:=true ; //despite the cert error, we continue
    writeln('VerifyCert:'+errStr);
  end;
  CertCloseStore(collect, 0);
  CertFreeCertificateContext(pSub);
end;

end.

