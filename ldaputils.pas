unit ldaputils;

{$mode objfpc}{$H+}

interface

uses
  Classes, windows,SysUtils,winldap,cert;

var
FConnection:PLDAP;
host,user,password,domain,filter,base:widestring;
port:ulong;
ldapSSL:boolean=false;
ldapTLS:boolean=false;
ldapDebug:boolean=false;
ldapattr:widestring='';

function Enumerate(const ABase: widestring; const AFilter: widestring; AComputerList: TStrings; ACNOnly: Boolean = False): Boolean;
function BindWinNTAuth(const Domain: widestring; const User: widestring; const Password: widestring): Boolean;
function SimpleBind(const DNName: widestring; const Password: widestring): Boolean;
function EnumerateUsers(const ABase: widestring; AComputerList: TStrings; ACNOnly: Boolean = False): Boolean;
function Connect(): Boolean;
function Disconnect(): Boolean;

function LDAPErrorCodeToMessage(err: Cardinal): string;

implementation

type
     TEnumeratedValueItem = record
       DN: string;
       Values: array of record
         AttributeName: string;
         AttributeValue: string;
       end;
     end;
     TEnumeratedValues = array of TEnumeratedValueItem;

function Disconnect(): Boolean;
begin
  Result := False;
  if Assigned(FConnection) then
  begin
    Result := ldap_unbind(FConnection) = LDAP_SUCCESS;
    FConnection := nil;
  end;
end;

function Connect(): Boolean;
begin
if not Assigned(FConnection) then
begin
  if ldapSSL
     then FConnection := ldap_sslinitW(PWideChar(Host), Port,1)
     else FConnection := ldap_initW(PWideChar(Host), Port);
  Result := Assigned(FConnection);
  {$IFDEF DEBUG_SLT_LDAP}
  if not Result then
    OutputDebugLDAP(LDAPErrorCodeToMessage(LdapGetLastError()));
  {$ENDIF DEBUG_SLT_LDAP}
end
else
  Result := True;
end;


function BindWinNTAuth(const Domain: widestring; const User: widestring; const Password: widestring): Boolean;
const
SEC_WINNT_AUTH_IDENTITY_ANSI    = 1;
SEC_WINNT_AUTH_IDENTITY_UNICODE = 2;
type
SEC_WINNT_AUTH_IDENTITY_W = record
  User: PWideChar;
  UserLength: ULONG;
  Domain: PWideChar;
  DomainLength: ULONG;
  Password: PWideChar;
  PasswordLength: ULONG;
  Flags: ULONG;
end;
var
WinNTAuth: SEC_WINNT_AUTH_IDENTITY_W;
ErrorCode: ULONG;
begin
Result := False;
if (User <> '') and (Password <> '') then
begin
  if Connect() then
  begin
    ZeroMemory(@WinNTAuth, SizeOf(WinNTAuth));
    WinNTAuth.User := PwideChar(User);
    WinNTAuth.UserLength := Length(User);
    WinNTAuth.Domain := PwideChar(Domain);
    WinNTAuth.DomainLength := Length(Domain);
    WinNTAuth.Password := PwideChar(Password);
    WinNTAuth.PasswordLength := Length(Password);
    WinNTAuth.Flags := SEC_WINNT_AUTH_IDENTITY_UNICODE;

    ErrorCode := ldap_bind_sW(FConnection, nil, PWideChar(@WinNTAuth), LDAP_AUTH_NEGOTIATE);
    Result := ErrorCode = LDAP_SUCCESS;
    {$IFDEF DEBUG_SLT_LDAP}
    if not Result then
      OutputDebugLDAP(LDAPErrorCodeToMessage(ErrorCode));
    {$ENDIF DEBUG_SLT_LDAP}
  end;
end;
end;

procedure Split(const Delimiter: Char; Input: string; const Strings: TStrings);
begin
   Assert(Assigned(Strings)) ;
   Strings.Clear;
   Strings.Delimiter := Delimiter;
   Strings.DelimitedText := Input;
end;

function Enumerate(const ABase: widestring; const AFilter: widestring; AComputerList: TStrings; ACNOnly: Boolean = False): Boolean;

function CreateDNParser(): TStringList;
begin
  if ACNOnly then
    Result := TStringList.Create()
  else
    Result := nil;
end;

var
LDAPMessages, LDAPEntry: PLDAPMessage;
CN: string;
DN:pwidechar;
DNParser: TStringList;
value:PPCharW;
s:tstrings;
i:byte;
item:string;
begin
Result := False;

LDAPMessages := nil;
try
  if ldap_search_sW(FConnection, PwideChar(ABase), LDAP_SCOPE_SUBTREE, PwideChar(AFilter), nil, 0, LDAPMessages) = LDAP_SUCCESS then
  begin
    DNParser := CreateDNParser();
    try
      LDAPEntry := ldap_first_entry(FConnection, LDAPMessages);
      while Assigned(LDAPEntry) do
      begin
        dn:=nil;
        if ldapattr<>''
           then
             begin
               s:=tstringlist.create;
               split(',',string(ldapattr ),s);
               item:='';
               for i:=0 to s.Count -1 do
                   begin
                   value:=ldap_get_valuesW(FConnection ,LDAPEntry ,pwidechar(widestring(s[i])));
                   if value<>nil
                      then item:=item+','+strpas(value^)
                      else item:=item+','+'';
                   end;
                   delete(item,1,1);
             end
           else
           begin
           DN := ldap_get_dnW(FConnection, LDAPEntry);
           item:=string(strpas(dn));
           end;
        if ACNOnly then
        begin
          DNParser.CommaText := item; //strpas(DN);
          CN := DNParser.Values['CN'];
          AComputerList.Add(CN);
        end
        else
        AComputerList.Add(item);
        LDAPEntry := ldap_next_entry(FConnection, LDAPEntry);
      end;
    finally
      FreeAndNil(DNParser);
    end;

    Result := AComputerList.Count > 0;
  end
  else writeln('ldap_search_sW failed:'+LDAPErrorCodeToMessage(LdapGetLastError()));
finally
  if Assigned(LDAPMessages) then
    ldap_msgfree(LDAPMessages);
end;
end;

//------------------------------------------------------------------------------
function EnumerateComputers(const ABase: string; AComputerList: TStrings; ACNOnly: Boolean = False): Boolean;
begin
Result := Enumerate(ABase, '(objectClass=computer)', AComputerList, ACNOnly);
end;

//------------------------------------------------------------------------------
function EnumerateUsers(const ABase: widestring; AComputerList: TStrings; ACNOnly: Boolean = False): Boolean;
begin
Result := Enumerate(ABase, '(objectClass=user)', AComputerList, ACNOnly);
end;

function EnumerateValues(const ABase: string; const ADN: string; out AValues: TEnumeratedValues; AAttributesList: TStrings = nil): Boolean;
var
LDAPMessages, LDAPEntry: PLDAPMessage;
DN: string;
iDN, iV: Integer;
itV: PBerElement;
Attr: PWideChar;
Value: PPCharW;
resLDAP: Cardinal;
begin
Result := False;

LDAPMessages := nil;
try
  resLDAP := ldap_search_sW(FConnection, PwideChar(ABase), LDAP_SCOPE_SUBTREE, PwideChar(ADN), nil, 0, LDAPMessages);
  if resLDAP = LDAP_SUCCESS then
  begin
    LDAPEntry := ldap_first_entry(FConnection, LDAPMessages);
    while Assigned(LDAPEntry) do
    begin
      DN := ldap_get_dnW(FConnection, LDAPEntry);
      iDN := Length(AValues);
      SetLength(AValues, iDN + 1);
      AValues[iDN].DN := DN;

      Attr := ldap_first_attributeW(FConnection, LDAPEntry, itV);
      while Assigned(Attr) do
      begin
        if (not Assigned(AAttributesList)) or (AAttributesList.IndexOf(Attr) >= 0) then
        begin
          Value := ldap_get_valuesW(FConnection, LDAPEntry, Attr);
          if Assigned(Value) and Assigned(Value^) then
          begin
            iV := Length(AValues[iDN].Values);
            SetLength(AValues[iDN].Values, iV + 1);
            AValues[iDN].Values[iV].AttributeName := Attr;
            AValues[iDN].Values[iV].AttributeValue := Value^;
          end;
        end;

        Attr := ldap_next_attributeW(FConnection, LDAPEntry, itV);
      end;

      LDAPEntry := ldap_next_entry(FConnection, LDAPEntry);
    end;

    Result := Length(AValues) > 0;
  end;
finally
  if Assigned(LDAPMessages) then
    ldap_msgfree(LDAPMessages);
end;
end;

function LDAPErrorCodeToMessage(err: Cardinal): string;
var
errstring: PWideChar;
begin
errstring := ldap_err2stringW(err);
Result := errstring;
end;

procedure LDAPCheck(const err: ULONG; const Critical: Boolean = true);
const
stLdapError       = 'LDAP error: %s!';
stLdapErrorEx     = 'LDAP error! %s: %s.';
var
  ErrorEx: PChar;
  msg: string;
  c: ULONG;
begin
  if (err = LDAP_SUCCESS) then exit;

  if ((ldap_get_option(FConnection , LDAP_OPT_SERVER_ERROR, @ErrorEx)=LDAP_SUCCESS) and Assigned(ErrorEx)) then
  begin
    msg := Format(stLdapErrorEx, [ldap_err2string(err), ErrorEx]);
    ldap_memfree(ErrorEx);
  end
  else
    msg := Format(stLdapError, [ldap_err2string(err)]);

  c := 0;
  if (ldap_get_option(FConnection, LDAP_OPT_SERVER_EXT_ERROR, @c) = LDAP_SUCCESS) then
    msg := msg + #10 + SysErrorMessage(c);

  if Critical then
    raise exception.Create(msg);
  //MessageDlg(msg, mtError, [mbOk], 0);
end;

function SimpleBind(const DNName: widestring; const Password: widestring): Boolean;
var
ErrorCode: ULONG;
version:nativeuint=3;
//VerifyCert:nativeuint=0;
begin
certdebug:=ldapDebug ;
Result := False;
if (DNName <> '') and (Password <> '') then
begin
  if Connect() then
  begin

    ldapcheck(ldap_set_option(FConnection, LDAP_OPT_REFERRALS, nil),true);
    ldapcheck(ldap_set_option(FConnection, LDAP_OPT_PROTOCOL_VERSION, @version),true); //to be able to deep search...
    if ldapSSL or ldapTLS then
       begin
         CertServerName:=host;
         ldapcheck(ldap_set_option(FConnection, LDAP_OPT_SERVER_CERTIFICATE, @VerifyCert),true);
       end;
    if ldapTLS
       then ldapcheck(ldap_start_tls_s(FConnection, nil, nil, nil, nil));
    ErrorCode := ldap_simple_bind_sW(FConnection, PWideChar(DNName), PWideChar(Password));
    Result := ErrorCode = LDAP_SUCCESS;
    //writeln(LDAPErrorCodeToMessage(ErrorCode));
    {$IFDEF DEBUG_SLT_LDAP}
    if not Result then
      OutputDebugLDAP(LDAPErrorCodeToMessage(ErrorCode));
    {$ENDIF DEBUG_SLT_LDAP}
  end
  else writeln('cannot connect:'+LDAPErrorCodeToMessage(LdapGetLastError()));
end;
end;

end.

