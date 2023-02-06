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
CertStrict:boolean=true;
ldapDebug:boolean=false;
ldapAttr:widestring='';
ldapReferrals:boolean=false;

function Enumerate(const ABase: widestring; const AFilter: widestring; AComputerList: TStrings; ACNOnly: Boolean = False): Boolean;
function ChangeAttr(user,attr,value:string):boolean;

function BindWinNTAuth(const Domain: widestring; const User: widestring; const Password: widestring): Boolean;
function SimpleBind(const DNName: widestring; const Password: widestring): Boolean;
function EnumerateUsers(const ABase: widestring; AComputerList: TStrings; ACNOnly: Boolean = False): Boolean;
function Connect(): Boolean;
function Disconnect(): Boolean;

function LDAPErrorCodeToMessage(err: Cardinal): string;

implementation

const LDAP_OPT_DEBUG_LEVEL = $5001;

type
     TEnumeratedValueItem = record
       DN: string;
       Values: array of record
         AttributeName: string;
         AttributeValue: string;
       end;
     end;
     TEnumeratedValues = array of TEnumeratedValueItem;

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
  if CertStrict =false then cert.CertUserAbort :=false;
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
version:nativeuint=3;
LDAP_OPT_OFF:nativeuint=0;
LDAP_OPT_ON:nativeuint=1;
begin
certdebug:=ldapDebug ;
Result := False;
//if (User = '') and (Password <> '') then
//begin
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

    //ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
    //defines how the client library should handle Referrals returned by the server
    if ldapReferrals=false
       then ldapcheck(ldap_set_option(FConnection, LDAP_OPT_REFERRALS, @LDAP_OPT_OFF),true)
       else ldapcheck(ldap_set_option(FConnection, LDAP_OPT_REFERRALS, @LDAP_OPT_ON),true);
    ldapcheck(ldap_set_option(FConnection, LDAP_OPT_PROTOCOL_VERSION, @version),true); //to be able to deep search...
    if ldapSSL or ldapTLS then
       begin
         cert.CertServerName:=host;
         ldapcheck(ldap_set_option(FConnection, LDAP_OPT_SERVER_CERTIFICATE, @VerifyCert),true);
       end;
    if ldapTLS
       then ldapcheck(ldap_start_tls_s(FConnection, nil, nil, nil, nil));

    ErrorCode := ldap_bind_sW(FConnection, nil, PWideChar(@WinNTAuth), LDAP_AUTH_NEGOTIATE);
    Result := ErrorCode = LDAP_SUCCESS;
    {$IFDEF DEBUG_SLT_LDAP}
    if not Result then
      OutputDebugLDAP(LDAPErrorCodeToMessage(ErrorCode));
    {$ENDIF DEBUG_SLT_LDAP}
  end
  else writeln('cannot connect:'+LDAPErrorCodeToMessage(LdapGetLastError()));
//end;
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



function SimpleBind(const DNName: widestring; const Password: widestring): Boolean;
var
ErrorCode: ULONG;
version:nativeuint=3;
LDAP_OPT_OFF:nativeuint=0;
LDAP_OPT_ON:nativeuint=1;
//VerifyCert:nativeuint=0;
begin
certdebug:=ldapDebug ;
Result := False;
if (DNName <> '') and (Password <> '') then
begin
  if Connect() then
  begin
    //ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
    //defines how the client library should handle Referrals returned by the server
    if ldapReferrals=false
       then ldapcheck(ldap_set_option(FConnection, LDAP_OPT_REFERRALS, @LDAP_OPT_OFF),true)
       else ldapcheck(ldap_set_option(FConnection, LDAP_OPT_REFERRALS, @LDAP_OPT_ON),true);
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

function ChangeAttr(user,attr,value:string):boolean;
type custom1LDAPModW = record
    mod_op: ULONG;
    mod_type: PWideChar;
    modv_bvals:^PLDAPBerVal; //pointer; //^PLDAPBerVal;
  end;
Pcustom1LDAPModW=^custom1LDAPModW;
type custom0LDAPModW = record
    mod_op: ULONG;
    mod_type: PWideChar;
    modv_strvals: pointer; //^PWideChar;
  end;
Pcustom0LDAPModW=^custom0LDAPModW;
var
   mod0:custom0LDAPModW;
   strvals:array[0..0] of pwidechar;
   mods0:array[0..1] of Pcustom0LDAPModW;//pointer
   //
   mod1:custom1LDAPModW;
   Bvals:array[0..0] of PLDAPBerVal;
   mods1:array[0..1] of Pcustom1LDAPModW;//pointer
begin
if lowercase(attr)<>'unicodepwd' then
begin
mod0.mod_op := LDAP_MOD_REPLACE; // or LDAP_MOD_BVALUES;
mod0.mod_type := pwidechar(widestring(attr)); //pwidechar('unicodePwd'); //'userPassword';
strvals[0]:=pwidechar(widestring(value)); //pwidechar(@test[0]);
//strvals[1]:=#0;
//writeln('1ok');
//writeln('2ok');
mod0.modv_strvals:=@strvals;
//writeln('3ok');
mods0[0]:=@mod0;
mods0[1]:=nil;
//ErrorCode:=ldap_modify_ext_sW(FConnection,pwidechar(widestring(user)),@mods,nil, nil);
ErrorCode:=ldap_modify_sW(FConnection,pwidechar(widestring(user)),@mods0);
Result := ErrorCode = LDAP_SUCCESS;
if not Result then
      writeln(LDAPErrorCodeToMessage(ErrorCode));
end;//if attr<>'unicodepwd' then

if lowercase(attr)='unicodepwd' then
begin
mod1.mod_op := LDAP_MOD_REPLACE or LDAP_MOD_BVALUES;
mod1.mod_type := pwidechar(widestring(attr)); //pwidechar('unicodePwd'); //'userPassword';
writeln('1');
bvals[0]:=getmem(64);   //??
bvals[0]^.bv_val :=pchar('"'+value+'"');
bvals[0]^.bv_len :=length(value)+2;
mod1.modv_bvals :=@bvals;
//mod1.modv_bvals :=getmem(64);;
writeln('2');
mods1[0]:=@mod1;
mods1[1]:=nil;
writeln('3');
ErrorCode:=ldap_modify_sW(FConnection,pwidechar(widestring(user)),@mods1);
Result := ErrorCode = LDAP_SUCCESS;
if not Result then
      writeln(LDAPErrorCodeToMessage(ErrorCode));

end;

end;

end.

