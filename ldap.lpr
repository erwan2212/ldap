program ldap;

uses windows,sysutils,classes,strutils,base64,
     ldaputils,winldap,wcrypt2,
     uriparser,
     rcmdline in '..\rcmdline-master\rcmdline.pas';

var


  items: TStrings;
  i:integer;
  URI: TURI;
  cmd: TCommandLineReader;

  id:alg_id;
  r:bool;
  hp:HCRYPTPROV=0;
  hh:HCRYPTHASH=0;
  len:dword=0;
  //hash:array[0..63] of byte;
  hash:array of byte;

  procedure log(msg:string);
  begin
    writeln(msg);
  end;

  function crypto_hash(algid:alg_id;data:LPCVOID;dataLen:DWORD;  hash:lpvoid;hashWanted:DWORD):boolean;
  var
          status:BOOL {$ifdef fpc}=FALSE{$endif fpc};
    	hProv:HCRYPTPROV;
    	hHash:HCRYPTHASH;
    	hashLen:DWORD;
    	buffer:PBYTE;
    	//PKERB_CHECKSUM pCheckSum;
    	Context:PVOID;
  begin
  log('**** crypto_hash ****');
    //writeln(inttohex(CALG_SHA1,4));writeln(inttohex(CALG_MD4,4));writeln(inttohex(CALG_MD5,4));
    log('datalen:'+inttostr(datalen));
    result:=false;
    if CryptAcquireContext(@hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
    	begin
          log('CryptAcquireContext OK');
    		if CryptCreateHash(hProv, algid, 0, 0, @hHash) then
    		begin
                  log('CryptCreateHash OK');
    			if CryptHashData(hHash, data, dataLen, 0) then
    			begin
                          log('CryptHashData OK');
    				if CryptGetHashParam(hHash, HP_HASHVAL, nil, @hashLen, 0) then
    				begin
                                  log('CryptGetHashParam OK:'+inttostr(hashLen));
                                  buffer:=Pointer(LocalAlloc(LPTR, hashLen));
    					if buffer<>nil  then
    					begin
                                          log('LocalAlloc OK');
    						result := CryptGetHashParam(hHash, HP_HASHVAL, buffer, @hashLen, 0);
                                                  log('CryptGetHashParam:'+BoolToStr(result,true));
                                                  //RtlCopyMemory(pointer(hash), buffer, min(hashLen, hashWanted));
                                                  log('hashLen:'+inttostr(hashLen));
                                                  log('hashWanted:'+inttostr(hashWanted));
                                                  //log(inttohex(hHash,sizeof(pointer)));
                                                  CopyMemory (hash, buffer, min(hashLen, hashWanted));
                                                  //log('HASH:'+ByteToHexaString (buffer^),1);
                                                  //
                                                  LocalFree(thandle(buffer));
    					end;//if(buffer = (PBYTE) LocalAlloc(LPTR, hashLen))
    				end; //CryptGetHashParam
    			end; //CryptHashData
    			CryptDestroyHash(hHash);
    		end; //CryptCreateHash
    		CryptReleaseContext(hProv, 0);
          end; //CryptAcquireContext
          log('**** crypto_hash:'+BoolToStr (result)+' ****');
  end;


//ldap.exe
//--connect="ldap://WIN-BBC4BS466Q5.home.lab:636/dc=home,dc=lab"
//--user="CN=Administrator,CN=Users,DC=home,DC=lab"
//--password="Password1234"
//--query="(&(objectClass=user)(mail=user1@home.lab))"
//--attr="mail,displayname,cn,distinguishedname"

begin
  //
  cmd := TCommandLineReader.create;
  cmd.declareString('connect', 'ldap://WIN-BBC4BS466Q5.home.lab:389/dc=home,dc=lab');
  cmd.declareString('domain', 'optional, ex:home.lab');
  cmd.declareString('user', 'CN=Administrator,CN=Users,DC=home,DC=lab');
  cmd.declarestring('password', 'password');
  //(userAccountControl:1.2.840.113556.1.4.803:=32) - password not required
  //(userAccountControl:1.2.840.113556.1.4.803:=65536) - never expires
  //(userAccountControl:1.2.840.113556.1.4.803:=2) - disabled accounts
  cmd.declarestring('query', '(&(objectClass=user)(mail=user1@home.lab))');

  cmd.declarestring('attr', 'optional, ex:samaccountname, if empty->cn');
  cmd.declarestring('mode', 'optional, simple|winnt','simple');
  cmd.declareint('debug', 'optional, 1->verbose',0);
  cmd.declareint('certstrict', '1 or 0',1);
  cmd.declareint('opt_referrals', 'optional, 1->follow referrals',0);
  cmd.declareint('xorpassword', 'optional, key=666, xor->base64, https://gchq.github.io/CyberChef',0);

  cmd.declarestring('changeattr', 'CN=Administrator,CN=Users,DC=home,DC=lab');
  cmd.declarestring('value', 'password');

  cmd.declarestring('hash', 'optional nthash|md5|md4|md2|sha1|sha256|sha384|sha512');

  cmd.parse(cmdline);
  //writeln(booltostr(cmd.existsProperty('user')));
  //writeln(cmd.readString('user'));

  if cmd.existsProperty('connect')=false then
  begin
  writeln('ldap.exe --help');
  exit;
  end;


  uri:=parseuri(cmd.readString('connect'));



 if cmd.existsProperty('connect') then
  begin
  //
        if cmd.readInt ('debug')=1 then ldapDebug :=true;
        if cmd.readInt ('opt_referrals')=1 then ldapReferrals :=true;
        // Connexion au serveur LDAP pour la récupération des adresses mail
        Host := uri.Host;
        domain:=cmd.readString('domain');
        base:=uri.document;
        port:=uri.Port; //389;  //636

        User := cmd.readString('user'); //'CN=Administrator,CN=Users,DC=home,DC=lab';
        Password := cmd.readString('password'); //'passwordxxxx';
        filter:=cmd.readString('query');//'DC=home,DC=lab';

        ldapattr :=widestring(cmd.readString('attr'));
        if port=636 then ldapSSL :=true;
        if (uri.Protocol='ldaps') and (port=389) then ldapTLS :=true;

        if cmd.readInt ('xorpassword')=1 then
        begin
        //https://gchq.github.io/CyberChef
        //input:password needs to be xor'ed then encoded to base64
        //output:password needs to be decoded from base64 then xor'ed
        //writeln(EncodeStringBase64(XorString ('666','passwordxxxx')));
        password:=widestring(Xorstring('666',DecodeStringBase64(ansistring(password))));
        end;

        if cmd.existsProperty('hash')=true then
        begin

        if uppercase(cmd.readString('hash'))='SHA512' then id:=$0000800e;
        if uppercase(cmd.readString('hash'))='SHA256' then id:=$0000800c;
        if uppercase(cmd.readString('hash'))='SHA384' then id:=$0000800d;
        if uppercase(cmd.readString('hash'))='SHA1' then id:=$00008004;
        if uppercase(cmd.readString('hash'))='MD5' then id:=$00008003;
        if uppercase(cmd.readString('hash'))='MD4' then id:=$00008002;
        if uppercase(cmd.readString('hash'))='NTHASH' then id:=$00008002;
        if uppercase(cmd.readString('hash'))='MD2' then id:=$00008001;



        // acquire a crypto context
        //PROV_RSA_AES    // prov_rsa_full
        // if(id == CALG_MD2 || id == CALG_MD4 || id == CALG_MD5) ...
        r:=CryptAcquireContext(@hp, nil, nil,PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
        if r=false then writeln('CryptAcquireContext failed');
        // create a hash object
        r:= CryptCreateHash(hp, id, 0, 0, @hh);
        if r=false then writeln('CryptCreateHash failed');
        // update hash object
        if cmd.readString('hash')='NTHASH'
           then r:= CryptHashData(hh, @password[1], length(password)*2, 0)
           else r:= CryptHashData(hh, @string(password)[1], length(password), 0);
        if r=false then writeln('CryptHashData failed');
        //
        fillchar(hash,sizeof(hash),0);
        r:=CryptGetHashParam(hh, HP_HASHVAL, nil, @len, 0);
        //writeln(len);
        setlength(hash,len);
        r:=CryptGetHashParam(hh, HP_HASHVAL, @hash[0], @len, 0);
        if r=false then writeln('CryptGetHashParam failed');

        //writeln(password);
        password:='';
        for i:=0 to len -1 do password:=password+(inttohex(ord(hash[i]),2));
        //writeln(password);

        CryptDestroyHash(hh);
        CryptReleaseContext(hp, 0);


        {
        crypto_hash(id,@string(password)[1],length(password) ,@hash[0],16);
        for i:=0 to 16 -1 do write(inttohex(ord(hash[i]),2)+' ');
                writeln;
        }
        end;

  //
  if cmd.readInt('certstrict')=0 then CertStrict :=false;
  if ldapDebug=true then
     begin
          writeln('protocol:'+uri.Protocol );
          writeln('host:'+Host );
          writeln('port:'+inttostr(Port)  );
          writeln('base:'+base   );
          writeln('domain:'+domain  );
          writeln('user:'+user  );
          writeln('password:'+password   );
          writeln('filter:'+filter   );
     end;
  //
        try
          try
          if cmd.readString('mode')='simple' then
          begin
              if not SimpleBind(User, Password) then
              raise Exception.Create('simplebind failed:'+LDAPErrorCodeToMessage(LdapGetLastError()));
          end;
          if cmd.readString('mode')='winnt' then
          begin
              if not BindWinNTAuth (domain,user,password) then
              raise Exception.Create('BindWinNTAuth failed:'+LDAPErrorCodeToMessage(LdapGetLastError()));
          end;

           if cmd.existsProperty('query') then
           begin
           items:=TStringlist.Create ;
           //if EnumerateUsers ('CN=Users,DC=home,DC=lab',items,false) then
           //if EnumerateUsers ('DC=home,DC=lab',items,false) then
           if enumerate(base,filter,items,false) then
           begin
           if ldapattr <>'' then writeln(ldapattr);;
           for i:=0 to items.Count-1  do writeln(items.Strings [i])
           end
           else writeln('enumerate:false');
           end;

           if cmd.existsProperty('changeattr') then
           begin
           if changeattr(cmd.readString('changeattr'),cmd.readString('attr'),cmd.readString('value'))
              then writeln('changeattr:true')
              else writeln('changeattr:false');
           end;

          except
            on e:exception do writeln(e.message);
          end;

        finally
          Disconnect();
        end;
  end; //if cmd.existsProperty('connect') then

end.

