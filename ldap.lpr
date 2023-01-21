program ldap;

uses windows,sysutils,classes,strutils,base64,
     ldaputils,winldap,
     uriparser,
     rcmdline in '..\rcmdline-master\rcmdline.pas';

var


  items: TStrings;
  i:integer;
  URI: TURI;
  cmd: TCommandLineReader;

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
  cmd.declareString('user', 'cn=admin,cn=users,cn=home,cn=lab|administrator');
  cmd.declarestring('password', 'password');
  cmd.declarestring('query', '(&(objectClass=user)(mail=user1@home.lab))');
  //cmd.declarestring('certenum', 'MY|ROOT');
  cmd.declarestring('attr', 'optional, ex:samaccountname, if empty->cn');
  cmd.declarestring('mode', 'optional, simple|winnt','simple');
  cmd.declareint('debug', 'optional, 1->verbose',0);
  cmd.declareint('opt_referrals', 'optional, 1->follow referrals',0);
  cmd.declareint('xorpassword', 'optional, key=666, xor->base64, https://gchq.github.io/CyberChef',0);

  cmd.parse(cmdline);
  //writeln(booltostr(cmd.existsProperty('user')));
  //writeln(cmd.readString('user'));


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

        if cmd.readInt ('debug')=1 then
        begin
        //https://gchq.github.io/CyberChef
        //input:password needs to be xor'ed then encoded to base64
        //output:password needs to be decoded from base64 then xor'ed
        //writeln(EncodeStringBase64(XorString ('666','passwordxxxx')));
        password:=widestring(Xorstring('666',DecodeStringBase64(ansistring(password))));
        end;

  //
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


          items:=TStringlist.Create ;
        //if EnumerateUsers ('CN=Users,DC=home,DC=lab',items,false) then
        //if EnumerateUsers ('DC=home,DC=lab',items,false) then
        if enumerate(base,filter,items,false) then
           begin
           if ldapattr <>'' then writeln(ldapattr);;
           for i:=0 to items.Count-1  do writeln(items.Strings [i])

           end
           else writeln('enumerate:false');

          except
            on e:exception do writeln(e.message);
          end;

        finally
          Disconnect();
        end;
  end; //if cmd.existsProperty('connect') then

end.

