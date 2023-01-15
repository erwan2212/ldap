program ldap;

uses windows,sysutils,classes, ldaputils,uriparser,
  rcmdline in '..\rcmdline-master\rcmdline.pas',cert;



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
  cmd.declareString('user', 'cn=admin,cn=users,cn=home,cn=lab');
  cmd.declarestring('password', 'password');
  cmd.declarestring('query', '(&(objectClass=user)(mail=user1@home.lab))');
  cmd.declarestring('certenum', 'blah');
  cmd.declarestring('attr', 'samaccountname');
  cmd.declareint('debug', '1',0);

  cmd.parse(cmdline);
  //writeln(booltostr(cmd.existsProperty('user')));
  //writeln(cmd.readString('user'));


  uri:=parseuri(cmd.readString('connect'));



 if cmd.existsProperty('connect') then
  begin
  //
        if cmd.readInt ('debug')=1 then ldapDebug :=true;
        // Connexion au serveur LDAP pour la récupération des adresses mail
        Host := uri.Host; //'192.168.1.121';
        //domain:='home.lab';
        base:=uri.document;//'(objectClass=user)'; //"(&(objectClass=user)(mail=user1@home.lab))"
        port:=uri.Port; //389;  //636

        User := cmd.readString('user'); //'CN=Administrator,CN=Users,DC=home,DC=lab';
        Password := cmd.readString('password'); //'passwordxxxx';
        filter:=cmd.readString('query');//'DC=home,DC=lab';

        ldapattr :=widestring(cmd.readString('attr'));
        if port=636 then ldapSSL :=true;
  //
          writeln('protocol:'+uri.Protocol );
          writeln('host:'+Host );
          writeln('port:'+inttostr(Port)  );
          writeln('base:'+base   );
          writeln('user:'+user  );
          writeln('password:'+password   );
          writeln('filter:'+filter   );
  //
        try
          try
          if not SimpleBind(User, Password) then
          //if not BindWinNTAuth (domain,'administrator','Password1310') then
            raise Exception.Create('Impossible de se faire reconnaître par le serveur LDAP');

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

 if cmd.existsProperty('certenum') then
   begin
   EnumCertificates (cmd.readstring('certenum'));
   end;

end.

