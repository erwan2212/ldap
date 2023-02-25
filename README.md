# ldap
Perform various operations (query, modify attribute) against a ldap/ldaps server.<br/>
<br/>
The following command line options are valid:<br/>
<br/>
--connect=<string>      ldap://WIN-BBC4BS466Q5.home.lab:389/dc=home,dc=lab<br/>
--domain=<string>       optional, ex:home.lab<br/>
--user=<string>         CN=Administrator,CN=Users,DC=home,DC=lab<br/>
--password=<string>     password<br/>
--query=<string>        (&(objectClass=user)(mail=user1@home.lab))<br/>
--attr=<string>         optional, ex:samaccountname, if empty->cn<br/>
--mode=<string>         optional, simple|winnt (default: simple)<br/>
--debug=<int>           optional, 1->verbose<br/>
--certstrict=<int>      1 or 0 (default: 1)<br/>
--opt_referrals=<int>   optional, 1->follow referrals<br/>
--xorpassword=<int>     optional, key=666, xor->base64, https://gchq.github.io/CyberChef<br/>
--changeattr=<string>   CN=Administrator,CN=Users,DC=home,DC=lab<br/>
--value=<string>        password<br/>
<br/>
