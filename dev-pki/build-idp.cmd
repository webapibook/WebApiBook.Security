makecert.exe -iv webapibook-ca.pvk -ic webapibook-ca.cer -n "CN=idp.example.org;O=Web API book;E=idp@webapibook.net" ^
 -sv idp.pvk -len 2048 -e 01/01/2020 -sky exchange idp.cer
pvk2pfx.exe -pvk idp.pvk -spc idp.cer -pfx idp.pfx