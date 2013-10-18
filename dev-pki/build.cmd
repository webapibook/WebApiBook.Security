makecert -r -n "CN=Demo Certification Authority;O=Web API Book" -sv webapibook-ca.pvk ^
 -len 2048 -e 01/01/2020 -cy authority webapibook-ca.cer

makecert.exe -iv webapibook-ca.pvk -ic webapibook-ca.cer -n "CN=localhost" -pe -sv localhost.pvk -len 2048 -e 01/01/2020 -sky exchange localhost.cer -eku 1.3.6.1.5.5.7.3.1
pvk2pfx.exe -pvk localhost.pvk -spc localhost.cer -pfx localhost.pfx

makecert.exe -iv webapibook-ca.pvk -ic webapibook-ca.cer -n "CN=www.example.net" ^
 -sv example.pvk -len 2048 -e 01/01/2020 -sky exchange example.cer -eku 1.3.6.1.5.5.7.3.1
pvk2pfx.exe -pvk example.pvk -spc example.cer -pfx example.pfx

makecert.exe -iv webapibook-ca.pvk -ic webapibook-ca.cer -n "CN=authzserver.example" ^
 -sv as.pvk -len 2048 -e 01/01/2020 -sky exchange as.cer -eku 1.3.6.1.5.5.7.3.1
pvk2pfx.exe -pvk as.pvk -spc as.cer -pfx as.pfx

makecert.exe -iv webapibook-ca.pvk -ic webapibook-ca.cer -n "CN=Alice;O=Web API book;E=alice@webapibook.net" ^
 -sv alice.pvk -len 2048 -e 01/01/2020 -sky exchange alice.cer -eku 1.3.6.1.5.5.7.3.2
pvk2pfx.exe -pvk alice.pvk -spc alice.cer -pfx alice.pfx

makecert.exe -iv webapibook-ca.pvk -ic webapibook-ca.cer -n "CN=Bob;O=Web API book;E=bob@webapibook.net" ^
 -sv bob.pvk -len 2048 -e 01/01/2020 -sky exchange bob.cer -eku 1.3.6.1.5.5.7.3.2
pvk2pfx.exe -pvk bob.pvk -spc bob.cer -pfx bob.pfx