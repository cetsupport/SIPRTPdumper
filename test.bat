"c:\Program Files\Wireshark\tshark.exe" -r test2.pcapng -q -X lua_script:volte.lua -X lua_script1:+818077272014 >result.log