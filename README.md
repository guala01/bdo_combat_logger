# BDO Combat Logger

Extract Black Desert kill/death feed from network traffic.

(It also shows names on anon arsha cause they are in plain text gj pa)

You need to record your internet traffic using Wireshark, open the program select your network card from the list and put "tcp port 8889" as filter right above the list to only capture bdo traffic.
Start recording when your fight starts once it's done stop the recording save as "file.pcpng" and place the saved pcapng in the same location as the python script run the script.

Script atm runs on today/this patch offsets which might change every maintenance or not idk

Packet structure is as such
5 bytes identify the combat string
1 byte is the kill/death flag
bytes right after are guild name
after 68 bytes there is the other player char name
after 66 bytes there is your char name
after 64 bytes there is your fam name
after 66 bytes there is the other player fam name
bytes that end the combat string

These values only refer to this patch(20/3/24) they might change every patch

To find the values you can open wireshark and kill/get killed ctrl+f select string in the search and type your name, 
once you have found the packet adjust the 5 first bytes as those identify the string and then play around with the names
offsets until you have a proper name extraction without artifacts or such.



