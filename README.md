# BDO Combat Logger

Extract Black Desert kill/death feed from network traffic.

(It also shows names on anon arsha cause they are in plain text gj pa)

Requires scapy to run:
```
pip install scapy
```
You need to record your internet traffic using Wireshark:
1. Open the program and select your network card from the list.
2. Put "tcp port 8889" as a filter right above the list to only capture BDO traffic.
3. Start recording when your fight starts.
4. Once it's done, stop the recording and save as "file.pcpng".
5. Place the saved pcapng in the same location as the python script.
6. Run the script.

Script atm runs on today/this patch offsets which might change every maintenance or not idk.

Packet structure is as such:
- 5 bytes identify the combat string
- 1 byte is the kill/death flag
- Bytes right after are guild name
- After 68 bytes there is the other player char name
- After 66 bytes there is your char name
- After 64 bytes there is your fam name
- After 66 bytes there is the other player fam name
- Bytes that end the combat string

These values only refer to this patch (20/3/24). They might change every patch.

To find the values:
1. Open Wireshark and kill/get killed.
2. Press `Ctrl+F` and select "String" in the search.
3. Type your name.
4. Once you have found the packet, adjust the 5 first bytes as those identify the string.
5. Play around with the names offsets until you have a proper name extraction without artifacts or such.
