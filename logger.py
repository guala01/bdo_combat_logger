from scapy.all import rdpcap
from scapy.layers.inet import TCP
from datetime import datetime
from collections import defaultdict

def extract_name(data, offset):
    name_end_offset = data.find(b'\x00\x00', offset)
    return data[offset:name_end_offset].decode('latin-1')

def process_packet(packet, next_packet, pattern, offsets, player_stats):
    if packet.haslayer(TCP) and packet[TCP].payload:
        data = bytes(packet[TCP].payload)
        start_index = data.find(pattern)
        
        if start_index != -1:
            if next_packet and next_packet.haslayer(TCP) and next_packet[TCP].payload:
                data += bytes(next_packet[TCP].payload)

            event_indicator_offset = start_index + len(pattern)
            guild_name_offset = event_indicator_offset + 1
            player1_charname_offset = event_indicator_offset + offsets['p1_c']
            player2_charname_offset = player1_charname_offset + offsets['p2_c']
            player2_famname_offset = player2_charname_offset + offsets['p2_f']
            player1_famname_offset = player2_famname_offset + offsets['p1_f']

            event = "killed" if data[event_indicator_offset] == 0 else "kill"
            guild_name = extract_name(data, guild_name_offset)
            player1_charname = extract_name(data, player1_charname_offset)
            player2_charname = extract_name(data, player2_charname_offset)
            player2_famname = extract_name(data, player2_famname_offset)
            player1_famname = extract_name(data, player1_famname_offset)

            timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S')

            if event == "kill":
                print(f"[{timestamp}] [{player2_famname}] [{player2_charname}] killed [{player1_famname}] [{player1_charname}] from the [{guild_name}] guild.")
                player_stats[player2_charname]['kills'] += 1
                player_stats[player1_charname]['deaths'] += 1
            else:
                print(f"[{timestamp}] [{player2_famname}] [{player2_charname}] was slain by [{player1_famname}] [{player1_charname}] from the [{guild_name}] guild")
                player_stats[player1_charname]['kills'] += 1
                player_stats[player2_charname]['deaths'] += 1

def analyze_pcapng(file_path, pattern, offsets):
    packets = rdpcap(file_path)
    player_stats = defaultdict(lambda: {'kills': 0, 'deaths': 0})
    
    for i in range(len(packets) - 1):
        packet = packets[i]
        next_packet = packets[i + 1] if i < len(packets) - 1 else None
        process_packet(packet, next_packet, pattern, offsets, player_stats)
    
    print("\nPlayer K/D Stats:")
    for player, stats in player_stats.items():
        kills = stats['kills']
        deaths = stats['deaths']
        kd_ratio = kills / deaths if deaths > 0 else kills
        print(f"Player: {player}, Kills: {kills}, Deaths: {deaths}, K/D Ratio: {kd_ratio:.2f}")

old_pattern = b'\x5c\x01\x00\xb6\x12'
pattern = b'\x00\x66\x01\x00\x71'
# Usage example
file_path = './file.pcapng'
offsets = {
    'p1_c': 63,
    'p2_c': 66,
    'p2_f': 62,
    'p1_f': 62
}
analyze_pcapng(file_path, pattern, offsets)
