import pyshark
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os

# Replace with the path to your PCAP folder and file name
pcap_folder = 'pcaps'
pcap_filename = 'book_dl_tcp_analysis.pcap'  # Change to your actual file name
pcap_file = os.path.join(pcap_folder, pcap_filename)

# Initialize lists to store data
timestamps = []
throughput = []
window_sizes = []
retransmissions = []
cumulative_retransmissions = []

# Analyze packets in the PCAP file
cap = pyshark.FileCapture(pcap_file)

# Variables to track retransmissions
retransmission_count = 0
window_sizes_dict = {}

# Process each packet
for packet in cap:
    if hasattr(packet, 'tcp'):
        timestamp = float(packet.sniff_time.timestamp())
        timestamps.append(timestamp)

        # Throughput: Calculate total bytes
        if hasattr(packet.tcp, 'len'):
            length = int(packet.tcp.len)
            throughput.append(length)

        # Window size
        if hasattr(packet.tcp, 'window_size'):
            window_size = int(packet.tcp.window_size)
            window_sizes.append(window_size)
            window_sizes_dict[timestamp] = window_size

        # Retransmissions
        if 'retransmission' in packet.tcp.field_names:
            retransmission_count += 1
            cumulative_retransmissions.append(retransmission_count)

# Create time intervals for throughput
time_intervals = np.arange(min(timestamps), max(timestamps), 1)

# Calculate throughput in Mbps (rolling sum over a 1-second window)
throughput_mbps = []
for t in time_intervals:
    bytes_in_interval = sum(length for ts, length in zip(timestamps, throughput) if t <= ts < t + 1)
    throughput_mbps.append(bytes_in_interval * 8 / 1e6)  # Convert bytes to Mbps

# Plotting

# 1. Throughput (Mbps) Over Time
plt.figure(figsize=(10, 6))
plt.plot(time_intervals, throughput_mbps, label='Throughput (Mbps)', color='blue')
plt.title('Throughput Over Time')
plt.xlabel('Time (s)')
plt.ylabel('Throughput (Mbps)')
plt.grid()
plt.legend()
plt.show()

# 2. Window Size (Bytes) Over Time
plt.figure(figsize=(10, 6))
plt.plot(list(window_sizes_dict.keys()), window_sizes_dict.values(), label='Window Size (Bytes)', color='green')
plt.title('Window Size Over Time')
plt.xlabel('Time (s)')
plt.ylabel('Window Size (Bytes)')
plt.grid()
plt.legend()
plt.show()

# 3. Cumulative Number of Retransmissions Over Time
plt.figure(figsize=(10, 6))
plt.plot(timestamps[:len(cumulative_retransmissions)], cumulative_retransmissions, label='Cumulative Retransmissions', color='red')
plt.title('Cumulative Number of Retransmissions Over Time')
plt.xlabel('Time (s)')
plt.ylabel('Cumulative Retransmissions')
plt.grid()
plt.legend()
plt.show()

# 4. Retransmission Graph
plt.figure(figsize=(10, 6))
plt.plot(timestamps[:retransmission_count], [1] * retransmission_count, label='Retransmissions', color='orange', marker='o', linestyle='None')
plt.title('Retransmission Events Over Time')
plt.xlabel('Time (s)')
plt.ylabel('Retransmissions')
plt.grid()
plt.legend()
plt.show()

# Cleanup
cap.close()
