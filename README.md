# pcap_packet_parsing
analyzes TCP transactions and flows and prints out outputs such as throughput, congestion window size, number of retransmission and triple ack etc, when the end of the flow is reached.

My analysis_pcap_tcp.py analyzes TCP transactions and flows and prints out required outputs when the end of the flow is reached. It opens a PCAP file in binary form and reads it with the DPKT library. I have made a custom class called “Flow” in order to store and calculate the data.

Python version 3.8 or higher and installation dpkt and socket library are required to run analysis_pcap_tcp.py. You can also read other pcap files and analyze them by changing the file names at line 31.
