# packet_send_simulate
packet send simulate program for sending packets export from wireshark

How to use this program
(1) use wireshark to sniffer target packet
(2) find specific packet, copy as a Hex Stream, and store in a text file
(3) compile the program
(4) use command `sudo ./packet_send_simulate -f <filename>` to send packet
