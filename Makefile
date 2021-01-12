packet_send_simulate: packet_send_simulate.o
	cc -o packet_send_simulate packet_send_simulate.o -lpcap

packet_send_simulate.o: packet_send_simulate.c
	cc -c packet_send_simulate.c -lpcap

clean: 
	rm packet_send_simulate packet_send_simulate.o
