from struct import unpack 

f = open('net.cap', 'r')
per_file_header = f.read(24)
num_packets = 0

while True:
	packet_header = f.read(16)
	if len(packet_header) == 0:
		break
	packet_header = unpack('<IIII', packet_header)
	num_packets += 1
	captured_length, total_length = packet_header[2], packet_header[3]
	
	assert captured_length == total_length
	data = f.read(captured_length)

print 'The number of packets is %d.' % num_packets

f.close()
