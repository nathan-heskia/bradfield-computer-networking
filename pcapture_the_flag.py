from struct import unpack 

f = open('net.cap', 'r')
per_file_header = f.read(24)
num_packets = 0

tcp_data = {}

tcp_data_bytes = 0

packet_header = f.read(16)

total_bytes = 16 + 24
while len(packet_header) != 0:
  packet_header = unpack('<IIII', packet_header)
  num_packets += 1
  captured_length, total_length = packet_header[2], packet_header[3]

  assert captured_length == total_length
  data = f.read(captured_length)

  total_bytes += captured_length



  ##### Ethernet Headers

  mac_header = data[:14]
  ether_type = mac_header[-2:]
  mac_dest_address = ':'.join('{:02x}'.format(ord(c)) for c in mac_header[:6])
  mac_src_address = ':'.join('{:02x}'.format(ord(c)) for c in mac_header[6:12])

  assert unpack('>H', ether_type)[0] == 0x0800  # Assert IPv4

  mac_payload_data = data[14:captured_length-4]




  ##### IP Headers

  # Internet Header Length is the lowest order 4 bits of the first byte of the header
  internet_header_length = unpack('B', mac_payload_data[0])[0] & 15
  # Multiply by 4 to get the header length in bytes, as it's specified in 32 bit words
  internet_header_length *= 4

  assert internet_header_length == 20 # Assert 20 byte length header

  ip_header = mac_payload_data[:20]
  ip_header_protocol = unpack('>B', ip_header[9])[0]
  ip_header_src_ip = unpack('>BBBB', ip_header[12:16])
  ip_header_dest_ip = unpack('>BBBB', ip_header[16:])

  assert ip_header_protocol == 6  # Assert TCP

  ip_total_length = unpack('>H', ip_header[2:4])[0]
  ip_data = mac_payload_data[20:ip_total_length]




  ##### TCP Headers

  tcp_header = ip_data[:20]

  print ":".join("{:02x}".format(ord(c)) for c in tcp_header)

  # Determine the ports used to communicate
  tcp_src_port = unpack('>H', tcp_header[:2])
  tcp_dest_port = unpack('>H', tcp_header[2:4])

  # Determine the length of each transport header

  tcp_data_offset = unpack('>B', tcp_header[12])[0] >> 4
  # Multiply by 4 to get the data offset in bytes, as it's specified in 32 bit words
  tcp_data_offset *= 4

  assert tcp_data_offset >= 20 and tcp_data_offset <= 60

  tcp_data_bytes += tcp_data_offset

  # Determine the sequence number for this packet
  tcp_syn = (unpack('>B', tcp_header[13])[0] >> 1) & 1
  tcp_ack = (unpack('>B', tcp_header[13])[0] >> 4) & 1

  if tcp_syn == 1:
    print 'SYN == 1'
  if tcp_ack == 1:
    print 'ACK == 1'

  tcp_seq_num = unpack('>I', tcp_header[4:8])[0]
  tcp_ack_num = unpack('>I', tcp_header[8:12])[0]

  print tcp_seq_num
  print tcp_ack_num

  # Extract the HTTP data from the packet and store it somewhere
  tcp_data[tcp_seq_num] = ip_data[tcp_data_offset:]


  mac_crc_checksum = data[captured_length-4:]

  assert len(mac_header) == 14
  assert len(mac_payload_data) == captured_length - 18
  assert len(mac_crc_checksum) == 4

  packet_header = f.read(16)

print 'The number of packets is %d.' % num_packets
print 'Total bytes: %d' % total_bytes
print 'TCP data bytes: %d' % tcp_data_bytes

f.close()
