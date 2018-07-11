import pyshark
from struct import unpack 

f = open('net.cap', 'rb')
cap = pyshark.FileCapture('net.cap')
per_file_header = f.read(24)
num_packets = 0

tcp_data = {}
packet_header = f.read(16)
output_f = open('out', 'wb')

while len(packet_header) != 0:
  packet_header = unpack('<IIII', packet_header)
  num_packets += 1
  captured_length, total_length = packet_header[2], packet_header[3]

  assert captured_length == total_length
  assert int(cap[num_packets-1].captured_length) == captured_length
  data = f.read(captured_length)

  ##### Ethernet Headers

  mac_header = data[:14]
  ether_type = mac_header[-2:]
  mac_dest_address = ':'.join('{:02x}'.format(c) for c in mac_header[:6])
  mac_src_address = ':'.join('{:02x}'.format(c) for c in mac_header[6:12])

  assert unpack('>H', ether_type)[0] == 0x0800  # Assert IPv4

  mac_payload_data = data[14:captured_length]

  ##### IP Headers

  # Internet Header Length is the lowest order 4 bits of the first byte of the header
  internet_header_length = mac_payload_data[0] & 15
  # Multiply by 4 to get the header length in bytes, as it's specified in 32 bit words
  internet_header_length *= 4

  assert internet_header_length == 20 # Assert 20 byte length header
  assert int(cap[num_packets-1].ip.hdr_len) == internet_header_length

  ip_header = mac_payload_data[:20]
  ip_header_protocol =  ip_header[9]
  ip_header_src_ip = unpack('>BBBB', ip_header[12:16])
  ip_header_dest_ip = unpack('>BBBB', ip_header[16:])

  assert ip_header_protocol == 6  # Assert TCP

  ip_total_length = unpack('>H', ip_header[2:4])[0]

  assert int(cap[num_packets-1].ip.len) == ip_total_length

  ip_data = mac_payload_data[20:ip_total_length]

  ##### TCP Headers

  tcp_header = ip_data[:20]

  #print ":".join("{:02x}".format(ord(c)) for c in tcp_header)

  # Determine the ports used to communicate
  tcp_src_port = unpack('>H', tcp_header[:2])
  tcp_dest_port = unpack('>H', tcp_header[2:4])

  # Determine the length of each transport header

  tcp_header_length = tcp_header[12] >> 4
  # Multiply by 4 to get the data offset in bytes, as it's specified in 32 bit words
  tcp_header_length *= 4

  assert tcp_header_length >= 20 and tcp_header_length <= 60
  assert int(cap[num_packets-1].tcp.hdr_len) == tcp_header_length

  tcp_header = ip_data[:tcp_header_length]

  # Determine the sequence number for this packet
  tcp_syn = (tcp_header[13] >> 1) & 1
  tcp_ack = (tcp_header[13] >> 4) & 1
  tcp_seq_num = unpack('>I', tcp_header[4:8])[0]
  tcp_ack_num = unpack('>I', tcp_header[8:12])[0]

  # Extract the HTTP data from the packet and store it somewhere
  assert int(cap[num_packets-1].tcp.len) == len(ip_data[tcp_header_length:])

  tcp_data[tcp_seq_num] = ip_data[tcp_header_length:]

  packet_header = f.read(16)


print('The number of packets is %d.' % num_packets)

sorted_keys = sorted(tcp_data.keys())

for k in sorted_keys:
  output_f.write(tcp_data[k])

f.close()
output_f.close()
