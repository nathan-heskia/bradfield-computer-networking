import random
import socket
import struct
import sys

assert len(sys.argv) == 3

classes = {
    'A': 1,
    'NS': 2,
    'MD': 3,
    'CNAME': 5,
}

classes_inverse = {
    1: 'A',
    2: 'NS',
    3: 'MD',
    5: 'CNAME',
}

hostname = sys.argv[1]
qtype = sys.argv[2]

assert qtype in classes

qtype = classes[qtype]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('8.8.8.8', 53)
message = bytes()

# Request id
request_id = random.randint(1, 2**16 - 1)
message += struct.pack('>H', request_id)
# Set RD to 1
message += struct.pack('>BB', 1, 0)
# Set QDCOUNT to 1
message += struct.pack('>H', 1)
# Set ANCOUNT, NSCOUNT, ARCOUNT to 0
message +=  struct.pack('>HHH', 0, 0, 0)

hostname_labels = hostname.split('.')

for name in hostname_labels:
    length = len(name)
    message += struct.pack('B' + 'B' * length, length, *(ord(x) for x in name))

message += struct.pack('>BHH', 0, 1, 1)

try:
    sent = sock.sendto(message, server_address)

    data, server = sock.recvfrom(2**20)
    print(type(data))
    assert server[0] == '8.8.8.8'
    assert server[1] == 53
finally:
    sock.close()

offset = 0
assert request_id == struct.unpack('>H', data[offset:offset + 2])[0]

offset += 2
assert 0x81 == data[offset]
offset += 1
assert 0x80 == data[offset]
# Assert number of questions is 1
offset += 1
assert 0x00 == struct.unpack('>BB', data[offset:offset + 2])[0]
assert 0x01 == struct.unpack('>BB', data[offset:offset + 2])[1]
print('Questions: 1')
# Get number of answers
offset += 2
num_answers = struct.unpack('>H', data[offset:offset + 2])[0]
print('Answer RRs: ' + str(num_answers))

# Get NSCOUNT
offset += 2

# Get ARCOUNT
offset += 2

# Get QNAME
offset += 2
length = data[offset]
name_labels = []
while length != 0:
    l = struct.unpack('>' + 'B'*length, data[offset + 1: offset + length + 1])
    name_labels.append(''.join([chr(x) for x in l]))
    offset += length + 1
    length = data[offset]

print('Name: ' + '.'.join(name_labels))

# Assert QTYPE
offset += 1
assert 0x00 == struct.unpack('>BB', data[offset:offset + 2])[0]
assert 0x01 == struct.unpack('>BB', data[offset:offset + 2])[1]
# Assert QCLASS
offset += 2
assert 0x00 == struct.unpack('>BB', data[offset:offset + 2])[0]
assert 0x01 == struct.unpack('>BB', data[offset:offset + 2])[1]

print('')

# Parse resource records
offset += 2
for i in range(0, num_answers):
    # TODO: Assert domain name

    # Assert type
    offset += 2
    qtype = struct.unpack('>BB', data[offset:offset + 2])[1]
    print('Query Type: ' + classes_inverse[qtype])

    # Assert class
    offset += 2
    assert 1 == struct.unpack('>BB', data[offset:offset + 2])[1]
    print('Class Type: 1 (Internet)')

    # Print TTL
    offset += 2
    print('Time To Live: ' + str(struct.unpack('>i', data[offset:offset + 4])[0]))

    # Get data length
    offset += 4
    rdlength = struct.unpack('>H', data[offset:offset + 2])[0]
    print('Data Length: ' + str(rdlength))

    offset += 2
    # Get data
    if qtype == 1:
        print('Address: ' + '.'.join([str(x) for x in struct.unpack('>BBBB', data[offset:offset + rdlength])]))
    offset += rdlength

    if i < num_answers - 1:
        print('')
