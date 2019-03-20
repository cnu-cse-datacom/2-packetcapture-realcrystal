import socket
import struct

def parsing_ethernet_header(data):
	ethernet_header = struct.unpack("!6c6c2s", data)
	"""
	unpack data, format : !6c6c2s
	! : network, big-endian (byte order)
	c : char
	s : char[]
	"""
	ether_src = convert_ethernet_address(ethernet_header[0:6])
	ether_dest = convert_ethernet_address(ethernet_header[6:12])
	ip_header = "0x"+ethernet_header[12].hex()

	print("=======ethernet_header=======")
	print("src_mac_address:", ether_src)
	print("dest_mac_address:", ether_dest)
	print("ip_version", ip_header)

def convert_ethernet_address(data):
	ethernet_addr = list()
	for i in data:
	#data : iterable object
		ethernet_addr.append(i.hex())
		#get data from data and push it to ethernet_addr (as hex format) 
	ethernet_addr = ":".join(ethernet_addr)
	#convert list to String, insert ":" between every element
	return ethernet_addr

def parsing_ip_header(data):
	ip_header = struct.unpack("!BBHHHBBHII", data)

	ip_version = ip_header[0]>>4
	ip_header_length = ip_header[0]&0x0f

	ip_DSC = ip_header[1]
	ip_ECN = ip_header[1]
	ip_total_length = ip_header[2]
	ip_id = ip_header[3]

	ip_flags = hex(ip_header[4])
	ip_rb = (ip_header[4]&0x8000)>>15
	ip_nf = (ip_header[4]&0x4000)>>14
	ip_fragments = (ip_header[4]&0x2000)>>13
	ip_offset = ip_header[4]&0x1fff

	ip_ttl = ip_header[5]
	ip_protocol = ip_header[6]
	ip_checksum = hex(ip_header[7])

	ip_src = convert_ip_address(ip_header[8]).decode("utf-8")
	ip_dest = convert_ip_address(ip_header[9]).decode("utf-8")


	print("=======IP header=======")
	print("ip_version:", ip_version)
	print("ip_Length:", ip_header_length)
	print("differentiated_service_codepoint:", ip_DSC)
	print("explicit_congestion_notification:", ip_ECN)
	print("total_length:", ip_total_length)
	print("identification ", ip_id)
	print("flags:", ip_flags)
	print(">>>reserved_bits:", ip_rb)
	print(">>>not_fragments:", ip_nf)
	print(">>>fragments:", ip_fragments)
	print(">>>fragments_offset:", ip_offset)
	print("Time to live:", ip_ttl)
	print("protocol:", ip_protocol)
	print("header checksum:", ip_checksum)
	print("source_ip_address:", ip_src)
	print("dest_ip_address:", ip_dest)

	return ip_protocol


def convert_ip_address(data):
	raw = struct.pack('I', data)
	octets = struct.unpack('BBBB', raw)[::-1]
	addr = b'.'.join([('%d' % o).encode('ascii')for o in bytearray(octets)])
	return addr



def parsing_tcp_header(data):
	tcp_header = struct.unpack("!HHIIBBHHH", data)	
	src_port = tcp_header[0]
	dec_port = tcp_header[1]
	seq_num = tcp_header[2]
	ack_num = tcp_header[3]
	header_len = 4 * (tcp_header[4] >> 4)

	flags = tcp_header[5]
	reserved = (tcp_header[5] & 0x0E00)>>9
	nonce = (tcp_header[5] & 0x0100)>>8
	cwr = (tcp_header[5] & 0x0080)>>7
	urgent = (tcp_header[5] & 0x0020)>>5
	ack = (tcp_header[5] & 0x0010)>>4
	push = (tcp_header[5] & 0x0008)>>3
	reset = (tcp_header[5] & 0x0004)>>2
	syn = (tcp_header[5] & 0x0002)>>2
	fin = tcp_header[5] & 0x0001

	win_size_value = tcp_header[6]
	checksum = tcp_header[7]
	urgent_pointer = tcp_header[8]

	print("=======tcp_header=======")
	print("src_port:", src_port)
	print("dec_port:", dec_port)
	print("seq_num:", seq_num)
	print("ack_num:", ack_num)
	print("header_len:", header_len)
	print("flags:", flags)
	print(">>>reserved:", reserved)
	print(">>>nonce:", nonce)
	print(">>>cwr:", cwr)
	print(">>>urgent:", urgent)
	print(">>>ack:", ack)
	print(">>>push:", push)
	print(">>>reset:", reset)
	print(">>>syn:", syn)
	print(">>>fin:", fin)
	print("window_size_value:", win_size_value)
	print("checksum:", checksum)
	print("urgent_pointer:", urgent_pointer)





def parsing_udp_header(data):
	udp_header = struct.unpack("!HHHH", data)

	src_port = udp_header[0]
	dst_port = udp_header[1]
	leng = udp_header[2]
	checksum = hex(udp_header[3])
	
	print("=======udp_header=======")
	print("src_port:", src_port)
	print("dst_port:", dst_port)
	print("leng:", leng)
	print("header checksum:", checksum)


recv_socket=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

while True:
	data = recv_socket.recvfrom(65565)
	parsing_ethernet_header(data[0][0:14])
	protocol  =  parsing_ip_header(data[0][14:34])
	if protocol == 6:
		parsing_tcp_header(data[0][34:54])
	elif protocol == 17:
		parsing_udp_header(data[0][34:42])
	else :
		print("@@@no udp, no tcp@@@")
