import sys
import dictionary


def readfile(file_path):
	file=open(file_path,"rb")
	byteBuffer=bytearray(file.read())

	return byteBuffer


##big endian 기준
def hex_to_dec(hexlist):
	_len=len(hexlist)
	if _len==1:
		return hexlist[0]
	else:
		i=_len-1
		decvalue=0
		while i>=0:
			decvalue=decvalue<<8
			decvalue=decvalue|hexlist[i]
			i=i-1

		return decvalue

##Endian 변환
def change_endian(hexlist):
	_len=len(hexlist)
	change_list=[]
	if _len==1:
		return hexlist[0]
	else:
		i=_len-1
		while i>=0:
			change_list.append(hexlist[i])
			i=i-1
		return change_list


def next_pkt_chk(_offset, byteBuffer):
	if len(byteBuffer)-1 >= _offset:
		return 1
	else:
		return 0

"""
Description:
File의 Magic Number를 이용해
정상적인 덤프파일인지 판별하는 함수

* pcap-ng 판별루틴 추가 예정

return:
1 : pcap 파일
0 : magic_number 불일치 파일
"""
def chk_file(byteBuffer):
	##Magic Number Check
	i=1
	mgcNum_buffer=[]
	mgcNum_pcap=[0xD4, 0xC3, 0xB2, 0xA1]

	for val in byteBuffer:
		if i % 5 == 0:
			if mgcNum_buffer==mgcNum_pcap:
				return 1
			else:
				return 0

		mgcNum_buffer.append(val)
		i=i+1


"""
* pcap-ng 추가 예정
Description:
	덤프파일을 Byte단위로 읽어온 후
	Global Header를 파싱하여 딕셔너리에 파싱결과를
	저장한 후 해당 딕셔너리를 반환하는 함수
Parameter:
	file_path: 분석할 파일의 경로
	file_type: 파일 타입(1이면 pcap, 2면 pcap-ng)
return:
	현재까지 읽은 offset 값(24)
"""
def parse_ghdr(file_type, byteBuffer):	
	##Pcap File
	if file_type == 1:
		i=0
		while i <= 25:
			if i>=0 and i<=3:
				dictionary.pcap_hdr_s['magic_number'].append(byteBuffer[i])

			elif i>=4 and i<=5:
				dictionary.pcap_hdr_s['version_major'].append(byteBuffer[i])

			elif i>=6 and i<=7:
				dictionary.pcap_hdr_s['version_minor'].append(byteBuffer[i])

			elif i>=8 and i<=11:
				dictionary.pcap_hdr_s['thiszone'].append(byteBuffer[i])

			elif i>=12 and i<=15:
				dictionary.pcap_hdr_s['sigfigs'].append(byteBuffer[i])

			elif i>=16 and i<=19:
				dictionary.pcap_hdr_s['snaplen'].append(byteBuffer[i])

			elif i>=20 and i<=23:
				dictionary.pcap_hdr_s['network'].append(byteBuffer[i])
			
			else:
				# offset return
				return 24
			i=i+1

def parse_rhdr(_offset, byteBuffer):
	rhdr_temp={
		'ts_sec':[],
		'ts_usec':[],
		'incl_len':[],
		'orig_len':[]
	}
	i=0
	while i <= 16:
		if i>=0 and i<=3:
			rhdr_temp['ts_sec'].append(byteBuffer[_offset+i])
		elif i>=4 and i<=7:
			rhdr_temp['ts_usec'].append(byteBuffer[_offset+i])
		elif i>=8 and i<=11:
			rhdr_temp['incl_len'].append(byteBuffer[_offset+i])
		elif i>=12 and i<=15:
			rhdr_temp['orig_len'].append(byteBuffer[_offset+i])

		i=i+1
	
	dictionary.pkt_hdr_s=rhdr_temp;
	return _offset+16;

def get_pktdata_length(snaplen, incl_len, orig_len):
	if incl_len == orig_len:
		return incl_len
	elif incl_len != orig_len:
		return snaplen

def read_rdata(_offset, byteBuffer, data_length):
	sys.stdout.write('data_length:')
	print(data_length)
	rdata=[]
	i=0
	while i<data_length:
		rdata.append(byteBuffer[_offset+i])
		i=i+1

	return rdata

def parse_ethernet(rdata, rdata_offset):
	eth_temp={
		'des_mac':[],
		'src_mac':[],
		'type_length':[],
		'data':[],
		'padding':[]
	}
	i=0
	rdata_length=len(rdata)
	while i<rdata_length:
		if i>=0 and i<=5:
			eth_temp['des_mac'].append(rdata[rdata_offset+i])
		elif i>=6 and i<=11:
			eth_temp['src_mac'].append(rdata[rdata_offset+i])
		elif i>=12 and i<=13:
			eth_temp['type_length'].append(rdata[rdata_offset+i])
		else:
			eth_temp['data'].append(rdata[rdata_offset+i])

		i=i+1
	
	##padding 판별용 변수
	# 실제 ethernet frame의 data필드에서 상위 프로토콜 데이터정보의 길이
	real_length=0

	##ethernet frame의 type/length값(상위 프로토콜 구분)에 따라 프로토콜별 파싱함수 호출
	# arp 프로토콜
	if eth_temp['type_length']==[0x08, 0x06]:
		real_length=parse_arp(eth_temp['data'])

	# ip_v4 프로토콜
	elif eth_temp['type_length']==[0x08, 0x00]:
		real_length=parse_ipv4(eth_temp['data'])
	
	# ip_v6 프로토콜
	elif eth_temp['type_length']==[0x86, 0xDD]:
		print("ipv6")
	
	# 분석 지원하지 않는 패킷
	else:
		print("Unkwon")
	
	# Padding 계산 후 삽입
	withoutPaddingLength=len(eth_temp['des_mac'])+len(eth_temp['src_mac'])+len(eth_temp['type_length'])+real_length
	sys.stdout.write("real_length:")
	print(real_length)
	if rdata_length==60 and rdata_length>withoutPaddingLength and real_length!=0:
		print("padding존재")
	
	
	dictionary.eth_frame=eth_temp


##씨발 이거 구조 좀 이상한거 같은데
# 좆나 프로그램 안에 offset 변수 존나게 많고
# 씨발 일반화 시킬 방법도 안떠오르고
# 다짜고 갈아엎어야지 씨발
def parse_arp(_data):
	arp_pkt_temp={
		'hardware_type':[],
		'protocol_type':[],
		'hardware_size':[],
		'protocol_size':[],
		'opcode':[],
		'sender_mac':[],
		'sender_ip':[],
		'target_mac':[],
		'target_ip':[]
	}
	
	arp_pkt_temp['hardware_type'].append(_data[0])
	arp_pkt_temp['hardware_type'].append(_data[1])

	arp_pkt_temp['protocol_type'].append(_data[2])
	arp_pkt_temp['protocol_type'].append(_data[3])

	arp_pkt_temp['hardware_size'].append(_data[4])

	arp_pkt_temp['protocol_size'].append(_data[5])

	arp_pkt_temp['opcode'].append(_data[6])
	arp_pkt_temp['opcode'].append(_data[7])
	
	print("--------------------ARP--------------------")
	sys.stdout.write("hardware_type : ")
	print(hex(arp_pkt_temp['hardware_type'][0])+" "+hex(arp_pkt_temp['hardware_type'][1]))
	sys.stdout.write("protocol_type : ")
	print(hex(arp_pkt_temp['protocol_type'][0])+" "+hex(arp_pkt_temp['protocol_type'][1]))
	sys.stdout.write("hardware_size : ")
	print(hex(arp_pkt_temp['hardware_size'][0]))
	sys.stdout.write("protocol_size : ")
	print(hex(arp_pkt_temp['protocol_size'][0]))
	sys.stdout.write("opcode : ")
	print(hex(arp_pkt_temp['opcode'][0])+" "+hex(arp_pkt_temp['opcode'][1]))
	

	sys.stdout.write("sender_mac : ")
	_offset=8
	i=0
	while i<hex_to_dec(arp_pkt_temp['hardware_size']):
		arp_pkt_temp['sender_mac'].append(_data[_offset+i])
		sys.stdout.write(hex(_data[_offset+i])+" ")
		i=i+1
	
	_offset=_offset+hex_to_dec(arp_pkt_temp['hardware_size'])
	print("")
	
	sys.stdout.write("sender_ip : ")
	i=0
	while i<hex_to_dec(arp_pkt_temp['protocol_size']):
		arp_pkt_temp['sender_ip'].append(_data[_offset+i])
		sys.stdout.write(hex(_data[_offset+i])+" ")
		i=i+1
		
	_offset=_offset+hex_to_dec(arp_pkt_temp['protocol_size'])
	print("")
	
	sys.stdout.write("target_mac : ")
	i=0
	while i<hex_to_dec(arp_pkt_temp['hardware_size']):
		arp_pkt_temp['target_mac'].append(_data[_offset+i])
		sys.stdout.write(hex(_data[_offset+i])+" ")
		i=i+1
	
	_offset=_offset+hex_to_dec(arp_pkt_temp['hardware_size'])
	print("")

	
	sys.stdout.write("target_ip : ")
	i=0
	while i<hex_to_dec(arp_pkt_temp['protocol_size']):
		arp_pkt_temp['target_ip'].append(_data[_offset+i])
		sys.stdout.write(hex(_data[_offset+i])+" ")
		i=i+1
	
	_offset=_offset+hex_to_dec(arp_pkt_temp['protocol_size'])
	print("")
	
	arp_pkt=arp_pkt_temp
	# Ethernet Padding 값 추출을 위해 지금까지 읽은 비트 수 반환
	return _offset

def parse_ipv4(_data):
	ipv4_pkt_temp={
		'ip_v':0,
		'ip_hl':0,
		'ip_tos':0,
		'ip_len':[],
		'ip_id':[],
		'flags':0,
		'ip_off':0,
		'ip_ttl':0,
		'ip_p':0,
		'ip_sum':[],
		'ip_src':[],
		'ip_dst':[],
		'option':[],
		'data':[]
	}
	# 읽은 바이트 수
	_offset=0

	##Header Length와 version정보 파싱
	# data read
	hl_and_v=_data[_offset]
	_offset=_offset+1

	# 상위 4비트, 하위 4비트 쪼개기
	temp=hl_and_v>>4
	ipv4_pkt_temp['ip_v']=temp
	temp=temp<<4
	ipv4_pkt_temp['ip_hl']=(temp^hl_and_v)*4
	
	# fragment offset 변수
	frag_offset=[]

	# ip header 파싱
	while _offset<ipv4_pkt_temp['ip_hl']:
		if _offset==1:
			ipv4_pkt_temp['ip_tos']=_data[_offset]
		elif _offset>=2 and _offset<=3:
			ipv4_pkt_temp['ip_len'].append(_data[_offset])
		elif _offset>=4 and _offset<=5:
			ipv4_pkt_temp['ip_id'].append(_data[_offset])
		elif _offset>=6 and _offset<=7:
			frag_offset.append(_data[_offset])
		elif _offset==8:
			ipv4_pkt_temp['ip_ttl']=_data[_offset]
		elif _offset==9:
			ipv4_pkt_temp['ip_p']=_data[_offset]
		elif _offset>=10 and _offset<=11:
			ipv4_pkt_temp['ip_sum'].append(_data[_offset])
		elif _offset>=12 and _offset<=15:
			ipv4_pkt_temp['ip_src'].append(_data[_offset])
		elif _offset>=16 and _offset<=19:
			ipv4_pkt_temp['ip_dst'].append(_data[_offset])
		else:
			ipv4_pkt_temp['option'].append(_data[_offset])

		_offset=_offset+1
	
	# flag, fragment offset 분할 후 삽입
	# 아젿같네 씨발 패킷구조를 뭐 이따구로 쳐만든거지
	#ㅇ나ㅓㅣㄴ아러ㅣ버리ㅏ어ㅓ임ㄴ 로그하나 찍는게 존나 노가다야 씨발 아나 씨발씨발씨발씨발씨발씨발
	temp=hex_to_dec(change_endian(frag_offset))
	ipv4_pkt_temp['flags']=temp>>13
	ipv4_pkt_temp['ip_off']=hex_to_dec(change_endian(frag_offset))^temp
	
	print("-----------------ipv4-----------------")
	sys.stdout.write("ip version:")
	print(ipv4_pkt_temp['ip_v'])
	sys.stdout.write("ip header length:")
	print(ipv4_pkt_temp['ip_hl'])
	sys.stdout.write("TOS:")
	print(hex(ipv4_pkt_temp['ip_tos']))
	sys.stdout.write("total_length:")
	print(hex(ipv4_pkt_temp['ip_len'][0])+" "+hex(ipv4_pkt_temp['ip_len'][1]))
	sys.stdout.write("identification:")
	print(hex(ipv4_pkt_temp['ip_id'][0])+" "+hex(ipv4_pkt_temp['ip_id'][1]))
	sys.stdout.write("flags:")
	print(hex(ipv4_pkt_temp['flags']))
	sys.stdout.write("frag_offset:")
	print(hex(ipv4_pkt_temp['ip_off']))
	print(hex(frag_offset[0])+" "+hex(frag_offset[1]))
	sys.stdout.write("ttl:")
	print(ipv4_pkt_temp['ip_ttl'])
	sys.stdout.write("protocol:")
	print(ipv4_pkt_temp['ip_p'])
	sys.stdout.write("ip_sum:")
	print(hex(ipv4_pkt_temp['ip_sum'][0])+" "+hex(ipv4_pkt_temp['ip_sum'][1]))
	sys.stdout.write("ip_src:")
	print(hex(ipv4_pkt_temp['ip_src'][0])+" "+hex(ipv4_pkt_temp['ip_src'][1])+" "+hex(ipv4_pkt_temp['ip_src'][2])+" "+hex(ipv4_pkt_temp['ip_src'][3]))
	sys.stdout.write("ip_dst:")
	print(hex(ipv4_pkt_temp['ip_dst'][0])+" "+hex(ipv4_pkt_temp['ip_dst'][1])+" "+hex(ipv4_pkt_temp['ip_dst'][2])+" "+hex(ipv4_pkt_temp['ip_dst'][3]))

	# ip data 부분 파싱
	#total_len=hex_to_dec(change_endian(ipv4_pkt_temp['ip_len']))
	total_len=len(_data)
	while _offset<total_len:
		ipv4_pkt_temp['data'].append(_data[_offset])
		sys.stdout.write(hex(_data[_offset])+" ")
		_offset=_offset+1
	print("")
	
	# 분석된 데이터 삽입
	ipv4_pkt=ipv4_pkt_temp
	
	# 상위 프로토콜 분류코드 인식 후 분기
	if ipv4_pkt_temp['ip_p']==1:
		print("icmp")
	elif ipv4_pkt_temp['ip_p']==6:
		_offset=_offset+parse_tcp(ipv4_pkt_temp['data'])
	elif ipv4_pkt_temp['ip_p']==17:
		_offset=_offset+parse_udp(ipv4_pkt_temp['data'])
	
	# 읽은 byte 수 리턴
	return _offset

def parse_tcp(_data):
	tcp_pkt_temp={
		'src_port':[],
		'dest_port':[],
		'seq_num':[],
		'ack_num':[],
		'hl':0,
		'reserved':0,
		'flags':0,
		'window_sz':[],
		'chk_sum':[],
		'urgent_p':[],
		'opt_pad':[],
		'data':[]
	}
	_offset=0   # 읽은 바이트 수
	hl_resrv=0 # header length와 reserved 필드를 분리하기 전 상태

	##tcp header 파싱
	while _offset<20:
		if _offset>=0 and _offset<=1:
			tcp_pkt_temp['src_port'].append(_data[_offset])
		elif _offset>=2 and _offset<=3:
			tcp_pkt_temp['dest_port'].append(_data[_offset])
		elif _offset>=4 and _offset<=7:
			tcp_pkt_temp['seq_num'].append(_data[_offset])
		elif _offset>=8 and _offset<=11:
			tcp_pkt_temp['ack_num'].append(_data[_offset])
		elif _offset==12:
			hl_resrv=_data[_offset]
		elif _offset==13:
			tcp_pkt_temp['flags']=_data[_offset]
		elif _offset>=14 and _offset<=15:
			tcp_pkt_temp['window_sz'].append(_data[_offset])
		elif _offset>=16 and _offset<=17:
			tcp_pkt_temp['chk_sum'].append(_data[_offset])
		elif _offset>=18 and _offset<=19:
			tcp_pkt_temp['urgent_p'].append(_data[_offset])
		
		_offset=_offset+1
	

	##hl_resrv 분할 후 header length 및 reserved 구하기
	tcp_pkt_temp['hl']=(hl_resrv>>4)
	hl_resrv=(tcp_pkt_temp['hl']<<4)^hl_resrv
	tcp_pkt_temp['reserved']=hl_resrv
	tcp_pkt_temp['hl']=tcp_pkt_temp['hl']*4

	print("-----------------tcp-----------------")
	sys.stdout.write("src_port:")
	print(hex_to_dec(change_endian(tcp_pkt_temp['src_port'])))
	sys.stdout.write("dest_port:")
	print(hex_to_dec(change_endian(tcp_pkt_temp['dest_port'])))
	sys.stdout.write("seq_num:")
	print(hex(tcp_pkt_temp['seq_num'][0])+" "+hex(tcp_pkt_temp['seq_num'][1])+" "+hex(tcp_pkt_temp['seq_num'][2])+" "+hex(tcp_pkt_temp['seq_num'][3])+" ")
	sys.stdout.write("ack_num:")
	print(hex(tcp_pkt_temp['ack_num'][0])+" "+hex(tcp_pkt_temp['ack_num'][1])+" "+hex(tcp_pkt_temp['ack_num'][2])+" "+hex(tcp_pkt_temp['ack_num'][3])+" ")
	sys.stdout.write("header_length:")
	print(tcp_pkt_temp['hl'])
	sys.stdout.write("reserved:")
	print(tcp_pkt_temp['reserved'])
	sys.stdout.write("flags:")
	print(hex(tcp_pkt_temp['flags']))
	sys.stdout.write("window_sz:")
	print(hex(tcp_pkt_temp['window_sz'][0])+" "+hex(tcp_pkt_temp['window_sz'][1]))
	sys.stdout.write("chk_sum:")
	print(hex(tcp_pkt_temp['chk_sum'][0])+" "+hex(tcp_pkt_temp['chk_sum'][1]))
	sys.stdout.write("urgent_p:")
	print(hex(tcp_pkt_temp['urgent_p'][0])+" "+hex(tcp_pkt_temp['urgent_p'][1]))


	sys.stdout.write("option and padding:")
	##option 및 padding 데이터 존재여부 확인 후 파싱
	if tcp_pkt_temp['hl']>20:
		while _offset<tcp_pkt_temp['hl']:
			tcp_pkt_temp['opt_pad'].append(_data[_offset])
			sys.stdout.write(hex(_data[_offset])+" ")
			_offset=_offset+1
	print("")
	
	sys.stdout.write("tcp data:")
	print(_offset)
	##tcp data 필드 파싱
	tcp_length=len(_data)
	while _offset<tcp_length:
		tcp_pkt_temp['data'].append(_data[_offset])
		sys.stdout.write(hex(_data[_offset])+" ")
		_offset=_offset+1

	print("")
	
	# 분석된 데이터 삽입
	tcp_pkt=tcp_pkt_temp
	
	# 읽은 byte 수 리턴
	return _offset


def parse_udp(_data):
	udp_pkt_temp={
		'src_port':[],
		'dest_port':[],
		'length':[],
		'chk_sum':[],
		'data':[]
	}

	_offset=0   # 읽은 바이트 수
	
	##udp header 파싱
	while _offset<8:
		if _offset>=0 and _offset<=1:
			udp_pkt_temp['src_port'].append(_data[_offset])
		elif _offset>=2 and _offset<=3:
			udp_pkt_temp['dest_port'].append(_data[_offset])
		elif _offset>=4 and _offset<=5:
			udp_pkt_temp['length'].append(_data[_offset])
		elif _offset>=6 and _offset<=7:
			udp_pkt_temp['chk_sum'].append(_data[_offset])
		
		_offset=_offset+1
	
	print("-----------------udp-----------------")
	sys.stdout.write("src_port:")
	print(hex_to_dec(change_endian(udp_pkt_temp['src_port'])))
	sys.stdout.write("dest_port:")
	print(hex_to_dec(change_endian(udp_pkt_temp['src_port'])))
	sys.stdout.write("length:")
	print(hex(udp_pkt_temp['length'][0])+" "+hex(udp_pkt_temp['length'][1]))
	sys.stdout.write("chk_sum:")
	print(hex(udp_pkt_temp['chk_sum'][0])+" "+hex(udp_pkt_temp['chk_sum'][1]))

	sys.stdout.write("udp data:")
	##udp data 파싱
	udp_length=len(_data)
	while _offset<udp_length:
		udp_pkt_temp['data'].append(_data[_offset])
		sys.stdout.write(hex(_data[_offset])+" ")
		_offset=_offset+1
	print("")

	udp_pkt=udp_pkt_temp
	return _offset