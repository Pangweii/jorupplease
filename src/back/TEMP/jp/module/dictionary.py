"""

Description:
프로그램에서 사용할 딕셔너리를 정의
ex) global_header, packet_header(record_header) 등

return:
"""

## Global Header
pcap_hdr_s={
	'magic_number':[],
	'version_major':[],
	'version_minor':[],
	'thiszone':[],
	'sigfigs':[],
	'snaplen':[],
	'network':[]
}

## Packet(Record) Header
pkt_hdr_s={
	'ts_sec':[],
	'ts_usec':[],
	'incl_len':[],
	'orig_len':[]
}

eth_frame={
	'des_mac':[],
	'src_mac':[],
	'type_length':[],
	'data':[],
	'padding':[]
}

arp_pkt={
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

ipv4_pkt={
	'ip_hl':0,
	'ip_v':0,
	'ip_tos':0,
	'ip_len':[],
	'ip_id':[],
	'flags':0,
	'ip_off':0,
	'ip_ttl':0,
	'ip_p':[],
	'ip_sum':[],
	'ip_src':[],
	'ip_dst':[],
	'option':[],
	'data':[]
}

tcp_pkt={
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

udp_pkt={
	'src_port':[],
	'dest_port':[],
	'length':[],
	'chk_sum':[],
	'data':[]
}

## Front-End의 Flow화면에 들어갈 정보
flow_s={
	'frm_num':'',
	'time':'',
	'src_ip':'',
	'dest_ip':'',
	'src_port':'',
	'dest_port':'',
	'protocol':'',
	'length':''
}

## flow의 hex값을 나타내기 위한 딕셔너리
flow_hex={
	'hfrm_num':[],
	'htime':[],
	'hsrc_ip':[],
	'hdest_ip':[],
	'hsrc_port':[],
	'hdest_port':[],
	'hprotocol':[],
	'hlength':[]
}

## 7계층프로토콜 구분정보
#  참조 딕셔너리(변경x)
protocol_type7={
	'http':'',
	'ftp':'',
	'smtp':'',
	'smtp':'',
	'pop':'',
	'telnet':'',
	'dns':''
}

## 프로토콜 별 카운트 값
#  초기 값은 0으로 세팅
protocol_cnt_s={
	'eth':0,
	'arp':0,
	'ipv4':0,
	'ipv6':0,
	'icmp':0,
	'tcp':0,
	'udp':0,
	'http':0,
	'ftp':0,
	'smtp':0,
	'smtp':0,
	'pop':0,
	'telnet':0,
	'dns':0
}

##I/O Count Dictionary
# 초기 값은 0으로 세팅
io_cnt_s={
	'inbound':0,
	'outbound':0
}

## 국가별 트래픽 카운트 값
#  초기 값은 0으로 세팅
#  키를 전부 추가하기엔 키의 개수가 방대하므로
#  트래픽 발생 시 키를 추가.
#  따라서 포함되지 않은 것은 0으로 간주된다.
geomap_cnt_s={}