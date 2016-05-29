import sys
sys.path.append("C:/Users/jinyoung/Documents/GitHub/TEMP/jp/module")
import function
import dictionary

fpath = "C:/Users/jinyoung/Documents/GitHub/TEMP/test_pcap/집에갈래요.pcap"

#파일 바이너리 오픈
byteBuffer=function.readfile(fpath)

#업로드 파일 체크
cap_chk=function.chk_file(byteBuffer)
if cap_chk == 0:
	print("파일을 다시 확인 해주세요.")
	sys.exit()

#offset 세팅 및 global header 파싱
_offset=0;
_offset=function.parse_ghdr(1, byteBuffer)


##2계층 프로토콜 확인
# ethernet일 경우
if dictionary.pcap_hdr_s['network']==[0x01, 0x00, 0x00, 0x00]:
	print("--------------------global header--------------------")
	print(hex(dictionary.pcap_hdr_s['magic_number'][0])+" "+hex(dictionary.pcap_hdr_s['magic_number'][1])+" "+hex(dictionary.pcap_hdr_s['magic_number'][2])+" "+hex(dictionary.pcap_hdr_s['magic_number'][3]))
	print(hex(dictionary.pcap_hdr_s['version_major'][0])+" "+hex(dictionary.pcap_hdr_s['version_major'][1]))
	print(hex(dictionary.pcap_hdr_s['version_minor'][0])+" "+hex(dictionary.pcap_hdr_s['version_minor'][1]))
	print(hex(dictionary.pcap_hdr_s['thiszone'][0])+" "+hex(dictionary.pcap_hdr_s['thiszone'][1])+" "+hex(dictionary.pcap_hdr_s['thiszone'][2])+" "+hex(dictionary.pcap_hdr_s['thiszone'][3]))
	print(hex(dictionary.pcap_hdr_s['sigfigs'][0])+" "+hex(dictionary.pcap_hdr_s['sigfigs'][1])+" "+hex(dictionary.pcap_hdr_s['sigfigs'][2])+" "+hex(dictionary.pcap_hdr_s['sigfigs'][3]))
	print(hex(dictionary.pcap_hdr_s['snaplen'][0])+" "+hex(dictionary.pcap_hdr_s['snaplen'][1])+" "+hex(dictionary.pcap_hdr_s['snaplen'][2])+" "+hex(dictionary.pcap_hdr_s['snaplen'][3]))
	print(hex(dictionary.pcap_hdr_s['network'][0])+" "+hex(dictionary.pcap_hdr_s['network'][1])+" "+hex(dictionary.pcap_hdr_s['network'][2])+" "+hex(dictionary.pcap_hdr_s['network'][3]))

	i=0
	frame_num=1
	#패킷 분석 루프
	while function.next_pkt_chk(_offset, byteBuffer):
		print("")
		sys.stdout.write("frame_number:")
		print(frame_num)
		#Record Header 파싱
		_offset=function.parse_rhdr(_offset, byteBuffer)
		
		print("--------------------record header--------------------")
		print(hex(dictionary.pkt_hdr_s['ts_sec'][0])+" "+hex(dictionary.pkt_hdr_s['ts_sec'][1])+" "+hex(dictionary.pkt_hdr_s['ts_sec'][2])+" "+hex(dictionary.pkt_hdr_s['ts_sec'][3]))
		print(hex(dictionary.pkt_hdr_s['ts_usec'][0])+" "+hex(dictionary.pkt_hdr_s['ts_usec'][1])+" "+hex(dictionary.pkt_hdr_s['ts_usec'][2])+" "+hex(dictionary.pkt_hdr_s['ts_usec'][3]))
		print(hex(dictionary.pkt_hdr_s['incl_len'][0])+" "+hex(dictionary.pkt_hdr_s['incl_len'][1])+" "+hex(dictionary.pkt_hdr_s['incl_len'][2])+" "+hex(dictionary.pkt_hdr_s['incl_len'][3]))
		print(hex(dictionary.pkt_hdr_s['orig_len'][0])+" "+hex(dictionary.pkt_hdr_s['orig_len'][1])+" "+hex(dictionary.pkt_hdr_s['orig_len'][2])+" "+hex(dictionary.pkt_hdr_s['orig_len'][3]))
		

		#Record Data 파싱
		pkt_length=function.get_pktdata_length(dictionary.pcap_hdr_s['snaplen'], dictionary.pkt_hdr_s['incl_len'], dictionary.pkt_hdr_s['orig_len'])
		rdata=function.read_rdata(_offset, byteBuffer, function.hex_to_dec(pkt_length))
		_offset=_offset+function.hex_to_dec(pkt_length)

		print("--------------------record data--------------------")
		i=0
		while i<len(rdata):
			sys.stdout.write(hex(rdata[i]))
			sys.stdout.write(" ")
			i=i+1
		print("")
		
		#Ethernet Frame 파싱
		rdata_offset=0
		function.parse_ethernet(rdata, rdata_offset)

		print("--------------------ethernet_frame--------------------")
		sys.stdout.write("des_mac : ")
		print(hex(dictionary.eth_frame['des_mac'][0])+" "+hex(dictionary.eth_frame['des_mac'][1])+" "+hex(dictionary.eth_frame['des_mac'][2])+" "+hex(dictionary.eth_frame['des_mac'][3])+" "+hex(dictionary.eth_frame['des_mac'][4])+" "+hex(dictionary.eth_frame['des_mac'][5]))
		sys.stdout.write("src_mac : ")
		print(hex(dictionary.eth_frame['src_mac'][0])+" "+hex(dictionary.eth_frame['src_mac'][1])+" "+hex(dictionary.eth_frame['src_mac'][2])+" "+hex(dictionary.eth_frame['src_mac'][3])+" "+hex(dictionary.eth_frame['src_mac'][4])+" "+hex(dictionary.eth_frame['src_mac'][5]))
		sys.stdout.write("type_length : ")
		print(hex(dictionary.eth_frame['type_length'][0])+" "+hex(dictionary.eth_frame['type_length'][1]))
		sys.stdout.write("data : ")
		i=0
		while i<len(dictionary.eth_frame['data']):
			sys.stdout.write(hex(dictionary.eth_frame['data'][i]))
			sys.stdout.write(" ")
			i=i+1

		print(" ")
		print(" ")
		print(" ")
		input("")
		frame_num=frame_num+1

else:
	print("해당 덤프파일의 2계층 프로토콜 분석을 지원하지 않습니다.")
	sys.exit()
