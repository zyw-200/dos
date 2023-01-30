import json
#https://www.cve-search.org/dataset/#data-feeds
#count:  3138 1371 1233
#count add denial of service:  5810 1873 1502
#some keywords in capec, solutions, refer to output/cve_item
#Only find the keywords in summary, the results are  1731 29 15
#Previous vulnerability CVE-2017-7651
#CWE-400 	Uncontrolled Resource Consumption
#CWE-789 	Memory Allocation with Excessive Size Value
#CWE-770: Allocation of Resources Without Limits or Throttling
#268 79
#405 143 original json
#405 143 new json
def output_dos():
	protocal_dos_count = 0
	exhaust_count = 0
	memory_exhaust_count = 0
	#fp = open("/home/yaowen/IoT_study/circl-cve-search-expanded.json")
	fp = open("/home/yaowen/dos/circl-cve-search-expanded_20230130.json")
	out_fp1 = open("output/protocol_dos_cve", "w+")
	out_fp2 = open("output/exhaust", "w+")
	out_fp3 = open("output/memory", "w+")
	lines = fp.readlines()
	for line in lines:
		vul_dict = json.loads(line) 
		cve_id = vul_dict['id']
		summary = vul_dict['summary']
		cwe_type = vul_dict['cwe']
		content = line
		#content = summary
		if ("dos" in content.lower() or "denial of service" in content.lower()) and "protocol" in content.lower():
			#out_fp1.write(cve_id+" "+cwe_type+"\n"+summary+"\n")
			protocal_dos_count+=1
			#sometimes exhaust is in solution
			if "exhaust" in content.lower():
				exhaust_count +=1 
				out_fp2.write(cve_id+" "+cwe_type+"\n"+summary+"\n")
				if "memory" in content.lower():
					memory_exhaust_count += 1	
					out_fp3.write(cve_id+" "+cwe_type+"\n"+summary+"\n")
		
	fp.close()
	out_fp1.close()
	out_fp2.close()
	out_fp3.close()
	print("count: ", protocal_dos_count, exhaust_count, memory_exhaust_count)

def output_dos_using_cwe():
	protocal_dos_count = 0
	exhaust_count = 0
	memory_exhaust_count = 0
	type_list = set()
	fp = open("/home/yaowen/IoT_study/circl-cve-search-expanded.json")
	out_fp1 = open("output/protocol_dos_cve", "w+")
	out_fp2 = open("output/exhaust", "w+")
	out_fp3 = open("output/memory", "w+")
	lines = fp.readlines()
	protocol_keywords = ["protocol", "http", "mqtt", "ftp", "dicom", "smtp", "rtsp", "ssh", "tls", "telnet"]
	cwe_type_list = ["CWE-1050", "CWE-770", "CWE-400", "CWE-789", "CWE-1325", "CWE-404", "CWE-401"]
	for line in lines:
		vul_dict = json.loads(line)
		cve_id = vul_dict['id']
		summary = vul_dict['summary']
		cwe_type = vul_dict['cwe']
		out_dict = {}
		out_dict['id'] = cve_id
		out_dict['cwe'] = cwe_type
		type_list.add(cwe_type)
		out_dict['summary'] = summary
		content = summary
		if (any(cwe_type == cwe for cwe in cwe_type_list) or "exhaust" in content.lower()) and any(keyword in content.lower() for keyword in protocol_keywords):
			exhaust_count +=1 
			json.dump(out_dict, out_fp2, indent=4)
			#out_fp2.write(cve_id+" "+cwe_type+"\n"+summary+"\n")
			if "memory" in content.lower():
				memory_exhaust_count += 1	
				#out_fp3.write(cve_id+" "+cwe_type+"\n"+summary+"\n")
				json.dump(out_dict, out_fp3, indent=4)

		
	fp.close()
	out_fp1.close()
	out_fp2.close()
	out_fp3.close()
	print(type_list)
	print("count: ", protocal_dos_count, exhaust_count, memory_exhaust_count)


def output_year_range():
	year_range = set()
	fp = open("/home/yaowen/IoT_study/circl-cve-search-expanded.json")
	lines = fp.readlines()
	for line in lines:
		vul_dict = json.loads(line) 
		cve_id = vul_dict['id']
		cve_year = int(cve_id[4:8])
		year_range.add(cve_year)
	fp.close()
	print(year_range)


def extract_item(cve_id):
	fp = open("/home/yaowen/IoT_study/circl-cve-search-expanded.json")
	output_file = "output/%s" %cve_id
	out_fp = open(output_file, "w+")
	lines = fp.readlines()
	for line in lines:
		vul_dict = json.loads(line) 
		cur_id = vul_dict['id']
		if cur_id == cve_id:
			json.dump(vul_dict, out_fp, indent=4)
			break
	fp.close()
	out_fp.close()


#output_year_range()
#output_dos()
output_dos_using_cwe()
#extract_item("CVE-2022-22228")
#extract_item("CVE-2017-7651")
#extract_item("CVE-2021-0229") 
#extract_item("CVE-2021-41039") 