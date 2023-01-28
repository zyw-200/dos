import json
#https://www.cve-search.org/dataset/#data-feeds
#count:  3138 1371 1233
def output_dos():
	protocal_dos_count = 0
	exhaust_count = 0
	memory_exhaust_count = 0
	fp = open("/home/yaowen/IoT_study/circl-cve-search-expanded.json")
	out_fp = open("protocol_dos_cve", "w+")
	lines = fp.readlines()
	for line in lines:
		if "dos" in line.lower() and "protocol" in line.lower():
			vul_dict = json.loads(line) 
			cve_id = vul_dict['id']
			summary = vul_dict['summary']
			print(cve_id, summary)
			out_fp.write(cve_id+"\n"+summary+"\n")
			protocal_dos_count+=1
			#sometimes exhaust is in solution
			if "exhaust" in line.lower():
				exhaust_count +=1 
				if "memory" in line.lower():
					memory_exhaust_count += 1			
	fp.close()
	out_fp.close()
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

output_year_range()
#output_dos()