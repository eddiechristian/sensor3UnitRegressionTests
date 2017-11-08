#!/usr/bin/python
import sys
import re
import hashlib
import getopt
import os
import inspect

def getFlowKey(line):
 event_type = getEvent_type(line)
 matchObj = re.match(r'.*src_ip":"([^"]*)","src_port":(\d*),"dest_ip":"([^"]*)","dest_port":(\d*),.*"proto":"([^"]*)",.*',line,re.M|re.I)
 if matchObj:
  m = hashlib.md5()
  m.update(matchObj.group(1))
  m.update(matchObj.group(2))
  m.update(matchObj.group(3))
  m.update(matchObj.group(4))
  m.update(matchObj.group(5))
  m.update(event_type)
  return m.hexdigest()

def getFlowId(line):
 matchObj = re.match(r'.*flow_id":"([^."]*)",.*',line,re.M|re.I)
 if matchObj:
  return matchObj.group(1)

def getComparableLine(line, flow_key):
 flow_id_field = '"flow_key":"%s",' % flow_key
 flow_id_line =  re.sub(r'"flow_id":"[^."]*",',flow_id_field ,line,flags=re.M|re.I)
 flow_time_line = re.sub(r'"timestamp":"[^"]*",' ,'' ,flow_id_line,flags=re.M|re.I)
 ret_val = re.sub(r',"flow":{.*' ,'}' ,flow_time_line,flags=re.M|re.I)
 return ret_val

def getEvent_type(line):
 matchObj = re.match(r'.*event_type":"([^."]*)",.*',line,re.M|re.I)
 if matchObj:
  return matchObj.group(1)

def getPcap_cnt(line):
 matchObj = re.match(r'.*pcap_cnt":(\d*),.*',line,re.M|re.I)
 if matchObj:
  return matchObj.group(1)

def getReason(line):
 matchObj = re.match(r'.*reason":"([^."]*)",',line,re.M|re.I)
 if matchObj:
  return matchObj.group(1)

def getKey(item):
 return item[0]

def filterLines(eve_filename):
 filtered_lines = []
 for count,line in enumerate(open(eve_filename)):
  event_type = getEvent_type(line)
  if event_type == "flow" or event_type == "dns" or event_type == "tls" or event_type == "http":
    filtered_lines.append(line)
 return filtered_lines

def getSortedComparableLines(filtered_lines):
 flows = set([])
 key_to_id_map = {}

 comparable_lines = []
 for line in filtered_lines:
  flow_key = getFlowKey(line)
  flow_id = getFlowId(line)
  key_to_id_map[flow_id] = flow_key
  comparable_line = getComparableLine(line,flow_key)
  #print "comparable_line" , comparable_line
  line_hash = hashlib.new('md5')
  line_hash.update(comparable_line)
  digest = line_hash.hexdigest()
  if digest not in flows:
   flows.add(digest)
   comparable_lines.append([digest,comparable_line])

 sorted_comparable_lines = sorted(comparable_lines,key=getKey)
 return [key_to_id_map, sorted_comparable_lines]

def usage ():
 print("usage:")
 print("  params:")
 print("   -p, write json to a file that can be compared with known good(eve.json.comparable).")
 print("   -v, version of docker stitcher image")

def test_flows_dns_http_tls(write_json, stitcher_version):
 flow_hash_digest = '097e2ea2a39062adb79f0b219aa19f94'
 stitcher_hash_digest = 'd41d8cd98f00b204e9800998ecf8427e'
 pcap_file = "/mnt/run/pcap/capture.pcap"
 cwd = os.getcwd()
 os.system("rm -f %s/eve.json; rm -f %s/stats.log; rm  -f %s/suricata.log; rm -f %s/packet_stats.log; rm -f %s/keyword_perf.log rm -f %s/fast.log" % (cwd, cwd, cwd, cwd, cwd, cwd))
 suricata_docker_run_cmd = "docker run --rm -it --privileged -v %s/:/var/log/suricata 217386048230.dkr.ecr.us-east-1.amazonaws.com/suricata_regression:latest -c /mnt/run/configs/suricata.yaml.unittest -r %s" % (cwd, pcap_file)
 os.system(suricata_docker_run_cmd)
 flows = set([])
 filtered_lines = filterLines("%s/eve.json" % cwd)

 flow_hash = hashlib.md5()

 (key_to_id_map, sorted_comparable_lines) = getSortedComparableLines(filtered_lines)
 for  tuple in sorted_comparable_lines:
  flow_hash.update(tuple[1])

 if write_json:
  comparable_filename = "%s/eve.json.comparable" % cwd
  comparable_json_file = open(comparable_filename,'w')
  for  tuple in sorted_comparable_lines:
   comparable_json_file.write(tuple[1])
  comparable_json_file.close()

 if flow_hash.hexdigest() != flow_hash_digest:
  print "%s FAILED flow_hash_digest does not match: %s for suricata" % (inspect.stack()[0][3], flow_hash.hexdigest())
  sys.exit()
 else:
  os.system("rm -f unittest.sock;rm -f unit-stitch.log")
  stitcher_docker_run_cmd = "docker run --net=host --rm -dit --privileged -v %s/:/mnt/run/  --name test-stitcher imagedist.irond.us/docker/stitcher:%s -c /mnt/run/configs/stitch.yaml.in.unittest" % (cwd,stitcher_version)
  os.system(stitcher_docker_run_cmd)
  os.system("./test-stitcher -t ./unittest.sock")
  os.system("docker stop test-stitcher")
  stitcher_hash = hashlib.md5()
  with open('unit-stitch.log', 'rb') as afile:
   buf = afile.read()
   stitcher_hash.update(buf)
  if stitcher_hash.hexdigest() != stitcher_hash_digest:
   print "%s FAILED stitcher_hash_digest does not match: %s for stitcher" % (inspect.stack()[0][3], stitcher_hash.hexdigest())
   sys.exit()
  else:
   print "%s PASSED " % (inspect.stack()[0][3] )

if __name__== "__main__":
 try:
     opts, args = getopt.getopt(sys.argv[1:], 'hpv:',['help','print','version='])
 except getopt.GetoptError as err:
     print(err)
     usage()
     sys.exit()
 log_dir = None
 write_json = False
 stitcher_version = "35"
 for opt, arg in opts:
   if opt in ('-p', '--print'):
    write_json = True
   elif opt in ('-v', '--version'):
    stitcher_version = arg
   elif opt in ('-h', '--help'):
    usage()
    sys.exit()

 [vars()[func](write_json, stitcher_version) for func in dir() if func.startswith('test_')]
