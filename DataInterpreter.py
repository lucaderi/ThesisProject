
# IT TAKES ONE COMMAND LINE ARGUMENT: A DIRECTORY - THIS WILL BE EXPLORED TO FIND ALL THE FILES INSIDE ANY SUBDIRECTORY TO COLLECT AND INTERPRET THEIR DATA

import sys
import os
import socket
import collections
from recordclass import recordclass
from netifaces import interfaces, ifaddresses, AF_INET
import ipaddress
import radix
import csv


# check parameters
if len(sys.argv) != 2:
    print("Usage: ", sys.argv[0], "directory_name")
    sys.exit()


# ---------------- data structures -------------------

rtree = radix.Radix()       # radix tree for ip lookup
local_IPs = {}              # dictionary to store separate ip's traffic statistics - {key=ip_address(str) : value=l7_protocols(dict)}
l7_protocols = {}           # dictionary to store separate l7 protocols statistics - {key=l7_proto_name(str) : value=indicators(dict)}
indicators = {}             # dictionary to store separate indicators bins - {key=indicator(str) : value=bins(list of Bin objects)}


Bin = recordclass('Bin', 'min max counter')     #Bin type, used to store and classify integer fields

duration_bins = []          # list to store flow duration bins statistics (one per protocol)
sentbytes_bins = []         # list to store flow bytes sent by local ip bins statistics (one per l7 protocol)
receivedbytes_bins = []     # list to store flow bytes received by local ip bins statistics (one per l7 protocol)
countries = {}              # dictionary to store countries bins statistics - {key=country(str) : value=counter(int)}





# ---------------- support functions -----------------

# returns a list of ipaddress.IPv4Network objects in cidr notation
def ip4_networks():
    ip_networks = []
    for inter in interfaces():
        if AF_INET in ifaddresses(inter):
            for link in ifaddresses(inter)[AF_INET]:
                # ignore loopback address
                if link['addr'].startswith('127.'):
                    continue
                # extract network address
                ip_subnet = ipaddress.ip_network(link['addr'] + "/" + link['netmask'], strict = False)
                ip_networks.append(ip_subnet)
                
    return ip_networks


# initialize data_structure as a list of Bin objects
def bins_constructor(range_values, number_of_bins, data_structure):
    for i in range(number_of_bins):
        if i == number_of_bins - 1:
            newBin = Bin(min=range_values[i], max=sys.maxsize, counter=0)
        else:
            newBin = Bin(min=range_values[i], max=range_values[i+1], counter=0)
        data_structure.append(newBin)

# analyze data and increment the right Bin counter
def place_in_bin(data, bins_list):
    i=0
    while i < len(bins_list):
        if data >= bins_list[i].min:
            if data < bins_list[i].max:
                bins_list[i].counter += 1
                return
        i += 1

def print_bins(bins):
    print()

    for i in range(len(bins) - 1):
        r = "[" + str(bins[i].min) + "-" + str(bins[i].max) + "]"
        print(f"{r:<13}||{str(bins[i].counter):>7}")
    lastrange = "[ >= " + str(bins[len(bins)-1].min) + " ]"
    print(f"{lastrange:<13}||{str(bins[len(bins)-1].counter):>7}")

    print()   






#-------------------- initialize indicators dictionary ----------------

# creates a dictionary with {key=indicator : value=bins(list)} where indicator = {flow_duration, sent_bytes, received_bytes}
def initialize_indicators_dictionary():

    ind_dict = {}

    # create list to store bins
    duration_bins = []          # flow_duration (ms)
    sentbytes_bins = []         # bytes sent by local ip
    receivedbytes_bins = []     # bytes received by local ip

    # set ranges values
    range_values_duration=[0, 30, 60, 300, 600, 1800, 6000, 18000]
    range_values_sentbytes=[0, 52, 64, 128, 256, 512, 1024, 4096, 10000]
    range_values_receivedbytes = [0, 52, 64, 128, 256, 512, 1024, 4096, 10000]

    # construct list of empty bins with given ranges for every indicator
    bins_constructor(range_values_duration, len(range_values_duration), duration_bins)
    bins_constructor(range_values_sentbytes, len(range_values_sentbytes), sentbytes_bins)
    bins_constructor(range_values_receivedbytes, len(range_values_receivedbytes), receivedbytes_bins)

    # add indicator and respective bin list to the dictionary
    ind_dict.update({'flow_duration' : duration_bins})    
    ind_dict.update({'sent_bytes' : sentbytes_bins})    
    ind_dict.update({'received_bytes' : receivedbytes_bins})

    return ind_dict



# get all local AF_INET ip networks (cidr notation)
local_netw = ip4_networks()

# create radix tree
for net in local_netw:
    rtree.add(str(net))


# --------------------------- computation -------------------------------

# walk the given directory and process data of files found
for dirpath, dirnames, files in os.walk(sys.argv[1]):
    dirnames.sort()
    files.sort()

    for file_name in files:
        with open(os.path.join(dirpath,file_name), 'r') as file:

            first_line = file.readline().split("|")
            
            # remove \n from last list element
            first_line[-1] = first_line[-1].replace('\n', '')

            if "IPV4_SRC_ADDR" in first_line:
                src_addr_index = first_line.index("IPV4_SRC_ADDR")
            else:
                print("no IPV4_SRC_ADDR among the fields")
                sys.exit()

            if "IPV4_DST_ADDR" in first_line:
                dst_addr_index = first_line.index("IPV4_DST_ADDR")
            else:
                print("no IPV4_DST_ADDR among the fields")
                sys.exit()
            

            if "FLOW_DURATION_MILLISECONDS" in first_line:
                flow_duration_index = first_line.index("FLOW_DURATION_MILLISECONDS")
            else:
                print("no FLOW_DURATION_MILLISECONDS among the fields")
                sys.exit()

            if "IN_BYTES" in first_line:
                inbytes_index = first_line.index("IN_BYTES")
            else:
                print("no IN_BYTES among the fields")
                sys.exit()
            
            if "OUT_BYTES" in first_line:
                outbytes_index = first_line.index("OUT_BYTES")
            else:
                print("no OUT_BYTES among the fields")
                sys.exit()

            if "L7_PROTO" in first_line:
                l7proto_index = first_line.index("L7_PROTO")
            else:
                print("no L7_PROTO among the fields")
                sys.exit()

            if "DST_IP_COUNTRY" in first_line:
                dst_ip_country_index = first_line.index("DST_IP_COUNTRY")
            else:
                print("no DST_IP_COUNTRY among the fields")
                sys.exit()
            

            for line in file:
                #create a list of fields
                flowFields = line.split("|")

                # remove \n from last list element
                flowFields[-1] = flowFields[-1].replace('\n', '')

                # src and dst ip address
                src_ip = flowFields[src_addr_index]
                dst_ip = flowFields[dst_addr_index]

                # flow duration
                flow_duration = int(flowFields[flow_duration_index])

                # src to dst bytes
                in_bytes = int(flowFields[inbytes_index])

                # dst to src bytes 
                out_bytes = int(flowFields[outbytes_index])


                # l7 protocol
                l7proto = flowFields[l7proto_index]
                
                if rtree.search_best(src_ip):
                    if src_ip not in local_IPs:
                        local_IPs.update({src_ip : {}})
                        
                    if l7proto not in list(local_IPs[src_ip].keys()):
                        indicators = initialize_indicators_dictionary()
                        local_IPs[src_ip].update({l7proto : indicators})
                        
                    place_in_bin(flow_duration, local_IPs[src_ip][l7proto]['flow_duration'])
                    place_in_bin(in_bytes, local_IPs[src_ip][l7proto]['sent_bytes'])
                    place_in_bin(out_bytes, local_IPs[src_ip][l7proto]['received_bytes'])

                if rtree.search_best(dst_ip):
                    if dst_ip not in local_IPs:
                        local_IPs.update({dst_ip : {}})
                        
                    if l7proto not in list(local_IPs[dst_ip].keys()):
                        indicators = initialize_indicators_dictionary()
                        #initialize_indicators_dictionary(indicators)
                        local_IPs[dst_ip].update({l7proto : indicators})
                        
                    place_in_bin(flow_duration, local_IPs[dst_ip][l7proto]['flow_duration'])
                    place_in_bin(out_bytes, local_IPs[dst_ip][l7proto]['sent_bytes'])
                    place_in_bin(in_bytes, local_IPs[dst_ip][l7proto]['received_bytes'])
                    



# create csv file
with open('prova.csv', 'w', newline='') as csvfile:
    fieldnames = ['ip_address', 'l7proto', 'indicator','bin', 'counter']
    writer = csv.writer(csvfile)

    writer.writerow(fieldnames)

    for ip in local_IPs:
        for proto in local_IPs[ip]:
            for ind in local_IPs[ip][proto]:
                bins = local_IPs[ip][proto][ind]
                for b in range(len(bins)):
                    min_value = local_IPs[ip][proto][ind][b].min
                    max_value = local_IPs[ip][proto][ind][b].max
                    minmaxrange = "[" + str(min_value) + "-" + str(max_value) + "]"
                    count = local_IPs[ip][proto][ind][b].counter
                    #binlist.append(minmaxrange)
                    writer.writerow([ip, proto, ind, minmaxrange, count])
    




