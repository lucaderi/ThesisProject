# STATISTICS ON %FLOW_DURATION_MILLISECONDS %IN_BYTES %OUT_BYTES %L7_PROTO (with a special attention to TLS based protocols) %DST_IP_COUNTRY
# THIS VERY FIRST VERSION IS WITHOUT ERROR CHECKING OR EXCEPTION HANDLING
# IT TAKES ONE COMMAND LINE ARGUMENT: A DIRECTORY - THIS WILL BE EXPLORED TO FIND ALL THE FILES INSIDE ANY SUBDIRECTORY TO COLLECT AND INTERPRET THEIR DATA


#next tasks: 
# 1-add dns query name (X)
# 2-sort out dst_ip_country 
# 3-fix it for all device ip addresses 
# 4-consider src and dst ip when needed 
# 5-add exception handling and error checking
# 6-make it work for data of specific directories in the tree

import sys
import os
import socket
import collections
from recordclass import recordclass
from netifaces import interfaces, ifaddresses, AF_INET


# check parameters
if len(sys.argv) != 2:
    print("Usage: ", sys.argv[0], "directory_name")
    sys.exit()


# ---------------- data structures -------------------

Bin = recordclass('Bin', 'min max counter')     #Bin type, used to store and classify integer fields

duration_bins = []          # list to store flow duration statistics
inbytes_bins = []           # list to store flow src-to-dst bytes statistics
outbytes_bins = []          # list to store flow dst-to-stc bytes statistics
l7proto_bins = []           # list to store flow l7 protocol number statistics
tls_proto_bins = []         # list to store flow l7 protocol-over-TLS number statistics
countries = {}              # dictionary to store countries statistics - {keys=countries(str) : values=counters(int)}
dns_query_hashes_bins = []  # list to store dns queries' hashes statistics




# ---------------- support functions -----------------
def ip4_addresses():
    ip_list = []
    for inter in interfaces():
        if AF_INET in ifaddresses(inter):
            for link in ifaddresses(inter)[AF_INET]:
                ip_list.append(link['addr'])
    return ip_list


def bins_constructor(range_values, number_of_bins, data_structure):
    for i in range(number_of_bins):
        if i == number_of_bins - 1:
            newBin = Bin(min=range_values[i], max=sys.maxsize, counter=0)
        else:
            newBin = Bin(min=range_values[i], max=range_values[i+1], counter=0)
        data_structure.append(newBin)


def place_in_bin(data, data_structure, number_of_bins):
    i=0
    while i < number_of_bins:
        if data >= data_structure[i].min:
            if data < data_structure[i].max:
                data_structure[i].counter += 1
        i += 1

def print_bins(bins):
    print()

    for i in range(len(bins) - 1):
        r = "[" + str(bins[i].min) + "-" + str(bins[i].max) + "]"
        print(f"{r:<13}||{str(bins[i].counter):>7}")
    lastrange = "[ >= " + str(bins[len(bins)-1].min) + " ]"
    print(f"{lastrange:<13}||{str(bins[len(bins)-1].counter):>7}")

    print()

def create_compressed_hash(name):
    domains = name.split(".")             
    if len(domains) > 1:
        domain = domains[-2] + "." + domains[-1]
    else:
        domain = domains[0]             
    domain = abs(hash(domain))
    compressed_hash = int(domain/(10 ** (len(str(domain)) - 3)))

    return compressed_hash



#-------------------- initialize data structures ----------------



# flow_duration
range_values_duration=[0, 10, 30, 50, 250, 600, 5000, 20000]
number_of_duration_bins = len(range_values_duration)
bins_constructor(range_values_duration, number_of_duration_bins, duration_bins)

# in_bytes = incoming flow bytes (src->dst)
range_values_inbytes=[0, 52, 64, 128, 256, 512, 1024, 4096, 10000]
number_of_inbytes_bins = len(range_values_inbytes)
bins_constructor(range_values_inbytes, number_of_inbytes_bins, inbytes_bins)

# out_bytes = outgoing flow bytes (dst->src)
range_values_outbytes = [0, 52, 64, 128, 256, 512, 1024, 4096, 10000]
number_of_outbytes_bins = len(range_values_outbytes)
bins_constructor(range_values_outbytes, number_of_outbytes_bins, outbytes_bins)

# l7 protocol number
range_values_l7proto = [0, 25, 50, 91, 92, 150]
number_of_l7proto_bins = len(range_values_l7proto)
bins_constructor(range_values_l7proto, number_of_l7proto_bins, l7proto_bins)

range_values_tls_proto = [0, 50, 100, 125, 150, 200]
number_of_tls_proto = len(range_values_tls_proto)
bins_constructor(range_values_tls_proto, number_of_tls_proto, tls_proto_bins)

range_values_dns_query = [0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
number_of_dns_query_bins = len(range_values_dns_query)
bins_constructor(range_values_dns_query, number_of_dns_query_bins, dns_query_hashes_bins)



# get local ip address (I MUST CONSIDER ALL THE LOCAL IP ADDRESSES)
# s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
# s.connect(("8.8.8.8", 80))
# local_ip_address = s.getsockname()[0]
# s.close()
# print(local_ip_address)


# get all local AF_INET ip addresses
interf = interfaces()
print(interf)
local_ips = ip4_addresses()
print(local_ips)




# walk the given directory and process data of files found
for dirpath, dirnames, files in os.walk(sys.argv[1]):
    for file_name in files:
        with open(os.path.join(dirpath,file_name), 'r') as file:

            #get index of destination ip country field (from first line)

            first_line = file.readline().split("|")
            
            # remove \n from last list element
            first_line[-1] = first_line[-1].replace('\n', '')
            

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
            
            if "DNS_QUERY" in first_line:
                dns_query_index = first_line.index("DNS_QUERY")
            else:
                print("no DNS_QUERY among the fields")
                sys.exit()
    
            

            for line in file:
                #create a list of fields
                flowFields = line.split("|")

                # remove \n from last list element
                flowFields[-1] = flowFields[-1].replace('\n', '')


                # flow duration
                flow_duration = int(flowFields[flow_duration_index])
                place_in_bin(flow_duration, duration_bins, number_of_duration_bins)


                # src to dst bytes
                in_bytes = int(flowFields[inbytes_index])
                place_in_bin(in_bytes, inbytes_bins, number_of_inbytes_bins)

                # dst to src bytes
                out_bytes = int(flowFields[outbytes_index])
                place_in_bin(out_bytes, outbytes_bins, number_of_outbytes_bins)


                # layer 7 (application) protocol number
                l7_proto = flowFields[l7proto_index]
                place_in_bin(int(float(l7_proto)), l7proto_bins, number_of_l7proto_bins)
                if int(float(l7_proto)) == 91:
                    if "." in l7_proto:
                        proto_number = int(l7_proto.split(".")[1])
                    else:
                        proto_number = 0
                    place_in_bin(proto_number, tls_proto_bins, number_of_tls_proto)


                # dst ip country
                # if source address is not one of my local ip addresses, ignore the line
                if flowFields[0] not in local_ips:
                    continue

                else:
                    #fetch destination ip country
                    dst_ip_country = flowFields[dst_ip_country_index]

                    if dst_ip_country == '':
                        dst_ip_country = 'Unknown'


                    #count how many times a certain destination country was encountered in flows
                    if dst_ip_country not in countries:
                        countries.update({dst_ip_country:1})
                    else:
                        countries[dst_ip_country] += 1

                #dns query name (last 2 domains)
                dns_query = flowFields[dns_query_index]

                if dns_query == '':
                    #dns_query = 'Unknown'
                    #meglio ignorarle proprio? Sono moltissime quindi suppongo di si
                    continue
                else:
                    dns_query_hash = create_compressed_hash(dns_query)
                
                place_in_bin(dns_query_hash, dns_query_hashes_bins, number_of_dns_query_bins)
                



print("FLOW_DURATION")
print_bins(duration_bins)
print("IN_BYTES")
print_bins(inbytes_bins)
print("OUT_BYTES")
print_bins(outbytes_bins)
print("L7_PROTO")
print_bins(l7proto_bins)
print("TLS-BASED PROTOCOL NUMBER")
print_bins(tls_proto_bins)

orderedCountries = collections.OrderedDict(sorted(countries.items()))
print("DST_IP_COUNTRY\n", list(orderedCountries.items()))

print("DNS_QUERY")
print_bins(dns_query_hashes_bins)

#
# *************************** if you'd like to plot it******************************
#import matplotlib.pyplot as plt
#names = list(orderedCountries.keys())
#values = list(orderedCountries.values())

#plt.bar(range(len(orderedCountries)),values,tick_label=names)
#plt.savefig('dst_countries_stat_29.png')
#plt.show()



