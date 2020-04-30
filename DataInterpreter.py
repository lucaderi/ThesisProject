# STATISTICS ON DESTINATION IP COUNTRIES ONLY
# THIS VERY FIRST VERSION IS WITHOUT ERROR CHECKING OR EXCEPTION HANDLING
# IT TAKES ONE COMMAND LINE ARGUMENT: A DIRECTORY - THIS WILL BE EXPLORED TO FIND ALL THE FILES INSIDE ANY SUBDIRECTORY TO COLLECT AND INTERPRET THEIR DATA


import sys
import os
import socket
from recordclass import recordclass


# check parameters
if len(sys.argv) != 2:
    print("Usage: ", sys.argv[0], "directory_name")
    sys.exit()


# ---------------- data structures -------------------

Bin = recordclass('Bin', 'min max counter')     #Bin type, used to store and classify integer fields

duration_bins = []          # list to store flow duration statistics
countries = {}              # dictionary to store countries statistics - {keys=countries(str) : values=counters(int)}





# ---------------- support functions -----------------
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
        if data > data_structure[i].min:
            if data < data_structure[i].max:
                data_structure[i].counter += 1
        i += 1


#-------------------- initialize data structures ----------------



# flow_duration
range_values_duration=[0, 10, 30, 50, 250, 600, 5000, 20000]
number_of_duration_bins = len(range_values_duration)
bins_constructor(range_values_duration, number_of_duration_bins, duration_bins)






# get local ip address (I MUST CONSIDER ALL THE LOCAL IP ADDRESSES)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
s.connect(("8.8.8.8", 80))
local_ip_address = s.getsockname()[0]
s.close()
print(local_ip_address)




# walk the given directory and process data of files found
for dirpath, dirnames, files in os.walk(sys.argv[1]):
    for file_name in files:
        with open(os.path.join(dirpath,file_name), 'r') as file:

            #get index of destination ip country field (from first line)

            first_line = file.readline().split("|")

            if "DST_IP_COUNTRY" in first_line:
                dst_ip_country_index = first_line.index("DST_IP_COUNTRY")
            else:
                print("no DST_IP_COUNTRY among the fields")
                sys.exit()
    
            if "FLOW_DURATION_MILLISECONDS" in first_line:
                flow_duration_index = first_line.index("FLOW_DURATION_MILLISECONDS")
            else:
                print("no FLOW_DURATION_MILLISECONDS among the fields")
                sys.exit()

            for line in file:
                #create a list of fields
                flowFields = line.split("|")



                # flow duration
                flow_duration = int(flowFields[flow_duration_index])
                place_in_bin(flow_duration, duration_bins, number_of_duration_bins)



                #if source address is not my local ip, ignore the line
                if flowFields[0] != local_ip_address:
                    continue

                else:
                    #fetch destination ip country
                    dst_ip_country = flowFields[dst_ip_country_index]

                    if dst_ip_country == '':
                        dst_ip_country = 'Unknown'

                    #print(dst_ip_country)

                    #count how many times a certain destination country was encountered in flows
                    if dst_ip_country not in countries:
                        countries.update({dst_ip_country:1})
                    else:
                        countries[dst_ip_country] += 1





print(list(countries.items()))
print(duration_bins)


#
# *************************** if you'd like to plot it******************************
# import matplotlib.pyplot as plt
# names = list(countries.keys())
# values = list(countries.values())

# plt.bar(range(len(countries)),values,tick_label=names)
# plt.savefig('dst_countries_stat.png')
# plt.show()



