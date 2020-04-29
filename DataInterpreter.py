# STATISTICS ON DESTINATION IP COUNTRIES ONLY
# THIS VERY FIRST VERSION IS WITHOUT ERROR CHECKING OR EXCEPTION HANDLING
# IT TAKES ONE COMMAND LINE ARGUMENT: A DIRECTORY - THIS WILL BE EXPLORED TO FIND ALL THE FILES INSIDE ANY SUBDIRECTORY TO COLLECT AND INTERPRET THEIR DATA


import sys
import os
import socket

#check parameters
if len(sys.argv) != 2:
    print("Usage: ", sys.argv[0], "directory_name")
    sys.exit()


countries = {}      # dictionary to store countries statistics - {keys=countries(str) : values=counters(int)}


# get local ip address 
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
    


            for line in file:
                #create a list of fields
                flowFields = line.split("|")

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


#
# *************************** if you'd like to plot it******************************
# import matplotlib.pyplot as plt
# names = list(countries.keys())
# values = list(countries.values())

# plt.bar(range(len(countries)),values,tick_label=names)
# plt.savefig('dst_countries_stat.png')
# plt.show()
         