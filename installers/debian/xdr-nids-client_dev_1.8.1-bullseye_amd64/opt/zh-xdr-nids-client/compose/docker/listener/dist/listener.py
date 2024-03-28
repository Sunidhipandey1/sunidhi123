''' Filename : listener.py
    Purpose/Description : Program for sniffing the network traffic on the network interface of the host and writing it json file.
    Author : Mahesh Banerjee
    Revised by : Lakshy Sharma
    Copyright (c) : Whizhack Technologies (P) Ltd.'''

# This file must be placed in this location: /opt/listener/

# Complete date manipulation libraries.
from datetime import datetime
import os
# Complete packet capture libraries.
import pyshark
import netifaces
# Complete configurations parsing libraries.
import re, gc
from configparser import ConfigParser
from collections import Counter

# We will be ignoring these layers to create connection type field.
LAYERS_TO_IGNORE = ["layer.eth","layer.tcp","layer.ip","layer.icmp","layer.udp", "layer.vxlan"]

def config_reader():
    ''' This function will read all the configurations from the config.ini file and pass them to the scripts. '''
    # Creating a configuration object.
    config_object = ConfigParser()
    # Reading the config file using the object.
    config_object.read("config.ini")
    # Collecting configurations.
    locations = config_object["LOCATIONS"]
    # Returning all values to main function for transport elsewhere.
    return locations

class InterfaceFinder():
    ''' This class helps the user find active interfaces on the capture device and sends it to the listener. '''

    def __interface_finder(self):
        ''' Finds and returns list of available interfaces. '''
        # Finding list of interfaces.
        interfaces_list = netifaces.interfaces()
        # Removing local host interface.
        try:
            interfaces_list.remove("lo")
        except:
            print("[!!] Didnt find localhost address. Thats odd... (This can lead to undefined behaviour)")
        return interfaces_list

    def __interface_checker(self, detected_interfaces):
        ''' Finds and returns list of active interfaces (active means which has been allotted an IP address.) '''
        active_interfaces = []
        for interface in detected_interfaces:
            addr = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addr:
                print("[*] Detected an active interface: {}".format(interface))
                active_interfaces.append(interface)
            else:
                continue
        if active_interfaces == []:
            print("[!!!] Couldnt find any active interface. Quitting")
            exit(1)
        return active_interfaces

    def __priority_checker(self, active_interfaces):
        ''' Checks if any priority interface was found and return the required value. '''
        enps_pattern = re.compile("^(enp[0-9]s[0-9]+)+$")
        ens_pattern = re.compile("^(ens[0-9]+)+$")
        eth_pattern = re.compile("^(eth[0-9]+)+$")
        eno_pattern = re.compile("^(eno[0-9]+)+$")
        priority_interfaces = ['eth0', 'ens5', 'eno1', 'eno2', 'ens3']
        selected_interface = set.intersection(set(priority_interfaces),set(active_interfaces))
        if len(selected_interface) > 0:
            print('[*] Found a priority interface. {}'.format(str(selected_interface)))
            return selected_interface
        elif len(selected_interface) == 0:
            for interface in active_interfaces:
                print("[*] Couldnt find any priority interface. Let me search a bit more...")
                if enps_pattern.match(interface):
                    print(f"[*] Found a suitable interface to capture on {interface}. Lets gooo!")
                    selected_interface = interface
                    return selected_interface
                elif ens_pattern.match(interface):
                    print(f"[*] Found a suitable interface to capture on {interface}. Lets gooo!")
                    selected_interface = interface
                    return selected_interface
                elif eth_pattern.match(interface):
                    print(f"[*] Found a suitable interface to capture on {interface}. Lets gooo!")
                    selected_interface = interface
                    return selected_interface
                elif eno_pattern.match(interface):
                    print(f"[*] Found a suitable interface to capture on {interface}. Lets gooo!")
                    selected_interface = interface
                    return selected_interface
        else:
            print('[!!] No priority interface found. Listening on any interface available. (This will result in absence of ethernet layer and give sll instead.)')
            selected_interface = 'any'
            return selected_interface

    def find_listen_interface(self):
        if 'PREFERRED_INT' in os.environ:
            preferred_interface = os.environ["PREFERRED_INT"]
            if preferred_interface != "none":
                interface = preferred_interface
                return interface
        interfaces = self.__interface_finder()
        active_interfaces = self.__interface_checker(interfaces)
        selected_interface = self.__priority_checker(active_interfaces)
        return selected_interface

def metadata_writer(i, packet, json_file):
    '''
    This function writes the id, timestamp and application linkage for each packet.
    '''

    json_file.write('{"id":'+str(i)+',')
    json_file.write('"timestamp":"'+str(packet.sniff_time)+'",')
    json_file.write('"app_linkage":"'+str(packet.highest_layer)+'",')
    return None

def non_vxlan_layer_writer(pkt, json_file, droplayers_path, dropfields_path):
    ''' This function starts parsing the packet layer by layer and writes data in a json file. '''
    # Setting the initial flag.
    layer_flag = 0
    # Setting a counter to see on which layer we are currently.
    j = len(pkt.layers)
    # Capturing how many layers we have in the packet.
    total_layers = len(pkt.layers)
    # Starting a for loop to iterate over each layer.
    for layer in pkt.layers:
        # Checking if we are writing the first layer.
        if j == total_layers:
            # Checking the flag to ensure the layer must be printed and not dropped.
            layer_flag = layer_dropper(layer, layer_flag, droplayers_path)
            if layer_flag == 0:
                # Write the layer header.
                json_file.write('"layer.'+layer.layer_name+'":{')
                # Call field writer to write internal fields.
                field_writer(layer, json_file, dropfields_path)
            else:
                j = j-1
        # If this is not the first layer then place a comma before adding the next layer.
        else:
            # Checking the flag to ensure the layer must be printed and not dropped.
            layer_flag = layer_dropper(layer, layer_flag, droplayers_path)
            if layer_flag == 0:
                # Write the layer header.
                json_file.write(',"layer.'+layer.layer_name+'":{')
                # Call field writer to write internal fields.
                field_writer(layer, json_file, dropfields_path)
        # Incrementing the counter.
        j = j+1

def vxlan_layer_writer(pkt, json_file, droplayers_path, dropfields_path):
    ''' This function starts parsing the vxlan packet layer by layer and writes data in a json file. '''
    # Setting the initial flag to dropping the layers.
    layer_flag = 1
    # Setting a counter to see on which layer we are currently.
    j = len(pkt.layers)
    # Capturing how many layers we have in the packet.
    total_layers = len(pkt.layers)
    # Setting vxlan pointer to 0
    vxlan_pos_flag = 0
    # setting Layer Skipping Flag to 1
    layer_skip = 1
    # Starting a for loop to iterate over each layer.
    for layer in pkt.layers:
        # Checking if we are writing the first layer.
        if j == total_layers:
            # Checking the flag to ensure the layers after the vxlan layer are printed and layer before vxlan are dropped.
            if layer.layer_name == "vxlan":
                # Found the postion of vxlan layer in the packet.
                vxlan_pos_flag = 1
                # Setting layer_skip flag to zero for printing the layers after vxlan.
                layer_skip = 0
            if layer_skip == 0:
                # Checking the flag to ensure the layer must be printed and not dropped.
                layer_flag = layer_dropper(layer, layer_flag, droplayers_path)
            if layer_flag == 0:
                # Write the layer header.
                json_file.write('"layer.'+layer.layer_name+'":{')
                # Call field writer to write internal fields.
                field_writer(layer, json_file, dropfields_path)
            else:
                j = j-1
        # If this is not the first layer then place a comma before adding the next layer.
        else:
            # Checking the flag to ensure the layer must be printed and not dropped.
            layer_flag = layer_dropper(layer, layer_flag, droplayers_path)
            if layer_flag == 0:
                # Write the layer header.
                json_file.write(',"layer.'+layer.layer_name+'":{')
                # Call field writer to write internal fields.
                field_writer(layer, json_file, dropfields_path)
        # Incrementing the counter.
        j = j+1

def vxlan_check(pkt):
    vxlan = "vxlan"
    state = 0
    for layer in pkt.layers:
        # Checking for VXLAN Layer in the packet
        if  layer.layer_name == vxlan:
            state = 1
            break
        else:
            state = 0
    return state

def layer_dropper(layer, flag, droplayers_path):
    ''' Function which sends the flag indicating whether to drop the layer. '''
    # Capturing the list of layers present in a packet.
    layer_list = layer_reader(droplayers_path)
    # If else statement to drop the layer.
    if layer.layer_name in layer_list:
        flag = 1
    else:
        flag = 0

    return flag

def layer_reader(droplayers_path):
    ''' This function parses a file and creates a list of layers needed to be dropped. '''
    captured_list = []
    layer_list = []
    # Opening file and reading all the values.
    with open(droplayers_path,"r") as fields_file:
        # Read and append all the layers as a list.
        captured_list = fields_file.readlines()
        # Iterate through each item on a list.
        for item in captured_list:
            # Check if any field is a comment and if not the strip the newline character before adding it to the field_list.
            if item[0] != '#':
                item = item.strip("\n")
                layer_list.append(item)
    # Return a layer list to the function after appending a null value.
    layer_list.append("")
    return layer_list

def field_writer(layer, json_file, dropfields_path):
    ''' This function writes fields present in each layer to the json file. '''
    # Setting the initial field and flag.
    field_no = 0
    flag = 0
    # Store number of fields in the present layer.
    fields_in_layer = len(layer._all_fields)
    # Setting up the counter.
    j = len(layer._all_fields)
    # Iterate over each field and write it in the file.
    for field in layer._all_fields:
        # If writing first field in the layer then enter the if block.
        if j == fields_in_layer:
            # Capturing the flag. This will tell which fields to drop.
            # If flag is 0 then write the field if it is 1 then dont write the field.
            flag = field_dropper(field, flag, dropfields_path)
            if (flag == 0):
                # Print the field as json key and write its value.
                field_name, val = field_cleaner(layer, field)
                json_file.write('"'+field_name+'":"'+val+'"')
            else:
                # If flag is 1 then reduce counter and try again.
                j = j-1
        else:
            # If it is not the first field then capture the flag.
            flag = field_dropper(field, flag, dropfields_path)
            if (flag == 0 ):
                # if flag is zero then write field or drop it.
                field_print_name, val = field_cleaner(layer, field)
                json_file.write(',"'+field_print_name+'":"'+val+'"')
        # Increment the counter.
        j = j + 1
    # Writing the closing bracket.

    json_file.write('}')

def field_cleaner(layer, field):
    # Get the field value and save in a variable.
    val = layer.get_field_value(field)
    # Replace the unwanted chars in the packet data.
    val = str(val).replace('\\','').replace('/','').replace('//','').replace('"','').replace('{','').replace('}','').replace(',','').replace('[','').replace(']','').replace('-','').replace('=','').replace('_','')
    # Capture the name of the field.
    field_name = str(field)
    # Return values to be written.
    return field_name, val

def field_dropper(field, flag, dropfields_path):
    ''' Function to drop the field by using a flag value. '''
    field_list = field_reader(dropfields_path)
    if field in field_list:
        # Removing the Payload field
        flag = 1
    else:
        # Do not remove this field.
        flag = 0
    return flag

def field_reader(dropfields_path):
    ''' A function to read the dropped fields from a file. '''
    # Declaring fields list to be captured.
    captured_list = []
    field_list = []
    # Opening file and reading all the values.
    with open(dropfields_path,"r") as fields_file:
        # Read and append all the fields as a list.
        captured_list = fields_file.readlines()
        # Iterate through each item on a list.
        for item in captured_list:
            # Check if any field is a comment and if not the strip the newline character before adding it to the field_list.
            if item[0] != '#':
                item = item.strip("\n")
                field_list.append(item)
    # Return a field list to the function after appending a null value.
    field_list.append("")
    return field_list

def newline_formatter(json_file):
    ''' This function formats the file in newline delimited json. '''
    json_file.write('}')
    json_file.write('\n')

def main():
    # Capturing configurations.
    locations = config_reader()
    droplayers_path = locations["droplayers_path"]
    dropfields_path = locations["dropfields_path"]
    print("[*] Loaded all configurations.")
    # Defining the packet file location.
    packet_file = open(locations["packet_path"], "w")
    print("[*] Opened file for writing data. {}".format(locations["packet_path"]))
    # Custom Tshark Parameters For Printing the Timestamp in UTC with Date and Time format.
    custom_param = {"-t": "ud"}
    # Finding capture interface.
    print("[#] Finding capture interfaces.")
    interface_finder_object = InterfaceFinder()
    cap_int = interface_finder_object.find_listen_interface()
    del interface_finder_object
    # Defining the live capture session from pyshark.
    print("[#] Setting capture parameters.")
    capture = pyshark.LiveCapture(cap_int, custom_parameters=custom_param)
    print("[*] Started capture successfully.")
    # Left here for future test purposes.
    #capture = pyshark.FileCapture('test.pcap', custom_parameters=custom_param)
    # Initiating the counter for writing the id of each packet.
    i = 0
    # Iterating over each packet in the live captured traffic.
    for packet in capture:
        # Calling the metadata writer.
        metadata_writer(i, packet, packet_file)
         # Checking for VXLAN Layer in the packet
        vxlan_state = vxlan_check(packet)
        if vxlan_state == 0:
           # Calling the parser function to read the data of each Non VXLAN Packet.
           packet_file.write('"vxlan_state":"False",')
           non_vxlan_layer_writer(packet, packet_file, droplayers_path, dropfields_path)
        else:
           # Calling the parser function to read the data of each VXLAN Packet.
           packet_file.write('"vxlan_state":"True",')
           vxlan_layer_writer(packet, packet_file, droplayers_path, dropfields_path)
        # Calling appropriate formatter for formating our data.
        newline_formatter(packet_file)
        # Incrementing the ID counter.
        i = i+1

main()
