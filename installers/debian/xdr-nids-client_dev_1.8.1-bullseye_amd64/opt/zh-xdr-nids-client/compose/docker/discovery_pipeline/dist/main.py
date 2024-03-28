# Filename : Network Host Discovery
# Purpose/Description : The code in this file scans the host live and communication in the network using packet analysis.
# Author : Lakshy Sharma
# Copyright (c) : Whizhack Technologies (P) Ltd.
# Revisions/Modifications : Lakshy Sharma
import json, time, os, sys
import boto3
from scapy.all import *
from datetime import datetime
import pyshark
import ipaddress

class aws_discovery():
    ''' Methods of this class are used for performing discovery operations on a client network. You can create an object and call suitable functions as per your need.'''

    def react_map_generator(self, json_map):
        ''' This map generates an aws map in format suitable for using with react js.'''

        compiled_json = {}
        network_map = {"name": "AWS Map", "children": []}
        #capture_timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        capture_timestamp = time.time()
        map_category = "aws"

        # Finding the regions and inserting them in the core aws map.
        for region in json_map.keys():
            vpc_data = []
            # Creating a entry for each region in the aws.
            network_map["children"].append({"name": region, "children": vpc_data})

            # Finding the vpcs inside the aws network.
            for vpc in json_map[region].keys():
                subnet_data = []
                vpc_data.append({"name": vpc, "children": subnet_data})

                for subnet in json_map[region][vpc].keys():
                    instance_data = []
                    subnet_data.append({"name": subnet, "children": instance_data})

                    for instance in json_map[region][vpc][subnet].keys():
                        instance_data.append({"name": instance})

        # Cleanup the structure.
        for aws_data in network_map["children"]:
            if aws_data["children"] == []:
                del aws_data["children"]
            else:
                for region_data in aws_data["children"]:
                    if region_data["children"] == []:
                        del region_data["children"]
                    else:
                        for vpc_data in region_data["children"]:
                            if vpc_data["children"] == []:
                                del vpc_data["children"]
                            else:
                                for subnet_data in vpc_data["children"]:
                                    if subnet_data.get("children") == [] or None:
                                        del subnet_data["children"]
                                    else:
                                        pass

        compiled_json['network_map'] =  json.dumps(network_map)
        compiled_json['attack_epoch_time'] = capture_timestamp
        compiled_json['map_category'] = map_category
        json_data = json.dumps(compiled_json)
        with open("/var/log/data/processed_data/network_map.json", "a") as file:
            if os.path.getsize("/var/log/data/processed_data/network_map.json") == 0:
                file.write(json_data)
            else:
                file.write("\n")
                file.write(json_data)

        return None

    def scanner(self):
        ''' This method creates a complete map of a client's AWS infrastructure and dumps it into a yaml file for further evaluation. 
        Inputs: None
        Outputs: None (Creates a file containing complete client infrastructure.)'''

        # Starting an empty dictionary for storing data.
        client_data = {}

        # Starting Region Mapping.
        #=============================
        # Capturing all client regions.
        regions_client = boto3.client('ec2')
        queried_regions = regions_client.describe_regions()
        for region in queried_regions['Regions']:
            region_name = region['RegionName']
            # Declaring a dictionary for storing the data of that region.
            client_data[region_name] = {}
        regions = client_data.keys()
        print("[i] Found {} regions.".format(len(client_data.keys())))

        # Starting VPC mapping.
        #==============================
        for region in regions:
            # Creating an empty dictionary to store data of all the VPCs.
            vpc_data = {}
            
            print("[i] Finding VPCs in Region {}".format(region))
            vpc_client = boto3.client('ec2', region_name=f"{region}")
            queried_vpcs = vpc_client.describe_vpcs()

            for vpc in queried_vpcs['Vpcs']:
                vpc_id = vpc['VpcId']
                vpc_data[vpc_id] = []
                print("[..] Finding subnets in VPC {}".format(vpc_id))

                # Finding the subnets inside the VPC.
                applicable_filter = [{"Name": "vpc-id","Values":["{}".format(vpc['VpcId'])]}]
                queried_subnets = vpc_client.describe_subnets(Filters=applicable_filter)
                subnets_data = {}
                for subnet in queried_subnets['Subnets']:
                    subnet_id = subnet['SubnetId']
                    subnets_data[subnet_id] = []
                    print("[...] Finding EC2 machines in subnet {}".format(subnet_id))

                    # Finding all the EC2 machines inside the subnet.
                    applicable_filter = [{"Name": "subnet-id","Values":["{}".format(subnet['SubnetId'])]}]
                    queried_instances = vpc_client.describe_instances(Filters=applicable_filter)
                    ec2_data = {}
                    for ec2 in queried_instances['Reservations']:
                        try:
                            for instance in ec2['Instances']:
                                # Catching relevant details.
                                ec2_id = instance['InstanceId']
                                if 'PublicIpAddress' in instance:
                                    ec2_data[ec2_id] = {"State":"{}".format(instance['State']['Name']),"Private_IP":"{}".format(instance['PrivateIpAddress']),"Public_IP":"{}".format(instance['PublicIpAddress'])}
                                else:
                                    ec2_data[ec2_id] = {"State":"{}".format(instance['State']['Name']),"Private_IP":"{}".format(instance['PrivateIpAddress'])}
                        except TypeError:
                            pass
                    # Starting creation of our nested data structure.
                    #==================================================
                    # Assigning each EC2 to respective subnets.
                    subnets_data[subnet_id] = ec2_data
                # Assigning each subnet to respective VPC.
                vpc_data[vpc_id] = subnets_data
            # Assigning each VPC to respective region.
            client_data[region] = vpc_data
        print("[i] Client network scan complete. Writing the output to a file.")

        json_data = json.dumps(client_data)
        with open("aws_scan.json", "w") as file:
            file.write(json_data)
            print("[i] aws_scan.json written successfully.")
        return client_data

    def __dictionary_depth(self, my_dict):
        ''' This function returns the total depth of our dictionary. '''
        if isinstance(my_dict, dict):
             return 1 + (max(map(self.dictionary_depth, my_dict.values())) if my_dict else 0)
        return 0

    def map_cleaner(self):
        ''' This function cleans the generated map by removing redundant regions which have no machines inside them.'''

        clean_map = {}

        with open("aws_scan.json", 'r') as client_map:
            unclean_map = json.load(client_map)

        for region in unclean_map.keys():
            # Defining the input dictionary for our function.
            input_dict = unclean_map[region]
            if self.__dictionary_depth(input_dict) < 4:
                # Checking depth of dictionary to determine if the region is empty or not.
                pass
            else:
                # If region is not empty then we add it to our clean map dictionary.
                clean_map[region] = input_dict
        
        json_data = json.dumps(clean_map)
        with open("clean_aws_map.json", "w") as file:
            file.write(json_data)
            print("[i] Data writen in clean_aws_map.json successfully.")
        
        return clean_map

class onpremise_discovery():

    def __bytes_to_decimal(self, bytes_mask):

        if (bytes_mask <= 0 or bytes_mask >= 0xFFFFFFFF):
            raise ValueError("Illegal netmask found", hex(bytes_mask))
        else:
            return 32 - int(round(math.log(0xFFFFFFFF - bytes_mask, 2)))
    
    def __cidr_notation_creator(self, bytes_network, bytes_mask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = self.__bytes_to_decimal(bytes_mask)
        network_cidr = f"{network}/{netmask}"
        print(f"Scanning the network: {network_cidr}")
        return network_cidr

    def find_network(self):

        # Removing unwaneted interfaces.
        for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:
            if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
                continue
            if netmask <= 0 or netmask == 0xFFFFFFFF:
                continue
            if (interface.startswith('docker') or interface.startswith('br-') or interface.startswith('tun')):
                continue        

            scan_network = self.__cidr_notation_creator(network, netmask)
            preferred_interface = os.environ["PREFERRED_INT"]
            if preferred_interface != "none":
                interface = preferred_interface
            return scan_network,interface

    def react_map_generator(self, scan_network, network_database):
        ''' 
        This function is responsible for generating a react focussed map from the collected data.
        '''
        compiled_json = {}
        network_map = {}
        raw_timestamp = datetime.now()
        #capture_timestamp = raw_timestamp.strftime("%d-%m-%Y %H:%M:%S")
        capture_timestamp = time.time()
        map_category = "onpremise"
        
        network_map["name"] = scan_network
        network_map["children"] = []
        for mac_address in network_database.keys():
            if len(network_database[mac_address]) >= 1:
                for element in network_database[mac_address]:
                    network_map["children"].append({"name": element})
            else:
                network_map["children"].append({"name": network_database[mac_address]})

        compiled_json['network_map'] =  json.dumps(network_map)
        compiled_json['attack_epoch_time'] = capture_timestamp
        compiled_json['map_category'] = map_category

        json_data = json.dumps(compiled_json)
        print(json_data)
        with open("/var/log/data/processed_data/network_map.json", "a") as file:
            if os.path.getsize("/var/log/data/processed_data/network_map.json") == 0:
        #with open("network_map.json", "a") as file:
        #    if os.path.getsize("network_map.json") == 0:
                file.write(json_data)
            else:
                file.write("\n")
                file.write(json_data)

    def passive_scanner(self):
        '''
        This function starts passive scanning on the network.
        '''

        # Initializing the databases and counters.
        # Schema {eth_addr: ipaddress}
        network_database = {}
        # Schema {eth_addr: list of app_linkages found for that address.}
        app_linkage_database = {}
        # Packet counter
        i = 0
        # Finding the network and interface which we will be scanning.
        scan_network,interface = self.find_network()
        print(f"Scanning the network: {scan_network} via the interface: {interface}")
        packet_capture = pyshark.LiveCapture(interface)
        #packet_capture = pyshark.FileCapture('/home/lakshy/log.pcap')

        for packet in packet_capture:
            if 'ip' in dir(packet):
                # Well well, Look who knows a better way to capture the application layer.
                host_app_linkage = packet.highest_layer

                # Only capturing the private ip addresses.
                if ipaddress.ip_address(packet.ip.src).is_private:
                    eth_addr = packet.eth.src
                    ip_addr = packet.ip.src
                elif ipaddress.ip_address(packet.ip.dst).is_private:
                    eth_addr = packet.eth.dst
                    ip_addr = packet.ip.dst
                
                # Adding data into respective datbases.
                # Network database
                if eth_addr not in network_database.keys():
                    network_database[eth_addr] = [ip_addr]
                else:
                    network_database[eth_addr].append(ip_addr)
                # Applications database.
                if eth_addr not in app_linkage_database.keys():
                    app_linkage_database[eth_addr] = [host_app_linkage]
                else:
                    app_linkage_database[eth_addr].append(host_app_linkage)

                # Increment the counter.
                i = i + 1

            # After some packets deposit the data into files.
            if i % 10000 == 0:
                # Cleaning the data and adding timestamp before entry.
                for eth_addr in network_database.keys():
                    network_database[eth_addr] = list(set(network_database[eth_addr]))
                for app_linkage in app_linkage_database.keys():
                    app_linkage_database[app_linkage] = list(set(app_linkage_database[app_linkage]))
                
                # If the list of the network hosts is empty then ignore this.
                if list(network_database.keys()) != []:
                    print(f"Completed iteration number: {int(i/10000)}")
                    self.react_map_generator(scan_network, network_database)
                    # TODO
                    # Yo duude! dont forget you can also collect the applications per host if you want.
                    #with open("app_database.json", "w") as file:
                    #    file.write(json.dumps(app_linkage_database))
                    #    file.write("\n")


                # Resetting the databases
                network_database = {}
                app_linkage_database = {}

class azure_discovery():
    pass

class controller():

    def init_detector(self):
        """ This function detects environment where the script is being run."""

        operating_environment = os.environ["OPERATING_ENV"]

        # Creating a dictionary of init_variables.
        init_variables = {}
        init_variables["operating_environment"] = operating_environment

        return init_variables

def main():
    # Find init environment variables.
    operator = controller()
    init_variables = operator.init_detector()

    if init_variables["operating_environment"] == "aws":
        while True:
            aws_mapper = aws_discovery()
            network_scan_result = aws_mapper.scanner()
            aws_mapper.react_map_generator(network_scan_result)
            time.sleep(3600)

    elif init_variables["operating_environment"] == "onpremise":
        while True:
            onpremise_mapper = onpremise_discovery()
            onpremise_mapper.passive_scanner()

    elif init_variables["operating_environment"] == "azure":
        while True:
            azure_mapper = azure_discovery()
            time.sleep(3600)

if __name__ == "__main__":
    main()
