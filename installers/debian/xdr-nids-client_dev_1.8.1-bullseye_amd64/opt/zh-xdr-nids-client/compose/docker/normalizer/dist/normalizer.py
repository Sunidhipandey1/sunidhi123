# Filename : Normalizer
# Purpose/Description : The code in this file takes Raws data from IDS, ml & dl feeds normalizes it and then sends it to the parted directory for further processing.
# Author : Hrushikesh Pradhan
# Copyright (c) : Whizhack Technologies (P) Ltd.
# Revisions/Modifications : Mahesh Banerjee ,Lakshy Sharma, Nikhilesh Kumar

# Complete datetime format.
from datetime import datetime
# Complete default libraries.
import time, json, os, re, gc
# Complete config processing libraries.
from configparser import ConfigParser
# Complete data processing libraries.
import pandas as pd

def config_reader():
    ''' This function will read all the configurations from the config.ini file and pass them to the scripts. '''
    # Creating a configuration object.
    config_object = ConfigParser()
    # Reading the config file using the object.
    config_object.read("/app/config.ini")
    # Collecting configurations.
    locations = config_object["LOCATIONS"]
    # Returning all values to main function for transport elsewhere.
    return locations

def file_lookup(packet_path, event_path, packet_processed_file_location, event_processed_file_location):
    ''' This function simply looks if the files exists or not.'''
    # Setting the regex expression.
    regex_exp = re.compile(r'part-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}\.json$')
    while True:
        # Searching for valid packet files.
        try:
            # Creating a list of files in the packets folder.
            packet_files_list = list(filter(regex_exp.search,os.listdir(packet_path)))
            # Finding the latest file and removing it from the list to avoid the file that logstash is still using.
            packet_files_list.remove(max(packet_files_list))
            # Finding the new latest file to process.
            packet_to_process_file = max(packet_files_list)
            # Creating the latest file location.
            packet_to_process_file_location = packet_path + packet_to_process_file
            del packet_files_list
            gc.collect()
        except ValueError:
            continue
        # Searching for valid event files.
        try:
            event_files_list = list(filter(regex_exp.search,os.listdir(event_path)))
            event_files_list.remove(max(event_files_list))
            event_to_process_file = max(event_files_list)
            event_to_process_file_location = event_path + event_to_process_file
            del event_files_list
            gc.collect()
        except ValueError:
            continue
        # Checking if the packet and event files have the same timestamp or not.
        if (packet_to_process_file == event_to_process_file):
            # If the timestamp is same then check if the files have been processed earlier or not.
            if (packet_to_process_file_location != packet_processed_file_location) and (event_to_process_file_location != event_processed_file_location):
                # If the files are new then return to main function.
                break
    # Cleanup and exit function.
    del regex_exp
    gc.collect()
    return packet_to_process_file_location, event_to_process_file_location, packet_to_process_file, event_to_process_file

def normalize(packet_path, suricata_path, packet_filename, event_filename, destination_path ):
    # Reading packet file and normalizing the data.
    with open(packet_path) as file:
        packet_data=[json.loads(line.rstrip("\n")) for line in file]
        pkt_dataframe = pd.json_normalize(packet_data)
        pkt_dataframe.to_json('/var/log/data/processed_data/listener_normalized.json', orient = 'records', lines = True)
        pkt_dataframe.to_json(destination_path + 'listener/'+packet_filename, orient='records', lines=True)
        del pkt_dataframe
        gc.collect()
    # Reading the event file and normalzing the data.
    with open(suricata_path) as file:
        event_data=[json.loads(line.rstrip("\n")) for line in file]
        eve_dataframe = pd.json_normalize(event_data)
        eve_dataframe.to_json('/var/log/data/processed_data/event_normalized.json', orient = 'records', lines = True)
        eve_dataframe.to_json(destination_path + 'ids/'+event_filename, orient='records', lines=True)
        del eve_dataframe
        gc.collect()
    return None

def file_expunger(packet_processed_file_location, event_processed_file_location):
    ''' This function deletes processed files to save disk space. '''
    os.remove(packet_processed_file_location)
    os.remove(event_processed_file_location)
    return None

def main():
    ''' This is the main function for orchestration. '''
    # Capturing the configurations.
    locations = config_reader()
    # Setting the target files
    event_path = locations["suricata_path"]
    packet_path = locations["packet_path"]
    destination_path = locations["destination_path"]
    # Setting the timestamp we need to look for.
    packet_processed_file_location = 0
    event_processed_file_location = 0
    # Starting an infinite loop.
    while True:
        print("[*] Starting the normalization loop.")
        # Catching the files which needs to be processed and passing it to the merger.
        packet_to_process_file_location, event_to_process_file_location, packet_file, event_file= file_lookup(packet_path, event_path,packet_processed_file_location, event_processed_file_location)
        print("[*] Found valid files. Starting normalization.")
        # Calling the normalizer function.
        normalize(packet_to_process_file_location, event_to_process_file_location, packet_file, event_file, destination_path)
        # Updating the processed file variables.
        packet_processed_file_location = packet_to_process_file_location
        event_processed_file_location = event_to_process_file_location
        # Expunging function which deletes the files once they have been processed to save disk space.
        print("[*] Deleting used files.")
        file_expunger(packet_processed_file_location, event_processed_file_location)

# Starting the function.
if __name__ == '__main__':
    # Calling main function to start merging the files.
    main()
