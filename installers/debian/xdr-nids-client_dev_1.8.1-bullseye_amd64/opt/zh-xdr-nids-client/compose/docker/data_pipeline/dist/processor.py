# Filename : IDS, Ml, Dl Pipeline
# Purpose/Description : The code in this file takes processed data from IDS, ml & dl sends it to the database for presentation.
# Author : Hrushikesh Pradhan
# Copyright (c) : Whizhack Technologies (P) Ltd.
# Revisions/Modifications : Mahesh Banerjee ,Lakshy Sharma , Nihalkumar Parsania, Nikhil Garg, Nikhilesh Kumar, Amisha Prashar

import json, os, gc, pickle, warnings, subprocess, sys,time, ndjson, ast
import pandas as pd
import polars as pl
import numpy as np
from ua_parser import user_agent_parser
from dateutil.tz import tzutc, UTC
from ipaddress import ip_address
# Setting initial variables for pandas.
pd.options.mode.chained_assignment = None
warnings.filterwarnings('ignore')

def list2Str(lst):
    try:
        if isinstance(lst, list):
            return",".join(lst)
        else:
            return lst
    except:
        print('Error in casting list: ', lst, sys.exc_info()[0])

def fun():
    ''' This function builds the model required by the DL engine.'''
    model = Sequential()
    model.add(Dense(49,input_dim =X_train.shape[1],activation = 'relu'))
    model.add(Dense(24,activation='softmax'))
    model.compile(loss ='sparse_categorical_crossentropy',optimizer = 'adam', metrics = ['accuracy'])
    return model

def port_extraction(df, port_type):
    port_cols = [col for col in df.columns if port_type in col]
    port_name = []
    port = []

    for index, row in df.iterrows():
        port_found = False
        for col in port_cols:
            if pd.notnull(row[col]):
                port_name.append(col)
                port.append(row[col])
                port_found = True
                break
        if not port_found:
            port_name.append('port not found')
            port.append(0)

    df[f'{port_type}_name'] = port_name
    df[port_type] = port
    df = df.drop(port_cols,axis = 'columns')

    del port_name, port, port_cols
    gc.collect()
    return df

def Flag_extraction(df, col_list, col_name, col_value):
    result = []
    result_value = []
    for index, row in df.iterrows():
        not_found = False
        for col in col_list:
            if pd.notnull(row[col]):
                result.append(col)
                result_value.append(row[col])
                not_found = True
                break
        if not not_found:
            result.append('Not found')
            result_value.append(0)

    df[col_name] = result
    df[col_value] = result_value
    df = df.drop(col_list,axis = 'columns')

    del result, result_value, col_list
    gc.collect()
    return df

def packet_data_load(packet_path, fields_list_path):

    # Creating work copies of the data.
    #===================================
    ml_dl_raw_dataframe = pd.read_json(packet_path, lines=True)
    
    # Performing ML and DL prediction.
    #===================================    
    ml_dl_raw_dataframe = ml_dl_raw_dataframe.dropna(axis=0, subset=['timestamp','layer.ip.ip.dst_host', 'layer.ip.ip.src_host', 'layer.eth.eth.src', 'layer.eth.eth.dst']).reset_index(drop = True)
    ml_dl_raw_dataframe = ml_dl_raw_dataframe.fillna(np.nan)
    
    # Features required for AI Analysis
    ai_features = ['layer.udp._ws.expert.severity', 'layer.tcp.tcp.analysis.window_update',
       'layer.tcp.tcp.flags.reset', 'layer.udp.udp.dstport',
       'layer.tcp._ws.expert.severity', 'layer.tcp.tcp.time_relative',
       'layer.tcp.tcp.flags.fin', 'layer.icmp.ip.dst_host',
       'layer.udp.udp.length', 'layer.tcp.tcp.analysis.lost_segment',
       'layer.icmp.tcp.ack', 'layer.tcp.tcp.option_len', 'layer.ip.ip.proto',
       'layer.tcp.tcp.time_delta', 'layer.icmp.tcp.flags.cwr',
       'layer.tcp.tcp.stream', 'layer.tcp.tcp.analysis.retransmission',
       'layer.icmp.tcp.flags.reset', 'layer.tcp.tcp.hdr_len',
       'layer.tcp.tcp.seq', 'layer.icmp.ip.ttl', 'layer.ip.ip.frag_offset',
       'layer.ip.ip.hdr_len', 'layer.icmp._ws.expert.message',
       'layer.ip.ip.ttl', 'layer.ip.ip.flags.mf', 'layer.ip.ip.dst_host',
       'layer.tcp.tcp.srcport', 'layer.icmp.ip.len',
       'layer.icmp.tcp.flags.ecn',
       'layer.tcp.tcp.analysis.fast_retransmission', 'layer.tcp.tcp.len',
       'layer.icmp.ip.src_host', 'layer.icmp.tcp.time_delta',
       'layer.tcp.tcp.flags.cwr',
       'layer.tcp.tcp.analysis.spurious_retransmission',
       'layer.icmp.tcp.time_relative', 'layer.icmp.tcp.flags.ack',
       'layer.icmp.udp.checksum.status', 'layer.icmp.icmp.code',
       'layer.icmp.udp.stream', 'layer.icmp.tcp.srcport',
       'layer.tcp.tcp.dstport', 'layer.icmp.tcp.dstport',
       'layer.udp.udp.stream', 'layer.ip.ip.len', 'layer.ip.ip.flags',
       'layer.ip.ip.dsfield.dscp', 'layer.tcp.tcp.flags.urg',
       'layer.icmp.tcp.seq', 'layer.tcp.tcp.flags.push',
       'layer.icmp.udp.length', 'layer.tcp.tcp.flags.ack',
       'layer.tcp.tcp.connection.rst', 'layer.udp._ws.expert.message',
       'layer.tcp.tcp.window_size', 'layer.data.tcp.reassembled.length',
       'layer.tcp.tcp.options.sack_perm', 'layer.ip.ip.src_host',
       'layer.tcp.tcp.connection.syn', 'app_linkage',
       'layer.tcp._ws.expert.message', 'layer.tcp.tcp.flags.syn',
       'layer.tcp.tcp.analysis.window_full', 'layer.tcp.tcp.ack',
       'layer.icmp.tcp.stream', 'layer.icmp.tcp.flags.push',
       'layer.udp.udp.checksum.status', 'layer.ip.ip.dsfield.ecn',
       'layer.tcp.tcp.flags.ecn', 'layer.icmp.tcp.window_size',
       'layer.ip.ip.flags.df', 'layer.udp.udp.srcport',
       'layer.icmp.tcp.flags.fin', 'layer.icmp.tcp.flags.syn',
       'layer.icmp._ws.expert.severity', 'id','timestamp',
       'layer.eth.eth.src', 'layer.eth.eth.dst']

    for i in ai_features:
        if i not in ml_dl_raw_dataframe.columns:
            ml_dl_raw_dataframe[i] = np.nan
    ml_dl_raw_dataframe = ml_dl_raw_dataframe[ai_features]

    # Getting categorical variables
    categorical_var_names = [key for key in dict(ml_dl_raw_dataframe.dtypes) if dict(ml_dl_raw_dataframe.dtypes)[key] not in ['float64', 'int64', 'float32', 'int32']]
    cat = ml_dl_raw_dataframe[categorical_var_names]
    ml_dl_raw_dataframe[categorical_var_names] = cat.applymap(lambda x:list2Str(x))
    ml_dl_raw_dataframe[categorical_var_names] = ml_dl_raw_dataframe[categorical_var_names].astype(str)

    #Cleaning columns names
    updated_columns = []
    for i in [i.split(".") for i in ml_dl_raw_dataframe.columns]:
        if len(i)>len(set(i)) and len(i)>1:
            i.pop(1)
            updated_columns.append(i)
        else:
            updated_columns.append(i)
        
    ml_dl_raw_dataframe.rename(columns=dict(zip(ml_dl_raw_dataframe.columns,[("_").join(i) for i in updated_columns])), inplace=True)
    del updated_columns
    gc.collect()   
   
    # Dropping df where destination Port and source_port is 24224
    ml_dl_raw_dataframe.drop(ml_dl_raw_dataframe[(ml_dl_raw_dataframe['layer_tcp_srcport'] == 24224)].index,inplace = True)
    ml_dl_raw_dataframe.drop(ml_dl_raw_dataframe[(ml_dl_raw_dataframe['layer_tcp_dstport'] == 24224)].index,inplace = True)
    ml_dl_raw_dataframe.reset_index(inplace = True,drop = True)

    ml_dl_raw_dataframe = port_extraction(ml_dl_raw_dataframe, 'srcport')
    ml_dl_raw_dataframe.srcport_name = [s.replace('layer_', '').replace('_srcport', '') for s in ml_dl_raw_dataframe.srcport_name]
    ml_dl_raw_dataframe = port_extraction(ml_dl_raw_dataframe, 'dstport')
    ml_dl_raw_dataframe.dstport_name = [s.replace('layer_', '').replace('_dstport', '') for s in ml_dl_raw_dataframe.dstport_name]
    
    # All required columns which are required after prediction
    required_columns = ['id','timestamp', 'app_linkage','layer_ip_src_host', 'layer_ip_dst_host','layer_eth_src', 'layer_eth_dst','dstport', 'srcport']
    available_columns = []
    for i in required_columns:
        if i in ml_dl_raw_dataframe.columns:
            available_columns.append(i)
    required_features = ml_dl_raw_dataframe.loc[:,available_columns]

    ## Time to Live
    check = ['layer_ip_ttl', 'layer_icmp_ip_ttl']
    time_to_live = []
    time_to_live_value = []
    # keeping the value of icmp ttl where icmp and ip having the value of ttl
    for index, row in ml_dl_raw_dataframe.iterrows():
        if pd.notnull(row['layer_ip_ttl']) and pd.notnull(row['layer_icmp_ip_ttl']):
            time_to_live.append('layer_icmp_ip_ttl')
            time_to_live_value.append(row['layer_icmp_ip_ttl'])
        elif pd.notnull(row['layer_ip_ttl']):
            time_to_live.append('layer_ip_ttl')
            time_to_live_value.append(row['layer_ip_ttl'])
        elif pd.notnull(row['layer_icmp_ip_ttl']):
            time_to_live.append('layer_icmp_ip_ttl')
            time_to_live_value.append(row['layer_icmp_ip_ttl'])
        else:
            time_to_live.append('missing_ttl')
            time_to_live_value.append(0)
    ml_dl_raw_dataframe['time_to_live'],ml_dl_raw_dataframe['time_to_live_value'] = time_to_live,time_to_live_value
    del time_to_live,time_to_live_value,check
    gc.collect()

    ml_dl_raw_dataframe = ml_dl_raw_dataframe.drop(['layer_ip_ttl','layer_icmp_ip_ttl'],axis = 'columns')
    
    # Cleaning values 
    ml_dl_raw_dataframe.time_to_live = [s.replace('layer_', '') for s in ml_dl_raw_dataframe.time_to_live]

    # Dropping and creating Features 

    ml_dl_raw_dataframe['stream_bytes'] = ml_dl_raw_dataframe[['layer_tcp_stream','layer_udp_stream', 'layer_icmp_tcp_stream','layer_icmp_udp_stream']].sum(axis=1, skipna=True)

    ml_dl_raw_dataframe.drop(['layer_tcp_stream','layer_udp_stream','layer_icmp_tcp_stream', 'layer_icmp_udp_stream'],axis = 'columns',inplace = True)

    # creating a feature by aggregating all severity features
    ml_dl_raw_dataframe['severity'] = ml_dl_raw_dataframe[['layer_udp__ws_expert_severity','layer_icmp__ws_expert_severity', 'layer_tcp__ws_expert_severity']].sum(axis=1, skipna=True)

    ml_dl_raw_dataframe = ml_dl_raw_dataframe.drop(['layer_udp__ws_expert_severity','layer_icmp__ws_expert_severity', 'layer_tcp__ws_expert_severity'],axis = 'columns')

    flag_extraction_config = [
    {'check': ['layer_icmp_udp_checksum_status', 'layer_udp_checksum_status'], 'flag': 'checksum', 'value': 'checksum_value'},
    {'check': ['layer_tcp_time_delta', 'layer_icmp_tcp_time_delta'], 'flag': 'time', 'value': 'time_value'},
    {'check': ['layer_tcp_flags_cwr','layer_icmp_tcp_flags_cwr'], 'flag': 'cwr_flags', 'value': 'cwr_flags_value'},
    {'check': ['layer_tcp_flags_ecn','layer_icmp_tcp_flags_ecn'], 'flag': 'ecn_flags', 'value': 'ecn_flags_value'},
    {'check': ['layer_tcp_flags_ack','layer_icmp_tcp_flags_ack'], 'flag': 'ack_flags', 'value': 'ack_flags_value'},
    {'check': ['layer_tcp_flags_push','layer_icmp_tcp_flags_push'], 'flag': 'push_flags', 'value': 'push_flags_value'},
    {'check': ['layer_tcp_flags_reset','layer_icmp_tcp_flags_reset'], 'flag': 'reset_flags', 'value': 'reset_flags_value'},
    {'check': ['layer_tcp_flags_syn','layer_icmp_tcp_flags_syn'], 'flag': 'syn_flags', 'value': 'syn_flags_value'},
    {'check': ['layer_tcp_flags_fin','layer_icmp_tcp_flags_fin'], 'flag': 'fin_flags', 'value': 'fin_flags_value'},
    {'check': ['layer_tcp_seq','layer_icmp_tcp_seq'], 'flag': 'seq', 'value': 'seq_value'},
    {'check': ['layer_tcp_ack','layer_icmp_tcp_ack'], 'flag': 'ack', 'value': 'ack_value'},
    {'check': ['layer_tcp_window_size','layer_icmp_tcp_window_size'], 'flag': 'tcp_window_size', 'value': 'tcp_window_size_value'},
    {'check': ['layer_tcp_time_relative','layer_icmp_tcp_time_relative'], 'flag': 'tcp_time_relative', 'value': 'tcp_time_relative_value'},
    {'check': ['layer_tcp_len','layer_udp_length'], 'flag': 'packet_len', 'value': 'packet_len_value'}
    ]

    for config in flag_extraction_config:
        check = config['check']
        flag = config['flag']
        value = config['value']
        ml_dl_raw_dataframe = Flag_extraction(ml_dl_raw_dataframe, check, flag, value)
        ml_dl_raw_dataframe[flag] = [s.replace('layer_', '') for s in ml_dl_raw_dataframe[flag]]
        del check
        gc.collect()

    #creates a single feature for all flags
    ml_dl_raw_dataframe['flag_name'] = [s.replace('_flags_cwr', '') for s in ml_dl_raw_dataframe.cwr_flags]
    ml_dl_raw_dataframe = ml_dl_raw_dataframe.drop(['ecn_flags','ack_flags','push_flags', 'reset_flags', 'syn_flags','fin_flags','cwr_flags'],axis = 'columns')
    ml_dl_raw_dataframe['layer_tcp_options_sack_perm'] = ml_dl_raw_dataframe['layer_tcp_options_sack_perm'].fillna(False).replace('04:02', True).fillna('Not TCP sack perm')
    
    # Unique value is 1 i.e. *20*
    ml_dl_raw_dataframe = ml_dl_raw_dataframe.drop('layer_ip_hdr_len',axis = 'columns')
    ml_dl_raw_dataframe['service'] = ml_dl_raw_dataframe.checksum
    ml_dl_raw_dataframe = ml_dl_raw_dataframe.drop(['checksum','tcp_time_relative'],axis = 'columns')
    
    # keeping only service beacuse it have more information than Flag_name
    ml_dl_raw_dataframe = ml_dl_raw_dataframe.drop(['flag_name'],axis = 'columns')
    
    #these features information in service
    ml_dl_raw_dataframe = ml_dl_raw_dataframe.drop(['seq','ack'],axis = 'columns')
    
    #Dropping 'src_port_name','dst_port_name' they have the same value as in service
    ml_dl_raw_dataframe = ml_dl_raw_dataframe.drop(['srcport_name','dstport_name'],axis = 'columns')


    #Del unwanted objects
    del available_columns, required_columns, categorical_var_names, cat
    gc.collect()

    return ml_dl_raw_dataframe, required_features

def ai_analyzer(ml_dl_raw_dataframe, ml_model_path, dl_model_path, required_features):

    # Read pickle File
    dl_model = pickle.load(open(dl_model_path,'rb'))
    ml_model = pickle.load(open(ml_model_path,'rb'))

    # For Ml,Dl prediction & probability.
    ml_label = ml_model.predict(ml_dl_raw_dataframe)
    ml_proba = pd.Series(np.max(ml_model.predict_proba(ml_dl_raw_dataframe), axis=1))
    dl_label = dl_model.predict(ml_dl_raw_dataframe)
    dl_proba = pd.Series(np.max(dl_model.predict_proba(ml_dl_raw_dataframe), axis=1))
    dl_label = [item for sublist in dl_label for item in sublist]
    ml_dl_raw_dataframe['ml_prediction'] = ml_label
    ml_dl_raw_dataframe['ml_probability'] = ml_proba
    ml_dl_raw_dataframe['dl_prediction'] = dl_label
    ml_dl_raw_dataframe['dl_probability'] = dl_proba   
    
    # Take necessary fields from ml_dl_prediction. 
    ml_dl_predicted_labels = ml_dl_raw_dataframe[['ml_prediction','ml_probability','dl_prediction', 'dl_probability']]
    del dl_model, ml_model, ml_label, dl_label, ml_dl_raw_dataframe, ml_proba, dl_proba
    gc.collect()
    
    # Assembling pred_labels with required_features then get data fro ids merger :-
    # +++=======================================================================+++
    processed_data = pd.concat([required_features,ml_dl_predicted_labels], axis=1)
    del ml_dl_predicted_labels, required_features
    gc.collect()
    
    # Resetting index and dropping null values in source host and destination host.
    processed_data = processed_data.reset_index(drop=True)
    processed_data = processed_data.dropna(axis=0, subset=['layer_ip_src_host', 'layer_ip_dst_host'])
    print(processed_data.shape)
    processed_data = processed_data.dropna(axis=0, subset=['ml_prediction', 'dl_prediction'])
    processed_data = processed_data.drop(processed_data[(processed_data['ml_probability'] < 0.3) | (processed_data['dl_probability'] < 0.7)].index)
    print(processed_data.shape)


    return processed_data

def signature_analyzer(event_path, processed_data):

    # Start IDS data Pre-processing :-
    # +++========================+++
    # Read eve file:
    init_eve_dataframe = pd.read_json(event_path,lines=True)
    
    required_list = ['http.http_user_agent', 'alert.metadata.malware_family','alert.metadata.attack_target', 'alert.metadata.cve','alert.metadata.tag','alert.metadata.mitre_tactics_id','alert.metadata.mitre_tactics_name', 'alert.metadata.mitre_techniques_id','alert.metadata.mitre_techniques_name']
    for i in required_list:
        if i not in init_eve_dataframe.columns:
            init_eve_dataframe[i] = np.nan
    init_eve_dataframe[required_list] = init_eve_dataframe[required_list].applymap(lambda x:list2Str(x)).astype(str)
   
    # Take necessary features
    init_eve_dataframe = init_eve_dataframe[['timestamp', 'src_ip', 'dest_ip', 'event_type', 'alert.signature', 'alert.category', 'alert.severity','http.http_user_agent', 'alert.metadata.malware_family','alert.metadata.attack_target', 'alert.metadata.cve','alert.metadata.tag','alert.metadata.mitre_tactics_id','alert.metadata.mitre_tactics_name', 'alert.metadata.mitre_techniques_id','alert.metadata.mitre_techniques_name']]
   
    # Normalize the timestamp fileds of both the event and packet data
    init_eve_dataframe["timestamp"]=init_eve_dataframe['timestamp'] = pd.to_datetime(init_eve_dataframe.timestamp).dt.tz_localize(None)
    processed_data["timestamp"]=processed_data['timestamp'] = pd.to_datetime(processed_data.timestamp).dt.tz_localize(None)
    print(init_eve_dataframe.shape)
    eve_dataframe = init_eve_dataframe.loc[init_eve_dataframe['event_type'] == 'alert']
    print(eve_dataframe.shape)

    
    
    # Perfoming merge.
    new_data = processed_data.copy()
 
    try:
        ids_merged_dataframe = pd.merge_asof(processed_data.sort_values('timestamp'), eve_dataframe.sort_values('timestamp'), on='timestamp', direction='forward')
        # Drop rows with missing values in these columns
        # ==============================================
        ids_merged_dataframe.dropna(axis=0, subset=['layer_ip_dst_host', 'layer_ip_src_host', 'src_ip', 'dest_ip'], inplace=True)
        # Define conditions for swapping the values of 'layer.ip.ip.src_host' and 'layer.ip.ip.dst_host'
        cond1 = (ids_merged_dataframe['layer_ip_src_host'] == ids_merged_dataframe['src_ip']) & (ids_merged_dataframe['layer_ip_dst_host'] == ids_merged_dataframe['dest_ip'])
        cond2 = (ids_merged_dataframe['layer_ip_src_host'] == ids_merged_dataframe['dest_ip']) & (ids_merged_dataframe['layer_ip_dst_host'] == ids_merged_dataframe['src_ip'])
        # Create a new dataframe with the rows that match condition 2
        swaping_dataframe = ids_merged_dataframe.loc[cond2].reset_index(drop=True)
        # Swap the values of 'layer.ip.ip.dst_host' and 'layer.ip.ip.src_host' in the new dataframe
        swaping_dataframe['layer_ip_dst_host'], swaping_dataframe['layer_ip_src_host'] = swaping_dataframe['dest_ip'], swaping_dataframe['src_ip']
        # Select the rows that match condition 1 in the original dataframe
        ids_merged_dataframe = ids_merged_dataframe.loc[cond1].reset_index(drop=True)
        # Concatenate the original dataframe and the new dataframe, and reset the index
        ids_merged_dataframe = pd.concat([ids_merged_dataframe, swaping_dataframe], axis = 0, ignore_index = True)
        # Drop the 'src_ip' and 'dest_ip' columns from the processed data and reset the index
        signature_data = ids_merged_dataframe.drop(['src_ip', 'dest_ip'], axis=1).reset_index(drop=True)
        del ids_merged_dataframe, swaping_dataframe
        gc.collect()
        if signature_data.shape[0]==0:
            raise TypeError("Merge UnSucessful")
        else: 

            print("[*] Merge Sucessful ", signature_data.shape)
            print("[***********************************]", signature_data.shape)
        
    except:
            # Rename columns using a dictionary
            print("** Start")
            features_to_consider = [col for col in eve_dataframe.columns if col != 'timestamp']
            eve_dataframe = eve_dataframe.drop_duplicates(subset=features_to_consider)
            print(eve_dataframe.shape)
            eve_dataframe.rename(columns={'src_ip': 'layer_ip_src_host', 'dest_ip': 'layer_ip_dst_host'}, inplace=True)
 
            features_to_consider = [col for col in new_data.columns if col not in ['timestamp', 'id']]            
            new_data = new_data.drop_duplicates(subset=features_to_consider)
            print(new_data.shape)
 
            signature_data = pd.concat([new_data, eve_dataframe], axis=0)
            # processed_data = [col for col in processed_data.columns if col not in ['timestamp', 'id']]            
            # processed_data = processed_data.drop_duplicates(subset=features_to_consider)
 
            signature_data =signature_data.reset_index(drop=True)
            print("[*] Merge UnSucessful ", signature_data.shape)
    return signature_data

def data_cleaner(processed_data):

    # Resetting any broken indexes.
    #=============================
    processed_data = processed_data.reset_index(drop=True)
    
    # Mapping the IP types
    #======================
    processed_data['src_host_type']= processed_data['layer_ip_src_host'].apply([lambda x: 'internal' if ip_address(x).is_private else 'external'])
    processed_data['dst_host_type']= processed_data['layer_ip_dst_host'].apply([lambda x: 'internal' if ip_address(x).is_private else 'external'])
    
    #Required Columns:
    #==================
    new_columns = ['service_name','attacker_ip','attacker_mac','attack_timestamp','target_ip','target_mac','ids_threat_class','ids_threat_type','ids_threat_severity','type_of_threat','packet_id','ml_threat_class', 'dl_threat_class', 'ml_accuracy','dl_accuracy','activity_type','mitre_tactics_id', 'mitre_tactics_name', 'mitre_techniques_id','mitre_techniques_name', 'malware_type', 'attacker_host_type', 'malware_cve_id','attackers_id_known','attacker_domain', 'intel_source_feed_name','attacker_port', 'target_port']    # New column creator loop.
    for i in range(len(new_columns)):
        last_column = len(processed_data.columns)
        processed_data.insert(loc=last_column, column=new_columns[i],value=None)
    del last_column
    gc.collect()
    #####################################################################
    ## Working on External

    # Condition for external to internal attack
    external_to_internal_condition = (processed_data['src_host_type'] == 'external') & (processed_data['dst_host_type'] == 'internal')
    # Condition for internal to external attack
    internal_to_external_condition = (processed_data['src_host_type'] == 'internal') & (processed_data['dst_host_type'] == 'external')
    # Condition for internal to internal attack
    internal_to_internal_condition = (processed_data['src_host_type'] == 'internal') & (processed_data['dst_host_type'] == 'internal')
    # Condition for external to external attack
    external_to_external_condition = ~external_to_internal_condition & ~internal_to_external_condition & ~internal_to_internal_condition
    
    # Process data for external to internal attack
    processed_data.loc[external_to_internal_condition, 'attacker_ip'] = processed_data.loc[external_to_internal_condition, 'layer_ip_src_host']
    processed_data.loc[external_to_internal_condition, 'attacker_mac'] = processed_data.loc[external_to_internal_condition, 'layer_eth_src']
    processed_data.loc[external_to_internal_condition, 'target_ip'] = processed_data.loc[external_to_internal_condition, 'layer_ip_dst_host']
    processed_data.loc[external_to_internal_condition, 'target_mac'] = processed_data.loc[external_to_internal_condition, 'layer_eth_dst']
    processed_data.loc[external_to_internal_condition, 'ids_threat_class'] = processed_data.loc[external_to_internal_condition, 'alert.category']
    processed_data.loc[external_to_internal_condition, 'ids_threat_type'] = processed_data.loc[external_to_internal_condition, 'alert.signature']
    processed_data.loc[external_to_internal_condition, 'ids_threat_severity'] = processed_data.loc[external_to_internal_condition, 'alert.severity']
    processed_data.loc[external_to_internal_condition, 'ml_threat_class'] = processed_data.loc[external_to_internal_condition, 'ml_prediction']
    processed_data.loc[external_to_internal_condition, 'dl_threat_class'] = processed_data.loc[external_to_internal_condition, 'dl_prediction']
    processed_data.loc[external_to_internal_condition, 'ml_accuracy'] = processed_data.loc[external_to_internal_condition, 'ml_probability'] * 100
    processed_data.loc[external_to_internal_condition, 'dl_accuracy'] = processed_data.loc[external_to_internal_condition, 'dl_probability'] * 100
    processed_data.loc[external_to_internal_condition, 'type_of_threat'] = 'External Attack'
    processed_data.loc[external_to_internal_condition, 'packet_id'] = processed_data.loc[external_to_internal_condition, 'id']
    processed_data.loc[external_to_internal_condition, 'attack_timestamp'] = processed_data.loc[external_to_internal_condition, 'timestamp']
    processed_data.loc[external_to_internal_condition, 'service_name'] = processed_data.loc[external_to_internal_condition, 'app_linkage']
    processed_data.loc[external_to_internal_condition, 'activity_type'] = processed_data.loc[external_to_internal_condition, 'alert.category']
    
    processed_data.loc[external_to_internal_condition, 'attacker_port'] = processed_data.loc[external_to_internal_condition, 'srcport']
    processed_data.loc[external_to_internal_condition, 'target_port'] = processed_data.loc[external_to_internal_condition, 'dstport']

    
    # Process data for internal to external attack
    processed_data.loc[internal_to_external_condition, 'attacker_ip'] = processed_data.loc[internal_to_external_condition, 'layer_ip_dst_host']
    processed_data.loc[internal_to_external_condition, 'attacker_mac'] = processed_data.loc[internal_to_external_condition, 'layer_eth_dst']
    processed_data.loc[internal_to_external_condition, 'target_ip'] = processed_data.loc[internal_to_external_condition, 'layer_ip_src_host']
    processed_data.loc[internal_to_external_condition, 'target_mac'] = processed_data.loc[internal_to_external_condition, 'layer_eth_src']
    processed_data.loc[internal_to_external_condition, 'ids_threat_class'] = processed_data.loc[internal_to_external_condition, 'alert.category']
    processed_data.loc[internal_to_external_condition, 'ids_threat_type'] = processed_data.loc[internal_to_external_condition, 'alert.signature']
    processed_data.loc[internal_to_external_condition, 'ids_threat_severity'] = processed_data.loc[internal_to_external_condition, 'alert.severity']
    processed_data.loc[internal_to_external_condition, 'ml_threat_class'] = processed_data.loc[internal_to_external_condition, 'ml_prediction']
    processed_data.loc[internal_to_external_condition, 'dl_threat_class'] = processed_data.loc[internal_to_external_condition, 'dl_prediction']
    processed_data.loc[internal_to_external_condition, 'ml_accuracy'] = processed_data.loc[internal_to_external_condition, 'ml_probability'] * 100
    processed_data.loc[internal_to_external_condition, 'dl_accuracy'] = processed_data.loc[internal_to_external_condition, 'dl_probability'] * 100
    processed_data.loc[internal_to_external_condition, 'type_of_threat'] = 'Internal Compromised Machine'
    processed_data.loc[internal_to_external_condition, 'packet_id'] = processed_data.loc[internal_to_external_condition, 'id']
    processed_data.loc[internal_to_external_condition, 'attack_timestamp'] = processed_data.loc[internal_to_external_condition, 'timestamp']
    processed_data.loc[internal_to_external_condition, 'service_name'] = processed_data.loc[internal_to_external_condition, 'app_linkage']
    processed_data.loc[internal_to_external_condition, 'activity_type'] = processed_data.loc[internal_to_external_condition, 'alert.category']

    
    processed_data.loc[internal_to_external_condition, 'attacker_port'] = processed_data.loc[internal_to_external_condition, 'dstport']
    processed_data.loc[internal_to_external_condition, 'target_port'] = processed_data.loc[internal_to_external_condition, 'srcport']
    
    
    # Process data for internal to internal attack
    processed_data.loc[internal_to_internal_condition, 'attacker_ip'] = processed_data.loc[internal_to_internal_condition, 'layer_ip_src_host']
    processed_data.loc[internal_to_internal_condition, 'attacker_mac'] = processed_data.loc[internal_to_internal_condition, 'layer_eth_src']
    processed_data.loc[internal_to_internal_condition, 'target_ip'] = processed_data.loc[internal_to_internal_condition, 'layer_ip_dst_host']
    processed_data.loc[internal_to_internal_condition, 'target_mac'] = processed_data.loc[internal_to_internal_condition, 'layer_eth_dst']
    processed_data.loc[internal_to_internal_condition, 'ids_threat_class'] = processed_data.loc[internal_to_internal_condition, 'alert.category']
    processed_data.loc[internal_to_internal_condition, 'ids_threat_type'] = processed_data.loc[internal_to_internal_condition, 'alert.signature']
    processed_data.loc[internal_to_internal_condition, 'ids_threat_severity'] = processed_data.loc[internal_to_internal_condition, 'alert.severity']
    processed_data.loc[internal_to_internal_condition, 'ml_threat_class'] = processed_data.loc[internal_to_internal_condition, 'ml_prediction']
    processed_data.loc[internal_to_internal_condition, 'dl_threat_class'] = processed_data.loc[internal_to_internal_condition, 'dl_prediction']
    processed_data.loc[internal_to_internal_condition, 'ml_accuracy'] = processed_data.loc[internal_to_internal_condition, 'ml_probability'] * 100
    processed_data.loc[internal_to_internal_condition, 'dl_accuracy'] = processed_data.loc[internal_to_internal_condition, 'dl_probability'] * 100
    processed_data.loc[internal_to_internal_condition, 'type_of_threat'] = 'Lateral Movement'
    processed_data.loc[internal_to_internal_condition, 'packet_id'] = processed_data.loc[internal_to_internal_condition, 'id']
    processed_data.loc[internal_to_internal_condition, 'attack_timestamp'] = processed_data.loc[internal_to_internal_condition, 'timestamp']
    processed_data.loc[internal_to_internal_condition, 'service_name'] = processed_data.loc[internal_to_internal_condition, 'app_linkage']
    processed_data.loc[internal_to_internal_condition, 'activity_type'] = processed_data.loc[internal_to_internal_condition, 'alert.category']
    
    
    processed_data.loc[internal_to_internal_condition, 'attacker_port'] = processed_data.loc[internal_to_internal_condition, 'srcport']
    processed_data.loc[internal_to_internal_condition, 'target_port'] = processed_data.loc[internal_to_internal_condition, 'dstport']

    # Process data for external to external attack
    processed_data.loc[external_to_external_condition, 'attacker_ip'] = processed_data.loc[external_to_external_condition, 'layer_ip_src_host']
    processed_data.loc[external_to_external_condition, 'attacker_mac'] = processed_data.loc[external_to_external_condition, 'layer_eth_src']
    processed_data.loc[external_to_external_condition, 'target_ip'] = processed_data.loc[external_to_external_condition, 'layer_ip_dst_host']
    processed_data.loc[external_to_external_condition, 'target_mac'] = processed_data.loc[external_to_external_condition, 'layer_eth_dst']
    processed_data.loc[external_to_external_condition, 'ids_threat_class'] = processed_data.loc[external_to_external_condition, 'alert.category']
    processed_data.loc[external_to_external_condition, 'ids_threat_type'] = processed_data.loc[external_to_external_condition, 'alert.signature']
    processed_data.loc[external_to_external_condition, 'ids_threat_severity'] = processed_data.loc[external_to_external_condition, 'alert.severity']
    processed_data.loc[external_to_external_condition, 'ml_threat_class'] = processed_data.loc[external_to_external_condition, 'ml_prediction']
    processed_data.loc[external_to_external_condition, 'dl_threat_class'] = processed_data.loc[external_to_external_condition, 'dl_prediction']
    processed_data.loc[external_to_external_condition, 'ml_accuracy'] = processed_data.loc[external_to_external_condition, 'ml_probability'] * 100
    processed_data.loc[external_to_external_condition, 'dl_accuracy'] = processed_data.loc[external_to_external_condition, 'dl_probability'] * 100
    processed_data.loc[external_to_external_condition, 'type_of_threat'] = 'Attack on External Server'
    processed_data.loc[external_to_external_condition, 'packet_id'] = processed_data.loc[external_to_external_condition, 'id']
    processed_data.loc[external_to_external_condition, 'attack_timestamp'] = processed_data.loc[external_to_external_condition, 'timestamp']
    processed_data.loc[external_to_external_condition, 'service_name'] = processed_data.loc[external_to_external_condition, 'app_linkage']
    processed_data.loc[external_to_external_condition, 'activity_type'] = processed_data.loc[external_to_external_condition, 'alert.category']
    
    processed_data.loc[external_to_external_condition, 'attacker_port'] = processed_data.loc[external_to_external_condition, 'srcport']
    processed_data.loc[external_to_external_condition, 'target_port'] = processed_data.loc[external_to_external_condition, 'dstport']
    

    processed_data = processed_data.drop(['id','event_type','src_host_type','dst_host_type','layer_ip_src_host', 'layer_ip_dst_host', 'layer_eth_src','layer_eth_dst','alert.category', 'alert.signature', 'alert.severity','timestamp', 'ml_prediction', 'dl_prediction', 'app_linkage'], axis=1)
    processed_data = processed_data.drop(['http.http_user_agent', 'alert.metadata.malware_family','alert.metadata.attack_target', 'alert.metadata.cve','alert.metadata.tag','alert.metadata.mitre_tactics_id','alert.metadata.mitre_tactics_name', 'alert.metadata.mitre_techniques_id','alert.metadata.mitre_techniques_name', 'dstport', 'srcport'], axis = 1)


    # Fixing timestamps
    #============================
    offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
    calculated_offset = offset / 60 / 60 * -1
    processed_data['timezone'] = "UTC"+ f"{calculated_offset}"
    return processed_data

def data_transform(service_name_dict_path, processed_data):

    # Exporting processed data.
    #=============================
    #data_from_temp = pl.read_csv(flow_data_path)
    #temp_output = data_from_temp.to_pandas()
    #final_output = temp_output.iloc[: , 1:]
    #del temp_output
    final_output = processed_data
    gc.collect()
    final_output['attack_timestamp'] = final_output['attack_timestamp'].astype('datetime64[s]')
    final_output['attack_epoch_time'] = final_output['attack_timestamp']
    final_output['attack_timestamp'] = final_output['attack_timestamp'].astype(str)
    final_output[['ids_threat_severity']] = final_output[['ids_threat_severity']].astype(float)
    final_output = final_output.replace(['None', 'nan'], np.nan)
    final_output.drop(['ml_probability', 'dl_probability'], axis = 1, inplace  = True)

    with open(service_name_dict_path) as file:
        # Loading ndjson data from file.
        service_name_dict=[json.loads(line.rstrip("\n")) for line in file]
        service_name_dict_df = pd.json_normalize(service_name_dict)
    
    # Defining lower bound and upper bound dl accuracy
    dataframe = pd.merge(final_output, service_name_dict_df, on='service_name', how='left')
    del final_output, service_name_dict_df
    gc.collect() 
    dataframe = dataframe.drop('service_name', axis=1).reset_index(drop = True)
    dataframe.columns = dataframe.columns.str.replace('new_service_name','service_name')

    return dataframe

def logger(dataframe):

    # Whitelisting system IP's
    # List of specific IPs to remove
    ip_list_1 = os.environ.get('IP')
    # Convert the string to list 
    if ip_list_1 is not None:
        ip_list_1 = ast.literal_eval(ip_list_1)
    else:
        ip_list_1 = [] # Handle the case where ip_list_1 is None
    
    # List of IP's to be Whitelisted
    ip_list_2 = [ '169.254.169.254','35.157.82.152','10.0.1.182','52.15.165.77','10.0.11.90' ]

    # Merge List of IP's
    ip_list = ip_list_1 + ip_list_2

    # Filtering out rows with specific IPs
    dataframe = dataframe[~dataframe['attacker_ip'].isin(ip_list)]
    dataframe = dataframe[~dataframe['target_ip'].isin(ip_list)]
    
    # Filtering data with alert severity  having value 1 for incident logs
    xdr_incident_df = dataframe[~dataframe["ids_threat_severity"].isin([2.0,2,3.0,3,np.nan])]
    if xdr_incident_df.empty:
        xdr_incident_df = dataframe[~dataframe["ids_threat_severity"].isin([2.0,2,3.0,3])]
        xdr_incident_df['attack_epoch_time'] = pd.to_datetime(xdr_incident_df['attack_timestamp'])
        xdr_incident_df = xdr_incident_df.loc[:, ['service_name','attacker_ip','attacker_mac','attack_timestamp','target_ip','target_mac','ids_threat_class','ids_threat_type','type_of_threat','packet_id','ml_threat_class','dl_threat_class','ml_accuracy','dl_accuracy','mitre_tactics_id','mitre_tactics_name','mitre_techniques_id','mitre_techniques_name','malware_type','attacker_host_type','malware_cve_id','attackers_id_known','attacker_domain','intel_source_feed_name','attacker_port','target_port','timezone','attack_epoch_time']]
        xdr_incident_df = xdr_incident_df.drop_duplicates(subset=xdr_incident_df.columns.difference(['packet_id']))
        xdr_incident_df = xdr_incident_df.drop(xdr_incident_df[(xdr_incident_df['ml_accuracy'] < 40) & (xdr_incident_df['dl_accuracy'] < 90)].index)
       
    else:
        xdr_incident_df['attack_epoch_time'] = pd.to_datetime(xdr_incident_df['attack_timestamp'])
        xdr_incident_df = xdr_incident_df.loc[:, ['service_name','attacker_ip','attacker_mac','attack_timestamp','target_ip','target_mac','ids_threat_class','ids_threat_type','type_of_threat','packet_id','ml_threat_class','dl_threat_class','ml_accuracy','dl_accuracy','mitre_tactics_id','mitre_tactics_name','mitre_techniques_id','mitre_techniques_name','malware_type','attacker_host_type','malware_cve_id','attackers_id_known','attacker_domain','intel_source_feed_name','attacker_port','target_port','timezone','attack_epoch_time']]
        xdr_incident_df = xdr_incident_df.drop_duplicates(subset=xdr_incident_df.columns.difference(['packet_id']))


    # Filtering data with alert severity  having value 2 for alert logs
    xdr_alert_df = dataframe[~dataframe["ids_threat_severity"].isin([1,1.0,3.0,3,np.nan])]
    if xdr_alert_df.empty:
        xdr_alert_df = dataframe[~dataframe["ids_threat_severity"].isin([1,1.0,3.0,3])]
        xdr_alert_df['attack_epoch_time'] = pd.to_datetime(xdr_alert_df['attack_timestamp'])
        xdr_alert_df = xdr_alert_df.loc[:, ['service_name','attacker_ip','attacker_mac','attack_timestamp','target_ip','target_mac','ids_threat_class','ids_threat_type','type_of_threat','packet_id','ml_threat_class','dl_threat_class','ml_accuracy','dl_accuracy','mitre_tactics_id','mitre_tactics_name','mitre_techniques_id','mitre_techniques_name','malware_type','attacker_host_type','malware_cve_id','attackers_id_known','attacker_domain','intel_source_feed_name','attacker_port','target_port','timezone','attack_epoch_time']]
        xdr_alert_df = xdr_alert_df.drop_duplicates(subset=xdr_alert_df.columns.difference(['packet_id']))
        xdr_alert_df = xdr_alert_df.drop(xdr_alert_df[(xdr_alert_df['ml_accuracy'] < 20) | (xdr_alert_df['ml_accuracy'] > 30) | (xdr_alert_df['dl_accuracy'] < 80) | (xdr_alert_df['dl_accuracy'] > 89)].index)
    else: 
        xdr_alert_df['attack_epoch_time'] = pd.to_datetime(xdr_alert_df['attack_timestamp'])
        xdr_alert_df = xdr_alert_df.loc[:, ['service_name','attacker_ip','attacker_mac','attack_timestamp','target_ip','target_mac','ids_threat_class','ids_threat_type','type_of_threat','packet_id','ml_threat_class','dl_threat_class','ml_accuracy','dl_accuracy','mitre_tactics_id','mitre_tactics_name','mitre_techniques_id','mitre_techniques_name','malware_type','attacker_host_type','malware_cve_id','attackers_id_known','attacker_domain','intel_source_feed_name','attacker_port','target_port','timezone','attack_epoch_time']]
        xdr_alert_df = xdr_alert_df.drop_duplicates(subset=xdr_alert_df.columns.difference(['packet_id']))

    # Filtering data with alert severity  having value 3 or greater for event logs
    xdr_event_df = dataframe[~dataframe["ids_threat_severity"].isin([1,1.0,2,2.0,np.nan])]
    if xdr_event_df.empty:
        xdr_event_df = dataframe[~dataframe["ids_threat_severity"].isin([1,1.0,2,2.0])]
        xdr_event_df['attack_epoch_time'] = pd.to_datetime(xdr_event_df['attack_timestamp'])
        xdr_event_df = xdr_event_df.loc[:, ['service_name','attacker_ip','attacker_mac','attack_timestamp','target_ip','target_mac','ids_threat_class','ids_threat_type', 'type_of_threat','packet_id', 'ml_threat_class','dl_threat_class','ml_accuracy','dl_accuracy','activity_type','malware_type','attackers_id_known','attacker_domain','intel_source_feed_name','attacker_port','target_port','timezone','attack_epoch_time']]
        xdr_event_df = xdr_event_df.drop_duplicates(subset=xdr_event_df.columns.difference(['packet_id']))
        xdr_event_df = xdr_event_df.drop(xdr_alert_df[(xdr_event_df['ml_accuracy'] < 10 )| (xdr_event_df['ml_accuracy'] > 20) | (xdr_event_df['dl_accuracy'] < 75) | (xdr_event_df['dl_accuracy'] > 79)].index)
        
    else: 
        xdr_event_df['attack_epoch_time'] = pd.to_datetime(xdr_event_df['attack_timestamp'])
        xdr_event_df = xdr_event_df.loc[:, ['service_name','attacker_ip','attacker_mac','attack_timestamp','target_ip','target_mac','ids_threat_class','ids_threat_type', 'type_of_threat','packet_id', 'ml_threat_class','dl_threat_class','ml_accuracy','dl_accuracy','activity_type','malware_type','attackers_id_known','attacker_domain','intel_source_feed_name','attacker_port','target_port','timezone','attack_epoch_time']]
        xdr_event_df = xdr_event_df.drop_duplicates(subset=xdr_event_df.columns.difference(['packet_id']))


    del dataframe
    gc.collect()

    # Dumping data to files
    xdr_incident_df.to_json('/app/xdr_incident.json', orient = 'records', lines = True)
    xdr_alert_df.to_json('/app/xdr_alert.json', orient = 'records', lines = True)
    xdr_event_df.to_json('/app/xdr_event.json', orient = 'records', lines = True)
    del xdr_incident_df, xdr_alert_df, xdr_event_df
    gc.collect()

    return None

def core_pipeline(packet_path,event_path):

    # Loading Dictionaries and binary files and initializing threshold variables.
    fields_list_path = '/app/fields.csv'
    service_name_dict_path = '/app/app_linkage-to-service_name_dict.json'
    ml_model_path = '/app/ml.pkl'
    dl_model_path = '/app/dl.pkl'
    flow_data_path = 'temp_file.csv'

    # Reading packet data.
    pkt_dataframe, feature_list = packet_data_load(packet_path, fields_list_path) 
    
    # Analysing packet data with trained AI Models.
    ai_data = ai_analyzer(pkt_dataframe, ml_model_path, dl_model_path, feature_list)
    del pkt_dataframe
    gc.collect()

    # Merging analysed data with signature info.
    signature_data = signature_analyzer(event_path, ai_data)
    del ai_data
    gc.collect()
    
    # Cleaning the processed data.
    clean_data = data_cleaner(signature_data)
    del signature_data
    gc.collect()

    # Translating the clean data into traffic for logging.
    transformed_data = data_transform(service_name_dict_path, clean_data)

    # Writing the data into a log file.
    logger(transformed_data)
    del transformed_data
    gc.collect()
    subprocess.run(["bash","/app/mover.sh"])

    return None

def main():
    packet_to_process_file_location = sys.argv[1]
    event_to_process_file_location = sys.argv[2]
    print("[i] Starting Data Processing.")
    core_pipeline(packet_to_process_file_location, event_to_process_file_location)

if __name__ == "__main__":
    main()
