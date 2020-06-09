from datetime import datetime
import os
import json
import stix2

"""
" Utils/stix_generator.py
" This file offers methods to parse various data we extracted with our tools
" to the standarised Stix2 format. As Stix2 is not suitable for all our data,
" we create a few custom objects.
"""


def generate_stix_observed_data(objects):
    """ Generates a stix observed data object
    - objects dict: The list of objects to put in observed data
    - return: sixt observed data
    """
    tsp = datetime.now()
    observed_data = stix2.ObservedData(first_observed=tsp,
                                     last_observed=tsp,
                                     number_observed=len(objects),
                                     objects=objects,
                                     allow_custom=True)
    return observed_data


def generate_stix_process_object(data, as_json=False):
    """ Generates a stix process object
    - data json: The process list json
    - return: sixt observed data
    """
    objects = {}
    pid_dict = {}
    for idx, d in enumerate(data):
        if d[0] != 'r':
            continue
        content = {"type": "process"}
        content['name'] = d[1]['binary']
        content['pid'] = d[1]['proc']['Cybox']['PID']
        content['created'] = d[1]['start_time']['string_value']
        pid_dict[d[1]['proc']['Cybox']['PID']] = str(idx)
        objects[str(idx)] = content
    # Add PPIDs
    for idx, d in enumerate(data):
        if d[0] != 'r' or type(d[1]['ppid']) == dict:
            continue
        if d[1]['ppid'] in pid_dict:
            objects[str(idx)]['parent_ref'] = pid_dict[d[1]['ppid']]

    observed_data = generate_stix_observed_data(objects)
    return json.loads(observed_data.serialize()) if as_json else observed_data


def generate_stix_custom_bash_object(data, as_json=False):
    """ Generates a custom stix bash history object
    - data json: The bash history json
    - return: sixt observed data
    """
    objects = {}
    objects[0] = {"type": "x_bash_history"}
    objects[0]['history'] = []
    for d in data:
        if d[0] != 'r':
            continue
        content = {'command': d[1]['command']}
        task = d[1]['task']
        if task:
            content['PID'] = task['Cybox']['PID']
        ts = d[1]['timestamp']
        if ts:
            content['timestamp'] = ts['string_value']
        objects[0]['history'].append(content)

    bash_object = generate_stix_observed_data(objects) 
    return json.loads(bash_object.serialize()) if as_json else bash_object


def generate_stix_netstat_object(data, as_json=False):
    """ Generates a stix netstat object
    - data json: The netstat json
    - return: sixt observed data
    """
    objects = {}
    ip_dict = {}
    idx = 0
    for d in data:
        if d[0] != 'r':
            continue
        if 'SAddr' not in d[1]:
            continue
        src_addr = d[1]['SAddr']
        src_port = d[1]['SPort']
        dst_addr = d[1]['DAddr']
        dst_port = d[1]['DPort']

        if src_addr not in ip_dict:
            if "::" in src_addr:
                objects[str(idx)] = {"type": "ipv6-addr", "value": src_addr}
            else:
                objects[str(idx)] = {"type": "ipv4-addr", "value": src_addr}
            ip_dict[src_addr] = str(idx)
            idx += 1

        if dst_addr not in ip_dict:
            if "::" in dst_addr:
                objects[str(idx)] = {"type": "ipv6-addr", "value": dst_addr}
            else:
                objects[str(idx)] = {"type": "ipv4-addr", "value": dst_addr}
            ip_dict[dst_addr] = str(idx)
            idx += 1

        network_content = {"type": "network-traffic"}
        network_content['src_ref'] = ip_dict[src_addr]
        network_content['dst_ref'] = ip_dict[dst_addr]
        network_content['protocols'] = [d[1]['Proto']['enum']]
        network_content['x_socket_state'] = d[1]['State']['enum']
        network_content['x_cmd'] = d[1]['Comm']
        if isinstance(src_port, int):
            network_content['src_port'] = src_port
        if isinstance(dst_port, int):
            network_content['dst_port'] = dst_port
        objects[str(idx)] = network_content
        idx += 1

    netstat_object = generate_stix_observed_data(objects) 
    return json.loads(netstat_object.serialize()) if as_json else netstat_object


def generate_stix_ifconfig_object(data, as_json=False):
    """ Generates a stix data object with network interfaces
    - data json: The interface list json
    - return: sixt observed data
    """
    objects = {}
    idx = 0
    for d in data:
        if d[0] != 'r':
            continue
        objects[str(idx)] = {"type": "ipv4-addr", "value": d[1]["ipv4"]}
        objects[str(idx+1)] = {"type": "mac-addr", "value": d[1]["MAC"]}
        objects[str(idx+2)] = {"type": "x_interface_config",
                               "name": d[1]["interface"],
                               "ip_ref": str(idx),
                               "mac_ref": str(idx+1)}
        idx += 2

    ifconfig_object = generate_stix_observed_data(objects)
    return json.loads(ifconfig_object.serialize()) if as_json else ifconfig_object


def generate_stix_custom_memmap_object(data, as_json=False):
    """ Generates a custom stix memmap object
    - data json: The memmap json
    - return: sixt observed data
    """
    objects = {}
    objects[0] = {"type": "x_memmap"}
    objects[0]['name'] = data[3][2]
    objects[0]['pid'] = data[3][3]
    objects[0]['memory'] = []
    for d in data:
        if d[0] != 'r':
            continue
        content = {'physical': hex(d[1]['Physical'])}
        content['virtual'] = hex(d[1]['Virtual'])
        content['size'] = d[1]['Size']
        objects[0]['memory'].append(content)

    memmap_object = generate_stix_observed_data(objects) 
    return json.loads(memmap_object.serialize()) if as_json else memmap_object


def generate_stix_directory_object(tdata, as_json=False):
    """ Generates stix directory and file objects combined as ObservedData
    - tdata tuple:
        - data json: The memmap json
        - path string: The path to the directory
    - return: sixt observed data
    """
    data, path = tdata
    objects = {}
    for d in data:
        if data[d]['type'] == "TSK_FS_NAME_TYPE_DIR":
            content = {"type": "directory"}
        elif data[d]['type'] == "TSK_FS_NAME_TYPE_REG":
            content = {"type": "file"}
            content["name"] = data[d]['name']
        content["path"] = os.path.join(path, data[d]['name'])
        content["inode"] = data[d]['inode']
        objects[d] = content

    directory_object = generate_stix_observed_data(objects) 
    return json.loads(directory_object.serialize()) if as_json else ifconfig_object


def generate_stix_cat_file_object(tdata, as_json=False):
    """ Generates a stix file object for a file that was cat
    - tdata tuple:
        - path string: The path to the file in the storage dump 
        - outpath string: The path where the files can be found on the pc
    - return: sixt observed data
    """
    path, outpath = tdata
    content = {"type": "file"}
    content["name"] = os.path.basename(path)
    content["path"] = path
    content["monitor machine"] = outpath 

    file_object = generate_stix_observed_data({"0":content})
    return json.loads(file_object.serialize()) if as_json else file_object


def generate_stix_custom_partition_object(data, as_json=False):
    """ Generates a custom stix partition object
    - data json: The partition list
    - return: sixt observed data
    """
    objects = {}
    idx = 0
    for part in data:
        content = {"type": "x_partition"}
        content["address"] = data[part]["addr"]
        content["description"] = data[part]["desc"]
        content["length"] = data[part]["len"]
        content["offset"] = data[part]["offset"]
        content["start"] = data[part]["start"]
        objects[str(idx)] = content
        idx += 1

    partition_object = generate_stix_observed_data(objects) 
    return json.loads(partition_object.serialize()) if as_json else partition_object


def generate_stix_custom_filesystem_object(data, as_json=False):
    """ Generates a custom stix filesystem object
    - data json: The filesystem data
    - return: sixt observed data
    """
    content = {"type": "x_filesystem"}
    content["fs_type"] = data["type"]

    filesystem_object = generate_stix_observed_data({"0":content}) 
    return json.loads(filesystem_object.serialize()) if as_json else filesystem_object
