import constants
import utils
import bluetooth._bluetooth as bluez
import struct


### HCI commands. ###

def hci_le_read_local_supported_features(sock):
    cmd_pkt = ""
    bluez.hci_send_cmd(sock, constants.OGF_LE_CTL,
                       constants.OCF_LE_READ_LOCAL_SUPPORTED_FEATURES,
                       cmd_pkt)

def hci_le_read_remote_used_features(sock, handle):
    cmd_pkt = struct.pack("<H", handle)
    bluez.hci_send_cmd(sock, constants.OGF_LE_CTL,
                       constants.OCF_LE_READ_REMOTE_USED_FEATURES, cmd_pkt)

# BLE and Bluetooth use the same disconnect command.
def hci_disconnect(sock, handle, reason=constants.HCI_OE_USER_ENDED_CONNECTION):
    cmd_pkt = struct.pack("<HB", handle, reason)
    bluez.hci_send_cmd(sock, bluez.OGF_LINK_CTL, bluez.OCF_DISCONNECT, cmd_pkt)

def hci_le_connect(sock, peer_bdaddr, interval=0x0004, window=0x004,
                   initiator_filter=constants.LE_FILTER_ALLOW_ALL,
                   peer_bdaddr_type=constants.LE_RANDOM_ADDRESS,
                   own_bdaddr_type=constants.LE_PUBLIC_ADDRESS,
                   min_interval=0x000F, max_interval=0x000F,
                   latency=0x0000, supervision_timeout=0x0C80,
                   min_ce_length=0x0001, max_ce_length=0x0001):
    package_bdaddr = utils.get_packed_bdaddr(peer_bdaddr)
    cmd_pkt = struct.pack("<HHBB", interval, window, initiator_filter,
                          peer_bdaddr_type)
    cmd_pkt += package_bdaddr
    cmd_pkt += struct.pack("<BHHHHHH", own_bdaddr_type, min_interval,
                           max_interval, latency, supervision_timeout,
                           min_ce_length, max_ce_length)
    bluez.hci_send_cmd(sock, constants.OGF_LE_CTL, constants.OCF_LE_CREATE_CONN,
                       cmd_pkt)

def hci_le_enable_scan(sock):
    _hci_le_toggle_scan(sock, 0x01)

def hci_le_disable_scan(sock):
    _hci_le_toggle_scan(sock, 0x00)

def _hci_le_toggle_scan(sock, enable):
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, constants.OGF_LE_CTL,
                       constants.OCF_LE_SET_SCAN_ENABLE, cmd_pkt)

def hci_le_set_scan_parameters(sock, scan_type=constants.LE_SCAN_ACTIVE,
                               interval=0x10, window=0x10,
                               own_bdaddr_type=constants.LE_RANDOM_ADDRESS,
                               filter_type=constants.LE_FILTER_ALLOW_ALL):
    # TODO: replace B with appropriate size and remove 0 padding.
    cmd_pkt = struct.pack("<BBBBBBB", scan_type, 0x0, interval, 0x0, window,
                          own_bdaddr_type, filter_type)
    bluez.hci_send_cmd(sock, constants.OGF_LE_CTL,
                       constants.OCF_LE_SET_SCAN_PARAMETERS, cmd_pkt)



### HCI Response parsing ###

def hci_le_parse_response_packet(pkt):
    """
    Parse a BLE packet.

    Returns a dictionary which contains the event id, length and packet type,
    and possibly additional key/value pairs that represent the parsed content of
    the packet.
    """
    result = {}
    ptype, event, plen = struct.unpack("<BBB", pkt[:3])
    result["packet_type"] = ptype
    result["bluetooth_event_id"] = event
    result["packet_length"] = plen
    # We give the user the full packet back as the packet is small, and the user
    # may have additional parsing they want to do.
    result["packet"] = utils.packet_as_hex_string(pkt)

    # We only care about events that relate to BLE.
    if event == bluez.EVT_NUM_COMP_PKTS:
        result["bluetooth_event_name"] = "EVT_NUM_COMP_PKTS"
        result.update(_handle_num_completed_packets(pkt[3:]))
    elif event == bluez.EVT_DISCONN_COMPLETE:
        result["bluetooth_event_name"] = "EVT_DISCONN_COMPLETE"
        result.update(_handle_disconn_complete(pkt[3:]))
    elif event == constants.EVT_LE_META_EVENT:
        result["bluetooth_event_name"] = "EVT_LE_META_EVENT"
        result.update(_handle_le_meta_event(pkt[3:]))
    elif event == bluez.EVT_CMD_STATUS:
        result["bluetooth_event_name"] = "EVT_CMD_STATUS"
        result.update(_handle_command_status(pkt[3:]))
    elif event == bluez.EVT_CMD_COMPLETE:
        result["bluetooth_event_name"] = "EVT_CMD_COMPLETE"
        result.update(_handle_command_complete(pkt[3:]))
    elif event == bluez.EVT_INQUIRY_COMPLETE:
        raise NotImplementedError("EVT_CMD_COMPLETE")
    else:
        result["bluetooth_event_name"] = "UNKNOWN"
    return result

def _handle_command_complete(pkt):
    result = {}
    ncmd, opcode = struct.unpack("<BH", pkt[:3])
    (ogf, ocf) = utils.ogf_and_ocf_from_opcode(opcode)
    result["number_of_commands"] = ncmd
    result["opcode"] = opcode
    result["opcode_group_field"] = ogf
    result["opcode_command_field"] = ocf
    result["command_return_values"] = ""
    if len(pkt) > 3:
        result["command_return_values"] = pkt[3:]
    # Since we only care about BLE commands, we ignore the command return values
    # here. A full-powered bluetooth parsing module would check the OCF above
    # and parse the return values based on that OCF. We return the return values
    # to the user should the used want to parse the return values.
    return result

def _handle_command_status(pkt):
    result = {}
    status, ncmd, opcode = struct.unpack("<BBH", pkt)
    (ogf, ocf) = utils.ogf_and_ocf_from_opcode(opcode)
    result["status"] = status
    result["number_of_commands"] = ncmd
    result["opcode"] = opcode
    result["opcode_group_field"] = ogf
    result["opcode_command_field"] = ocf
    return result

def _handle_le_meta_event(pkt):
    result = {}
    subevent, = struct.unpack("B", pkt[0])
    result["bluetooth_le_subevent_id"] = subevent
    pkt = pkt[1:]
    if subevent == constants.EVT_LE_CONN_COMPLETE:
        result["bluetooth_le_subevent_name"] = "EVT_LE_CONN_COMPLETE"
        result.update(_handle_le_connection_complete(pkt))
    elif subevent == constants.EVT_LE_CONN_UPDATE_COMPLETE:
        result["bluetooth_le_subevent_name"] = "EVT_LE_CONN_UPDATE_COMPLETE"
        raise NotImplementedError("EVT_LE_CONN_UPDATE_COMPLETE")
    elif subevent == constants.EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE:
        result["bluetooth_le_subevent_name"] = "EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE"
        result.update(_handle_le_read_remote_used_features(pkt))
    elif subevent ==constants.EVT_LE_ADVERTISING_REPORT:
        result["bluetooth_le_subevent_name"] = "EVT_LE_ADVERTISING_REPORT"
        result.update(_handle_le_advertising_report(pkt))
    else:
        result["bluetooth_le_subevent_name"] = "UNKNOWN"
    return result

def _handle_le_advertising_report(pkt):
    result = {}
    num_reports = struct.unpack("<B", pkt[0])[0]
    report_pkt_offset = 0
    result["number_of_advertising_reports"] = num_reports
    result["advertising_reports"] = []
    for i in range(0, num_reports):
        report = {}
        report_event_type = struct.unpack("<B", pkt[report_pkt_offset + 1])[0]
        report["report_type_id"] = report_event_type
        bdaddr_type = struct.unpack("<B", pkt[report_pkt_offset + 2])[0]
        report["peer_bluetooth_address_type"] = bdaddr_type
        device_addr = utils.packed_bdaddr_to_string(
            pkt[report_pkt_offset + 3:report_pkt_offset + 9])
        report["peer_bluetooth_address"] = device_addr
        report_data_length, = struct.unpack("<B", pkt[report_pkt_offset + 9])
        report["report_metadata_length"] = report_data_length
        if report_event_type == constants.LE_ADV_IND:
            report["report_type_string"] = "LE_ADV_IND"
        elif report_event_type == constants.LE_ADV_DIRECT_IND:
            report["report_type_string"] = "LE_ADV_DIRECT_IND"
        elif report_event_type == constants.LE_ADV_SCAN_IND:
            report["report_type_string"] = "LE_ADV_SCAN_IND"
        elif report_event_type == constants.LE_ADV_NONCONN_IND:
            report["report_type_string"] = "LE_ADV_NONCONN_IND"
        elif report_event_type == constants.LE_ADV_SCAN_RSP:
            report["report_type_string"] = "LE_ADV_SCAN_RSP"
            local_name_len, = struct.unpack("<B", pkt[report_pkt_offset + 11])
            name = pkt[report_pkt_offset + 12:report_pkt_offset + 12 + (local_name_len - 1)]
            report["peer_name"] = name
        else:
            report["report_type_string"] = "UNKNOWN"
        # Each report length is (2 (event type, bdaddr type) + 6 (the address)
        #    + 1 (data length field) + data length + 1 (rssi)) bytes long.
        report_pkt_offset = report_pkt_offset +  10 + report_data_length + 1
        rssi, = struct.unpack("<b", pkt[report_pkt_offset - 1])
        report["rssi"] = rssi
        result["advertising_reports"].append(report)
    return result

def _handle_le_read_remote_used_features(pkt):
    result = {}
    result["features"] = []
    status, handle = struct.unpack("<BH", pkt[:3])
    result["status"] = status
    result["handle"] = status
    for i in range(8):
        result["features"].append(struct.unpack("<B", pkt[3 + i])[0])
    return result

def _handle_disconn_complete(pkt):
    status, handle, reason = struct.unpack("<BHB", pkt)
    return {"status": status, "handle": handle, "reason": reason}

def _handle_num_completed_packets(pkt):
    result = {}
    num_connection_handles = struct.unpack("<B", pkt[0])[0]
    pkt = pkt[1:]
    result["num_connection_handles"] = num_connection_handles
    result["handles"] = []
    for i in range(num_connection_handles):
        handle, = struct.unpack("<H", pkt[0:2])
        completed_packets, = struct.unpack("<H", pkt[2:4])
        result["handles"].append({"handle": handle,
                                  "num_completed_packets": completed_packets})
        pkt = pkt[4:]
    return result

def _handle_le_connection_complete(pkt):
    result = {}
    status, handle, role, peer_bdaddr_type = struct.unpack("<BHBB", pkt[0:5])
    device_address = utils.packed_bdaddr_to_string(pkt[5:11])
    interval, latency, supervision_timeout, master_clock_accuracy = \
        struct.unpack("<HHHB", pkt[11:])
    result["status"] = status
    result["handle"] = handle
    result["role"] = role
    result["peer_bluetooth_address_type"] = peer_bdaddr_type
    result["peer_device_address"] = device_address
    result["interval"] = interval
    result["latency"] = latency
    result["supervision_timeout"] = supervision_timeout
    result["master_clock_accuracy"] = master_clock_accuracy
    return result
