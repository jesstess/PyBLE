import sys
import bluetooth._bluetooth as bluez
import ble

def parse_events(sock, desired_event, loop_count=10):
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, flt)
    for i in range(loop_count):
        pkt = sock.recv(255)
        parsed_packet = ble.hci_le_parse_response_packet(pkt)
        if parsed_packet["bluetooth_event_id"] == desired_event:
            return parsed_packet
        if "bluetooth_le_subevent_id" in parsed_packet and \
                parsed_packet["bluetooth_le_subevent_id"] == desired_event:
            return parsed_packet

dev_id = 0
try:
    sock = bluez.hci_open_dev(dev_id)
except:
    print "Error accessing bluetooth device", dev_id
    sys.exit(1)

if len(sys.argv) < 2:
    print "Please provide a bluetooth device address."
    sys.exit(1)

ble.hci_le_connect(sock, sys.argv[1],
                     own_bdaddr_type=ble.constants.LE_RANDOM_ADDRESS)
result = parse_events(sock, ble.constants.EVT_LE_CONN_COMPLETE)
handle = result["handle"]

ble.hci_le_read_remote_used_features(sock, handle)
result = parse_events(
    sock, ble.constants.EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE)
ble.hci_disconnect(sock, handle)
# Ensure that we disconnected.
parse_events(sock, bluez.EVT_DISCONN_COMPLETE)

print "Features used for %s: %s" % (sys.argv[1], result["features"])
