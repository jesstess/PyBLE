import sys
import bluetooth._bluetooth as bluez
import ble

def parse_events(sock, loop_count=100):
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, flt)
    for i in range(loop_count):
        pkt = sock.recv(255)
        parsed_packet = ble.hci_le_parse_response_packet(pkt)
        if "bluetooth_le_subevent_name" in parsed_packet and \
                parsed_packet["bluetooth_le_subevent_name"] == 'EVT_LE_ADVERTISING_REPORT':
            for report in parsed_packet["advertising_reports"]:
                print "Found BLE device:", report['peer_bluetooth_address']
                for k, v in report.items():
                    print "\t%s: %s" % (k, v)

dev_id = 0
try:
    sock = bluez.hci_open_dev(dev_id)
except:
    print "Error accessing bluetooth device", dev_id
    sys.exit(1)

ble.hci_le_set_scan_parameters(sock)
ble.hci_le_enable_scan(sock)
parse_events(sock, 30)
ble.hci_le_disable_scan(sock)
