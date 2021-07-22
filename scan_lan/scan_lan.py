import scapy.all as scapy
import requests
import socket
import yaml
import re


# vars
vars_file = "vars" # Path to the vars file
lan_subnet = "192.168.1.0/24" # Address and CIDR of the local network
with open(vars_file) as f: 
    vars = yaml.safe_load(f)
known_macs = vars["known_macs"]
bot_token = vars["bot_token"]
bot_chat_id = vars["bot_chat_id"]


def scan(ip):
    # Scan the local subnet using scapy
    scanned = scapy.arping(ip)
    i = 0
    devices = {}
    # Iterate over each scanned device and collect their data in a dictionary
    for device in scanned[0]:
        i += 1
        devices[i] = {"mac":device[1].src,"ip":device[1].psrc,"hostname":socket.getfqdn(device[1].psrc)}
    return devices

def analyse_macs(hosts):
    # Loop through the dictionary and compare found MAC addresses with the knows MACs
    for host in hosts.values():
        if host["mac"] in known_macs:
            print(str(host["mac"]) + " - OK")
        else:
            print(str(host["mac"]) + " - ERROR - unknown MAC")
            # Alert Telegram if a new device is detected
            telegram_bot_sendtext("\[WARNING] Unknown device detected\nMAC address: " +
                str(host["mac"]) + "\nHostname: " + str(host["hostname"]))

def telegram_bot_sendtext(bot_message):
    # Send Telegram message
    send_text = ('https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' +
        bot_chat_id + '&parse_mode=Markdown&text=' + bot_message)
    response = requests.get(send_text)

if __name__=="__main__":
    results = scan(lan_subnet)
    analyse_macs(results)
