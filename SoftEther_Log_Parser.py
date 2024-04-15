import re as regex
import csv

ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
cid_pattern = r'CID-\d{4}-[0-9A-Fa-f]{10}'
date_time_pattern = r'\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\b'
terminated_pattern = r'\b.*\b terminated\.'
connection_patern = r'\b.*\bbeen created\.'

log_file_path = "kens-vpn-001_server_log_vpn_20240325.log"
ip_list_path = "ip_list.csv"


#ip_list = "89.255.123.215, 78.65.56.25"

#string1 = 'this si s atre sifdg 89.255.123.215 and here is the CID "CID-1314-22C30A1575" word\nthis si s atre sifdg 78.65.56.25 and here is the CID "CID-1356-56B30T1575" word'
#string2 = "No Ip address 12 245457854217"
#string3 = 'CID stufi "CID-1314-22C30A1575" word'

#cid_matches = regex.findall(cid_pattern, string3)
#ip_matches = regex.findall(ip_pattern, string1)

#print("IP Matches:", ip_matches)
#print("CID Matches:", cid_matches)


def open_ip_list(list_path):
    with open(list_path, 'r') as file:
        csv_read = csv.reader(file)
        list_of_ips = list(csv_read)
        file.close()
    return list_of_ips

def open_log_file(log_path):
    with open(log_path) as log_file:
        file_lines = log_file.read().splitlines()
        log_file.close()
    return file_lines



def gather_connections_from_list(log_file, ip_list):
    conn_list = []
    for ip in ip_list:
        for line in log_file:
            ip_match = regex.findall(ip_pattern, line)
            if(ip_match == ip):
                connection_match = regex.findall(connection_patern, line)
                if(connection_match):
                    cid_match = regex.findall(cid_pattern, line)
                    if(cid_match):
                        date_time_match = regex.findall(date_time_pattern, line)                    
                        conn = Connection(ip_match, cid_match, date_time_match)
                        conn_list.append(conn)
    return conn_list

def gather_terminated_sessions(log_file, conn_list):
    for line in log_file:
        terminated_session_match = regex.findall(terminated_pattern, line)
        if(terminated_session_match):
            cid_match = regex.findall(cid_pattern, line)
            #for conn in conn_list:
            #    if(conn.cid == cid_match):
            date_time_match = regex.findall(date_time_pattern, line)
            set_terminated_connection(cid_match, conn_list, date_time_match)
            


def gather_all_connections():
    conn_list = []
    for line in log_file:
        ip_match = regex.findall(ip_pattern, line)
        if(ip_match):
            date_time_match = regex.findall(date_time_pattern, line)
            cid_match = regex.findall(cid_pattern, line)
            conn = Connection(ip_match, cid_match, date_time_match)
            conn_list.append(conn)
    return conn_list


def set_terminated_connection(cid, conn_list, disconnected_date_time):
    for conn in conn_list:
        if(conn.CID == cid):
            conn.Result = "Terminated"
            conn.Disconnected_Date_Time = disconnected_date_time
            return
    return



class Connection:
    def __init__(self, IP, CID, Connected_Date_Time):
        self.IP = IP
        self.CID = CID
        self.Connected_Date_Time = Connected_Date_Time
        self.Result = None
        self.Disconnected_Date_Time = None

    
    def Print(self):
        if(self.Result == "Terminated"):
            print(self.CID, " | ", self.IP, " attempted connection at ", self.Connected_Date_Time, " terminated at ", self.Disconnected_Date_Time)

        elif(self.Result == "Connected"):
            return

    def Save(self):
        save_string = str(self.CID) + " | " + str(self.IP) + " attempted connection at " + str(self.Connected_Date_Time) + " terminated at " + str(self.Disconnected_Date_Time) + "\n"
        return save_string




ip_list = open_ip_list(ip_list_path)
log_file = open_log_file(log_file_path)

list_of_connections = gather_all_connections()

gather_terminated_sessions(log_file, list_of_connections)

for conn in list_of_connections:
    conn.Print()
    print(conn.Save())


with open("connections.txt", "w") as file:
    for conn in list_of_connections:
        file.write(conn.Save())
    file.close()

