#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

import struct
import socket

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.rules = self.get_rules(config['rule'])
        self.geo_ips = self.get_geo_ips('geoipdb.txt')
        self.http_requests = dict()

    
    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        if (ord(pkt[0]) & 0x0f) < 5 or len(pkt) < 20:
            return

        result, protocol = self.get_verdict(pkt_dir, pkt)
        if result == 'pass':
            self.send(pkt_dir, pkt)
        elif result == 'deny':
            if protocol == 'tcp':
                self.send(self.reverse_direction(pkt_dir), self.get_deny_tcp_pkt(pkt))
            elif protocol == 'dns':
                res_pkt, should_pass = self.get_deny_dns_pkt(pkt)
                if should_pass:
                    self.send(self.reverse_direction(pkt_dir), res_pkt)
            
    def send(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)

    def reverse_direction(self, pkt_dir):
        return PKT_DIR_OUTGOING if pkt_dir == PKT_DIR_INCOMING else PKT_DIR_INCOMING

    def get_deny_tcp_pkt(self, pkt):
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]

        start = pkt[0:2] + struct.pack('!H', 40) + struct.pack('!L', 0) + struct.pack('!B', 128) + struct.pack('!B', 6) + struct.pack('!H', 0)
        ip_checksum = self.checksum(start + dst_ip + src_ip, False)
        result_pkt = start[0:10] + struct.pack("!H", ip_checksum) + dst_ip + src_ip

        tcp_header = pkt[4 * (ord(pkt[0]) & 0x0f):]
        src_port = tcp_header[0:2]
        dst_port = tcp_header[2:4]
        seq_num = self.increase_by_one(tcp_header[4:8])
        ack_num = self.increase_by_one(tcp_header[8:12])
        flags_and_window = struct.pack('!L', 1343488000)
        urgent = tcp_header[18:20]
        tcp_checksum = self.checksum(dst_ip + src_ip + dst_port + src_port + ack_num + seq_num + flags_and_window + struct.pack('!L', 0) + urgent, True)

        result_pkt += dst_port + src_port + ack_num + seq_num + flags_and_window + struct.pack("!H", tcp_checksum) + urgent
        return result_pkt

    def increase_by_one(self, a):
        return struct.pack('!L', (struct.unpack('!L', a)[0] + 1))

    def get_deny_dns_pkt(self, pkt):      
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]

        udp_header = pkt[4 * (ord(pkt[0]) & 0x0f):]
        src_port = udp_header[0:2]
        dst_port = udp_header[2:4]

        udp_index = 8  
        dns_id = udp_header[udp_index : udp_index + 2]
        flags = struct.pack('!H', 2**15)
        qdcount = struct.pack('!H', 1)
        ancount = struct.pack('!H', 1)
        nsqount = struct.pack('!H', 0)
        arcount = struct.pack('!H', 0)

        udp_index += 12
        while ord(pkt[udp_index + 20]): 
            udp_index += 1

        qname = udp_header[4 * (ord(pkt[0]) & 0x0f) : udp_index + 1]

        udp_index += 1
        qtype = udp_header[udp_index : udp_index + 2]
        q_type = struct.unpack('!H', qtype)[0]

        udp_index += 2
        if q_type == 28: return ('', False)
        qclass = struct.pack('!H', 1)

        udp_length = 2 * len(qname + qtype + qclass) + 30
        udp_index = udp_length
        length = udp_length + 20

        start = pkt[0:2] + struct.pack('!H', length) + struct.pack('!L', 0) + struct.pack('!B', 128) + struct.pack('!B', 17) + struct.pack('!H', 0)
        ip_checksum = self.checksum(start + dst_ip + src_ip, False)
        result_pkt = start[0:10] + struct.pack("!H", ip_checksum) + dst_ip + src_ip

        udp_start = dst_port + src_port + struct.pack('!H', udp_length) + struct.pack('!H', 0)
        udp_start += dns_id + flags + qdcount + ancount + nsqount + arcount
        udp_start += qname + qtype + qclass
        udp_start += qname + qtype + qclass + struct.pack('!L', 1) + struct.pack('!H', 4) + socket.inet_aton('169.229.49.130')

        udp_checksum = self.checksum(dst_ip + src_ip + struct.pack('!B', 0) + struct.pack('!B', 17) + struct.pack('!H', udp_length) + udp_start, False)
        result_pkt += dst_port + src_port + struct.pack('!H', udp_length) + struct.pack('!H', udp_checksum) + udp_start[8:]

        return (result_pkt, True)
         
    
    def checksum(self, data, is_tcp):
        result = 26 if is_tcp else 0
        
        for ind in range(0, len(data), 2):
            result += struct.unpack('!H', data[ind : ind + 2])[0]
            
        if len(data) % 2 == 1:
            result += struct.unpack('!B', data[len(data) - 1])

        while result >> 16:
            result = (result & (2**16 - 1)) + (result >> 16)

        return (~result) & (2**16 - 1)


    def get_rules(self, file):
        rules = []

        f = open(file, 'r')
        all_lines = f.readlines()

        for line in all_lines:
            line = line.lower()
            if not (line.startswith('%') or line.isspace()):
                rules.append(line.split())

        f.close()
        return rules
        

    def get_geo_ips(self, file):
        result = []

        f = open(file, 'r')
        all_lines = f.readlines()

        for line in all_lines:
            line = line.lower()
            if not (line.startswith('%') or line.isspace()):
                result.append(line.split())

        f.close()
        return result
    
    def country_by_ip(self, arr, ip):
        l = 0
        r = len(arr) - 1

        while l <= r:
            middle = (l + r) / 2
            curr = arr[middle]

            if self.ip_larger_than(curr[0], ip):
                r = middle - 1
            elif self.ip_larger_than(ip, curr[1]):
                l = middle + 1
            else:
                return curr[2]
        
        return 'NOT_IN_ANY_RANGE'

    def ip_larger_than(self, first, second):
        firstArr = first.split('.')
        secondArr = second.split('.')
        result = []

        for i in range(0, 4):
            result.append(self.compare_helper(int(firstArr[i]), int(secondArr[i])))

        for i in range(0, 4):
            if result[i] == 1:
                return True
            if result[i] == -1:
                return False

        return False   
        
    def compare_helper(self, first, second):
        if first > second:
            return 1
        elif first == second:
            return 0
        else:
            return -1

    def get_verdict(self, pkt_dir, pkt):
        protocol = struct.unpack('!B', pkt[9:10])[0]
        src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
        proto_header = pkt[4 * (ord(pkt[0]) & 0x0f):]

        # ICMP
        if protocol == 1:
            if len(proto_header) < 4: return ('drop', 'icmp')
            ext_ip = src_ip if pkt_dir == PKT_DIR_INCOMING else dst_ip
            type_field = ord(proto_header[0])

            return (self.check_rules('icmp', ext_ip, type_field), 'icmp')

        # TCP
        if protocol == 6:
            if len(proto_header) < 20: return ('drop', 'tcp')
            ext_ip = src_ip if pkt_dir == PKT_DIR_INCOMING else dst_ip
            ext_port = struct.unpack('!H', proto_header[0:2])[0] if pkt_dir == PKT_DIR_INCOMING else struct.unpack('!H', proto_header[2:4])[0]

            if ext_port == 80:
                self.log_time(ext_ip, ext_port, proto_header[20:], pkt_dir)
            return (self.check_rules('tcp', ext_ip, ext_port), 'tcp')
       
        # UDP
        if protocol == 17:
            if len(proto_header) < 8: return ('drop', 'udp')

            ext_ip = src_ip if pkt_dir == PKT_DIR_INCOMING else dst_ip
            ext_port = struct.unpack('!H', proto_header[0:2])[0] if pkt_dir == PKT_DIR_INCOMING else struct.unpack('!H', proto_header[2:4])[0]

            # DNS
            if ext_port == 53:
                
                return self.dns_situation(proto_header[8:], ext_ip)
    
            else:
                return (self.check_rules("udp", ext_ip, ext_port), 'udp')

        return ('pass', 'other')
    
    def dns_situation(self, header, ext_ip):
        if len(header) < 12: return ('drop', 'dns')
        question_number = struct.unpack('!H', header[4:6])[0]
        question = header[12:]

        index = 0
        try:
            while ord(question[index]) != 0:
                index += ord(question[index]) + 1
        except IndexError:
            return ('drop', 'dns')
        
        q_name_bytes = question[:index + 1]
        if len(question) < len(q_name_bytes) + 4: return ('drop', 'dns')

        q_name = ''
        index = 0
        try:
            while ord(question[index]) != 0:
                for ind in range(1, ord(question[index]) + 1):
                    q_name += chr(ord(question[index + ind]))
                index += ord(question[index]) + 1
                if ord(question[index]) != 0:
                    q_name += '.'
        except IndexError:
            return ('drop', 'dns')
        
        q_type = struct.unpack('!H', question[len(q_name_bytes) : len(q_name_bytes) + 2])[0]
        q_class = struct.unpack('!H', question[len(q_name_bytes) + 2 : len(q_name_bytes) + 4])[0]

        if (question_number == 1) and q_class == 1 and (q_type == 1 or q_type == 28):    
            return (self.check_dns_rules(q_name), 'dns')
        
        return (self.check_rules('udp', ext_ip, 53), 'udp')

    def check_dns_rules(self, domain):
        for rule in self.rules:
            if rule[1] == 'dns':
                dns_result = self.check_dns_rule(rule[2], domain)
                if dns_result: return rule[0]
                
        return 'pass'

    def check_dns_rule(self, dns_rule, domain):
        if dns_rule == domain:
            return True
        elif dns_rule.startswith('*'):
            return len(dns_rule) == 1 or domain.endswith(dns_rule[1:])

        return False

    def check_rules(self, protocol_name, ext_ip, ext_port):
        
        for rule in self.rules:
            if protocol_name == rule[1]:
                ip_result = self.check_ip(rule[2], ext_ip)
                port_result = self.check_port(rule[3], ext_port)

                if ip_result and port_result:
                    return rule[0]

        return 'pass'

    def check_ip(self, ip_rule, ext_ip):
        if ip_rule == 'any' or ip_rule == ext_ip:
            return True
        elif len(ip_rule) == 2:
            return ip_rule == self.country_by_ip(self.geo_ips, ext_ip)
        else:
            if not '/' in ip_rule:
                return False
            
            ip_rule, prefix = ip_rule.split("/")
            prefix = int(prefix)
            if prefix == 0: return True
            return self.is_in_subnet(ip_rule, self.get_sub_mask_int(prefix), ext_ip)

   

    def is_in_subnet(self, addr, mask_int, ip):
        addr_int = struct.unpack("!I", socket.inet_aton(addr))[0]
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]

        host_min = addr_int & mask_int
        if host_min < 0: host_min += 2**32
        host_max = host_min | ~mask_int
        if host_max < 0: host_max += 2**32

        return ip_int > host_min and ip_int < host_max

    def get_sub_mask_int(self, prefix):
        mask_int = 0
        for i in range(0, prefix):
            mask_int += 2**(31 - i)
        
        return mask_int


    def check_port(self, port_rule, ext_port):
        if port_rule == 'any' or port_rule == str(ext_port):
            return True

        if '-' not in port_rule:
            return False

        arr = port_rule.split('-')  
        return ext_port >= int(arr[0]) and ext_port <= int(arr[1])

    
    def log_time(self, ext_ip, ext_port, data, pkt_dir):
        if pkt_dir == PKT_DIR_OUTGOING:
            self.http_requests[(ext_ip, ext_port)] = data
            return
        
        if not (ext_ip, ext_port) in self.http_requests:
            return

        request = self.http_requests[(ext_ip, ext_port)]
        arr = request.split('\r\n')
        methodArr = arr[0].split(' ')
        method = methodArr[0]

        if method not in ['GET', 'POST', 'PUT', 'DROP']:
            return

        path = methodArr[1]
        version = methodArr[2]
        
        
        host_name = ''

        for header in arr:
            if header.find('Host:') != -1:
                host_name = header[header.find('Host:') + 6:]
                host_name = host_name.split(':')[0]

        if not self.check_log_rules(host_name):
            return

        responce = data

        if not (len(responce) > 15 and responce[:4] == 'HTTP'):
            return 
        
        responceArr = responce.split('\r\n')
        responce_method_arr = responceArr[0].split(' ')
        status_code = responce_method_arr[1]
        object_size = '-1'

        for header in responceArr:
            if header.find('Content-Length:') != -1:
                object_size = header[header.find('Content-Length:') + 16:]
                object_size = object_size.split(':')[0]

        self.writeIntoLog(host_name, method, path, version, status_code, object_size)
        del self.http_requests[(ext_ip, ext_port)]


    def check_log_rules(self, domain):
        for rule in self.rules:
            if rule[1] == 'http':
                dns_result = self.check_log_rule(rule[2], domain)
                if dns_result: 
                    return True
                
        return False

    def check_log_rule(self, dns_rule, domain):
        if dns_rule == domain:
            return True
        elif dns_rule.startswith('*'):
            return len(dns_rule) == 1 or domain.endswith(dns_rule[1:])

        return False

    def writeIntoLog(self, host_name, method, path, version, status_code, object_size):
        f = open('http.log', 'a')
        currInfo = host_name + ' '
        currInfo += method + ' '
        currInfo += path + ' '
        currInfo += version + ' '
        currInfo += status_code + ' '
        currInfo += object_size + '\r\n'

        f.write(currInfo)
        f.flush()
        f.close()