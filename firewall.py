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
    
    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        if (ord(pkt[0]) & 0x0f) < 5 or len(pkt) < 20:
            return

        result = self.get_verdict(pkt_dir, pkt)
        if result == 'pass':
            if pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            
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
            if len(proto_header) < 4: return 'drop'
            ext_ip = src_ip if pkt_dir == PKT_DIR_INCOMING else dst_ip
            type_field = ord(proto_header[0])

            return self.check_rules('icmp', ext_ip, type_field)

        # TCP
        if protocol == 6:
            if len(proto_header) < 20: return 'drop'
            ext_ip = src_ip if pkt_dir == PKT_DIR_INCOMING else dst_ip
            ext_port = struct.unpack('!H', proto_header[0:2])[0] if pkt_dir == PKT_DIR_INCOMING else struct.unpack('!H', proto_header[2:4])[0]

            return self.check_rules('tcp', ext_ip, ext_port)
       
        # UDP
        if protocol == 17:
            if len(proto_header) < 8: return 'drop'

            ext_ip = src_ip if pkt_dir == PKT_DIR_INCOMING else dst_ip
            ext_port = struct.unpack('!H', proto_header[0:2])[0] if pkt_dir == PKT_DIR_INCOMING else struct.unpack('!H', proto_header[2:4])[0]

            # DNS
            if ext_port == 53:
                
                return self.dns_situation(proto_header[8:], ext_ip)
    
            else:
                return self.check_rules("udp", ext_ip, ext_port)

        return 'pass'
    
    def dns_situation(self, header, ext_ip):
        if len(header) < 12: return 'drop'
        question_number = struct.unpack('!H', header[4:6])[0]
        question = header[12:]

        index = 0
        try:
            while ord(question[index]) != 0:
                index += ord(question[index]) + 1
        except IndexError:
            return 'drop'
        
        q_name_bytes = question[:index + 1]
        if len(question) < len(q_name_bytes) + 4: return 'drop'

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
            return 'drop'
        
        q_type = struct.unpack('!H', question[len(q_name_bytes) : len(q_name_bytes) + 2])[0]
        q_class = struct.unpack('!H', question[len(q_name_bytes) + 2 : len(q_name_bytes) + 4])[0]

        if (question_number == 1) and q_class == 1 and (q_type == 1 or q_type == 28):    
            return self.check_dns_rules(q_name)
        
        return self.check_rules('udp', ext_ip, 53)

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
