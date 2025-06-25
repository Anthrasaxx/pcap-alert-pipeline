#!/usr/bin/env python3
"""
PCAP Network Information Extractor
Extracts IP addresses, MAC addresses, hostnames, usernames, and other network information from PCAP files
"""

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.netbios import NBTSession
from scapy.layers.smb import *
from collections import defaultdict
import argparse
import json
import re
import os
import sys

class PCAPAnalyzer:
    def __init__(self):
        self.ip_addresses = set()
        self.mac_addresses = set()
        self.hostnames = set()
        self.usernames = set()
        self.dns_queries = set()
        self.http_hosts = set()
        self.dhcp_info = []
        self.smb_info = []
        self.netbios_names = set()
        self.email_addresses = set()
        self.protocols = defaultdict(int)
        self.conversations = defaultdict(int)
        
    def extract_basic_info(self, packet):
        """Extract basic IP and MAC information"""
        try:
            if packet.haslayer(Ether):
                self.mac_addresses.add(packet[Ether].src)
                self.mac_addresses.add(packet[Ether].dst)
        except Exception as e:
            pass
            
        try:
            if packet.haslayer(IP):
                self.ip_addresses.add(packet[IP].src)
                self.ip_addresses.add(packet[IP].dst)
                
                # Count protocol usage
                if packet.haslayer(TCP):
                    self.protocols['TCP'] += 1
                elif packet.haslayer(UDP):
                    self.protocols['UDP'] += 1
                elif packet.haslayer(ICMP):
                    self.protocols['ICMP'] += 1
                    
                # Track conversations
                conv = f"{packet[IP].src}:{packet[IP].dst}"
                self.conversations[conv] += 1
        except Exception as e:
            pass
    
    def extract_dns_info(self, packet):
        """Extract DNS queries and responses"""
        try:
            if packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qr == 0:  # Query
                    if dns.qd:
                        try:
                            hostname = dns.qd.qname.decode('utf-8').rstrip('.')
                            self.dns_queries.add(hostname)
                            self.hostnames.add(hostname)
                        except:
                            pass
                else:  # Response
                    if dns.an:
                        try:
                            for i in range(dns.ancount):
                                rr = dns.an[i]
                                if hasattr(rr, 'rrname'):
                                    hostname = rr.rrname.decode('utf-8').rstrip('.')
                                    self.hostnames.add(hostname)
                        except:
                            pass
        except Exception as e:
            pass
    
    def extract_dhcp_info(self, packet):
        """Extract DHCP information"""
        if packet.haslayer(DHCP):
            dhcp_info = {
                'client_mac': packet[Ether].src if packet.haslayer(Ether) else 'Unknown',
                'options': {}
            }
            
            try:
                for option in packet[DHCP].options:
                    try:
                        if isinstance(option, tuple) and len(option) >= 2:
                            key, value = option[0], option[1]
                            if key == 'hostname':
                                hostname = value.decode('utf-8') if isinstance(value, bytes) else str(value)
                                self.hostnames.add(hostname)
                                dhcp_info['hostname'] = hostname
                            elif key == 'vendor_class_id':
                                dhcp_info['vendor'] = value.decode('utf-8') if isinstance(value, bytes) else str(value)
                            elif key == 'requested_addr':
                                dhcp_info['requested_ip'] = str(value)
                            dhcp_info['options'][str(key)] = str(value)
                        elif isinstance(option, str):
                            # Handle string options (like 'end')
                            dhcp_info['options'][option] = True
                    except Exception as e:
                        # Skip malformed options
                        continue
            except Exception as e:
                # Skip entire DHCP processing if options are malformed
                pass
            
            try:
                if packet.haslayer(BOOTP):
                    bootp = packet[BOOTP]
                    if bootp.yiaddr != '0.0.0.0':
                        dhcp_info['assigned_ip'] = bootp.yiaddr
                        self.ip_addresses.add(bootp.yiaddr)
            except Exception as e:
                pass
                    
            if dhcp_info['options'] or 'hostname' in dhcp_info or 'assigned_ip' in dhcp_info:
                self.dhcp_info.append(dhcp_info)
    
    def extract_http_info(self, packet):
        """Extract HTTP information"""
        try:
            if packet.haslayer(HTTPRequest):
                http_req = packet[HTTPRequest]
                if hasattr(http_req, 'Host'):
                    host = http_req.Host.decode('utf-8')
                    self.http_hosts.add(host)
                    self.hostnames.add(host)
                
                # Look for usernames in HTTP headers or URLs
                if hasattr(http_req, 'Authorization'):
                    auth = http_req.Authorization.decode('utf-8')
                    # Basic auth extraction
                    if 'Basic' in auth:
                        try:
                            import base64
                            encoded = auth.split('Basic ')[1]
                            decoded = base64.b64decode(encoded).decode('utf-8')
                            if ':' in decoded:
                                username = decoded.split(':')[0]
                                self.usernames.add(username)
                        except:
                            pass
        except Exception as e:
            pass
        
        # Extract from raw HTTP data
        try:
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                if isinstance(payload, bytes):
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        
                        # Look for common authentication patterns
                        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                        emails = re.findall(email_pattern, payload_str)
                        self.email_addresses.update(emails)
                        
                        # Look for username patterns in forms
                        username_patterns = [
                            r'username=([^&\s]+)',
                            r'user=([^&\s]+)',
                            r'login=([^&\s]+)',
                            r'"username":\s*"([^"]+)"',
                            r'"user":\s*"([^"]+)"'
                        ]
                        
                        for pattern in username_patterns:
                            matches = re.findall(pattern, payload_str, re.IGNORECASE)
                            self.usernames.update(matches)
                    except:
                        pass
        except Exception as e:
            pass
    
    def extract_smb_info(self, packet):
        """Extract SMB/CIFS information"""
        if packet.haslayer(NBTSession):
            # NetBIOS names
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                if isinstance(payload, bytes):
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        # Look for NetBIOS names (simplified)
                        netbios_pattern = r'[A-Z0-9]{1,15}\x00'
                        matches = re.findall(netbios_pattern, payload_str)
                        for match in matches:
                            name = match.rstrip('\x00')
                            if len(name) > 0:
                                self.netbios_names.add(name)
                    except:
                        pass
    
    def extract_additional_info(self, packet):
        """Extract additional network information"""
        # ARP information
        try:
            if packet.haslayer(ARP):
                arp = packet[ARP]
                self.ip_addresses.add(arp.psrc)
                self.ip_addresses.add(arp.pdst)
                self.mac_addresses.add(arp.hwsrc)
                self.mac_addresses.add(arp.hwdst)
        except Exception as e:
            pass
    
    def analyze_pcap(self, pcap_file):
        """Main analysis function"""
        print(f"Analyzing PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            total_packets = len(packets)
            
            print(f"Processing {total_packets} packets...")
            
            for i, packet in enumerate(packets):
                if i % 1000 == 0:
                    print(f"Processed {i}/{total_packets} packets...")
                
                try:
                    self.extract_basic_info(packet)
                    self.extract_dns_info(packet)
                    self.extract_dhcp_info(packet)
                    self.extract_http_info(packet)
                    self.extract_smb_info(packet)
                    self.extract_additional_info(packet)
                except Exception as e:
                    # Skip problematic packets but continue processing
                    continue
                
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return False
            
        print(f"Finished processing {total_packets} packets")
        return True
    
    def generate_report(self, output_format='text'):
        """Generate analysis report"""
        if output_format == 'json':
            return self._generate_json_report()
        else:
            return self._generate_text_report()
    
    def _generate_text_report(self):
        """Generate text format report"""
        report = []
        report.append("=" * 80)
        report.append("PCAP NETWORK ANALYSIS REPORT")
        report.append("=" * 80)
        
        # IP Addresses
        report.append(f"\nIP ADDRESSES ({len(self.ip_addresses)}):")
        report.append("-" * 40)
        for ip in sorted(self.ip_addresses):
            report.append(f"  {ip}")
        
        # MAC Addresses
        report.append(f"\nMAC ADDRESSES ({len(self.mac_addresses)}):")
        report.append("-" * 40)
        for mac in sorted(self.mac_addresses):
            report.append(f"  {mac}")
        
        # Hostnames
        report.append(f"\nHOSTNAMES ({len(self.hostnames)}):")
        report.append("-" * 40)
        for hostname in sorted(self.hostnames):
            report.append(f"  {hostname}")
        
        # Usernames
        if self.usernames:
            report.append(f"\nUSERNAMES ({len(self.usernames)}):")
            report.append("-" * 40)
            for username in sorted(self.usernames):
                report.append(f"  {username}")
        
        # Email Addresses
        if self.email_addresses:
            report.append(f"\nEMAIL ADDRESSES ({len(self.email_addresses)}):")
            report.append("-" * 40)
            for email in sorted(self.email_addresses):
                report.append(f"  {email}")
        
        # DNS Queries
        if self.dns_queries:
            report.append(f"\nDNS QUERIES ({len(self.dns_queries)}):")
            report.append("-" * 40)
            for query in sorted(self.dns_queries):
                report.append(f"  {query}")
        
        # HTTP Hosts
        if self.http_hosts:
            report.append(f"\nHTTP HOSTS ({len(self.http_hosts)}):")
            report.append("-" * 40)
            for host in sorted(self.http_hosts):
                report.append(f"  {host}")
        
        # NetBIOS Names
        if self.netbios_names:
            report.append(f"\nNETBIOS NAMES ({len(self.netbios_names)}):")
            report.append("-" * 40)
            for name in sorted(self.netbios_names):
                report.append(f"  {name}")
        
        # DHCP Information
        if self.dhcp_info:
            report.append(f"\nDHCP INFORMATION ({len(self.dhcp_info)} entries):")
            report.append("-" * 40)
            for i, dhcp in enumerate(self.dhcp_info):
                report.append(f"  Entry {i+1}:")
                for key, value in dhcp.items():
                    if key != 'options':
                        report.append(f"    {key}: {value}")
        
        # Protocol Statistics
        report.append(f"\nPROTOCOL STATISTICS:")
        report.append("-" * 40)
        for protocol, count in sorted(self.protocols.items()):
            report.append(f"  {protocol}: {count} packets")
        
        # Top Conversations
        report.append(f"\nTOP CONVERSATIONS:")
        report.append("-" * 40)
        sorted_conversations = sorted(self.conversations.items(), key=lambda x: x[1], reverse=True)
        for conv, count in sorted_conversations[:10]:
            report.append(f"  {conv}: {count} packets")
        
        return "\n".join(report)
    
    def _generate_json_report(self):
        """Generate JSON format report"""
        return json.dumps({
            'ip_addresses': list(self.ip_addresses),
            'mac_addresses': list(self.mac_addresses),
            'hostnames': list(self.hostnames),
            'usernames': list(self.usernames),
            'email_addresses': list(self.email_addresses),
            'dns_queries': list(self.dns_queries),
            'http_hosts': list(self.http_hosts),
            'netbios_names': list(self.netbios_names),
            'dhcp_info': self.dhcp_info,
            'protocols': dict(self.protocols),
            'conversations': dict(self.conversations)
        }, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Extract network information from PCAP files')
    parser.add_argument('pcap_file', nargs='?', default='capture.pcap', help='Path to PCAP file (default: capture.pcap)')
    parser.add_argument('-o', '--output', help='Output file (default: report.json)', default='report.json')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='json',
                       help='Output format (default: json)')
    
    args = parser.parse_args()
    
    # Check if the PCAP file exists
    import os
    if not os.path.exists(args.pcap_file):
        print(f"❌ Error: PCAP file '{args.pcap_file}' not found.")
        if args.pcap_file == 'capture.pcap':
            print("💡 Tip: Place your PCAP file as 'capture.pcap' in the same directory, or specify the path:")
            print("   python pcap_analyzer.py /path/to/your/file.pcap")
        sys.exit(1)
    
    analyzer = PCAPAnalyzer()
    
    if analyzer.analyze_pcap(args.pcap_file):
        report = analyzer.generate_report(args.format)
        
        # Always save to file (default: report.json)
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to: {args.output}")
        
        # Also print to stdout if it's a text report
        if args.format == 'text':
            print("\n" + report)
    else:
        print("Failed to analyze PCAP file")

if __name__ == "__main__":
    main()
