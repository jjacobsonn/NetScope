#!/usr/bin/env python3
"""
NetScope - Network Device Discovery and Bandwidth Monitor
Author: Jackson Jacobson (please credit me if you use this code!)
"""

from scapy.all import ARP, Ether, srp
import netifaces
import sys
import psutil
import time
import subprocess
import socket
from collections import defaultdict
from mac_vendor_lookup import MacLookup
from tqdm import tqdm

# Device manufacturer identification
gaming_manufacturers = {
    'Microsoft': ['xbox', 'xbx'],
    'Sony': ['playstation', 'ps3', 'ps4', 'ps5'],
    'Nintendo': ['nintendo', 'switch']
}

device_manufacturers = {
    'Apple': ['macbook', 'iphone', 'ipad', 'ipod', 'mac'],
    'Google': ['pixel', 'chrome', 'nest'],
    'Amazon': ['alexa', 'echo', 'kindle', 'fire'],
    'Samsung': ['galaxy', 'samsung'],
    'Roku': ['roku'],
    'Sonos': ['sonos'],
    'Ring': ['ring']
}

# MAC address prefixes for accurate device identification
GAMING_MAC_PREFIXES = {
    # Xbox
    '7C:ED:8D': 'Xbox',
    'E4:95:6E': 'Xbox One',
    '00:1D:D8': 'Xbox 360',
    '00:22:48': 'Xbox 360',
    
    # PlayStation
    '00:04:1F': 'PlayStation',
    '00:13:15': 'PlayStation',
    '00:15:C1': 'PlayStation',
    '00:19:C5': 'PlayStation',
    '00:1D:0D': 'PlayStation',
    '00:1F:A7': 'PlayStation',
    '00:D9:D1': 'PlayStation',
    '28:0D:FC': 'PlayStation',
    '00:50:F2': 'PlayStation 3',
    '00:D9:D1': 'PlayStation 4',
    'C8:3F:26': 'PlayStation 5',
    
    # Nintendo
    '00:09:BF': 'Nintendo',
    '00:17:AB': 'Nintendo',
    '00:1C:BE': 'Nintendo',
    '00:1F:32': 'Nintendo',
    '00:21:47': 'Nintendo',
    '00:22:AA': 'Nintendo',
    '00:24:F3': 'Nintendo',
    '40:F4:07': 'Nintendo',
    '58:BD:A3': 'Nintendo',
    '78:A2:A0': 'Nintendo',
    '7C:BB:8A': 'Nintendo',
    '98:B6:E9': 'Nintendo'
}

def get_local_ip_and_interface():
    try:
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface.startswith(('en', 'wlan', 'eth', 'wi')):  # Common network interface prefixes
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr'], addrs[netifaces.AF_INET][0]['netmask'], iface
    except Exception as e:
        print(f"Error finding local IP/interface: {e}")
        sys.exit(1)
    return None, None, None

def scan_network(ip_range, iface):
    try:
        print(f"Starting network scan on interface {iface} for range {ip_range}")
        print("This will take approximately 20-30 seconds for a thorough scan...")
        devices = []
        
        # Phase 1: Use arp-scan for comprehensive device discovery
        print("\nPhase 1/2: Running arp-scan (faster and more thorough)...")
        try:
            # Run arp-scan with retry and timing options
            cmd = ['sudo', 'arp-scan', '--interface', iface, '--localnet', '--retry=3', 
                  '--timeout=1000', '--backoff=2']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse arp-scan output
            for line in result.stdout.split('\n'):
                # Looking for lines with MAC addresses (xx:xx:xx:xx:xx:xx format)
                if ':' in line and line[0].isdigit():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip, mac = parts[0], parts[1]
                        if ip not in [d['ip'] for d in devices]:
                            device = get_device_info(ip, mac)
                            devices.append(device)
                            print(f"Found device: {ip} ({mac}) - {device['manufacturer']}")
        except Exception as e:
            print(f"Error running arp-scan: {e}")
            
        # If arp-scan found few devices, try nmap as backup
        if len(devices) < 2:
            print("\nPhase 2/2: Running nmap scan (15-20 seconds)...")
            try:
                # Run nmap scan with aggressive timing and host discovery options
                cmd = ['nmap', '-sn', '--min-rate=1000', '--max-retries=2', 
                      '--host-timeout=30s', ip_range]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                # Parse nmap output for IP addresses
                import re
                ip_pattern = re.compile(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)')
                mac_pattern = re.compile(r'MAC Address: ([0-9A-F:]{17})', re.IGNORECASE)
                
                ips = ip_pattern.findall(result.stdout)
                macs = mac_pattern.findall(result.stdout)
                
                # Add devices found by nmap
                for i, ip in enumerate(ips):
                    if ip not in [d['ip'] for d in devices]:
                        mac = macs[i] if i < len(macs) else "Unknown"
                        device = {'ip': ip, 'mac': mac}
                        devices.append(device)
                        print(f"Found device: {ip} ({mac})")
            except Exception as e:
                print(f"Error running nmap scan: {e}")
        
        # Remove duplicate devices by IP
        devices = list({device['ip']: device for device in devices}.values())
        
        if not devices:
            print("\nWarning: No devices responded to scan. This is unusual.")
            print("Try running the script with sudo privileges.")
            print(f"Debug info - Interface: {iface}, IP Range: {ip_range}")
        else:
            print(f"\nFound {len(devices)} devices on the network.")
        
        return devices
    except Exception as e:
        print(f"Error scanning network: {e}")
        print("Make sure you're running with sudo privileges")
        print(f"Debug info - Interface: {iface}, IP Range: {ip_range}")
        return []

def monitor_network_usage(devices, duration=120):
    """Monitor network traffic for discovered devices using connection tracking."""
    print(f"\nMonitoring network traffic for {duration} seconds...")
    print("(Higher accuracy monitoring - tracking individual connections)")
    
    # Initialize progress bar
    pbar = tqdm(total=duration, desc="Monitoring", unit="sec")
    
    # Initialize device stats
    device_stats = defaultdict(lambda: {'bytes_sent': 0, 'bytes_recv': 0})
    
    try:
        time_start = time.time()
        
        while time.time() - time_start < duration:
            # Get all network connections
            connections = psutil.net_connections(kind='all')
            
            # Update connection stats for each device
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    remote_ip = conn.raddr[0] if conn.raddr else None
                    for device in devices:
                        if device['ip'] == remote_ip:
                            try:
                                # Get process stats for this connection
                                process = psutil.Process(conn.pid)
                                io_stats = process.io_counters()
                                device_stats[remote_ip]['bytes_sent'] += io_stats.write_bytes
                                device_stats[remote_ip]['bytes_recv'] += io_stats.read_bytes
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
            
            # Update progress bar
            current_time = time.time()
            pbar.n = int(current_time - time_start)
            pbar.refresh()
            
            time.sleep(1)
        
        pbar.close()
        return device_stats
        
    except Exception as e:
        print(f"Error monitoring network usage: {e}")
        return defaultdict(lambda: {'bytes_sent': 0, 'bytes_recv': 0})

def get_device_type(manufacturer, hostname, mac):
    """Identify device type based on manufacturer, hostname, and MAC address."""
    
    # Check for gaming consoles by MAC prefix
    mac_prefix = mac[:8].upper()  # Get first three octets
    
    # Gaming console MAC prefixes
    gaming_prefixes = {
        '7C:ED:8D': 'Microsoft Xbox',
        'E4:95:6E': 'Microsoft Xbox',
        '0C:DD:24': 'Microsoft Xbox',
        '70:2E:0D': 'Microsoft Xbox',
        '00:50:F2': 'Microsoft Xbox',
        '58:BD:A3': 'Nintendo Switch',
        'C0:B8:83': 'Nintendo Switch',
        '00:1D:BC': 'Nintendo Wii',
        '7C:BB:8A': 'Nintendo Switch',
        '00:13:A8': 'Sony PlayStation',
        '00:15:C1': 'Sony PlayStation',
        '00:19:C5': 'Sony PlayStation',
        '00:1F:A7': 'Sony PlayStation',
        '00:D9:D1': 'Sony PlayStation',
        'A8:E3:EE': 'Sony PlayStation'
    }
    
    # Common device manufacturers and their typical identifiers
    device_types = {
        'eero': 'Mesh Router',
        'Intel Corporate': 'Computer',
        'Apple': 'Apple Device',
        'Amazon Technologies': 'Amazon Device',
        'Google': 'Google Device',
        'Samsung Electronics': 'Samsung Device',
        'Roku': 'Streaming Device',
        'NVIDIA': 'NVIDIA Device',
        'Ubiquiti': 'Network Device',
        'Nest': 'Smart Home Device',
        'Ring': 'Security Camera',
        'Sonos': 'Speaker',
        'TP-Link': 'Network Device',
        'NETGEAR': 'Network Device'
    }
    
    # Check for gaming consoles first
    for brand, keywords in gaming_manufacturers.items():
        if brand.lower() in manufacturer.lower():
            return "Gaming Console"
        if hostname != "Unknown":
            if any(keyword.lower() in hostname.lower() for keyword in keywords):
                return "Gaming Console"
    
    # Check other device types
    for brand, types in device_manufacturers.items():
        if brand.lower() in manufacturer.lower():
            return types[0]
    
    return "Unknown Device"

def get_hostname(ip):
    """Try multiple methods to get device hostname."""
    try:
        # Try reverse DNS lookup first
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except (socket.herror, socket.gaierror):
        pass
    
    try:
        # Try NetBIOS name lookup
        import nmb.NetBIOS
        nb = nmb.NetBIOS.NetBIOS()
        names = nb.queryIPForName(ip, timeout=1)
        if names and names[0]:
            return names[0]
    except Exception:
        pass
    
    return None

def get_device_info(ip, mac):
    """Get comprehensive device information with improved accuracy."""
    info = {
        'ip': ip,
        'mac': mac,
        'manufacturer': 'Unknown',
        'hostname': None,
        'type': 'Unknown'
    }
    
    # Get hostname
    hostname = get_hostname(ip)
    if hostname:
        info['hostname'] = hostname.lower()
    
    try:
        # Get manufacturer from MAC lookup
        mac_lookup = MacLookup()
        info['manufacturer'] = mac_lookup.lookup(mac)
        
        # Get device type based on MAC prefix
        mac_prefix = mac.upper()[:8]
        if mac_prefix in GAMING_MAC_PREFIXES:
            info['type'] = GAMING_MAC_PREFIXES[mac_prefix]
            return info
        
        # Check manufacturer and hostname against known gaming devices
        manufacturer_lower = info['manufacturer'].lower()
        hostname_lower = info['hostname'].lower() if info['hostname'] else ''
        
        # Check gaming manufacturers
        for brand, keywords in gaming_manufacturers.items():
            if any(keyword in manufacturer_lower for keyword in keywords) or \
               any(keyword in hostname_lower for keyword in keywords):
                info['type'] = f'{brand} Gaming Console'
                return info
        
        # Check other device manufacturers
        for brand, types in device_manufacturers.items():
            if any(keyword in manufacturer_lower for keyword in types) or \
               any(keyword in hostname_lower for keyword in types):
                info['type'] = brand
                return info
        
        # If we got this far but have a manufacturer, call it an IoT device
        if info['manufacturer'] != 'Unknown':
            info['type'] = 'IoT Device'
            
    except Exception as e:
        print(f"Error getting device info: {e}")
    
    return info

def format_bytes(bytes):
    """Format bytes with adaptive units (B, KB, MB, GB)."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} TB"

def get_traffic_color(bytes_per_sec):
    """Get color code based on traffic intensity."""
    if bytes_per_sec > 1024 * 1024:  # >1MB/s
        return '\033[91m'  # Red
    elif bytes_per_sec > 1024 * 100:  # >100KB/s
        return '\033[93m'  # Yellow
    else:
        return '\033[92m'  # Green

def print_device_stats(devices, device_stats, duration):
    """Print formatted device statistics with colors."""
    print("\nNetwork Usage Report:")
    print("=" * 80)
    print(f"{'IP Address':<15} {'Device Type':<15} {'Manufacturer':<20} {'Traffic Rate':<15} {'Total Traffic':<15}")
    print("-" * 80)
    
    # Sort devices by total traffic
    sorted_devices = sorted(devices, 
                          key=lambda d: (device_stats[d['ip']]['bytes_sent'] + 
                                       device_stats[d['ip']]['bytes_recv']),
                          reverse=True)
    
    for device in sorted_devices:
        ip = device['ip']
        stats = device_stats[ip]
        total_bytes = stats['bytes_sent'] + stats['bytes_recv']
        bytes_per_sec = total_bytes / duration
        
        color = get_traffic_color(bytes_per_sec)
        reset = '\033[0m'
        
        print(f"{ip:<15} "
              f"{device['type']:<15} "
              f"{device['manufacturer'][:19]:<20} "
              f"{color}{format_bytes(bytes_per_sec)}/s{reset:<15} "
              f"{format_bytes(total_bytes):<15}")
    
    print("=" * 80)

# Main
ip, netmask, iface = get_local_ip_and_interface()
if ip and netmask and iface:
    # Extract the network portion of the IP address
    ip_parts = ip.split('.')
    network_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"  # Use network address instead of host IP
    print(f"Scanning network: {network_ip} on interface: {iface}")
    devices = scan_network(network_ip, iface)
    if devices:
        for i, device in enumerate(devices, 1):
            print(f"Device {i}: IP: {device['ip']}, MAC: {device['mac']}")
        
        # Monitor network usage
        device_stats = monitor_network_usage(devices)
        
        # Display results
        print("\nNetwork Usage Statistics:")
        print("-" * 50)
        
        # Sort devices by total traffic
        device_traffic = []
        for device in devices:
            ip = device['ip']
            stats = device_stats[ip]
            sent_mb = stats['bytes_sent'] / (1024 * 1024)
            recv_mb = stats['bytes_recv'] / (1024 * 1024)
            total_mb = sent_mb + recv_mb
            device_traffic.append((device, total_mb, sent_mb, recv_mb))
        
        # Sort by total traffic in descending order
        device_traffic.sort(key=lambda x: x[1], reverse=True)
        
        # Display sorted results
        for device, total_mb, sent_mb, recv_mb in device_traffic:
            device_type = device.get('device_type', 'Unknown Device')
            hostname = device['hostname'] if device['hostname'] != 'Unknown' else device['ip']
            
            print(f"\nDevice: {hostname}")
            print(f"Type: {device_type}")
            print(f"IP: {device['ip']}")
            print(f"MAC: {device['mac']} ({device['manufacturer']})")
            print(f"Data Sent: {sent_mb:.2f} MB")
            print(f"Data Received: {recv_mb:.2f} MB")
            print(f"Total Traffic: {total_mb:.2f} MB")
        
        # Print detailed device stats with colors
        print_device_stats(devices, device_stats, duration=120)
    else:
        print("No devices found. Check network connection or permissions.")
else:
    print("Could not determine local IP or interface. Ensure you're connected to WiFi.")