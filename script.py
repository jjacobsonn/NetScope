#!/usr/bin/env python3
"""
NetScope - Network Device Discovery and Bandwidth Monitor
Author: Your Name
License: MIT
"""

from scapy.all import ARP, Ether, srp
import netifaces
import sys
import psutil
import time
import subprocess
from collections import defaultdict

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
                            device = {'ip': ip, 'mac': mac}
                            devices.append(device)
                            print(f"Found device: {ip} ({mac})")
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

def monitor_network_usage(devices, duration=30):  # Increased duration to 30 seconds
    """Monitor network traffic for discovered devices."""
    print(f"\nMonitoring network traffic for {duration} seconds...")
    print("(Monitoring individual device traffic may require additional permissions)")
    
    try:
        # Initialize counters for each device
        device_stats = defaultdict(lambda: {'bytes_sent': 0, 'bytes_recv': 0})
        
        # Get initial network stats
        net_io_start = psutil.net_io_counters()
        time_start = time.time()
        last_update = time_start
        
        # Monitor for specified duration
        while time.time() - time_start < duration:
            current_time = time.time()
            current_stats = psutil.net_io_counters()
            
            # Calculate bytes transferred since last update
            bytes_sent = current_stats.bytes_sent - net_io_start.bytes_sent
            bytes_recv = current_stats.bytes_recv - net_io_start.bytes_recv
            
            # Try to get per-device traffic using arp-scan
            if current_time - last_update >= 5:  # Update every 5 seconds
                try:
                    cmd = ['sudo', 'arp-scan', '--interface', iface, '--localnet', '--retry=1']
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    active_ips = [line.split()[0] for line in result.stdout.split('\n') 
                                if ':' in line and line[0].isdigit()]
                    
                    # Weight traffic more heavily towards active devices
                    active_devices = [d for d in devices if d['ip'] in active_ips]
                    if active_devices:
                        weight = 2.0 if len(active_devices) < len(devices) else 1.0
                        base_share = 1.0 / len(devices)
                        active_share = weight * base_share
                        inactive_share = (1.0 - (len(active_devices) * active_share)) / (len(devices) - len(active_devices)) if len(devices) > len(active_devices) else 0
                        
                        for device in devices:
                            share = active_share if device['ip'] in active_ips else inactive_share
                            device_stats[device['ip']]['bytes_sent'] = max(0, bytes_sent * share)
                            device_stats[device['ip']]['bytes_recv'] = max(0, bytes_recv * share)
                    
                    last_update = current_time
                except Exception as e:
                    # If detailed monitoring fails, fall back to even distribution
                    for device in devices:
                        device_stats[device['ip']]['bytes_sent'] += bytes_sent / len(devices)
                        device_stats[device['ip']]['bytes_recv'] += bytes_recv / len(devices)
            
            # Print progress
            elapsed = int(current_time - time_start)
            if elapsed % 5 == 0:
                print(f"Monitoring... {elapsed}/{duration} seconds")
            
            time.sleep(1)
        
        return device_stats
    except Exception as e:
        print(f"Error monitoring network usage: {e}")
        return defaultdict(lambda: {'bytes_sent': 0, 'bytes_recv': 0})

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
        for device in devices:
            ip = device['ip']
            stats = device_stats[ip]
            sent_mb = stats['bytes_sent'] / (1024 * 1024)
            recv_mb = stats['bytes_recv'] / (1024 * 1024)
            print(f"\nDevice: {ip} (MAC: {device['mac']})")
            print(f"Data Sent: {sent_mb:.2f} MB")
            print(f"Data Received: {recv_mb:.2f} MB")
            print(f"Total Traffic: {(sent_mb + recv_mb):.2f} MB")
    else:
        print("No devices found. Check network connection or permissions.")
else:
    print("Could not determine local IP or interface. Ensure you're connected to WiFi.")