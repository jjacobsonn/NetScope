# NetScope

<p align="center">
  <img src="assets/images/icon.png" alt="NetScope Logo" width="200">
</p>

Ever wondered which devices are hogging your network bandwidth? NetScope is here to help! It's a simple yet powerful tool that shows you exactly what's happening on your network - from finding hidden devices to tracking who's using the most data.

## What can it do?

**Finds All Your Devices**
- Discovers every device on your network, even the sneaky ones
- Uses smart scanning techniques to ensure nothing gets missed
- Falls back to alternative methods if the first scan doesn't work

**Shows You the Data**
- Tracks how much data each device is sending and receiving
- Updates in real-time so you can spot bandwidth hogs
- Gives you clear, easy-to-read statistics for each device

## Getting Started

### What you'll need
- Python 3.x (if you're on a Mac, you probably already have this!)
- A few Python packages that do the heavy lifting:
  ```
  scapy         # For network scanning
  netifaces     # For finding network interfaces
  psutil        # For monitoring network traffic
  ```
- Some helper tools:
  - `arp-scan` (super helpful for finding devices)
  - `nmap` (optional, but nice to have as a backup)

### Quick Setup

1. First, let's install the helper tools (on macOS):
```bash
brew install arp-scan
brew install nmap  # Optional, but recommended
```

2. Then, grab the Python packages:
```bash
pip3 install scapy netifaces psutil
```

## Using NetScope

Ready to spy on your network? Here's how:

1. Open your terminal
2. Navigate to where you saved NetScope
3. Run it with:
```bash
sudo python3 script.py
```

(Yes, it needs sudo - we're doing some low-level network stuff here! 🔒)

### What happens next?

1. NetScope will scan your network (takes about 30 seconds)
2. It'll show you all the devices it finds
3. Then it starts monitoring network traffic (another 30 seconds)
4. Finally, you get a nice report showing who's using what

### Behind the Scenes

**Finding Devices**
- First tries the quick and reliable `arp-scan`
- If that misses anything, falls back to other methods
- Uses multiple scanning techniques to make sure nothing hides

**Tracking Traffic**
- Watches your network in real-time
- Checks which devices are active every 5 seconds
- Smartly distributes bandwidth usage between active devices
- Shows you easy-to-read statistics

## Good to Know

**Pro Tips**
- Works best on networks you own or manage
- Some devices might play hide-and-seek (looking at you, firewalls!)
- Traffic stats are best-effort estimates
- Modern devices might use privacy features that make them harder to track

**Current Limitations**
- Can't track individual packets (that would be crazy complex!)
- Some devices might not show up if they:
  - Are sleeping 😴
  - Have strict firewalls 🛡️
  - Use privacy features 🕵️
  - Are just being stubborn 😤

**What's Next?**
We've got some cool features planned:
- Friendly device names instead of just IP addresses
- Identifying device manufacturers
- Long-term monitoring
- Pretty graphs and charts
- Device categorization
- History tracking

Want to help make NetScope even better? Contributions are welcome! 🎉
