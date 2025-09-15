# 🕵️‍♂️ GUI-Based Packet Sniffer with Radar Deploy

A user-friendly and powerful **GUI-based Network Packet Sniffer** developed in Python. This tool allows you to **capture live packets**, either by protocol or in **Radar Deploy mode**, which captures all traffic. Once capture ends, you can **search for specific packets** using IP address or protocol filters.

---

## 🚀 Features

- 📡 **Real-Time Packet Capturing**
- 🎛️ **Two Modes**
  - **Protocol-Specific Mode**: Filter traffic based on protocols like TCP, UDP, ICMP
  - **Radar Deploy Mode**: Capture all protocols simultaneously
- 🔎 **Post-Capture Filtering**
  - Search packets based on IP and Protocol
- 🖥️ **Graphical User Interface**
  - Built with [Tkinter](https://docs.python.org/3/library/tkinter.html) for a smooth, native experience
- 📄 **Detailed Packet Metadata**
  - View IP, ports, protocol, payload size, timestamps, etc.

---

## 🧰 Tech Stack

| Tool | Description |
|------|-------------|
| [Python](https://www.python.org/) | Core programming language |
| [Tkinter](https://docs.python.org/3/library/tkinter.html) | Built-in GUI library |
| [Scapy](https://scapy.readthedocs.io/en/latest/) | Packet crafting and sniffing |
| [Threading](https://docs.python.org/3/library/threading.html) | To handle real-time sniffing without freezing GUI |
| [Datetime](https://docs.python.org/3/library/datetime.html) | Timestamping |
| [OS](https://docs.python.org/3/library/os.html) | Platform-level interaction (e.g., permissions) |

---

## 📦 Installation

```bash
# 1. Clone the repository
git clone https://github.com/Khani-Kingsman/packet-sniffer-gui.git
cd packet-sniffer-gui

# 2. (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate       # On Windows use `venv\Scripts\activate`

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python Net-Snif.py

 ```

## 📁 Directory Structure

---

 ```
packet-sniffer-gui/
├── Net-Snif.py                                   # Entry point
├── gui/                                          # GUI-related components (Tkinter)
├── sniffer/                                      # Scapy-based packet capturing logic
├── utils/                                        # Filtering, formatting, helpers
├── requirements.txt
└── README.md

 ```
## 🧪 Usage Instructions

---
 ```
Step 1: Launch the GUI
python Net-Snif.py

Step 2: Choose the network interface and sniffing mode

Step 3: Start and stop packet capture

Step 4: Search packets by:
        - Source/Destination IP
        - Protocol Type

 ```
 
## Note: You may need administrator/root privileges to sniff packets.

## 🔒 Permissions

 ```
 
 On Linux/macOS, run with elevated permissions:
sudo python Net-Snif.py

  ```
## 🙌 Acknowledgments

 -	*Scapy for enabling packet-level access*

 -	*Tkinter for the simple and native GUI*

 -	*Python's open-source ecosystem*

## 📄 License

This project is licensed under the MIT License.
You are free to use, modify, and distribute this software with attribution.
