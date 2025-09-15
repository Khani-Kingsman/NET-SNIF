import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import *
from scapy.arch.windows import get_windows_if_list
import threading
import os
from datetime import datetime


# Disable Scapy logging to prevent verbose output in the console
# log_level = logging.ERROR
# logging.getLogger("scapy.runtime").setLevel(log_level)

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("1000x800")  # Increased size for better layout
        self.root.minsize(800, 600)  # Minimum size

        # Variables
        self.sniffing = False
        self.selected_interface = tk.StringVar()
        self.selected_protocol_filter = tk.StringVar(value="All")  # Default to "All"
        self.packet_counter = 0
        # Stores captured packets: {treeview_item_id: {'packet_no': int, 'summary': tuple, 'details': string}}
        self.captured_packets_data = {}

        # GUI Setup
        self.setup_ui()

    def on_packet_select(self, event):
        selected_items = self.packet_tree.selection()
        if selected_items:
            item_id = selected_items[0]
            # Retrieve detailed info using the stored item_id
            packet_info_dict = self.captured_packets_data.get(item_id)
            if packet_info_dict:
                detailed_info = packet_info_dict['details']
            else:
                detailed_info = "No details available for this packet."

            self.packet_detail_display.config(state=tk.NORMAL)
            self.packet_detail_display.delete(1.0, tk.END)
            self.packet_detail_display.insert(tk.END, detailed_info)
            self.packet_detail_display.config(state=tk.DISABLED)

    def update_packet_display(self, packet_summary, detailed_packet_info, original_packet_no):
        """
        Updates the Treeview with a new packet summary and stores its detailed info.
        :param packet_summary: A tuple containing (time, src, dst, protocol, length, info)
        :param detailed_packet_info: A string containing the formatted detailed packet info
        :param original_packet_no: The original sequential number of the packet
        """
        # Insert into Treeview, using original_packet_no for the first column (text)
        item_id = self.packet_tree.insert("", tk.END, text=str(original_packet_no), values=packet_summary)

        # Store detailed info linked to the item_id, including the original packet number and summary
        self.captured_packets_data[item_id] = {
            'packet_no': original_packet_no,
            'summary': packet_summary,
            'details': detailed_packet_info
        }
        self.packet_tree.see(item_id)  # Scroll to the new item

    def _format_packet_details(self, packet):
        """Formats the full packet details in a Wireshark-like structured way."""
        detail_output = []  # Ensure detail_output is initialized here

        try:
            detail_output.append(
                f"--- Packet {self.packet_counter} ({datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}) ---")
            detail_output.append(f"Packet Length: {len(packet)} bytes\n")

            # Layer 2: Ethernet
            if packet.haslayer(Ether):
                ether = packet[Ether]
                ether_type_name = "Unknown"
                if ether.type == 0x800:
                    ether_type_name = "IPv4"
                elif ether.type == 0x806:
                    ether_type_name = "ARP"
                elif ether.type == 0x86DD:
                    ether_type_name = "IPv6"

                detail_output.append("[ Ethernet II ]")
                detail_output.append(f"    Source MAC: {ether.src}")
                detail_output.append(f"    Destination MAC: {ether.dst}")
                detail_output.append(f"    Type: {hex(ether.type)} ({ether_type_name})\n")

            # Layer 3: IP or ARP
            if packet.haslayer(IP):
                ip = packet[IP]
                ip_protocol_name = "Unknown"
                if ip.proto == 1:
                    ip_protocol_name = "ICMP"
                elif ip.proto == 6:
                    ip_protocol_name = "TCP"
                elif ip.proto == 17:
                    ip_protocol_name = "UDP"

                detail_output.append("[ Internet Protocol Version 4 ]")
                detail_output.append(f"    Version: {ip.version}")
                detail_output.append(f"    Header Length: {ip.ihl * 4} bytes")
                detail_output.append(f"    Total Length: {ip.len} bytes")
                detail_output.append(f"    Identification: {ip.id}")
                detail_output.append(f"    Flags: {ip.flags} (DF:{bool(ip.flags & 0x2)}, MF:{bool(ip.flags & 0x4)})")
                detail_output.append(f"    Fragment Offset: {ip.frag}")
                detail_output.append(f"    Time to Live (TTL): {ip.ttl}")
                detail_output.append(f"    Protocol: {ip.proto} ({ip_protocol_name})")
                detail_output.append(f"    Checksum: {hex(ip.chksum)}")
                detail_output.append(f"    Source IP: {ip.src}")
                detail_output.append(f"    Destination IP: {ip.dst}\n")
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                detail_output.append("[ Address Resolution Protocol ]")
                detail_output.append(f"    Hardware type: {arp.hwtype} (Ethernet)")
                detail_output.append(f"    Protocol type: {hex(arp.ptype)} (IPv4)")
                detail_output.append(f"    Hardware size: {arp.hwlen}")
                detail_output.append(f"    Protocol size: {arp.plen}")
                detail_output.append(f"    Opcode: {arp.op} ({'Request' if arp.op == 1 else 'Reply'})")
                detail_output.append(f"    Sender MAC: {arp.hwsrc}")
                detail_output.append(f"    Sender IP: {arp.psrc}")
                detail_output.append(f"    Target MAC: {arp.hwdst}")
                detail_output.append(f"    Target IP: {arp.pdst}\n")

            # Layer 4: TCP, UDP, ICMP
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                detail_output.append("[ Transmission Control Protocol ]")
                detail_output.append(f"    Source Port: {tcp.sport}")
                detail_output.append(f"    Destination Port: {tcp.dport}")
                detail_output.append(f"    Sequence Number: {tcp.seq}")
                detail_output.append(f"    Acknowledgement Number: {tcp.ack}")
                detail_output.append(f"    Data Offset: {tcp.dataofs * 4} bytes")
                detail_output.append(f"    Flags: {tcp.flags}")
                flags_str_list = []  # Use a local variable to avoid NameError if TCP layer not present
                if tcp.flags & 0x01: flags_str_list.append("FIN")
                if tcp.flags & 0x02: flags_str_list.append("SYN")
                if tcp.flags & 0x04: flags_str_list.append("RST")
                if tcp.flags & 0x08: flags_str_list.append("PSH")
                if tcp.flags & 0x10: flags_str_list.append("ACK")
                if tcp.flags & 0x20: flags_str_list.append("URG")
                detail_output.append(f"        [{', '.join(flags_str_list)}]")
                detail_output.append(f"    Window Size: {tcp.window}")
                detail_output.append(f"    Checksum: {hex(tcp.chksum)}")
                detail_output.append(f"    Urgent Pointer: {tcp.urgptr}\n")

                # HTTP over TCP
                if (tcp.dport == 80 or tcp.sport == 80) and packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/")):
                            detail_output.append("[ Hypertext Transfer Protocol ]")
                            detail_output.append("--- HTTP Payload (First 500 chars) ---")
                            detail_output.append(payload[:500] + ("..." if len(payload) > 500 else "") + "\n")
                    except:
                        pass  # Not UTF-8 or not HTTP

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                detail_output.append("[ User Datagram Protocol ]")
                detail_output.append(f"    Source Port: {udp.sport}")
                detail_output.append(f"    Destination Port: {udp.dport}")
                detail_output.append(f"    Length: {udp.len} bytes")
                detail_output.append(f"    Checksum: {hex(udp.chksum)}\n")

                # DNS over UDP
                if (udp.dport == 53 or udp.sport == 53) and packet.haslayer(DNS):
                    dns = packet[DNS]
                    detail_output.append("[ Domain Name System ]")
                    detail_output.append(f"    Transaction ID: {hex(dns.id)}")
                    detail_output.append(f"    Flags: {hex(dns.flags)}")
                    if dns.qr == 0:
                        detail_output.append("        Type: Query")
                    else:
                        detail_output.append("        Type: Response")

                    # Simplified DNS Type/Class Name Mapping
                    dns_type_map = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
                    dns_class_map = {1: "IN"}

                    if dns.qd:  # Query section
                        detail_output.append("\n    Queries:")
                        for qd in dns.qd:
                            qname = qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                            qtype_name = dns_type_map.get(qd.qtype, 'Unknown')
                            qclass_name = dns_class_map.get(qd.qclass, 'Unknown')
                            detail_output.append(f"        Name: {qname}")
                            detail_output.append(f"        Type: {qtype_name} ({qd.qtype})")
                            detail_output.append(f"        Class: {qclass_name} ({qd.qclass})")

                    if dns.an:  # Answer section
                        detail_output.append("\n    Answers:")
                        for an in dns.an:
                            aname = an.rrname.decode('utf-8', errors='ignore').rstrip('.')
                            atype_name = dns_type_map.get(an.type, 'Unknown')
                            aclass_name = dns_class_map.get(an.rclass, 'Unknown')
                            rdata_val = an.rdata
                            if isinstance(rdata_val, bytes):
                                try:
                                    rdata_val = rdata_val.decode('utf-8', errors='ignore')
                                except:
                                    pass
                            detail_output.append(f"        Name: {aname}")
                            detail_output.append(f"        Type: {atype_name} ({an.type})")
                            detail_output.append(f"        Class: {aclass_name} ({an.rclass})")
                            detail_output.append(f"        TTL: {an.ttl} seconds")
                            detail_output.append(f"        Data: {rdata_val}")
                    detail_output.append("")  # Empty line for spacing

            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                icmp_type_map = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
                icmp_code_map = {
                    (3, 0): "Network Unreachable", (3, 1): "Host Unreachable",
                    (3, 2): "Protocol Unreachable", (3, 3): "Port Unreachable"
                }  # Common codes

                icmp_type_name = icmp_type_map.get(icmp.type, 'Unknown')
                icmp_code_name = icmp_code_map.get((icmp.type, icmp.code), 'Unknown')

                detail_output.append("[ Internet Control Message Protocol ]")
                detail_output.append(f"    Type: {icmp.type} ({icmp_type_name})")
                detail_output.append(f"    Code: {icmp.code} ({icmp_code_name})")
                detail_output.append(f"    Checksum: {hex(icmp.chksum)}\n")

            # Raw data (Payload)
            if packet.haslayer(Raw) and not (
                    packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80)):
                raw_data = packet[Raw].load
                detail_output.append("[ Raw Data ]")
                try:
                    # Attempt to decode as UTF-8, replace non-decodable characters
                    decoded_payload = raw_data.decode('utf-8', errors='replace')
                    detail_output.append("--- Decoded Payload (First 200 chars) ---")
                    detail_output.append(decoded_payload[:200] + ("..." if len(decoded_payload) > 200 else ""))
                except:
                    detail_output.append(f"--- Binary Data ({len(raw_data)} bytes) ---")
                    # Display hex dump of first few bytes
                    hex_dump = ' '.join([f'{b:02x}' for b in raw_data[:50]])
                    detail_output.append(f"Hex: {hex_dump}...")
                detail_output.append("\n")

            # Add a representation of the entire packet (Scapy's summary)
            detail_output.append("--- Scapy Summary ---")
            detail_output.append(packet.summary() + "\n")

            return "\n".join(detail_output)

        except Exception as e:
            # Fallback if any error occurs during detailed formatting
            return f"--- Error formatting packet details: {e}\nFull packet summary: {packet.summary()}\nRaw packet: {bytes(packet).hex()}"

    def setup_ui(self):
        # --- Top Frame for Controls (Interface, Protocol, Buttons) ---
        top_controls_frame = ttk.Frame(self.root, padding="10 10 0 0")
        top_controls_frame.pack(fill=tk.X, padx=10, pady=5)

        # Interface Selection
        frame_interface = ttk.LabelFrame(top_controls_frame, text="Network Interface", padding=10)
        frame_interface.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

        # Get interfaces - works for both Windows and Linux/Mac
        if os.name == 'nt':
            interfaces = []
            for iface in get_windows_if_list():
                # Handle both old and new Scapy versions for description and name/guid
                name = iface.get('name', '') or iface.get('guid', '')
                desc = iface.get('description', '') or iface.get('name', '')
                # Ensure we have a valid name to use for sniffing
                if name:
                    interfaces.append(f"{desc} ({name})")
        else:
            try:
                # get_if_list() provides interface names directly for non-Windows
                interfaces = get_if_list()
            except Scapy_Exception as e:
                messagebox.showerror("Scapy Error", f"Could not list interfaces: {e}\n"
                                                    "Please ensure Npcap/WinPcap (Windows) or libpcap (Linux/Mac) is installed correctly.")
                interfaces = ["No interfaces found! (Error)"]

        if not interfaces:
            interfaces = ["No interfaces found!"]

        ttk.Label(frame_interface, text="Select Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_dropdown = ttk.Combobox(frame_interface, textvariable=self.selected_interface, values=interfaces,
                                               state="readonly")
        self.interface_dropdown.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        if interfaces:
            self.interface_dropdown.set(interfaces[0])

        # Protocol Selection
        frame_protocols = ttk.LabelFrame(top_controls_frame, text="Radar Packet detection",
                                         padding=10)  # Changed label here
        frame_protocols.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

        protocol_options = ["Radar Deploy", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "SSH", "FTP", "TELNET"]
        ttk.Label(frame_protocols, text="Filter Protocol:").pack(side=tk.LEFT, padx=5)
        self.protocol_dropdown = ttk.Combobox(frame_protocols, textvariable=self.selected_protocol_filter,
                                              values=protocol_options, state="readonly")
        self.protocol_dropdown.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.protocol_dropdown.set("Radar Deploy")  # Default selection

        # Buttons
        frame_buttons = ttk.Frame(top_controls_frame, padding=10)
        frame_buttons.pack(side=tk.LEFT, padx=5, pady=5)

        self.btn_start = ttk.Button(frame_buttons, text="Start Sniffing", command=self.start_sniffing,
                                    style="Accent.TButton")
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(frame_buttons, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_clear = ttk.Button(frame_buttons, text="Clear Packets", command=self.clear_packets)
        self.btn_clear.pack(side=tk.LEFT, padx=5)

        # --- Search Functionality ---
        frame_search = ttk.LabelFrame(self.root, text="Search Packets", padding=10)
        frame_search.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(frame_search, text="Search (IP/Protocol):").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(frame_search, width=40)
        self.search_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        self.btn_search = ttk.Button(frame_search, text="Search", command=self.perform_search)
        self.btn_search.pack(side=tk.LEFT, padx=5)

        self.btn_reset_search = ttk.Button(frame_search, text="Reset Search", command=self.reset_search)
        self.btn_reset_search.pack(side=tk.LEFT, padx=5)

        # --- Packet Display (Treeview) ---
        frame_packet_list = ttk.LabelFrame(self.root, text="Captured Packets List", padding=10)
        frame_packet_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Treeview for packet summary
        self.packet_tree = ttk.Treeview(frame_packet_list,
                                        columns=("Time", "Source", "Destination", "Protocol", "Length", "Info"),
                                        show="headings")

        # Define column headings
        self.packet_tree.heading("#0", text="No.")  # Hidden column for the packet number
        self.packet_tree.heading("Time", text="Time", anchor=tk.W)
        self.packet_tree.heading("Source", text="Source", anchor=tk.W)
        self.packet_tree.heading("Destination", text="Destination", anchor=tk.W)
        self.packet_tree.heading("Protocol", text="Protocol", anchor=tk.W)
        self.packet_tree.heading("Length", text="Length", anchor=tk.W)
        self.packet_tree.heading("Info", text="Info", anchor=tk.W)

        # Define column widths (adjust as needed)
        self.packet_tree.column("#0", width=40, stretch=tk.NO)  # Hidden but used for internal ID
        self.packet_tree.column("Time", width=120, stretch=tk.NO)
        self.packet_tree.column("Source", width=150, stretch=tk.NO)
        self.packet_tree.column("Destination", width=150, stretch=tk.NO)
        self.packet_tree.column("Protocol", width=80, stretch=tk.NO)
        self.packet_tree.column("Length", width=70, stretch=tk.NO)
        self.packet_tree.column("Info", width=300, stretch=tk.YES)

        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar for Treeview
        tree_scrollbar = ttk.Scrollbar(frame_packet_list, orient="vertical", command=self.packet_tree.yview)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.configure(yscrollcommand=tree_scrollbar.set)

        # Bind selection event to display detailed packet info
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        # --- Detailed Packet Display ---
        frame_packet_details = ttk.LabelFrame(self.root, text="Packet Details", padding=10)
        frame_packet_details.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.packet_detail_display = scrolledtext.ScrolledText(frame_packet_details, wrap=tk.WORD,
                                                               font=('Consolas', 10), state=tk.DISABLED)
        self.packet_detail_display.pack(fill=tk.BOTH, expand=True)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready. Select an interface and click Start.")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X, padx=10,
                                                                                               pady=5)

    def start_sniffing(self):
        iface_raw = self.selected_interface.get()
        if not iface_raw:
            messagebox.showerror("Error", "Please select a network interface!")
            return

        # Extract just the interface name/GUID for Scapy's sniff()
        # For Windows, the format is 'Description (GUID)', we need the GUID.
        # For Linux/Mac, it's just the interface name.
        if os.name == 'nt' and '(' in iface_raw and ')' in iface_raw:
            iface = iface_raw.split('(')[-1].rstrip(')')
        else:
            iface = iface_raw

        # Get the selected protocol filter
        protocol_filter = self.selected_protocol_filter.get()
        bpf_filter = self._get_bpf_filter(protocol_filter)

        self.sniffing = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.interface_dropdown.config(state=tk.DISABLED)  # Disable interface selection during sniffing
        self.protocol_dropdown.config(state=tk.DISABLED)  # Disable protocol selection during sniffing
        self.search_entry.config(state=tk.DISABLED)  # Disable search during sniffing
        self.btn_search.config(state=tk.DISABLED)  # Disable search button during sniffing
        self.btn_reset_search.config(state=tk.DISABLED)  # Disable reset search button during sniffing

        self.status_var.set(f"Sniffing on '{iface_raw}' with filter '{protocol_filter}'...")

        # Clear previous packets before starting new sniff
        self.clear_packets()

        sniff_thread = threading.Thread(target=self.run_sniffer, args=(iface, bpf_filter,), daemon=True)
        sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.interface_dropdown.config(state="readonly")  # Re-enable interface selection
        self.protocol_dropdown.config(state="readonly")  # Re-enable protocol selection
        self.search_entry.config(state=tk.NORMAL)  # Re-enable search
        self.btn_search.config(state=tk.NORMAL)  # Re-enable search button
        self.btn_reset_search.config(state=tk.NORMAL)  # Re-enable reset search button
        self.status_var.set("Sniffing stopped.")

    def clear_packets(self):
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.packet_detail_display.config(state=tk.NORMAL)
        self.packet_detail_display.delete(1.0, tk.END)
        self.packet_detail_display.config(state=tk.DISABLED)
        self.packet_counter = 0
        self.captured_packets_data.clear()
        self.search_entry.delete(0, tk.END)  # Clear search entry too
        self.status_var.set("Packets cleared. Ready. Select an interface and click Start.")

    def _get_bpf_filter(self, protocol_selection):
        """Constructs BPF filter string based on selected protocol."""
        filters = {
            "Radar Deploy": None,  # No filter
            "TCP": "tcp",
            "UDP": "udp",
            "ICMP": "icmp",
            "ARP": "arp",
            "DNS": "udp port 53 or tcp port 53",
            "HTTP": "tcp port 80",
            "HTTPS": "tcp port 443",
            "SSH": "tcp port 22",
            "FTP": "tcp port 20 or tcp port 21",
            "TELNET": "tcp port 23",
        }
        return filters.get(protocol_selection, None)

    def run_sniffer(self, iface, bpf_filter):
        try:
            # The 'filter' argument applies a BPF filter before Scapy processes the packet,
            # making it more efficient for large traffic.
            sniff(
                iface=iface,
                prn=self.process_packet,
                store=False,  # Don't store packets in Scapy's internal list
                stop_filter=lambda _: not self.sniffing,  # Stop when self.sniffing becomes False
                filter=bpf_filter  # Apply the BPF filter
            )
        except Scapy_Exception as e:
            # Handle common Scapy errors, e.g., permissions
            err_msg = f"Sniffing failed: {e}\n"
            if "No such device" in str(e):
                err_msg += "The selected interface might not exist or is not active. "
                err_msg += "On Linux, try running with 'sudo' or ensure correct permissions."
            elif "Permission denied" in str(e):
                err_msg += "Permission denied. Please run the script with administrator/root privileges."
            elif "No pcap_loop/pcap_next_ex support" in str(e):
                err_msg += "Missing packet capture library (Npcap/WinPcap on Windows, libpcap on Linux/Mac). Please install it."
            messagebox.showerror("Sniffing Error", err_msg)
            self.stop_sniffing()  # Stop sniffing gracefully
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"An unexpected error occurred during sniffing: {e}")
            self.stop_sniffing()

    def process_packet(self, packet):
        # DEBUGGING: Print to console to confirm if packets are being received by Scapy
        print(f"Packet captured! No: {self.packet_counter + 1}, Summary: {packet.summary()}")

        self.packet_counter += 1  # Increment for the new packet

        current_time = datetime.now().strftime('%H:%M:%S.%f')[:-3]  # Milliseconds precision

        src_ip = ""
        dst_ip = ""
        src_port = ""
        dst_port = ""
        protocol = "Unknown"
        info = ""  # This 'info' is for the Treeview summary

        # --- Populate src_ip, dst_ip, src_port, dst_port, protocol, and info for Treeview Summary ---
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            info += f"Ether: {src_mac} -> {dst_mac}"

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto  # Numeric protocol
            # Map common numeric protocols to names
            if protocol == 1:
                protocol = "ICMP"
            elif protocol == 6:
                protocol = "TCP"
            elif protocol == 17:
                protocol = "UDP"
            elif protocol == 50:
                protocol = "ESP"  # Example for other common protocols
            elif protocol == 51:
                protocol = "AH"

            info += f" IP: {src_ip} -> {dst_ip}"

        elif packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            protocol = "ARP"
            info = f"ARP: Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"

        # --- Transport Layers for Treeview Summary (info string) ---
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
            flags = packet[TCP].flags
            flag_str = ""
            if flags & 0x01: flag_str += "F"  # FIN
            if flags & 0x02: flag_str += "S"  # SYN
            if flags & 0x04: flag_str += "R"  # RST
            if flags & 0x08: flag_str += "P"  # PSH
            if flags & 0x10: flag_str += "A"  # ACK
            if flags & 0x20: flag_str += "U"  # URG
            info += f" TCP:{src_port}->{dst_port} [{flag_str}] Seq={packet[TCP].seq} Ack={packet[TCP].ack}"

            # Application layer protocols over TCP for summary
            if dst_port == 80 or src_port == 80:
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/")):
                            protocol = "HTTP"
                            info = f"HTTP {payload.splitlines()[0][:80]}..."
                    except:
                        pass
            elif dst_port == 443 or src_port == 443:
                protocol = "HTTPS"
                info = f"HTTPS {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            elif dst_port == 22 or src_port == 22:
                protocol = "SSH"
                info = f"SSH {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            elif dst_port in [20, 21] or src_port in [20, 21]:
                protocol = "FTP"
                info = f"FTP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            elif dst_port == 23 or src_port == 23:
                protocol = "TELNET"
                info = f"TELNET {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
            info += f" UDP:{src_port}->{dst_port} Len={packet[UDP].len}"

            # Application layer protocols over UDP for summary
            if dst_port == 53 or src_port == 53:
                protocol = "DNS"
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    if dns.qr == 0 and dns.qd:  # DNS Query
                        qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        info = f"DNS Query {qname}"
                    elif dns.qr == 1 and dns.an:  # DNS Response
                        aname = dns.an.rrname.decode('utf-8', errors='ignore').rstrip('.')
                        rdata = dns.an.rdata
                        if hasattr(rdata, 'decode'):
                            try:
                                rdata = rdata.decode('utf-8', errors='ignore')
                            except:
                                pass
                        info = f"DNS Response {aname} -> {rdata}"
                    else:
                        info = f"DNS {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

        # Ensure source and destination are present
        if not src_ip and packet.haslayer(Ether):
            src_ip = src_mac  # Fallback to MAC if no IP
            dst_ip = dst_mac  # Fallback to MAC if no IP

        # Prepare packet summary for Treeview
        packet_summary = (
            current_time,
            f"{src_ip}:{src_port}" if src_port else src_ip,
            f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
            protocol,
            len(packet),
            info.strip()  # Use the 'info' string generated above for the summary
        )

        # Generate detailed packet representation for the lower pane
        # Pass the full packet object to _format_packet_details for complete analysis
        detailed_packet_info = self._format_packet_details(packet)

        # Use root.after to safely update GUI from a separate thread
        self.root.after(0, self.update_packet_display, packet_summary, detailed_packet_info, self.packet_counter)

    def perform_search(self):
        search_term = self.search_entry.get().strip().lower()
        self.packet_tree.delete(*self.packet_tree.get_children())  # Clear current display

        # Re-populate based on search term
        for item_id, packet_info_dict in self.captured_packets_data.items():
            packet_no = packet_info_dict['packet_no']
            summary_values = packet_info_dict['summary']
            # summary_values: (time, src_ip_port, dst_ip_port, protocol, length, info)

            # Check for match in Source, Destination, or Protocol
            match_found = False
            if not search_term:  # If search term is empty, show all packets
                match_found = True
            else:
                # Check Source
                if search_term in summary_values[1].lower():  # Source column
                    match_found = True
                # Check Destination
                elif search_term in summary_values[2].lower():  # Destination column
                    match_found = True
                # Check Protocol
                elif search_term in summary_values[3].lower():  # Protocol column
                    match_found = True

            if match_found:
                # Re-insert into treeview using the original packet number and summary values
                self.packet_tree.insert("", tk.END, text=str(packet_no), values=summary_values)

        self.status_var.set(
            f"Search complete for '{search_term}'. Displaying {len(self.packet_tree.get_children())} matching packets.")

    def reset_search(self):
        self.search_entry.delete(0, tk.END)
        self.perform_search()  # Calling perform_search with empty string will display all packets
        self.status_var.set("Search reset. Displaying all captured packets.")


if __name__ == "__main__":
    root = tk.Tk()
    # Apply a modern theme
    style = ttk.Style()
    style.theme_use('clam')  # 'clam', 'alt', 'default', 'classic'

    # Configure some styles for better appearance
    style.configure('TFrame', background='#e0e0e0')
    style.configure('TLabelFrame', background='#e0e0e0', foreground='#333333', font=('Segoe UI', 10, 'bold'))
    style.configure('TLabel', background='#e0e0e0', foreground='#333333')
    style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=6)
    style.map('TButton', background=[('active', '#cccccc')])
    style.configure('TCombobox', font=('Segoe UI', 10), padding=3)

    # Accent button style for Start Sniffing
    style.configure('Accent.TButton', background='#4CAF50', foreground='white')
    style.map('Accent.TButton',
              background=[('active', '#66BB6A'), ('!disabled', '#4CAF50')],
              foreground=[('active', 'white'), ('!disabled', 'white')])

    app = PacketSnifferGUI(root)

    root.mainloop()
