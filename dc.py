import tkinter as tk
from tkinter import messagebox,ttk
from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import time
import logging
from statistics import mean, stdev
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

def scan_network(ip_range, interface, output_box):
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast / arp_request
        answered_list = scapy.srp(arp_broadcast_packet, iface=interface, timeout=1, verbose=False)[0] 
        """ srp() returns a tuple with two lists: answered packets and unanswered Packets """
        
        output_box.delete("1.0", tk.END) 
        output_box.insert(tk.END, "ARP Scan Results:\n") 

        for sent, received in answered_list:
            output_box.insert(tk.END, f"IP Address: {received.psrc} - MAC Address: {received.hwsrc}\n")
    except Exception as e:
        messagebox.showerror("Error", f"ARP Scan failed: {e}")

def log_packet(packet):
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" 
        src_ip = packet[IP].src    
        dst_ip = packet[IP].dst    
        packet_size = len(packet)   
        
        log_entry = f"{timestamp}, Protocol: {protocol}, Source: {src_ip}, Destination: {dst_ip}, Size: {packet_size} bytes\n"

        with open("traffic.log", "a") as log_file: 
                                                   
                                                  
            log_file.write(log_entry)               
        return log_entry.strip()                    
    except Exception as e:
        return f"Error logging packet: {e}"
    
def start_logging(interface, output_box):
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, "Packet Sniffing started. Logs will be saved to 'traffic.log'.\n")
    
    def sniff_task():
        sniff(iface=interface, prn=lambda pkt: output_box.insert(tk.END, log_packet(pkt) + "\n"), store=False, count=100)
    
    threading.Thread(target=sniff_task).start()

def send_icmp(output_box,target_ip, packet_count=10, packet_size=64):
    latencies = []
    total_bytes_sent = 0

    for i in range(packet_count):
        packet = IP(dst=target_ip) / ICMP() / Raw(load="X" * (packet_size - 28))
        send_time = time.time()
        reply = sr1(packet, timeout=1, verbose=0)
        recv_time = time.time()

        if reply:
            latency = (recv_time - send_time) * 1000
            latencies.append(latency)
            total_bytes_sent += len(packet)
            output_box.insert(tk.END, "Creating an ICMP packet...\n")
            output_box.insert(tk.END, f"Reply from {target_ip}: time={latency:.2f} ms \n")
            
        else:
            output_box.insert(tk.END, f"Request timed out for {target_ip}")

        time.sleep(0.1)

    if latencies:
        avg_latency = mean(latencies)
        jitter = stdev(latencies) if len(latencies) > 1 else 0
        throughput = total_bytes_sent / (sum(latencies) / 1000)
        data_rate = total_bytes_sent / (packet_count * packet_size)
        output_box.insert(tk.END, f"Average Latency: {avg_latency:.2f} ms, Jitter: {jitter:.2f} ms, Throughput: {throughput:.2f} Bps, Data Rate: {data_rate:.2f} \n")
        logging.info(f"Target: {target_ip}, Avg Latency: {avg_latency:.2f} ms, Jitter: {jitter:.2f} ms, Throughput: {throughput:.2f} Bps, Data Rate: {data_rate:.2f}")
    else:
        output_box.insert(tk.END, "No replies received. Metrics cannot be calculated.")

def send_tcp_syn(output_box , target_ip, target_port, packet_count=10):
    latencies = []
    total_bytes_sent = 0

    for i in range(packet_count):
        packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
        send_time = time.time()
        reply = sr1(packet, timeout=1, verbose=0)
        recv_time = time.time()

        if reply and reply.haslayer(TCP) and reply[TCP].flags == "SA":
            latency = (recv_time - send_time) * 1000
            latencies.append(latency)
            total_bytes_sent += len(packet)
            output_box.insert(tk.END, f"Reply from {target_ip}:{target_port} - time={latency:.2f} ms \n")
            print()
        else:
            output_box.insert(tk.END, f"Request timed out for {target_ip}:{target_port}")

        time.sleep(0.1)

    if latencies:
        avg_latency = mean(latencies)
        jitter = stdev(latencies) if len(latencies) > 1 else 0
        throughput = total_bytes_sent / (sum(latencies) / 1000)
        data_rate = total_bytes_sent / packet_count
        output_box.insert(tk.END, f"Average Latency: {avg_latency:.2f} ms, Jitter: {jitter:.2f} ms, Throughput: {throughput:.2f} Bps, Data Rate: {data_rate:.2f} \n")
        logging.info(f"Target: {target_ip}:{target_port}, Avg Latency: {avg_latency:.2f} ms, Jitter: {jitter:.2f} ms, Throughput: {throughput:.2f} Bps, Data Rate: {data_rate:.2f}")
    else:
        output_box.insert(tk.END, "No replies received. Metrics cannot be calculated. \n")

def open_new_window(choice):
    new_window = tk.Toplevel(root)
    new_window.title(f"Option {choice}")

    if choice == 1:
        def start():
            ip_range = ip_entry.get()
            interface = interface_entry.get()
            scan_network(ip_range,interface,output_box)
        
        tk.Label(new_window, text="Network Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        interface_entry = tk.Entry(new_window, width=30)
        interface_entry.grid(row=0, column=1, padx=5, pady=5)
        interface_entry.insert(0, "Wi-Fi")  

        tk.Label(new_window, text="IP Range:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        ip_entry = tk.Entry(new_window, width=30)
        ip_entry.grid(row=1, column=1, padx=5, pady=5)
        ip_entry.insert(0, "192.168.1.1/24")  

        output_box = tk.Text(new_window, height=20, width=100)
        output_box.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        output_box.insert(tk.END, "Results of the ARP scan will appear here...")
        
        tk.Button(new_window, text="Start ARP Scan", command=start).grid(row=3, column=0, columnspan=2, pady=10)

        tk.Button(new_window, text="Close", command=new_window.destroy).grid(row=4, column=0, columnspan=2, pady=10)
    elif choice == 2:
        tk.Label(new_window, text="Filter by IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        ip_entry = tk.Entry(new_window, width=30)
        ip_entry.grid(row=0, column=1, padx=5, pady=5)
        ip_entry.insert(0, "")  

        tk.Label(new_window, text="Filter by Protocol:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        protocol_var = tk.StringVar()
        protocol_dropdown = ttk.Combobox(new_window, textvariable=protocol_var, state="readonly")
        protocol_dropdown['values'] = ("All", "TCP", "UDP", "ICMP")
        protocol_dropdown.current(0)  
        protocol_dropdown.grid(row=1, column=1, padx=5, pady=5)

        output_box = tk.Text(new_window, height=20, width=60)
        output_box.grid(row=2, column=0, columnspan=2, padx=5, pady=10)

        # status_label = tk.Label(root)
        # status_label.pack(pady=5)
        sniffing_active = True

        def packet_analysis(destination_ip="10.9.0.6", protocols=["TCP", "UDP", "ICMP"]): 
            def packet_filter(packet):
                if IP in packet and packet[IP].dst == destination_ip:
                    if "TCP" in protocols and TCP in packet:
                        return True
                    if "UDP" in protocols and UDP in packet:
                        return True
                    if "ICMP" in protocols and ICMP in packet:
                        return True
                return False

            def process_packet(packet):
                if IP in packet:
                    protocol = "UNKNOWN"
                    src_port = dst_port = "N/A"

                    if TCP in packet:
                        protocol = "TCP"
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                    elif UDP in packet:
                        protocol = "UDP"
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                    elif ICMP in packet:
                        protocol = "ICMP"
                        src_port = "N/A"
                        dst_port = "N/A"

                    packet_info = (
                        f"Packet Details:\n"
                        f"  Source IP: {packet[IP].src}\n"
                        f"  Destination IP: {packet[IP].dst}\n"
                        f"  Source Port: {src_port}\n"
                        f"  Destination Port: {dst_port}\n"
                        f"  Protocol: {protocol}\n"
                        "-" * 50 + "\n"
                    )
                    output_box.insert(tk.END, packet_info)
                    output_box.see(tk.END)

            def stop_sniffing_thread():
                global sniffing_active
                sniffing_active = False

            sniff(filter=f"host {destination_ip}", prn=process_packet, store=0, lfilter=packet_filter)

        def start_sniffing():
            global sniffing_active
            sniffing_active = True  
            
            destination_ip = ip_entry.get().strip()
            selected_protocols = protocol_var.get()

            if selected_protocols == "All":
                protocols = ["TCP", "UDP", "ICMP"]  
            else:
                protocols = [selected_protocols]  
            
            if not destination_ip:
                # status_label.config(text="Error: Please enter a valid IP address.")
                return

            output_box.delete("1.0", tk.END)
            # status_label.config(text=f"Starting capture for IP: {destination_ip}...")

            sniff_thread = threading.Thread(target=packet_analysis, args=(destination_ip, protocols), daemon=True)
            sniff_thread.start()


        def stop_sniffing():
            global sniffing_active
            sniffing_active = False  
            # status_label.config(text="Capture stopped.")
        tk.Button(new_window, text="Start Capture", command=start_sniffing).grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(new_window, text="Stop Capture", command=stop_sniffing).grid(row=4, column=0, columnspan=2, pady=10)
        tk.Button(new_window, text="Close", command=new_window.destroy).grid(row=5, column=0, columnspan=2, pady=10)

    elif choice == 3:
        tk.Label(new_window, text="Select an Option:").pack(pady=10)
        tk.Button(new_window, text="ICMP (Ping)", command=lambda: open_choice(1)).pack(pady=5)
        tk.Button(new_window, text="TCP (SYN)", command=lambda: open_choice(2)).pack(pady=5)
        
        tk.Button(new_window, text="Exit", command=new_window.destroy).pack(pady=10)

        def open_choice(protocol_type):
            def sending():                
                src_ip = ip_entry_src.get()
                num_packet = int(num_packet_entry.get())
                size = int (size_packet_entry.get())
                port_tx = int(port.get())
                if protocol_type==1:

                    send_icmp(output_box,src_ip,num_packet,size)
                elif protocol_type == 2:
                    
                    send_tcp_syn(output_box,src_ip,port_tx,num_packet)

            
            new_window_1 = tk.Toplevel(new_window)
            new_window_1.title(f"Protocol {protocol_type}")
            tk.Label(new_window_1, text="IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
            ip_entry_src = tk.Entry(new_window_1, width=30)
            ip_entry_src.grid(row=0, column=1, padx=5, pady=5)
            ip_entry_src.insert(0, "10.9.0.5")  

            tk.Label(new_window_1, text="Number of Packets:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
            num_packet_entry = tk.Entry(new_window_1, width=30)
            num_packet_entry.grid(row=1, column=1, padx=5, pady=5)
            num_packet_entry.insert(0, "5")

            tk.Label(new_window_1, text="Size of Packets:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
            size_packet_entry = tk.Entry(new_window_1, width=30)
            size_packet_entry.grid(row=2, column=1, padx=5, pady=5)
            size_packet_entry.insert(0, "5")
            
            tk.Label(new_window_1, text="Port Number:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
            port = tk.Entry(new_window_1, width=30)
            port.grid(row=3, column=1, padx=5, pady=5)
            port.insert(0, "5")

            output_box = tk.Text(new_window_1, height=20, width=100)
            output_box.grid(row=4, column=0, columnspan=2, padx=5, pady=5)
            
            
            tk.Button(new_window_1, text="Send Packet", command=sending).grid(row=5, column=0, columnspan=2, pady=10)

            
            tk.Button(new_window_1, text="Close", command=new_window_1.destroy).grid(row=6, column=0, columnspan=2, pady=10)

    elif choice == 4:
        def start():
            interface = interface_entry.get()
            start_logging(interface, output_box)
        
        tk.Label(new_window, text="Network Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        interface_entry = tk.Entry(new_window, width=30)
        interface_entry.grid(row=0, column=1, padx=5, pady=5)
        interface_entry.insert(0, "Wi-Fi")  
        
        output_box = tk.Text(new_window, height=20, width=100)
        output_box.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        output_box.insert(tk.END, "Results of the ARP scan will appear here...")
        
        tk.Button(new_window, text="Start ARP Scan", command=start).grid(row=3, column=0, columnspan=2, pady=10)

        tk.Button(new_window, text="Close", command=new_window.destroy).grid(row=4, column=0, columnspan=2, pady=10)

root = tk.Tk()
root.geometry("500x300")
root.title("Main Menu")

tk.Label(root, text="Select an Option:").pack(pady=10)

tk.Button(root, text="ARP Scanning", command=lambda: open_new_window(1)).pack(pady=5)
tk.Button(root, text="Packet Analysis", command=lambda: open_new_window(2)).pack(pady=5)
tk.Button(root, text="Custom Packet Creation & Network Performance Measure", command=lambda: open_new_window(3)).pack(pady=5)
tk.Button(root, text="Traffic Monitoring and Logging", command=lambda: open_new_window(4)).pack(pady=5)

tk.Button(root, text="Exit", command=root.quit).pack(pady=10)

root.mainloop()