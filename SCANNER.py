import tkinter as tk
from tkinter import messagebox, scrolledtext
from scapy.all import ARP, Ether, srp
import socket
import threading

def scan_network(ip_range):
    # Send ARP requests
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]

    hosts = []
    for sent, received in result:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    return hosts

def scan_ports(ip, ports=[22, 80, 443, 139, 445]):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def perform_scan():
    ip_range = entry.get()
    if not ip_range:
        messagebox.showerror("Input Error", "Please enter an IP range, e.g., 192.168.1.0/24")
        return

    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, f"Scanning network {ip_range}...\n")

    def thread_scan():
        hosts = scan_network(ip_range)
        for host in hosts:
            ip = host['ip']
            mac = host['mac']
            open_ports = scan_ports(ip)
            ports_str = ', '.join(map(str, open_ports)) if open_ports else "No open ports found"
            text_area.insert(tk.END, f"[+] Host UP: {ip} | MAC: {mac} | Ports: {ports_str}\n")
        text_area.insert(tk.END, "Scan complete.\n")

    threading.Thread(target=thread_scan).start()

# GUI setup
root = tk.Tk()
root.title("Network Scanner")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

label = tk.Label(frame, text="Enter IP Range (e.g., 192.168.1.0/24):")
label.pack()

entry = tk.Entry(frame, width=40)
entry.pack()

scan_button = tk.Button(frame, text="Start Scan", command=perform_scan)
scan_button.pack(pady=5)

text_area = scrolledtext.ScrolledText(frame, width=80, height=20)
text_area.pack()

root.mainloop()
