from scapy.all import sniff, IP, TCP
import threading
import queue
import pandas as pd
import time

class PacketCapture:
    """
    A class to capture network packets using Scapy and store the captured data.
    Attributes
    ----------
    packet_queue : queue.Queue
        A queue to store packet information.
    stop_capture : threading.Event
        An event to signal the capture thread to stop.
    capture_thread : threading.Thread or None
        The thread running the packet capture.
    packets_data : list
        A list to store captured packet data.
    Methods
    -------
    packet_callback(packet):
        Processes each captured packet and adds it to the queue.
    start_capture(interface="eth0", packet_count=100):
        Starts packet capture on a separate thread.
    stop():
        Stops the packet capture.
    get_captured_data():
        Returns the captured data as a DataFrame.
    """
    def __init__(self):
        """
        Constructor for PacketCapture.
        
        Initializes the packet capture object with the required data structures.
        """
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.capture_thread = None
        self.packets_data = []
        
    def packet_callback(self, packet):
        """Processes each captured packet and adds it to the queue"""
        if IP in packet and TCP in packet:
            packet_info = {
                'timestamp': time.time(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'protocol': packet[IP].proto,
                'size': len(packet),
                'flags': packet[TCP].flags
            }
            self.packets_data.append(packet_info)
            self.packet_queue.put(packet_info)
            
    def start_capture(self, interface="eth0", packet_count=100):
        """Inits the packet capture on a separate thread"""
        def capture_thread():
            """
            Thread function that starts the packet capture using Scapy.
        
            Parameters are passed from the start_capture method.
            """
            sniff(iface=interface,
                 prn=self.packet_callback,
                 count=packet_count,
                 store=0,
                 stop_filter=lambda _: self.stop_capture.is_set())
            
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()
        
    def stop(self):
        """Stops the packet capture"""
        self.stop_capture.set()
        if self.capture_thread:
            self.capture_thread.join()
            
    def get_captured_data(self):
        """Returns the captured data as a DataFrame"""
        return pd.DataFrame(self.packets_data)
