import time
import queue
import threading
import pandas as pd
import pytest
from src.packet_capture import PacketCapture, IP, TCP

# Fake classes to simulate Scapy packets

class FakeIP:
    def __init__(self, src, dst, proto):
        """
        Constructor for FakeIP.
        
        Parameters
        ----------
        src : str
            Source IP address.
        dst : str
            Destination IP address.
        proto : int
            Protocol number.
        """
        self.src = src
        self.dst = dst
        self.proto = proto

class FakeTCP:
    def __init__(self, sport, dport, flags):
        """
        Constructor for FakeTCP.
        
        Parameters
        ----------
        sport : int
            Source port.
        dport : int
            Destination port.
        flags : str
            TCP flags, e.g. "S" for SYN, "A" for ACK, etc.
        """
        self.sport = sport
        self.dport = dport
        self.flags = flags

class FakePacket:
    """
    Simulates a Scapy packet that contains the IP and TCP layers.
    """
    def __init__(self, ip_layer, tcp_layer, size):
        """
        Constructor for FakePacket.
        
        Parameters
        ----------
        ip_layer : FakeIP
            An instance of FakeIP representing the IP layer.
        tcp_layer : FakeTCP
            An instance of FakeTCP representing the TCP layer.
        size : int
            The size of the packet in bytes.
        """
        self.layers = {IP: ip_layer, TCP: tcp_layer}
        self._size = size

    def __contains__(self, item):
        """
        Checks if the given item is in the packet's layers.
        
        Parameters
        ----------
        item : object
            The item to search for in the packet's layers.
        
        Returns
        -------
        bool
            True if the item is in the packet's layers, False otherwise.
        """
        return item in self.layers

    def __getitem__(self, item):
        """
        Retrieves the specified layer from the packet's layers.

        Parameters
        ----------
        item : type
            The layer type (e.g., IP, TCP) to retrieve from the packet.

        Returns
        -------
        object
            The corresponding layer object from the packet's layers.
        """

        return self.layers[item]

    def __len__(self):
        """
        Returns the size of the packet.

        Returns
        -------
        int
            The size of the packet in bytes.
        """

        return self._size

# Fake function to replace sniff during testing
def fake_sniff(*args, **kwargs):
    """
    Simulates the sniff function by calling the callback with a fake packet,
    as many times as specified by 'count'.
    """
    packet_count = kwargs.get('count', 1)
    prn = kwargs.get('prn')
    for _ in range(packet_count):
        ip = FakeIP(src="192.168.1.1", dst="192.168.1.2", proto=6)
        tcp = FakeTCP(sport=12345, dport=80, flags="S")
        fake_packet = FakePacket(ip, tcp, 100)
        prn(fake_packet)

# Test for the packet_callback method
def test_packet_callback():
    """
    Tests the packet_callback method.

    Creates a PacketCapture object and a fake packet, and calls the
    packet_callback method with the fake packet. The test then asserts
    that the packet information was added to the packets_data list, and
    that the queue is not empty.
    """
    pc = PacketCapture()
    ip = FakeIP(src="10.0.0.1", dst="10.0.0.2", proto=6)
    tcp = FakeTCP(sport=1111, dport=80, flags="A")
    packet = FakePacket(ip, tcp, 120)
    
    pc.packet_callback(packet)
    
    # Check that the packet information was added
    assert len(pc.packets_data) == 1
    packet_info = pc.packets_data[0]
    assert packet_info['src_ip'] == "10.0.0.1"
    assert packet_info['dst_ip'] == "10.0.0.2"
    assert packet_info['src_port'] == 1111
    assert packet_info['dst_port'] == 80
    assert packet_info['protocol'] == 6
    assert packet_info['size'] == 120
    assert packet_info['flags'] == "A"
    
    # Check that the queue is not empty
    assert not pc.packet_queue.empty()

# Test for the get_captured_data method
def test_get_captured_data():
    """
    Tests the get_captured_data method.

    Creates a PacketCapture object and a fake packet, adds the packet to the
    capture object using the packet_callback method, and then retrieves the
    captured data using the get_captured_data method. The test then asserts that
    the returned data is a Pandas DataFrame with the expected columns and shape.
    """
    pc = PacketCapture()
    ip = FakeIP(src="192.168.0.1", dst="192.168.0.2", proto=6)
    tcp = FakeTCP(sport=2222, dport=443, flags="S")
    packet = FakePacket(ip, tcp, 150)
    
    pc.packet_callback(packet)
    df = pc.get_captured_data()
    
    assert isinstance(df, pd.DataFrame)
    assert df.shape[0] == 1
    assert "src_ip" in df.columns
    assert "dst_ip" in df.columns

# Test for the start_capture method using monkeypatch to replace sniff
def test_start_capture(monkeypatch):
    """
    Tests the start_capture method using monkeypatch to replace sniff.

    Creates a PacketCapture object, replaces sniff with the fake_sniff function,
    starts the simulated capture with count=2, waits for the capture thread to
    finish, and checks that 2 packets were captured.
    """
    pc = PacketCapture()
    # Replace sniff with the fake_sniff function
    monkeypatch.setattr("packet_capture.sniff", fake_sniff)
    
    # Start the simulated capture with count=2
    pc.start_capture(packet_count=2)
    
    # Wait for the capture thread to finish
    pc.capture_thread.join(timeout=1)
    
    # Check that 2 packets were captured
    assert len(pc.packets_data) == 2

# Test for the stop method
def test_stop(monkeypatch):
    """
    Tests the stop method.

    Creates a PacketCapture object, starts a simulated capture with a
    fake_sniff function that sleeps for 0.5 seconds, calls the stop method, and
    checks that the capture thread is no longer active.
    """
    pc = PacketCapture()
    
    # Create a fake_sniff function that simulates a long capture
    def fake_sniff_sleep(*args, **kwargs):
        """
        Simulates a long capture by sleeping for 0.5 seconds.

        This function is used to test the stop method, by simulating a capture that
        takes longer than expected.
        """
        time.sleep(0.5)
    
    monkeypatch.setattr("packet_capture.sniff", fake_sniff_sleep)
    
    pc.start_capture(packet_count=1)
    # Call stop immediately
    pc.stop()
    
    # Check that the capture thread is no longer active
    assert not pc.capture_thread.is_alive()

