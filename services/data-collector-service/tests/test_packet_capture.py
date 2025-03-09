# test_packet_capture.py

import pytest
from unittest.mock import patch, MagicMock
import time
import pandas as pd
from src.packet_capture import PacketCapture

@pytest.fixture
def packet_capture_instance():
    """
    Fixture that initializes a PacketCapture instance for use in the tests.
    
    Returns:
        A PacketCapture instance.
    """
    return PacketCapture()

def test_initialization(packet_capture_instance):
    """
    Verifies that the class initializes with the correct data structures and attributes.
    
    The constructor initializes the object with a queue to store packet information,
    an event to signal the capture thread to stop, a thread to run the capture,
    and a list to store the captured packet data.
    """
    pc = packet_capture_instance
    assert pc.packet_queue is not None, "packet_queue should be initialized"
    assert not pc.stop_capture.is_set(), "stop_capture should be False initially"
    assert pc.capture_thread is None, "capture_thread should be None initially"
    assert pc.packets_data == [], "packets_data should be an empty list initially"

def test_packet_callback(packet_capture_instance):
    """
    Verifies that packet_callback stores packet information in the list and in the queue.
    
    packet_callback receives a Scapy packet object as an argument and stores
    the packet information in the list of captured packets and the queue.
    """
    pc = packet_capture_instance
    
    # Create a mock "packet" with the necessary properties
    mock_packet = MagicMock()
    mock_packet.__contains__.side_effect = lambda x: True  # So that IP and TCP appear to exist
    mock_packet.__getitem__.side_effect = lambda x: mock_packet  # Return the same mock when accessing IP or TCP
    
    # Assign simulated attributes
    type(mock_packet).src = '127.0.0.1'
    type(mock_packet).dst = '192.168.0.1'
    type(mock_packet).sport = 12345
    type(mock_packet).dport = 80
    type(mock_packet).proto = 6
    type(mock_packet).flags = 'S'
    mock_packet.__len__.return_value = 60  # Simulate len(packet)

    # Call the packet_callback method
    pc.packet_callback(mock_packet)
    
    # Verify that the packet was stored in the packets_data list
    assert len(pc.packets_data) == 1
    
    # Verify the packet information was stored correctly
    packet_info = pc.packets_data[0]
    assert packet_info['src_ip'] == '127.0.0.1'
    assert packet_info['dst_ip'] == '192.168.0.1'
    assert packet_info['protocol'] == 6
    assert packet_info['size'] == 60
    
    # Verify that the packet was also added to the queue
    assert not pc.packet_queue.empty()

@patch('packet_capture.sniff')
def test_start_capture(mock_sniff, packet_capture_instance):
    """
    Verifies that start_capture launches a thread and calls sniff() with the correct arguments.
    
    This test uses a mock for the sniff function to ensure it is called with the expected parameters
    when start_capture is invoked. It checks that a thread is started and the sniff function 
    is configured with the correct network interface and packet count.
    """
    pc = packet_capture_instance  # Get the PacketCapture instance
    
    # Start the packet capture with specified interface and packet count
    pc.start_capture(interface='eth0', packet_count=10)
    
    # Briefly wait for the thread to start
    time.sleep(0.1)
    
    # Verify that the sniff function was called exactly once
    mock_sniff.assert_called_once()
    
    # Retrieve the keyword arguments used in the sniff call
    _, kwargs = mock_sniff.call_args
    
    # Check that the correct interface and packet count are passed to sniff
    assert kwargs['iface'] == 'eth0'
    assert kwargs['count'] == 10
    
    # Ensure the packet callback function is passed to sniff
    assert callable(kwargs['prn'])
    
    # Stop the packet capture and verify the stop event is set
    pc.stop()
    assert pc.stop_capture.is_set()

def test_get_captured_data(packet_capture_instance):
    """
    Verifies that get_captured_data returns a DataFrame with the expected columns.
    
    This test sets the packets_data attribute of the PacketCapture instance
    with a sample packet and checks if the method returns a DataFrame with
    the correct format and data.
    """
    pc = packet_capture_instance
    
    # Simulate captured packet data
    pc.packets_data = [
        {
            'timestamp': 123456.0,
            'src_ip': '10.0.0.1',
            'dst_ip': '10.0.0.2',
            'src_port': 1234,
            'dst_port': 80,
            'protocol': 6,
            'size': 60,
            'flags': 'S'
        }
    ]
    
    # Retrieve the captured data as a DataFrame
    df = pc.get_captured_data()
    
    # Verify that the result is a DataFrame
    assert isinstance(df, pd.DataFrame), "Result should be a DataFrame"
    
    # Check that the expected columns are present
    assert 'timestamp' in df.columns, "'timestamp' column should be present"
    assert 'src_ip' in df.columns, "'src_ip' column should be present"
    assert 'dst_ip' in df.columns, "'dst_ip' column should be present"
    assert 'src_port' in df.columns, "'src_port' column should be present"
    
    # Verify the DataFrame has the correct number of rows
    assert len(df) == 1, "DataFrame should have one row"
    
    # Check that the data in the DataFrame matches the input data
    assert df.at[0, 'src_ip'] == '10.0.0.1', "src_ip should match the input data"


