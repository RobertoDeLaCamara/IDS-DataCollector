#!/usr/bin/env python3
# data-collector-server.py

import sys
import time
import argparse
import signal
import threading
import logging
import os
import glob
import datetime
import configparser

from logging.handlers import TimedRotatingFileHandler

import pyarrow as pa
import pyarrow.parquet as pq

from packet_capture import PacketCapture

###############################################################################
# Paths relative to /src
###############################################################################
LOG_FILE = "../data/data-collector-server.log"
CAPTURES_DIR = "../data/captures"
DEFAULT_CONFIG_PATH = "../config/server_config.ini"

# Ensure the ../data directory structure exists
os.makedirs("../data", exist_ok=True)
os.makedirs(CAPTURES_DIR, exist_ok=True)

###############################################################################
# Logging configuration
# Rotate logs daily at midnight, keep 7 backups
###############################################################################
handler = TimedRotatingFileHandler(LOG_FILE, when="midnight", backupCount=7)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

###############################################################################
# Helper to read config from ../config/daemon_config.ini
###############################################################################
def load_config(config_file):
    """Load daemon settings from an INI file if present."""
    if not os.path.isfile(config_file):
        logger.warning("Config file %s not found. Using defaults.", config_file)
        return {}

    config = configparser.ConfigParser()
    try:
        config.read(config_file)
        return config
    except Exception as e:
        logger.error("Error reading config file %s: %s", config_file, e)
        return {}

###############################################################################
# PacketCaptureDaemon
###############################################################################
class PacketCaptureDaemon:
    def __init__(self, interface="eth0", packet_count=100,
                 rotation_interval=0, max_captures=5):
        """
        :param interface: Network interface to capture from
        :param packet_count: Number of packets to capture before the sniff ends
        :param rotation_interval: If > 0, periodically exports captures
        :param max_captures: Keep only N capture files, remove older ones
        """
        self.interface = interface
        self.packet_count = packet_count
        self.packet_capture = PacketCapture()
        self.capture_thread = None
        self.running = False

        self.rotation_interval = rotation_interval
        self.max_captures = max_captures
        self.stop_rotation = threading.Event()
        self.rotation_thread = None

    def start(self):
        """
        Starts the packet capture daemon.

        Initiates packet capture on the specified network interface using the 
        provided packet count. If a rotation interval is set, it also starts 
        a separate thread to periodically export captured data and manage 
        rotating capture files. Logs warnings if the daemon is already running.

        Raises
        ------
        Logging warnings if the daemon is already running.
        """

        if self.running:
            logger.warning("Daemon is already running.")
            return
        self.running = True

        logger.info("Starting capture on interface=%s, packet_count=%d",
                    self.interface, self.packet_count)
        self.capture_thread = threading.Thread(
            target=self.packet_capture.start_capture,
            kwargs={"interface": self.interface, "packet_count": self.packet_count}
        )
        self.capture_thread.start()

        # If rotation_interval is enabled, start a rotation thread
        if self.rotation_interval > 0:
            logger.info("Auto-rotation every %d seconds", self.rotation_interval)
            self.rotation_thread = threading.Thread(target=self._auto_rotate)
            self.rotation_thread.start()

    def stop(self):
        """
        Stops the packet capture daemon.

        Stops the packet capture and, if enabled, the rotation thread. If the daemon
        is not running, logs a warning and does nothing.

        """
        if not self.running:
            logger.warning("Daemon is not running.")
            return

        logger.info("Stopping capture...")
        self.packet_capture.stop()
        if self.capture_thread:
            self.capture_thread.join()

        if self.rotation_thread:
            logger.info("Stopping rotation thread...")
            self.stop_rotation.set()
            self.rotation_thread.join()

        self.running = False
        logger.info("Capture stopped.")

    def status(self):
        """
        Reports the current status of the daemon.

        Prints a message indicating whether the daemon is currently running
        or stopped.
        """
        if self.running:
            logger.info("Daemon is running.")
        else:
            logger.info("Daemon is stopped.")

    def get_data(self, head=5):
        """
        Prints the first <head> rows of the captured data.

        If no data has been captured yet, prints a message indicating so.
        Otherwise, prints the first <head> rows of the captured data.

        Parameters
        ----------
        head : int, optional
            Number of rows to print. Defaults to 5.
        """
        df = self.packet_capture.get_captured_data()
        if df.empty:
            logger.info("No data captured yet.")
        else:
            logger.info("Captured data (first %d rows):\n%s", head, df.head(head))

    def export_parquet(self, file_path):
        """
        Exports captured packet data to a Parquet file.

        Retrieves the captured data from the packet capture and exports it
        to the specified file path in Parquet format. If no data has been captured,
        logs a message indicating that there is nothing to export.

        Parameters
        ----------
        file_path : str
            The file path where the Parquet file will be saved.
        """

        df = self.packet_capture.get_captured_data()
        if df.empty:
            logger.info("No data captured yet, nothing to export.")
            return
        table = pa.Table.from_pandas(df)
        pq.write_table(table, file_path)
        logger.info("Data exported to %s", file_path)

    def _auto_rotate(self):
        """Periodically export data to a timestamped Parquet file and prune old ones."""
        while not self.stop_rotation.is_set():
            self.stop_rotation.wait(self.rotation_interval)
            if self.stop_rotation.is_set():
                break

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = os.path.join(CAPTURES_DIR, f"capture_{timestamp}.parquet")
            logger.info("Rotating capture -> %s", out_file)
            self.export_parquet(out_file)
            self._prune_older_files()

    def _prune_older_files(self):
        """Keep only the N newest capture files."""
        pattern = os.path.join(CAPTURES_DIR, "capture_*.parquet")
        files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
        if len(files) > self.max_captures:
            old = files[self.max_captures:]
            for f in old:
                try:
                    os.remove(f)
                    logger.info("Removed old capture file: %s", f)
                except OSError as e:
                    logger.error("Error removing file %s: %s", f, e)


###############################################################################
# Signal handling
###############################################################################
def setup_signal_handlers(daemon):
    """
    Set up signal handlers for the daemon.

    This function sets up signal handlers for the SIGINT and SIGTERM signals.
    When either of these signals is received, the daemon is stopped and the
    program exits with status code 0.

    Parameters
    ----------
    daemon : DataCollectorDaemon
        The daemon object to stop on signal reception.
    """
    def handle_signal(signum, frame):
        logger.info("Received signal %d, stopping daemon...", signum)
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

###############################################################################
# CLI
###############################################################################
def main():
    """
    Main entry point for the packet capture daemon command-line interface.

    Parses command-line arguments to control the behavior of the daemon, including 
    starting, stopping, checking status, printing captured data, and exporting data 
    to a file. It also reads configuration settings from a config file if available 
    and sets up signal handlers for graceful shutdown.

    Commands
    --------
    start : Start the packet capture daemon.
    stop : Stop the packet capture daemon.
    status : Report the current status of the daemon.
    data : Print the first few rows of captured data.
    export : Export captured data to a specified file.

    Parameters are extracted from command-line arguments, which can override 
    defaults or configuration file settings for network interface, packet count, 
    data rotation, and max captures.
    """

    parser = argparse.ArgumentParser(
        description="Daemon that captures packets, stores logs/captures in ../data, reads config from ../config."
    )
    parser.add_argument("command", choices=["start", "stop", "status", "data", "export"],
                        help="start/stop/status/data/export")
    parser.add_argument("--interface", default="eth0",
                        help="Network interface to capture (default eth0)")
    parser.add_argument("--packet-count", type=int, default=100,
                        help="Number of packets to capture (default 100)")
    parser.add_argument("--data-head", type=int, default=5,
                        help="Rows to show for 'data' command")

    # Rotation arguments
    parser.add_argument("--rotation-interval", type=int, default=0,
                        help="Interval in seconds to automatically rotate exports (0=disabled)")
    parser.add_argument("--max-captures", type=int, default=5,
                        help="Max number of rotated capture files to keep")

    # Manual export argument
    parser.add_argument("--export-file", default="../data/capturas.parquet",
                        help="File path for 'export' command (default ../data/capturas.parquet)")

    # Config file argument
    parser.add_argument("--config-file", default=DEFAULT_CONFIG_PATH,
                        help="Path to config file (default ../config/daemon_config.ini)")

    args = parser.parse_args()

    # Load config from ../config, if it exists
    config = load_config(args.config_file)

    # If needed, override CLI defaults with config values
    # Example usage: reading from [daemon] section
    if "daemon" in config:
        args.interface = config["daemon"].get("interface", args.interface)
        args.packet_count = config["daemon"].getint("packet_count", args.packet_count)
        args.rotation_interval = config["daemon"].getint("rotation_interval", args.rotation_interval)
        args.max_captures = config["daemon"].getint("capture_backup_count", args.max_captures)

    daemon = PacketCaptureDaemon(
        interface=args.interface,
        packet_count=args.packet_count,
        rotation_interval=args.rotation_interval,
        max_captures=args.max_captures
    )

    setup_signal_handlers(daemon)

    if args.command == "start":
        daemon.start()
        # Keep alive in foreground to process signals
        while True:
            time.sleep(1)

    elif args.command == "stop":
        daemon.stop()

    elif args.command == "status":
        daemon.status()

    elif args.command == "data":
        daemon.get_data(args.data_head)

    elif args.command == "export":
        daemon.export_parquet(args.export_file)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()


