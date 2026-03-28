"""
Author: Samuel Barth-Ibe
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary mapping common port numbers to their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter allows controlled access to private attributes.
    # Rather than directly accessing self.__target, the getter/setter pattern lets us
    # add validation logic (like rejecting empty strings) without changing how outside
    # code reads or writes the property. It enforces encapsulation cleanly.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, which means it automatically gets the
# target property (getter and setter) and the private __target storage without
# rewriting them. For example, calling super().__init__(target) in PortScanner's
# constructor delegates the target setup entirely to the parent class.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, any connection failure (e.g., scanning an unreachable host)
        # would raise an unhandled exception and crash the entire program. Since we're
        # using threads, an unhandled exception in one thread could cause unpredictable
        # behavior. The try-except block ensures each port is handled gracefully.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            service_name = common_ports.get(port, "Unknown")
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned concurrently instead of waiting
    # for each connection attempt to time out before moving to the next. Without threads,
    # scanning 1024 ports with a 1-second timeout each would take over 17 minutes.
    # With threading, all ports are scanned nearly simultaneously, finishing in seconds.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, result[0], result[1], result[2], str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")

if __name__ == "__main__":
    try:
        target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
        if target == "":
            target = "127.0.0.1"

        start_input = input("Enter start port (1-1024): ").strip()
        start_port = int(start_input)
        if not (1 <= start_port <= 1024):
            print("Port must be between 1 and 1024.")
            exit()

        end_input = input("Enter end port (1-1024): ").strip()
        end_port = int(end_input)
        if not (1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
            exit()

        if end_port < start_port:
            print("End port must be greater than or equal to start port.")
            exit()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for p in open_ports:
        print(f"Port {p[0]}: {p[1]} ({p[2]})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    history = input("Would you like to see past scan history? (yes/no): ").strip().lower()
    if history == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# A banner-grabbing feature could be added that connects to open ports and reads
# the first bytes of data returned by the service to identify the software version.
# It would use a nested if-statement: if the port is open, and if the banner
# response is not empty, it would display the version string alongside the port result.
# Diagram: See diagram_101587059.png in the repository root



