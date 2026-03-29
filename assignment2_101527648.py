"""
Author: Student 101527648
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# TODO: Import the required modules (Step ii)
import socket
import threading
import sqlite3
import os
import platform
import datetime


# Print Python version and OS name (Step iii)
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")


# This dictionary maps common port numbers to their associated network service names
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
    # Using @property and @target.setter allows controlled access to the private
    # attribute self.__target without exposing it directly. The setter lets us
    # add validation logic — in this case, rejecting empty strings — so the object
    # always stays in a valid state. This is a key principle of encapsulation in OOP:
    # data should only be modified through controlled interfaces, not directly.
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
# PortScanner inherits from NetworkTool using class PortScanner(NetworkTool),
# which means it automatically gets the target property, its getter/setter, and
# the destructor without rewriting them. For example, when PortScanner.__init__
# calls super().__init__(target), it reuses NetworkTool's constructor to store
# and validate the target IP. This avoids code duplication and follows the DRY principle.
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
        # Without try-except, any network error — such as a refused connection,
        # a timeout, or an unreachable host — would raise an unhandled exception
        # and crash the entire program. Since scan_port runs inside a thread,
        # an unhandled exception in one thread could cause unpredictable behaviour
        # and corrupt self.scan_results. The try-except ensures each port is handled
        # gracefully regardless of what the network returns.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
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
    # Threading allows multiple ports to be scanned simultaneously rather than
    # waiting for each one to time out before moving to the next. Without threads,
    # scanning 1024 ports with a 1-second timeout each would take over 17 minutes
    # in the worst case. With threads, all ports are scanned concurrently, reducing
    # total scan time to roughly the length of a single timeout.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()


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
        if not rows:
            print("No past scans found.")
        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.OperationalError:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    try:
        target_input = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
        target = target_input if target_input else "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        if not (1 <= start_port <= 1024):
            print("Port must be between 1 and 1024.")
            exit()

        end_port = int(input("Enter end port (1-1024): "))
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
    print(f"\nScanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: Open ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if history == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# I would add a Quick Summary Filter feature that groups open ports into service
# categories (WEB, REMOTE ACCESS, EMAIL, OTHER) after scanning. It would use list
# comprehensions to filter open ports by port number into each category, for example:
# web_ports = [item for item in open_ports if item[0] in [80, 443, 8080]].
# This gives the user a cleaner, organized summary instead of a flat list of ports.
# Diagram: See diagram_101527648.png in the repository root
