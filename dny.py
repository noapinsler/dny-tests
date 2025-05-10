import socket
import threading
import logging
import subprocess
import re
import struct
import platform


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DNSForwarder:
  def __init__(self):
    self.local_dns = self.get_local_dns()  # Automatically detect local DNS
    self.local_port = 53
    self.google_dns = '8.8.8.8'  # Google DNS as fallback
    self.google_port = 53
    self.listen_port = 53
    self.socket = None

  def get_local_dns(self):
    try:
      current_os = platform.system().lower()

      if current_os == 'windows':
        # Windows: use ipconfig
        output = subprocess.check_output(['ipconfig', '/all'], encoding='utf-8', errors='ignore')
        matches = re.findall(r'DNS Servers[^\d]*(\d+\.\d+\.\d+\.\d+)', output)
        if matches:
          dns = matches[0]
          logging.info("Found local DNS from ipconfig: %s", dns)
          return dns

      elif current_os in ['linux', 'darwin']:
        # macOS or Linux: try /etc/resolv.conf
        with open('/etc/resolv.conf', 'r') as f:
          for line in f:
            if line.startswith('nameserver'):
              dns = line.split()[1]
              logging.info("Found local DNS in resolv.conf: %s", dns)
              return dns

        # macOS fallback
        if current_os == 'darwin':
          output = subprocess.check_output(['scutil', '--dns'], encoding='utf-8', errors='ignore')
          match = re.search(r'nameserver\[0\] : (\d+\.\d+\.\d+\.\d+)', output)
          if match:
            dns = match.group(1)
            logging.info("Found local DNS from scutil: %s", dns)
            return dns

      # Fallback
      default_dns = '8.8.8.8'
      logging.warning("Could not detect local DNS, using default: %s", default_dns)
      return default_dns

    except Exception as e:
      logging.error("Error detecting local DNS: %s", str(e))
      return '8.8.8.8'

  def start(self):
    self.configure_local_dns()
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.socket.bind(('0.0.0.0', self.listen_port))
    logging.info("DNS Forwarder listening on port %d", self.listen_port)
    logging.info("Primary DNS: %s, Fallback DNS: %s", self.local_dns, self.google_dns)

    while True:
      try:
        data, client_address = self.socket.recvfrom(1024)
        threading.Thread(target=self.handle_query, args=(data, client_address)).start()
      except Exception as e:
        logging.error("Error in main loop: %s", str(e))

  def get_network_interfaces(self):
    """Get list of available network interfaces based on OS."""
    system = platform.system().lower()
    interfaces = []

    if system == "darwin":  # macOS
      try:
        active_interface = subprocess.check_output(['route', 'get', 'default'], encoding='utf-8', errors='ignore')
        for line in active_interface.split('\n'):
          if 'interface:' in line:
            interface_name = line.split(':')[1].strip()
            services = subprocess.check_output(['networksetup', '-listallnetworkservices'], encoding='utf-8', errors='ignore')
            for service in services.split('\n'):
              if service.strip() and not service.startswith('*'):
                service_info = subprocess.check_output(['networksetup', '-getinfo', service.strip()], encoding='utf-8', errors='ignore')
                if interface_name in service_info:
                  interfaces.append(service.strip())
                  break
      except Exception as e:
        logging.error(f"Error getting network interfaces on macOS: {str(e)}")

    elif system == "windows":
      try:
        output = subprocess.check_output(['ipconfig'], encoding='utf-8', errors='ignore')
        current_interface = None
        for line in output.split('\n'):
          if 'adapter' in line.lower():
            current_interface = line.split(':')[0].strip()
          elif 'IPv4' in line and current_interface:
            interfaces.append(current_interface)
            current_interface = None
      except Exception as e:
        logging.error(f"Error getting network interfaces on Windows: {str(e)}")

    elif system == "linux":
      try:
        output = subprocess.check_output(['ip', 'route', 'get', '8.8.8.8'], encoding='utf-8', errors='ignore')
        if 'dev' in output:
          interface = output.split('dev')[1].split()[0]
          interfaces.append(interface)
      except Exception as e:
        logging.error(f"Error getting network interfaces on Linux: {str(e)}")

    return interfaces

  def get_active_interface(self):
    """Get the active network interface."""
    interfaces = self.get_network_interfaces()
    if interfaces:
      return interfaces[0]  # Return the first (and should be only) active interface
    return None

  def set_dns_linux(self, dns_ip="127.0.0.1"):
    """Set DNS server for Linux systems."""
    try:
      resolv_conf = "/etc/resolv.conf"
      with open(resolv_conf, "w") as f:
        f.write(f"nameserver {dns_ip}\n")
      logging.info(f"Successfully set DNS to {dns_ip} on Linux")
      return True
    except Exception as e:
      logging.error(f"Failed to set DNS on Linux: {str(e)}")
      return False

  def set_dns_macos(self, interface=None, dns_ip="127.0.0.1"):
    """Set DNS server for macOS systems."""
    if interface is None:
      interface = self.get_active_interface()
      if interface is None:
        logging.error("No active network interface found")
        return False

    try:
      subprocess.run(["networksetup", "-setdnsservers", interface, dns_ip], check=True)
      logging.info(f"Successfully set DNS to {dns_ip} on macOS for interface {interface}")
      return True
    except subprocess.CalledProcessError as e:
      logging.info(f"Failed to set DNS on macOS: {str(e)}")
      return False
    except Exception as e:
      logging.info(f"Unexpected error setting DNS on macOS: {str(e)}")
      return False

  def set_dns_windows(self, interface=None, dns_ip="127.0.0.1"):
    """Set DNS server for Windows systems."""
    if interface is None:
      # Try to find the active network interface using ipconfig
      output = subprocess.check_output(['ipconfig'], encoding='utf-8', errors='ignore')
      interfaces = re.findall(r'(\S+):\s+.IPv4.:\s*(\d+\.\d+\.\d+\.\d+)', output)

      if interfaces:
        # Get the first active interface found
        interface = interfaces[0][0]
        logging.info(f"Found active interface: {interface}")

      else:
        logging.error("No active network interface found on Windows.")
        return False

    try:
      # Run the netsh command with correct syntax
      result = subprocess.run(
        ["netsh", "interface", "ip", "set", "dns", f'name={interface}', "static", dns_ip],
        capture_output=True, text=True
      )
      if result.returncode != 0:
        logging.error(f"Failed to set DNS: {result.stderr}")
        return False

      logging.info(f"Successfully set DNS to {dns_ip} on Windows for interface {interface}")
      return True
    except subprocess.CalledProcessError as e:
      logging.error(f"Failed to set DNS on Windows: {str(e)}")
      return False
    except Exception as e:
      logging.error(f"Unexpected error setting DNS on Windows: {str(e)}")
      return False

    return False

  def configure_local_dns(self, dns_ip="127.0.0.1"):
    """Configure DNS settings based on the operating system."""
    system = platform.system().lower()
    success = False

    if system == "linux":
      success = self.set_dns_linux(dns_ip)
    elif system == "darwin":  # macOS
      success = self.set_dns_macos(None, dns_ip)
    elif system == "windows":
      success = self.set_dns_windows(None, dns_ip)
    else:
      logging.info(f"Unsupported operating system: {system}")
      return False

    if success:
      logging.info(f"DNS successfully configured to {dns_ip}")
    return success

  def handle_query(self, data, client_address):
    try:
      query_id = struct.unpack('!H', data[:2])[0]
      logging.info("Received DNS query with ID: %d", query_id)

      local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      local_socket.settimeout(10)
      local_socket.sendto(data, (self.local_dns, self.local_port))

      try:
        response_data, _ = local_socket.recvfrom(1024)
        if len(response_data) > 12:
          answer_count = struct.unpack('!H', response_data[6:8])[0]
          if answer_count > 0:
            logging.info("Local DNS resolved query ID: %d", query_id)
            self.socket.sendto(response_data, client_address)
            return
        logging.info("Local DNS returned no answers for query ID: %d, trying Google DNS", query_id)

      except socket.timeout:
        logging.info("Local DNS timeout for query ID: %d, trying Google DNS", query_id)
      finally:
        local_socket.close()

      google_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      google_socket.settimeout(5)
      google_socket.sendto(data, (self.google_dns, self.google_port))

      try:
        response_data, _ = google_socket.recvfrom(1024)
        logging.info("Google DNS resolved query ID: %d", query_id)
        self.socket.sendto(response_data, client_address)
      except socket.timeout:
        logging.error("Google DNS timeout for query ID: %d", query_id)
      finally:
        google_socket.close()

    except Exception as e:
      logging.error("Error handling query: %s", str(e))

if __name__ == "__main__":
  dns_forwarder = DNSForwarder()
  dns_forwarder.start()
