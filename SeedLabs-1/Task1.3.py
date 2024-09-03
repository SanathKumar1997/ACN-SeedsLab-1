from scapy.all import IP, ICMP, sr1, conf
import time

def traceroute(dest_ip, max_hops=30, timeout=2):
    # Initialize Scapy configuration to suppress unwanted output
    conf.verb = 0

    # Iterate through TTL values from 1 to max_hops
    for ttl in range(1, max_hops + 1):
        # Create an IP packet with the specified TTL and destination IP
        ip_packet = IP(dst=dest_ip, ttl=ttl)
        # Create an ICMP packet
        icmp_packet = ICMP()

        # Send the packet and wait for a reply (sr1 sends packets and returns the first reply)
        reply = sr1(ip_packet / icmp_packet, timeout=timeout)

        # If there is a reply, extract and print the source IP address
        if reply:
            print(f"{ttl}  {reply.src}")
            
            # If the destination is reached, stop the traceroute
            if reply.src == dest_ip:
                print("Reached the destination.")
                break
        else:
            print(f"{ttl}  *")  # If no reply, print an asterisk (common in traceroute outputs)

        # Sleep for a short time to avoid flooding the network with packets
        time.sleep(1)

if __name__ == "__main__":
    # Set the destination IP address
    destination_ip = "1.2.3.4"  # Replace with the desired IP address or hostname

    # Start the traceroute
    traceroute(destination_ip)
