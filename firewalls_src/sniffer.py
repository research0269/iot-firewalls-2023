from scapy import all as sc
from scapy.layers.http import HTTPRequest, HTTPResponse
from netfilterqueue import NetfilterQueue
import re, os, logging, tldextract, difflib

logger = logging.getLogger(__name__)

class Sniffer:
    def __init__(self, input_iface=None, output_iface=None, device=None, queue_num=0, tailscale=False, iptables_backup=None):
        self.input_iface = input_iface if input_iface else "eth0"
        self.output_iface = output_iface if output_iface else "eth1"
        self.queue = NetfilterQueue()
        self.QUEUE_NUM = queue_num
        self.device = device
        self.tailscale = tailscale
        # self.iptables_backup_fp = iptables_backup if iptables_backup else "iptables.bak"

        # os.system("iptables-save > {}".format(self.iptables_backup_fp))
        # logger.info("Saved iptables to %s.", self.iptables_backup_fp)

        self._insert_iptables()

    
    def __del__(self):
        self.cleanup()
    
    def _insert_iptables(self):
        if self.device:
            if self.tailscale:
                os.system(
                    "iptables -I ts-forward 3 -i {} -o {} -m mac --mac-source {} -j NFQUEUE --queue-num {}".format(
                        self.input_iface, 
                        self.output_iface, 
                        self.device.mac,
                        self.QUEUE_NUM
                    )
                )
                os.system(
                    "iptables -I ts-input -i {} -m mac --mac-source {} -j NFQUEUE --queue-num {}".format(
                        self.input_iface, 
                        self.device.mac,
                        self.QUEUE_NUM
                    )
                )
                logger.info("Forwarding packtes sent from %s to NFQUEUE (queue_num = %d).", self.device.mac, self.QUEUE_NUM)
            else:
                os.system(
                    "iptables -I FORWARD -i {} -o {} -m mac --mac-source {} -j NFQUEUE --queue-num {}".format(
                        self.input_iface, 
                        self.output_iface, 
                        self.device.mac,
                        self.QUEUE_NUM
                    )
                )
                os.system(
                    "iptables -I INPUT -i {} -m mac --mac-source {} -j NFQUEUE --queue-num {}".format(
                        self.input_iface, 
                        self.device.mac,
                        self.QUEUE_NUM
                    )
                )
                logger.info("Forwarding packtes sent from %s to NFQUEUE (queue_num = %d).", self.device.mac, self.QUEUE_NUM)

            if self.device.ip:
                if self.tailscale:
                    os.system("iptables -I ts-forward 4 -i {} -o {} -d {} -j NFQUEUE --queue-num {}".format(
                        self.output_iface,
                        self.input_iface,
                        self.device.ip,
                        self.QUEUE_NUM
                    ))
                    logger.info("Forwarding packtes sent to %s to NFQUEUE (queue_num = %d).", self.device.ip, self.QUEUE_NUM)
                else:
                    os.system("iptables -I FORWARD -i {} -o {} -d {} -j NFQUEUE --queue-num {}".format(
                        self.output_iface,
                        self.input_iface,
                        self.device.ip,
                        self.QUEUE_NUM
                    ))
                    logger.info("Forwarding packtes sent to %s to NFQUEUE (queue_num = %d).", self.device.ip, self.QUEUE_NUM)
        else:
            os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(self.QUEUE_NUM))
            logger.warning("No device is found. Sending all packets to NFQUEUE.")

    def _process_packet(self, pkt):
        sc_pkt = sc.IP(pkt.get_payload())
        log = {"device_mac": "", "protocol": "", "remote_ip": "", "local_ip": "", "remote_port": -1, "local_port": -1, "direction": "", "hostname": "UNKNOWN", "action": ""}
        if sc.UDP in sc_pkt and sc.DNS in sc_pkt:
            if (sc_pkt[sc.UDP].dport == 5353 and sc_pkt[sc.IP].dst == "224.0.0.251") or (sc_pkt[sc.UDP].sport == 5353 and sc_pkt[sc.IP].src == "224.0.0.251"):
                is_allowed = self._process_mdns(sc_pkt)
                if is_allowed:
                    pkt.accept()
                else:
                    pkt.drop()
            else:
                is_allowed = self._process_dns(sc_pkt, log)
                if is_allowed:
                    pkt.accept()
                else:
                    logger.info("[DNS] Original DNS query dropped.")
                    pkt.drop()
        elif sc.UDP in sc_pkt or sc.TCP in sc_pkt:
            is_allowed = self._process_udp_tcp(sc_pkt, log)
            if is_allowed:
                pkt.accept()
            else:
                pkt.drop()
        elif sc.ARP in sc_pkt:
            logger.debug("Get an ARP packet: %s", sc_pkt.summary())
            pkt.accept()
        elif sc.DHCP in sc_pkt:
            logger.debug("Get an DHCP packet: %s", sc_pkt.summary())
            pkt.accept()
        elif sc.ICMP in sc_pkt:
            logger.debug("Get an ICMP packet: %s", sc_pkt.summary())
            pkt.accept()
        else:
            # any other requests are allowed
            logger.debug("Get an UNKNOWN packet: %s", sc_pkt.summary())
            pkt.accept()

    def _process_mdns(self, pkt):
        logger.info("Get an mDNS packet: %s", pkt.summary())
        if pkt.haslayer(sc.DNSQR):
            qname = pkt[sc.DNSQR].qname.decode('utf-8')
            if qname.endswith("."):
                qname = qname[:-1]
            logger.info("[mDNS] The device is querying: {}".format(qname))
        if pkt.haslayer(sc.DNSRR):
            logger.info(f"[mDNS] Got a response: {pkt[sc.DNS].an}")
            logger.info("mDNS is allowed.")
            return True
        else:
            logger.info("mDNS is not allowed!")
            return False

    def _process_dns(self, pkt, log):
        if pkt.haslayer(sc.DNSQR):
            qname = pkt[sc.DNSQR].qname.decode('utf-8')
            if qname.endswith("."):
                qname = qname[:-1]
            logger.info("[DNS] The device is querying: {}".format(qname))

            if qname.endswith(".local"):
                # mdns traffic
                return True
                
            if self.device.feature == "ip":
                logger.info("[DNS] IP-based rules are applied. Only mappings are added.")
                new_ips = self.device.update_hostname_ip_mapping(qname)
                self._dns_reply(pkt, qname=qname, ipset=new_ips)
                return False

            qsd, qd, qtld = tldextract.extract(qname)
            qdomain = qd + '.' + qtld
            
            if self._is_allowed(qname=qname, qdomain=qdomain):
                # if it is a DNS response, record all the ip addresses
                logger.info("[DNS] The queried hostname is allowed!")
                if pkt.haslayer(sc.DNSRR):
                    logger.info("[DNS] Received a DSN reply!")
                    ipset = set([])
                    for rr in pkt[sc.DNS].an:
                        if rr.type == 'A':
                            ipset.add(rr.rdata)
                            if not rr.rdata in self.device.ip_name_mapping:
                                self.device.ip_name_mapping[rr.rdata].append(qname)
                    self.device.allowlist['ip'] = self.device.allowlist['ip'].union(ipset)
                    logger.debug("[DNS] Add {} to allowlist.".format(ipset))
                else:
                    new_ips = self.device.add_allowed_hostname(qname)
                    self._dns_reply(pkt, qname=qname, ipset=new_ips)
                    return False
            else:
                logger.info("[DNS] The queried hostname is not allowed!")
                if pkt.haslayer(sc.DNSRR) and pkt[sc.DNS].an:
                    for rr in pkt[sc.DNS].an:
                        if rr.type == 'A':
                            self.device.ip_name_mapping[rr.rdata].append(qname)
                else:
                    self.device.update_hostname_ip_mapping(qname)
        else:
            logger.error("[DNS] There is no DNSQR layer in the received DNS packet. Summary of the packet: {}".format(pkt.summary()))
        # don't do anything if it is a query or a response about a non-allowed domain
        return True

    def _dns_reply(self, pkt, qname, ipset):
        # modified from https://jasonmurray.org/posts/scapydns/
        ip_layer = sc.IP(src = pkt[sc.IP].dst, dst = pkt[sc.IP].src)
        udp_layer = sc.UDP(dport = pkt[sc.UDP].sport, sport = pkt[sc.UDP].dport)

        dns_response = None
        for ip in ipset:
            new_dns_response = sc.DNSRR(rrname=qname, type='A', ttl=600, rdata=ip)
            if dns_response:
                dns_response = dns_response / new_dns_response
            else:
                dns_response = new_dns_response

        dns_layer = sc.DNS(
            id=pkt[sc.DNS].id,
            qd=pkt[sc.DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=len(ipset),
            nscount=0,
            arcount=0,
            an=dns_response
        )
        reply = ip_layer / udp_layer / dns_layer
        sc.send(reply)
        logger.info("[DNS] Response sent for {}. Include IPs: {}".format(qname, ipset))
    
    def _process_udp_tcp(self, pkt, log):
        """
        Decide whether the incoming pkt should be dropped. Log the result.

        INPUT:  (scapy) pkt, must be udp or tcp packet
        
        OUTPUT: return False if the pkt should be dropped,
                otherwise, return True
        """
        if sc.TCP in pkt:
            log['protocol'] = 'tcp'
            layer = sc.TCP
        elif sc.UDP in pkt:
            log['protocol'] = 'udp'
            layer = sc.UDP
        else:
            return False
        
        if pkt[sc.IP].src == self.device.ip:
            # if the packet is sent by local device
            log['device_mac'] = self.device.mac
            log['remote_ip'] = pkt[sc.IP].dst
            log['local_ip'] = pkt[sc.IP].src
            log['remote_port'] = pkt[layer].dport
            log['local_port'] = pkt[layer].sport
            log['direction'] = 'outbound'
        elif pkt[sc.IP].dst == self.device.ip:
            # if the packet is sent by remote server
            log['device_mac'] = self.device.mac
            log['remote_ip'] = pkt[sc.IP].src
            log['local_ip'] = pkt[sc.IP].dst
            log['remote_port'] = pkt[layer].sport
            log['local_port'] = pkt[layer].dport
            log['direction'] = 'inbound'
        else:
            # broadcast
            return True
        
        if log['remote_ip'] in self.device.ip_name_mapping:
            log['hostname'] = self.device.get_hostname_by_ip(log['remote_ip'], log['remote_port'])
        
        if self.device.feature == "ip":
            # when IP-based rules are deployed
            action = self._is_allowed(ip=log['remote_ip'])
            log["action"] = "Accept" if action else "Drop"
            self._log_traffic(log)
            return action
            
        if log['remote_ip'] in self.device.allowlist['ip']:
            # processing STUN
            if log['remote_port'] == 3475 and log['protocol'] == 'tcp' and log['direction'] == 'inbound':
                self._process_stun(pkt)

            # processing HTTP
            # if log['remote_port'] == 80 and log['protocol'] == 'tcp':
            #     self._process_http(pkt)

            log["action"] = "Accept"
            self._log_traffic(log)
            return True
        elif self.device.feature == "none":
            # allowing everything.
            log["action"] = "Accept"
            self._log_traffic(log)
            return True
        else:
            log["action"] = "Drop"
            self._log_traffic(log)
            return False
    
    def _process_stun(self, pkt):
        logger.debug("Receive an STUN packet: %s", pkt.summary())
        logger.debug("...Content: {}".format(pkt[sc.TCP].payload))
        if sc.Raw in pkt:
            address = pkt[sc.Raw].load
            try:
                address = address.decode('utf-8')
            except (UnicodeDecodeError, AttributeError):
                pass
            logger.info("[STUN] Found a new hostname: {}".format(address))
            self.device.add_allowed_hostname(address)
            logger.info("[STUN] Added {} to allowlist.".format(address))
    
    def _process_http(self, pkt):
        if pkt.haslayer(HTTPRequest):
            method = pkt[HTTPRequest].Method.decode()
            if pkt.haslayer(sc.Raw):
                logger.info("[HTTP][{}] Content: {}".format(method, self._http_decode(pkt[sc.Raw].load)))
            else:
                logger.debug("[HTTP] Cannot process the request.")
        elif pkt.haslayer(HTTPResponse):
            if pkt.haslayer(sc.Raw):
                logger.info("[HTTP][Response] Content: {}".format(self._http_decode(pkt[sc.Raw].load)))
        elif pkt.haslayer(sc.Raw):
            logger.info("[HTTP] Content: {}".format(self._http_decode(pkt[sc.Raw].load)))
        else:
            logger.debug("[HTTP] This is not an HTTP request or HTTP response.")

    def _http_decode(self, s, encodings=('utf8', 'ascii', 'ISO-8859-1', 'latin1')):
        for encoding in encodings:
            try:
                logger.debug(f"[HTTP] Try {encoding}...")
                return s.decode(encoding)
            except UnicodeDecodeError:
                logger.debug(f"[HTTP] The content cannot be decoded by {encoding}")
        logger.warning("[HTTP] Cannot decode the content. Use default and ignore errors instead.")
        return s.decode('ascii', 'ignore')

    def _log_traffic(self, log):
        msg = "[{action}] {local_ip}:{local_port} ({mac}) {direction} {remote_ip}:{remote_port} ({hostname})".format(
            action=log['action'],
            local_ip = log['local_ip'],
            local_port = log['local_port'],
            mac = log['device_mac'],
            direction = '-->' if log['direction'] == 'outbound' else '<--',
            remote_ip = log['remote_ip'],
            remote_port = log['remote_port'],
            hostname=log['hostname']
        )
        logger.info(msg)

    def _is_allowed(self, ip=None, qname=None, qdomain=None):
        if self.device.feature == "hostname" and qname is not None and qname in self.device.allowlist['hostname']:
            return True
        if self.device.feature == "domain" and qdomain is not None and qdomain in self.device.allowlist['domain']:
            return True
        if self.device.feature == "ip" and ip is not None and ip in self.device.allowlist['ip']:
            return True
        if self.device.feature == "none":
            return True
        if self.device.feature == "hostname" and self.device.pattern_enabled:
            logger.debug(f"Looking for patterns for {qname}...")
            if not self.device.allowlist["patterns"]:
                return False
            guesses = difflib.get_close_matches(qname, self.device.allowlist["patterns"].keys())
            for guess in guesses:
                pat = self.device.allowlist["patterns"][guess]
                m = re.match(pat, qname)
                if m:
                    self.device.allowlist["patterns"][qname] = pat
                    logger.debug(f"A match found, add the associated pattern of {qname}s to allowlist.")
                    return True
        return False

    def cleanup(self):
        logger.debug(f"IP-hostname mappings: {self.device.ip_name_mapping}")
        logger.info("Restoring iptables...")
        # os.system("iptables-restore < {}".format(self.iptables_backup_fp))
        if self.device:
            if self.tailscale:
                os.system(
                    "iptables -D ts-forward -i {} -o {} -m mac --mac-source {} -j NFQUEUE --queue-num {}".format(
                        self.input_iface, 
                        self.output_iface, 
                        self.device.mac,
                        self.QUEUE_NUM
                    )
                )
                os.system(
                    "iptables -D ts-input -i {} -m mac --mac-source {} -j NFQUEUE --queue-num {}".format(
                        self.input_iface, 
                        self.device.mac,
                        self.QUEUE_NUM
                    )
                )
            else:
                os.system(
                    "iptables -D FORWARD -i {} -o {} -m mac --mac-source {} -j NFQUEUE --queue-num {}".format(
                        self.input_iface, 
                        self.output_iface, 
                        self.device.mac,
                        self.QUEUE_NUM
                    )
                )
                os.system(
                    "iptables -D INPUT -i {} -m mac --mac-source {} -j NFQUEUE --queue-num {}".format(
                        self.input_iface, 
                        self.device.mac,
                        self.QUEUE_NUM
                    )
                )
            logger.info("Removing mac-related iptables rules (mac=%s, queue_num=%d)", self.device.mac, self.QUEUE_NUM)

            if self.device.ip:
                if self.tailscale:
                    os.system("iptables -D ts-forward -i {} -o {} -d {} -j NFQUEUE --queue-num {}".format(
                        self.output_iface,
                        self.input_iface,
                        self.device.ip,
                        self.QUEUE_NUM
                    ))
                else:
                    os.system("iptables -D FORWARD -i {} -o {} -d {} -j NFQUEUE --queue-num {}".format(
                        self.output_iface,
                        self.input_iface,
                        self.device.ip,
                        self.QUEUE_NUM
                    ))
                logger.info("Removing IP-related iptables rules (IP=%s, queue_num=%d).", self.device.ip, self.QUEUE_NUM)
        logger.info("Removed all added rules. iptables cleaned up!")
    
    def start(self):
        logger.info("Sniffer starts...")
        try:
            self.queue.bind(self.QUEUE_NUM, self._process_packet)
            self.queue.run()
        except KeyboardInterrupt:
            logger.info("Keyboard Interrupt detected!")
