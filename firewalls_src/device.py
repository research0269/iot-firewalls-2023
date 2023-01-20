import socket, logging, tldextract, pathlib, json
from collections import defaultdict

import constants

logger = logging.getLogger(__name__)

class Device:
    """
    Constructor:
        mac:        mac address of the device
        ip:         ip address of the device
        name:       (optional) a human-readable name for the device
        product:    the product name of the device, which is used for finding the ruleset
        feature:    the feature that the ruleset is based on
        thresh:     the thresh for ruleset generation
    """
    def __init__(self, mac="", ip="", name="", product="", feature="", pattern_enabled=False, local_allowlist=False, thresh=0, tailscale=False, nslookup_loop=1):
        self.mac = mac
        self.ip = ip
        self.name = name
        self.product = product
        self.thresh = thresh
        self.feature = feature
        self.pattern_enabled = pattern_enabled
        self.local_allowlist = local_allowlist
        self.NSLOOKUP_LOOP = nslookup_loop
        self.tailscale = tailscale
        self.ip_name_mapping = defaultdict(list)
        self.allowlist = self._set_allowlist()

    def _set_allowlist(self):
        allowlist = {
            'hostname': set([]),
            'domain': set([]),
            'ip': set([])
        }
        unresolvable_hostnames = set()

        if self.product == "" or self.thresh == 0 or self.feature == "none":
            return allowlist

        if self.tailscale or self.local_allowlist:
            rule_fp = f'{constants.LOCAL_ALLOWLIST_DIR}/{self.product}/{self.feature}/{self.thresh}.csv'
            unresolvable_fp = f'{constants.LOCAL_ALLOWLIST_DIR}/{self.product}/unresolvable_hostnames.csv'
        else:
            rule_fp = f'{constants.ALLOWLIST_DIR}/{self.product}/{self.feature}/{self.thresh}.csv'
            unresolvable_fp = f'{constants.ALLOWLIST_DIR}/{self.product}/unresolvable_hostnames.csv'

        # getting rules
        logger.info("Getting rules from file: %s", rule_fp)
        rule_set = self._read_rule_set(rule_fp)
        if len(rule_set) == 0:
            logger.error("Cannot find file: %s", rule_fp)
            return allowlist

        allowlist[self.feature] = rule_set
        if self.feature == 'domain':
            hostname_rule_fp = f'{constants.ALLOWLIST_DIR}/{self.product}/hostname/1.csv' if not self.tailscale else f'{constants.LOCAL_ALLOWLIST_DIR}/{self.product}/hostname/1.csv'
            logger.info("Importing hostname-based rules to establish initial set of allowed IPs.")
            rule_set = self._read_rule_set(hostname_rule_fp)
            if len(rule_set) != 0:
                adopted_rule_set = set()
                for hostname in rule_set:
                    domain = self._get_domain_from_hostname(hostname)
                    if domain in allowlist["domain"]:
                        adopted_rule_set.add(hostname)
                allowlist['hostname'] = adopted_rule_set
            else:
                logger.warning("No initial IP addresses can be added.")
        elif self.feature == "hostname" and self.pattern_enabled:
            logger.info("Enabling pattern-based allowlist...")
            allowlist["patterns"] = self.enable_pattern_matching(allowlist=allowlist)

        # adding manually created rules
        # if self.product == "ring_camera" and self.feature == "hostname":
        #     logger.info("Adding manually created rules!")
        #     logger.info("Adding stickupcammini.ring.com as an allowed hostname, and a2z.com as an allowed domain.")
        #     allowlist[self.feature].add("stickupcammini.ring.com")
        #     allowlist["domain"].add("a2z.com")
        if self.product == 'wyze_camera':
            man_add_rules = [
                # "167.160.91.114", "45.56.83.7", # old rules
                "66.23.207.162", "192.99.36.44", "104.149.138.170" # new rules
            ]
            logger.info("Adding manually created rules!")
            logger.info("Adding {} as allowed IPs.".format(', '.join(man_add_rules)))
            allowlist["ip"] = allowlist['ip'].union(set(man_add_rules))

        # getting rules that is not resolvable anymore
        if pathlib.Path(unresolvable_fp).is_file():
            unresolvable_hostnames = self._read_rule_set(unresolvable_fp)

        if len(allowlist["hostname"]) != 0:
            # the length is only zero when IP-based rules are applied.
            update_unrsv_hostname = False
            logger.info("Creating initial rule set...")
            for i in range(self.NSLOOKUP_LOOP):
                logger.info("Getting IPs by hostnames (%d / %d)...", i+1, self.NSLOOKUP_LOOP)
                for hostname in allowlist["hostname"]:
                    if not hostname in unresolvable_hostnames:
                        inplace = False
                        new_ips = self._update_ip_by_hostname(hostname, inplace=inplace, show_unresolve_warning=False)
                        if new_ips:
                            allowlist["ip"] = allowlist["ip"].union(new_ips)
                        elif not inplace:
                            # if new_ips is None but inplace=False, then a network error occur
                            unresolvable_hostnames.add(hostname)
                            update_unrsv_hostname = True
            logger.info(
                "Received {} hostnames. {} hostnames cannot be resolved."
                .format(len(allowlist['hostname']), len(unresolvable_hostnames)))
            logger.info("Got allowed IPs. Found %d in total.", len(allowlist["ip"]))

            # if there is new hostnames that can no longer be resolved, save the unresolvable hostnames
            if update_unrsv_hostname:
                with open(unresolvable_fp, 'w') as f:
                    for hostname in unresolvable_hostnames:
                        f.write(f"{hostname}\n")
                logger.info("Saved unresolvable hostnames to file: {}".format(unresolvable_fp))

        logger.info(
            "Finishing initializing rules, incuding {} IP-based rules, {} hostname-based rules, {} domain-based rules."
            .format(len(allowlist["ip"]), len(allowlist["hostname"]), len(allowlist["domain"])))

        return allowlist

    def _read_rule_set(self, fp: str) -> set:
        try:
            with open(fp, 'r') as f:
                rule_set = set([line.rstrip() for line in f if line != "\n" and line != ""])
        except FileNotFoundError:
            logger.warning("Cannot find file: %s", fp)
            rule_set = set()
        return rule_set

    def _update_ip_by_hostname(self, hostname: str, inplace: bool = False, show_unresolve_warning: bool = True):
        if hostname == "(mdns)":
            new_ip = "224.0.0.251"
            self.ip_name_mapping[new_ip].append(hostname)
            if inplace:
                self.allowlist["ip"] = self.allowlist["ip"].add(new_ip)
                return
            else:
                return set([new_ip])
        new_ips = self.update_hostname_ip_mapping(
            hostname, 
            show_unresolve_warning = show_unresolve_warning)
        if inplace:
            self.allowlist["ip"] = self.allowlist["ip"].union(new_ips)
            return
        else:
            return new_ips if len(new_ips) != 0 else None

    def _get_domain_from_hostname(self, hostname: str) -> str:
        qsd, qd, qtld = tldextract.extract(hostname)
        return qd + '.' + qtld

    def add_manual_rules(self, feature: str, rules: set = None, rules_fp: str = None, ):
        if rules is None and rules_fp is None:
            return set()
        
        if rules is None:
            rules = self._read_rule_set(rules_fp)
        
        if feature == "hostname":
            for rule in rules:
                self.add_allowed_hostname(rule)
        else:
            self.allowlist[feature] = self.allowlist[feature].union(rules)

    def update_hostname_ip_mapping(self, hostname: str, port= None, show_unresolve_warning: bool = True) -> set:
        try:
            new_ips = set({addr[-1][0] for addr in socket.getaddrinfo(hostname, 0, family=socket.AF_INET)})
            for ip in new_ips:
                ip_port = "{}:{}".format(ip, port)
                if port:
                    if not ip_port in self.ip_name_mapping:
                        self.ip_name_mapping[ip_port].append(hostname)
                    elif self.ip_name_mapping[ip_port][-1] != hostname:
                        self.ip_name_mapping[ip_port].append(hostname)
                else:
                    if not ip in self.ip_name_mapping or self.ip_name_mapping[ip][-1] != hostname:
                        self.ip_name_mapping[ip].append(hostname)
            return new_ips
        except socket.gaierror:
            if show_unresolve_warning:
                logger.warning("Cannot resolve hostname: %s", hostname)
            return set()

    def _add_port_to_ip_mapping(self, ip, port):
        ip_port = "{}:{}".format(ip, port)
        if ip_port in self.ip_name_mapping:
            return
        if len(self.ip_name_mapping[ip]) == 1:
            hostname = self.ip_name_mapping[ip][-1]
            self.ip_name_mapping[ip_port].append(hostname)
    
    def get_hostname_by_ip(self, ip, port):
        self._add_port_to_ip_mapping(ip, port)
        ip_port = "{}:{}".format(ip, port)
        if ip_port in self.ip_name_mapping:
            return self.ip_name_mapping[ip_port][-1]
        elif ip in self.ip_name_mapping:
            return self.ip_name_mapping[ip][-1]

    def add_allowed_hostname(self, hostname: str, update_ip: bool = True) -> set:
        if not hostname in self.allowlist["hostname"]:
            self.allowlist["hostname"].add(hostname)
        if update_ip:
            new_ips = self.update_hostname_ip_mapping(hostname)
            self.allowlist["ip"] = self.allowlist["ip"].union(new_ips)
            if len(new_ips) != 0:
                logger.debug("Add following IPs to allowlist: {}".format(new_ips))
            else:
                logger.debug("No IPs added.")
            return new_ips
        else:
            return set()

    def update_thresh(self, thresh):
        if isinstance(thresh, int):
            self.thresh = thresh
            if self.thresh != 0:
                self.allowlist = self._set_allowlist()
    
    def update_feature(self, feature):
        if feature in self.allowlist:
            self.feature = feature
            self.allowlist = self._set_allowlist()
    
    def enable_pattern_matching(self, allowlist=None, inplace=False):
        if self.tailscale or self.local_allowlist:
            fp = f'{constants.LOCAL_ALLOWLIST_DIR}/{self.product}/patterns/{self.product}-pattern-map.json'
        else:
            fp = f'{constants.ALLOWLIST_DIR}/{self.product}/patterns/{self.product}-pattern-map.json'
        if allowlist is None:
            allowlist = self.allowlist

        logger.info("Getting patterns from file: %s", fp)
        try:
            with open(fp, 'r') as f:
                patterns = json.load(f)
        except FileNotFoundError:
            logger.error("Cannot find file: %s", fp)
            return

        adopted_patterns = {}
        for hostname in allowlist["hostname"]:
            if hostname in patterns:
                adopted_patterns[hostname] = patterns[hostname]

        self.pattern_enabled = True
        if inplace:
            allowlist["patterns"] = adopted_patterns
            return
        else:
            return adopted_patterns
