import json, difflib, re, logging, math
import pandas as pd

from util.general import format_filename, log
from rule_creation.extract_patterns import combine_similar_hostnames

RULE_GEN_LEVELS = [
    'product', 
    'vendor', 
    'type', 
    'others'
]

def getThreshes(data_len):
    if data_len <= 10:
        occ_thresh = list(range(1, data_len+1))
    else:
        occ_thresh = [1,2,3,4,5]
        new_thresh = [int(0.1 * x * data_len) for x in range(math.ceil(50/data_len), 10)]
        if new_thresh[0] == 5:
            new_thresh = new_thresh[1:]
        occ_thresh.extend(new_thresh)
    return occ_thresh

def getRulesByOccurrence(flows, by='remote_ip', occurrence=1):
    count_df = flows[~flows[by].isna()].groupby(by).device_id.nunique()
    rules = count_df[count_df >= occurrence].index
    return list(rules)

def getRulesByPattern(flows, pattern_map, thresh=1):
    hostnames = set(getRulesByOccurrence(flows, by="short_hostname", occurrence=thresh))
    pat_dict = {orig_hostname: hostname_pattern for orig_hostname, hostname_pattern in pattern_map.items() if orig_hostname in hostnames}
    return pat_dict

def getRulesByPatternPort(flows, pattern_map, thresh=1):
    hostnames = set(getRulesByOccurrence(flows, by="hostname_port", occurrence=thresh))
    pat_dict = {orig_hostname: hostname_pattern for orig_hostname, hostname_pattern in pattern_map.items() if orig_hostname in hostnames}
    return pat_dict

def getRulesByPattern2(flows, thresh=1, cluster_thresh=0.25, logger=None):
    # hostnames = set(getRulesByOccurance(flows, by="short_hostname", occurance=hostname_thresh))
    pat_df = combine_similar_hostnames(flows.short_hostname.dropna().unique(), logger=logger, eps_thresh=cluster_thresh, verbose=False)
    if thresh != 1:
        pat_df = pat_df.rename(columns={"orig_hostname": "short_hostname"})
        flow_pats = flows.join(pat_df.set_index("short_hostname"), on="short_hostname")
        dev_count = flow_pats[~flow_pats["hostname_pattern"].isna()].groupby("hostname_pattern").device_id.nunique()
        patterns = dev_count[dev_count >= thresh].index.values
        rules_df = pat_df[pat_df.hostname_pattern.isin(patterns)].drop_duplicates()
        rules = {hostname: pattern for hostname, pattern in zip(rules_df.short_hostname, rules_df.hostname_pattern)}
    else:
        rules = dict(zip(pat_df.orig_hostname, pat_df.hostname_pattern))
    return rules

def get_sample_dict_by_levels(df, levels=[], vp=None, vendor=None, devtype=None):
    sample_dict = {}
    for level in levels:
        assert level in RULE_GEN_LEVELS, "Incorrect level!"
        if level == 'product':
            sample_dict[level] = df[df.vendor_product.values == vp]
        elif level == 'vendor':
            sample_dict[level] = df[(df.vendor_product.values != vp) & (df.device_vendor.values == vendor)]
        elif level == 'type':
            sample_dict[level] = df[(df.vendor_product.values != vp) & (df.device_type.values == devtype)]
        elif level == 'others':
            sample_dict[level] = df[(df.vendor_product.values != vp) & (df.device_type.values != devtype)]
    return sample_dict

def get_product_pattern(vendor_product, input_dir, port=False):
    RULE_TYPE = "port-pattern" if port else "pattern"
    fn = format_filename(f"{vendor_product}-{RULE_TYPE}-map.json")
    fp = f"{input_dir}/{fn}"

    with open(fp, "r") as f:
        patterns = json.load(f)
    return patterns

def series_divide(s1, s2):
    return s1/s2

def isPatternMatched(hostname, rules):
    '''
    Whether the hostname can be matched by a pattern in rules.
    ---
    INPUT:
        hostname:   (str) the hostname
        rules:      (dict) {<hostname>: <pattern>, ...}
    ---
    RETURN:
        (bool) whether the hostname will be covered by rules
    '''
    if hostname is None:
        return False
    if hostname in rules:
        return True
    guesses = difflib.get_close_matches(hostname, rules.keys())
    for guess in guesses:
        try:
            m = re.match(rules[guess], hostname)
        except Exception as e:
            print(f"{hostname}\t{guess}\t{rules[guess]}")
            raise e
        if m:
            # rules[hostname] = rules[guess]
            return True
    return False

def getRuleDevCov(rules, dev_flows, by='remote_ip', include_dns=False, logger=None):
    # return the fraction of allowable traffic for each device

    # all traffic
    traffic = dev_flows.groupby('device_id').size()

    if include_dns:
        dns = dev_flows[dev_flows.remote_port == 53]
        flows = dev_flows[dev_flows.remote_port != 53]
    else:
        flows = dev_flows
    
    # create criterion for what kind of traffic is allowed based on rules
    if by == 'hostname_pattern':
        log(f"[getRuleDevCov] generating pattern-matching result for {flows.short_hostname.nunique()} unique hostnames...", logging.DEBUG, logger=logger)
        hostnames_in_flows, hostnames_in_rules = set(flows.short_hostname.unique()), set(rules.keys())
        hostnames_allowed = hostnames_in_flows.intersection(hostnames_in_rules)
        hostname_unknown = hostnames_in_flows.difference(hostnames_in_rules)
        # log(f"[getRuleDevCov] analyzing {len(hostname_unknown)} unsure hostnames...", logging.DEBUG, logger=logger)
        pattern_match = set([hostname for hostname in hostname_unknown if isPatternMatched(hostname, rules)])
        pattern_match = pattern_match.union(hostnames_allowed)
        log(f"[getRuleDevCov] applying result to all traffic...", logging.DEBUG, logger=logger)
        allow_traffic_criterion = flows["short_hostname"].isin(pattern_match)
    elif by == "hostname_pattern_port":
        log(f"[getRuleDevCov] generating pattern-matching result for {flows.hostname_port.nunique()} unique hostname:port...", logging.DEBUG, logger=logger)
        hostnames_in_flows, hostnames_in_rules = set(flows.hostname_port.unique()), set(rules.keys())
        hostnames_allowed = hostnames_in_flows.intersection(hostnames_in_rules)
        hostname_unknown = hostnames_in_flows.difference(hostnames_in_rules)
        # log(f"[getRuleDevCov] analyzing {len(hostname_unknown)} unsure hostnames...", logging.DEBUG, logger=logger)
        pattern_match = set([hostname for hostname in hostname_unknown if isPatternMatched(hostname, rules)])
        pattern_match = pattern_match.union(hostnames_allowed)
        log(f"[getRuleDevCov] applying result to all traffic...", logging.DEBUG, logger=logger)
        allow_traffic_criterion = flows["hostname_port"].isin(pattern_match)
    else:
        allow_traffic_criterion = flows[by].isin(rules)
    
    try:
        if include_dns:
            flows = pd.concat([dns, flows[allow_traffic_criterion]])
            allowable_traffic = flows.groupby('device_id').size()
        else:
            allowable_traffic = flows[allow_traffic_criterion].groupby('device_id').size()
    except KeyError:
        allowable_traffic = pd.Series(0, index=traffic.index)

    norm = allowable_traffic.combine(traffic, series_divide, fill_value=0).dropna()
    return norm
