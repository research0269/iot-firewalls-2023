import pandas as pd
import tldextract
from datetime import datetime

from util.general import print_log
import constants


######### Handling devices #########

def get_geo_by_tz(tz):
    for loc in constants.TZ_DICT.keys():
        if tz in constants.TZ_DICT[loc]:
            return loc

def get_start_ts(dev_id, flows):
    return pd.to_datetime(flows[flows.device_id == dev_id].ts.min(), unit="s")

def format_raw_dev_data(devs, cleaned_devs, dev_types, flows):
    devs = devs.drop(columns=["device_vendor", "device_name", "device_type"])
    cleaned_devs = cleaned_devs.set_index("device_id")
    devs = devs.join(cleaned_devs, on="device_id")
    devs = devs.dropna(subset=["device_vendor", "device_name"])
    devs.loc[:, "vendor_product"] = [f"{vendor}:{product}" for vendor, product in zip(devs.device_vendor, devs.device_name)]
    devs = devs.join(dev_types.set_index("vendor_product"), on="vendor_product")
    devs.loc[:, "start_ts"] = [get_start_ts(devid, flows) for devid in devs.device_id]
    devs.loc[:, "tz_geo"] = [get_geo_by_tz(tz) for tz in devs.tz]

    devs = devs[["device_id", "user_key", "device_vendor", "device_name", "vendor_product", "device_type", "start_ts", "tz", "tz_geo"]]
    return devs

######### Handling flows #########

def remove_local_network(flows):
    print_log(f"Original amount of flows: {len(flows.index)}")
    new_flows = flows[flows.remote_hostname.values != "(Local Network)"]
    print_log(f"After removing local network: {len(new_flows.index)}")
    return new_flows

def remove_case_sensitivity(flows):
    flows.loc[:, "fixed_domain"] = flows.fixed_domain.str.lower()
    flows.loc[:, "fixed_hostname"] = flows.fixed_hostname.str.lower()
    if "short_domain" in flows.columns:
        flows.loc[:, "short_domain"] = flows.short_domain.str.lower()
    if "short_hostname" in flows.columns:
        flows.loc[:, "short_hostname"] = flows.short_hostname.str.lower()

def remove_question_mark(feature):
    return feature[:-1] if not pd.isna(feature) and feature.endswith("?") else feature

def remove_port_from_hostname(hostname):
    if pd.isna(hostname):
        return hostname
    if ":" not in hostname:
        return hostname
    is_quesionable = hostname.endswith("?")
    colon_index = hostname.index(":")
    if is_quesionable:
        return hostname[:colon_index] + "?"
    else:
        return hostname[:colon_index]

def remove_weird_sni(flows):
    # remove unwanted 
    flows = flows[flows.short_hostname != "sfserver/d9f7f2e6"]

    flows.loc[:, "short_hostname"] = [bytes.decode(hostname) if isinstance(hostname, bytes) else hostname for hostname in flows.short_hostname]
    flows.loc[:, "short_domain"] = [bytes.decode(domain) if isinstance(domain, bytes) else domain for domain in flows.short_domain]

    # remove hostname startswith `*.`
    print_log(flows.loc[flows.short_hostname.str.startswith("*.", na=False), "short_hostname"].unique())
    flows.loc[flows.short_hostname.str.startswith("*.", na=False), ["short_hostname"]] = flows.loc[flows.short_hostname.str.startswith("*.", na=False), "short_hostname"].map(lambda x: x[2:])
    print_log(flows.loc[flows.short_hostname.str.startswith("*.", na=False), "short_hostname"].unique())

    return flows

def remove_unqualified_devices(devs, flows):
    REMOVED_DEV_IDS = ['sb4cbfbe9cf']
    devs = devs[~devs.device_id.isin(REMOVED_DEV_IDS)]
    flows = flows[~flows.device_id.isin(REMOVED_DEV_IDS)]
    return devs, flows

def fill_domain_by_hostname(domain, hostname):
    if not pd.isna(domain):
        return domain
    if pd.isna(hostname):
        return domain
    
    is_quesionable = hostname.endswith("?")
    short_hostname = hostname[:-1] if is_quesionable else hostname

    subdomain, sld, tld = tldextract.extract(short_hostname)
    hostname_domain = sld + '.' + tld if tld != "" else sld
    hostname_domain = hostname_domain + '?' if is_quesionable else hostname_domain

    return hostname_domain

def fill_feature_by_same_group(known_dict, map_by_value, feature_value, group_value, count_list):
    if count_list[0] % 1000000 == 0:
        print_log("[fill_feature_by_same_group] progress: {}".format(count_list[0]/count_list[1]))
    count_list[0] += 1
    
    short_feature_value = remove_question_mark(feature_value)
    
    # feature_value is NaN
    if pd.isna(feature_value) or pd.isna(short_feature_value):
        return feature_value

    # feature_value is already accurate
    if not feature_value.endswith('?'):
        return feature_value
    
    # don't have that group_value, cannot fix
    if not group_value in known_dict:
        return feature_value
    
    # no same ip / asn
    if not map_by_value in known_dict[group_value]:
        return feature_value

    # if there is a match (i.e. the non-questionmark version is correct)
    if short_feature_value in known_dict[group_value][map_by_value]:
        return short_feature_value
    else:
        return feature_value

def fill_feature_for_all(known_dict, map_by_value, feature_value, count_list):
    if count_list[0] % 1000000 == 0:
        print_log("[fill_feature_for_all] progress: {}".format(count_list[0]/count_list[1]))
    count_list[0] += 1
    
    short_feature_value = remove_question_mark(feature_value)

    # in case of feature_value is NaN
    if pd.isna(feature_value):
        return feature_value

    # in case of feature_value is already accurate
    if not feature_value.endswith('?'):
        return feature_value
    
    # in case where map_by_value is unknown
    if not map_by_value in known_dict:
        return feature_value

    # incase feature value cannot be found in group
    if short_feature_value in known_dict[map_by_value]:
        return short_feature_value
    else:
        return feature_value

def get_grouped_feature_map(known_df, feature, group_name, map_by="remote_ip"):
    '''
    Get the feature mapping for each group. The mapping could be IP-based or ASN-based.
    ---
    known_df:   (DataFrame) the dataframe that contains all the mapping information
    feature:    (str) the feature name, expected to be `remote_reg_domain` or `remote_hostname` or `fixed_domain` or `fixed_hostname`
    group_name: (str) the group name, expected to be `vendor_product` or `device_vendor`
    map_by:     (str) the col name of mapping basis, expected to be `remote_ip` or `asn`. Default to `remote_ip`.
    ---
    RETURN:
        (dict) {<group_name>: {<ip_addr>: [<feature_value_1>, ..., <feature_value_n>]}} where n >= 1
    '''
    known_gb = known_df.groupby([group_name, map_by])[feature]
    known_dict = {}
    total = known_df[map_by].nunique()
    count = 1
    for group_ip, feature_values in known_gb:
        if count % 10000 == 0:
            print_log("[get_grouped_feature_map] progress: {}".format(count/total))
        if not group_ip[0] in known_dict:
            known_dict[group_ip[0]] = {}
        known_dict[group_ip[0]][group_ip[1]] = list(feature_values.dropna().unique())
        count += 1
    return known_dict

def clean_feature_by_same_group(flows, feature, group_name, known_dict, output_col_name, map_by="remote_ip"):
    q_orig_len = len(flows[flows[feature].str.endswith('?').fillna(False)].index)
    orig_total_len = len(flows.index)
    
    count = [1, orig_total_len]
    flows.loc[:, output_col_name] = [
        fill_feature_by_same_group(known_dict, by, feature_value, group_value, count) \
        for by, feature_value, group_value in zip(flows[map_by], flows[feature], flows[group_name])
    ]
    
    q_new_len = len(flows[flows[output_col_name].str.endswith('?').fillna(False)].index)
    new_total_len = len(flows.index)
    
    print_log(f"New dataframe has {new_total_len} flows, compared to {orig_total_len} in the original flows.")
    print_log(f"Questionable {feature} drop from {q_orig_len / orig_total_len} to {q_new_len / new_total_len}.")
    
    return flows

def get_feature_map(known_df, feature, map_by="remote_ip"):
    '''
    Get the feature mapping based on all the data. 
    ---
    known_df:   (DataFrame) the dataframe that contains all the mapping information
    feature:    (str) the feature name, expected to be `remote_reg_domain` or `remote_hostname` or `fixed_domain` or `fixed_hostname`
    map_by:     (str) the col name of mapping basis, expected to be `remote_ip` or `asn`. Default to `remote_ip`.
    ---
    RETURN:
        (dict) {<mapby>: [<feature_value_1>, ..., <feature_value_n>]} where n >= 1
    '''
    known_gb = known_df.groupby(map_by)[feature]
    known_dict = {}
    total = known_df[map_by].nunique()
    count = 1
    for map_by_value, feature_values in known_gb:
        if count % 10000 == 0:
            print_log("precompute: {}".format(count/total))
        known_dict[map_by_value] = list(feature_values.dropna().unique())
        count += 1
    return known_dict

def clean_feature_by_asn(flows, known_dict, feature, output_col_name):
    q_orig_len = len(flows[flows[feature].str.endswith('?', na=False)].index)
    orig_total_len = len(flows.index)
    
    count = [1, orig_total_len]
    
    flows.loc[:, output_col_name] = [
        fill_feature_for_all(known_dict, asn, feature_value, count) \
        for feature_value, asn in zip(flows[feature], flows.asn)
    ]
    
    q_new_len = len(flows[flows[output_col_name].str.endswith('?').fillna(False)].index)
    new_total_len = len(flows.index)
    
    print_log(f"New dataframe has {new_total_len} flows, compared to {orig_total_len} in the original flows.")
    print_log(f"Questionable {feature} drop from {q_orig_len / orig_total_len} to {q_new_len / new_total_len}.")
    
    return flows

def clean_domain_by_hostname(domain, hostname):
    if pd.isna(hostname):
        return domain
    if hostname.endswith("?"):
        return domain
    
    # now the hostname is determined
    subdomain, sld, tld = tldextract.extract(hostname)
    hostname_domain = sld + '.' + tld if tld != "" else sld

    if domain is None:
        # update domain if domain is unknown
        return hostname_domain
    if domain.endswith("?"):
        # remove question mark if domain is unreliable
        return hostname_domain
    # should be cases where domain is reliable
    if hostname_domain != domain:
        # in case hostname and domain are not consistent
        print_log(f"\t{hostname}\t{domain}")
    return domain

def process_domains(flows, out_fp):
    for map_by in ['asn']:
        for group in ["vendor_product", "device_vendor"]:
            print_log(f"\n### Cleaning domain data from same {group} based on {map_by} ###")
            target_feature = "fixed_domain" if "fixed_domain" in flows.columns else "remote_reg_domain"
            print_log(f"target_feature = {target_feature}")
            KNOWN_DF = flows.loc[~flows[target_feature].str.endswith('?', na=False), [map_by, target_feature, group]].drop_duplicates()
            print_log(f"...Computing {group}-domain mapping...")
            KNOWN_DICT = get_grouped_feature_map(KNOWN_DF, feature=target_feature, group_name=group, map_by=map_by)
            print_log("...Updating domains...")
            clean_feature_by_same_group(flows, feature=target_feature, group_name=group, known_dict=KNOWN_DICT, output_col_name="fixed_domain")
            print_log("...Writing to file...")
            flows.to_parquet(out_fp)

    print_log("\nCleaning domain data from same asn...")
    KNOWN_ASN_DF = flows[(~flows.fixed_domain.str.endswith('?').fillna(False)) & (~flows.fixed_domain.isna())].loc[:, ['fixed_domain', 'asn']].drop_duplicates()
    print_log("...Computing asn-domain mapping...")
    KNOWN_ASN_DICT = get_feature_map(KNOWN_ASN_DF, feature="fixed_domain", map_by="asn")
    print_log("...Updating domains...")
    clean_feature_by_asn(flows, known_dict=KNOWN_ASN_DICT, feature="fixed_domain", output_col_name="fixed_domain")
    print_log("...Writing to file...")
    flows.to_parquet(out_fp)

def process_hostname(flows, out_fp):
    # the order here is important
    for map_by in ['remote_ip', 'asn']:
        for group in ["vendor_product", "device_vendor"]:
            print_log(f"\n### Cleaning hostname data from same {group} based on {map_by} ###")
            target_feature = "fixed_hostname" if "fixed_hostname" in flows.columns else "remote_hostname"
            print_log(f"target_feature = {target_feature}")
            KNOWN_DF = flows.loc[~flows[target_feature].str.endswith('?').fillna(False), [map_by, target_feature, group]].drop_duplicates()
            print_log(f"...Computing {group}-hostname mapping...")
            KNOWN_DICT = get_grouped_feature_map(KNOWN_DF, feature=target_feature, group_name=group, map_by=map_by)
            clean_feature_by_same_group(flows, feature=target_feature, group_name=group, known_dict=KNOWN_DICT, output_col_name="fixed_hostname", map_by=map_by)
            print_log("...Writing to file...")
            flows.to_parquet(out_fp)

    print_log("\n### Cleaning hostname data from same asn ###")
    KNOWN_ASN_DF = flows.loc[~flows.fixed_hostname.str.endswith('?').fillna(False), ['fixed_hostname', 'asn']].drop_duplicates()
    print_log("...Computing asn-hostname mapping...")
    KNOWN_ASN_DICT = get_feature_map(KNOWN_ASN_DF, feature="fixed_hostname", map_by="asn")
    print_log("...Updating hostnames...")
    clean_feature_by_asn(flows, known_dict=KNOWN_ASN_DICT, feature="fixed_hostname", output_col_name="fixed_hostname")
    print_log("...Writing to file...")
    flows.to_parquet(out_fp)

    flows.loc[:, "fixed_hostname"] = [remove_port_from_hostname(hostname) for hostname in flows.fixed_hostname]
    flows.loc[:, "fixed_domain"] = [remove_port_from_hostname(domain) for domain in flows.fixed_domain]

    print_log("\n### Updating domains by hostname ###")
    print_log(f"fixed_domain before cleaning: {get_questionmark_percentage(flows, 'fixed_domain')}")
    flows.loc[:, "fixed_domain"] = [clean_domain_by_hostname(domain, hostname) for domain, hostname in zip(flows.fixed_domain, flows.fixed_hostname)]
    print_log(f"fixed_domain after cleaning: {get_questionmark_percentage(flows, 'fixed_domain')}")
    flows.to_parquet(out_fp)

def get_determined_features(flows, enforce_update=False):
    print_log("getting short_domain and short_hostname...")
    if "short_domain" not in flows.columns or enforce_update:
        flows.loc[:, 'short_domain'] = [remove_question_mark(domain) for domain in flows.fixed_domain]
    if "short_hostname" not in flows.columns or enforce_update:
        flows.loc[:, 'short_hostname'] = [remove_question_mark(hostname) for hostname in flows.fixed_hostname]
    
    # remove port from hostname and domains
    print_log("removing ports...")
    flows.loc[:, "short_hostname"] = [remove_port_from_hostname(hostname) for hostname in flows.short_hostname]
    flows.loc[:, "short_domain"] = [remove_port_from_hostname(domain) for domain in flows.short_domain]

    print_log("removing weird sni...")
    flows = remove_weird_sni(flows)

    # remove IP from hostname and domain
    print_log("removing IP...")
    flows.loc[flows.remote_ip == flows.short_domain, "short_domain"] = None
    flows.loc[flows.remote_ip == flows.short_hostname, "short_hostname"] = None

    return flows

def format_raw_flow_data(flows, devs, output_fp):
    flows.loc[:, "ts"] = pd.to_datetime(flows.ts, unit="s")
    flows = flows.join(devs.set_index("device_id")[["device_vendor", "device_name", "vendor_product", "device_type", "start_ts", "tz", "tz_geo"]], on="device_id")
    flows = remove_local_network(flows)
    flows.loc[:, "remote_reg_domain"] = flows.remote_reg_domain.astype("string")
    flows.loc[:, "remote_hostname"] = flows.remote_hostname.astype("string")
    flows = add_flow_features(flows)

    flows.loc[:, "fixed_domain"] = flows.remote_reg_domain
    flows.loc[:, "fixed_hostname"] = flows.remote_hostname

    remove_case_sensitivity(flows)
    flows.loc[:, "fixed_domain"] = [fill_domain_by_hostname(domain, hostname) for domain, hostname in zip(flows.fixed_domain, flows.fixed_hostname)]

    print_log("\nCleaning hostnames...")
    process_hostname(flows, output_fp)
    print_log("\nCleaning domains...")
    process_domains(flows, output_fp)

    flows = get_determined_features(flows)

    return flows

def add_flow_features(flows, enforce_update=False):
    # add subnet/24
    if "subnet_24" not in flows.columns or enforce_update:
        flows.loc[:, "subnet_24"] = [".".join(ip.split(".")[:3] + ["0"]) if not pd.isna(ip) else None for ip in flows.remote_ip]
    # add network (i.e., bgp prefix)
    if "network" not in flows.columns or enforce_update:
        flows.loc[:, "network"] = [".".join(ip.split(".")[:2] + ["0", "0"]) if not pd.isna(ip) else None for ip in flows.remote_ip]
    # add asn
    if "asn" not in flows.columns or enforce_update:
        flows.loc[:, "asn"] = [constants.ASNDB.lookup(remote_ip)[0] if not pd.isna(remote_ip) else remote_ip for remote_ip in flows.remote_ip]

    # add ip_port
    if "ip_port" not in flows.columns or enforce_update:
        flows.loc[:, "ip_port"] = [f"{ip}:{port}" if not pd.isna(ip) else None for ip, port in zip(flows.remote_ip, flows.remote_port)]
    # add domain_port
    if "domain_port" not in flows.columns or enforce_update:
        flows.loc[:, "domain_port"] = [f"{domain}:{port}" if not pd.isna(domain) else None for domain, port in zip(flows.short_domain, flows.remote_port)]
    # add hostname_port
    if "hostname_port" not in flows.columns or enforce_update:
        flows.loc[:, "hostname_port"] = [f"{hostname}:{port}" if not pd.isna(hostname) else None for hostname, port in zip(flows.short_hostname, flows.remote_port)]

    return flows

######### Helpers #########

def get_questionmark_percentage(flows, feature):
    return len(flows[flows[feature].str.endswith("?", na=False)].index) / len(flows.index)

# ===============================================================================

def main():
    devs = pd.read_csv(constants.DEVS_CSV_FP)
    cleaned_devs = pd.read_csv(constants.CLEANED_DEVS_CSV_FP)
    dev_types = pd.read_csv(constants.DEVTYPE_CSV_FP)
    flows = pd.read_csv(constants.FLOWS_CSV_FP)

    devs = format_raw_dev_data(devs, cleaned_devs, dev_types, flows)
    flows = format_raw_flow_data(flows, devs, constants.ALL_FLOWS_FP)

    devs, flows = remove_unqualified_devices(devs, flows)

    devs.to_parquet(constants.DEVS_FP)
    flows.to_parquet(constants.ALL_FLOWS_FP)

    return devs, flows

def get_flow_only_data():
    print_log("Readding data...")
    flows = pd.read_parquet(constants.ALL_FLOWS_FP)
    print_log("Sorting data...")
    # a flow is identified by ["device_id", "remote_ip", "device_port", "remote_port", "protocol"]
    # ts is used for preventing port reuse --- if the the same identifier show up 24 hours later, it could be a new flow
    flows = flows.sort_values(by=["device_id", "remote_ip", "device_port", "remote_port", "protocol", "ts"])
    print_log("Calculating time diff...")
    flows.loc[:, "flow_ts_skip"] = flows.groupby(["device_id", "remote_ip", "device_port", "remote_port", "protocol"]).ts.diff().dt.total_seconds().div(3600)
    print_log("Filtering out entries from the same flow...")
    flows = flows[(flows.flow_ts_skip.isna()) | (flows.flow_ts_skip > 24)]

    print_log("Writing to file...")
    flows.to_parquet(constants.FLOWS_FP)

if __name__ == "__main__":
    main()
    get_flow_only_data()
    print_log("Done!")