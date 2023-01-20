import pandas as pd
import json

from data_eval.base import getRulesByOccurrence, get_product_pattern, getThreshes
from util.general import format_filename, ensure_dir_exists
import constants

def feature_to_dir_name(f):
    if f == "remote_ip":
        return "ip"
    elif f == "short_hostname":
        return "hostname"
    elif f == "short_domain":
        return "domain"
    elif f == "hostname_pattern":
        return "pattern"
    else:
        return f

def create_rules(flow_fp, devs_fp, features, output_dir, vps=None):
    flows = pd.read_parquet(flow_fp)
    devs = pd.read_parquet(devs_fp)
    
    if vps is None:
        vps = devs.vendor_product.unique()

    for vp in vps:
        vp_devs = devs[devs.vendor_product==vp]
        vp_flows = flows[flows.vendor_product==vp]
        occ_thresh = getThreshes(vp_devs.device_id.nunique())

        for by in features:
            use_pattern = by == 'hostname_pattern'
            for occ in occ_thresh:
                if use_pattern:
                    rules = get_product_pattern(vp, input_dir=constants.PATTERN_DIR, port=False)
                    fn = f"{output_dir}/{format_filename(vp)}/patterns/{format_filename(vp)}-pattern-map.json"
                    ensure_dir_exists(fn, fp_type="file")
                    with open(fn, "w") as f:
                        json.dump(rules, f, indent=4)
                else:
                    rules = getRulesByOccurrence(vp_flows, by, occ)
                    rules_series = pd.Series(rules)
                    fn = f"{output_dir}/{format_filename(vp)}/{feature_to_dir_name(by)}/{occ}.csv"
                    ensure_dir_exists(fn, fp_type="file")
                    rules_series.to_csv(fn, index=False)