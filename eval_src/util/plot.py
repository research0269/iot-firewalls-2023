import pandas as pd

import constants

def format_vp(vp):
    if vp == "google:google-home":
        vp = "google:home"
    elif vp == "nintendo:nintendo_switch":
        vp = "nintendo:switch"
    vp = vp.replace(":", " ")
    vp = vp.title()
    return vp

def format_dev_type(dev_type):
    if dev_type is None:
        return ""
    elif dev_type == "tv":
        return "TV"
    dev_type = dev_type.replace("_", " ")
    dev_type = dev_type.title()
    return dev_type

def format_feature(feature):
    if feature == "short_hostname":
        return "Hostname"
    elif feature == "short_domain":
        return "Domain"
    elif feature == "remote_ip":
        return "IP"
    else:
        print("Unknown feature")

def get_top_20_products():
    devs = pd.read_parquet(constants.DEVS_FP)
    vps = devs.vendor_product.value_counts().head(20).index.tolist()
    return vps