import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import numpy as np
from tabulate import tabulate

from variability_analysis.plot_port import get_vp_devs_data
import constants

def plot_attack_surface(data):
    devs = pd.read_parquet(constants.DEVS_FP)
    data = data.join(devs[["vendor_product", "device_type"]].drop_duplicates().set_index("vendor_product"), on="vp")
    plot_data = data.groupby(["device", "device_type"]).has_shared_domain.value_counts().rename("vulnerable_func_count").reset_index()
    plot_data.loc[~plot_data.has_shared_domain, "vulnerable_func_count"] = 0
    plot_data = plot_data.groupby("device_type").has_shared_domain.value_counts().rename("result").reset_index()
    plot_data.loc[:, "device_type"] = [devtype.replace("_", " ").capitalize() for devtype in plot_data.device_type]
    plot_data = plot_data.pivot(index="device_type", columns="has_shared_domain", values="result").rename(columns={False: "Not Contain Shared Domains", True: "Contain Shared Domains"}).fillna(0)
    # plot_data.loc[:, "Total"] = [s+v for s, v in zip(plot_data.Secure, plot_data.Vulnerable)]
    # plot_data.loc[:, "Secure"] = plot_data.Secure / plot_data.Total
    # plot_data.loc[:, "Vulnerable"] = plot_data.Vulnerable / plot_data.Total
    plot_data = plot_data[["Not Contain Shared Domains", "Contain Shared Domains"]].sort_values(by="Not Contain Shared Domains", ascending=False)
    print(plot_data)
    
    ax = plot_data[["Not Contain Shared Domains", "Contain Shared Domains"]].plot.barh(stacked=True, color=["royalblue", "gainsboro"], figsize=(6, 3.5))
    ax.xaxis.set_ticks(np.arange(0, 4, 1))
    ax.set_xlabel("Number of Devices")
    ax.set_ylabel("Device Type")
    # ax.xaxis.set_major_formatter(mtick.PercentFormatter(1, decimals=0))
    ax.invert_yaxis()
    ax.legend(ncol=2, bbox_to_anchor=(0.35, 1), loc='lower center')
    plt.tight_layout()
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/attack2.png")
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/attack2.pdf")


def calculate_attack_surface(fp):
    # get the domain-based allowlist with the highest threshold
    data = pd.read_csv(fp)[["device","functionality","thresh_domain"]]
    print(data)
    # get the list of allowed domains
    allowlists = data[["device", "thresh_domain"]].groupby("device").min().reset_index()
    allowlists = allowlists[allowlists.thresh_domain != 0]
    allowlists.loc[:, "vp"] = [label_to_vp(label) for label in allowlists.device]
    allowlists.loc[:, "allowlist_fp"] = [get_allowlist_fp(label, "domain", thresh) for label, thresh in zip(allowlists.vp, allowlists.thresh_domain)]
    allowlists.loc[:, "allowlist_len"] = [get_allowlist_len(fp) for fp in allowlists.allowlist_fp]

    # are these domains shared
    shared_domains = get_public_endpoints()
    shared_domains = shared_domains.index.to_list()
    allowlists.loc[:, "n_shared_domain"] = [shares_domain(shared_domains, fp) for fp in allowlists.allowlist_fp]
    allowlists.loc[:, "has_shared_domain"] = [n != 0 for n in allowlists.n_shared_domain]

    # link results
    results = data.join(allowlists[["device", "vp", "thresh_domain", "has_shared_domain"]].set_index(["device", "thresh_domain"]), on=["device", "thresh_domain"])
    print(results)
    return results

def get_public_endpoints_test():
    # flows = get_vp_devs_data(constants.FLOWS_FP, constants.VPS, columns=["device_id", "user_key", "device_vendor", "device_type", "short_domain", "remote_port"])
    flows = pd.read_parquet(constants.FLOWS_FP, columns=["device_id", "user_key", "device_vendor", "device_type", "short_domain", "remote_port"])
    flows = flows[(flows.remote_port != 123) & (flows.remote_port != 53)]
    flows = flows[(flows.device_type != "voice_assistant") & (flows.device_type != "streaming") & (flows.device_type != "speaker")]
    noise_estimation = flows.groupby(["short_domain", "device_vendor"]).user_key.nunique()
    flows = flows.join(noise_estimation, on=["short_domain", "device_vendor"], rsuffix="_count")
    flows = flows[flows.user_key_count > 1]
    
    print(flows[flows.short_domain == "ecobee.com"].device_vendor.unique())
    print(flows[(flows.short_domain == "ecobee.com") & (flows.device_vendor == "google")].drop_duplicates())

    print(flows[flows.device_id == "s96deca2999"].drop_duplicates())

def get_public_endpoints():
    flows = get_vp_devs_data(constants.FLOWS_FP, constants.VPS, columns=["user_key", "device_vendor", "device_type", "short_domain", "remote_port"])
    print(flows.device_vendor.nunique())
    flows = flows[(flows.remote_port != 123) & (flows.remote_port != 53)]
    flows = flows[(flows.device_type != "voice_assistant") & (flows.device_type != "streaming") & (flows.device_type != "speaker")]
    noise_estimation = flows.groupby(["short_domain", "device_vendor"]).user_key.nunique()
    flows = flows.join(noise_estimation, on=["short_domain", "device_vendor"], rsuffix="_count")
    flows = flows[flows.user_key_count > 1]
    flows = flows[flows.short_domain != "(mdns)"]
    # print(flows[(flows.short_domain=="myqdevice.com") & (flows.device_vendor == "philips")])
    rank = flows.groupby("short_domain").device_vendor.nunique().sort_values(ascending=False)
    shared_endpoints = rank[rank > 1]
    shared_endpoints.to_csv("shared_endpoints.csv")
    return shared_endpoints

def create_public_endpoints_table():
    data = get_public_endpoints()
    data = data.head(11).reset_index()
    # data = data[data.short_domain != "(mdns)"].reset_index()
    data.loc[:, "rank"] = data.index + 1
    data = data[["rank", "short_domain", "device_vendor"]]
    table = data.head(10).values
    headers = ["#", "Domain", "Num of Contacted Vendors"]
    print(tabulate(table, headers, tablefmt="latex"))

def shares_domain(shared_domains, allowlist_fp):
    allowlists = pd.read_csv(allowlist_fp, header=None).rename(columns={0: "domain"})
    allowed_domains_set = set(allowlists.domain.to_list())
    shared_domains_set = set(shared_domains)
    return len(allowed_domains_set.intersection(shared_domains_set))

def get_allowlist_len(fp):
    allowlists = pd.read_csv(fp, header=None).rename(columns={0: "domain"})
    return len(allowlists.index)

def get_allowlist_fp(label, fmt, thresh):
    vp = label_to_vp(label)
    vendor, devname = vp.split(":")
    if fmt in ["domain", "hostname", "ip"]:
        fp = f"{constants.RULES_DIR}/{vendor}/{devname}/product/{get_full_fmt_name(fmt)}.t{thresh}.csv"
        return fp
    else:
        return None

def get_full_fmt_name(fmt):
    if fmt == "hostname":
        return "short_hostname"
    elif fmt == "domain":
        return "short_domain"
    elif fmt == "ip":
        return "remote_ip"
    return None

def label_to_vp(label):
    if label == "Amazon Echo Dot":
        return "amazon:echo"
    elif label == "Amazon Fire Stick":
        return "amazon:fire"
    elif label == "TP-Link Switch":
        return "tplink:switch"
    elif label == "Google Home":
        return "google:google-home"
    elif label == "Belkin Wemo":
        return "belkin:switch"
    elif label == "Nintendo Switch":
        return "nintendo:nintendo_switch"
    elif label == "Sonos One":
        return "sonos:speaker"

    vp = ":".join([name.lower() for name in label.split(" ")])
    return vp
