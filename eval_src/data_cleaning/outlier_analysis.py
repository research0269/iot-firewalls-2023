import pandas as pd
import tldextract

import constants

def detect_outliers(flows, out_fp, threshold=.5):
    vp_groups = flows.groupby("vendor_product")

    outlier_dfs = []
    try:
        for vp, vp_flows in vp_groups:
            print(f"\n########### {vp} ###########")
            dev_count = vp_flows.device_id.nunique()
            if dev_count < 10:
                print(f"{vp} only has {dev_count} devices, skip...")
            else:
                common_domains = vp_flows.groupby("short_domain").device_id.nunique()
                common_domains = common_domains[common_domains > threshold*dev_count].index.values
                common_ips = vp_flows.groupby("remote_ip").device_id.nunique()
                common_ips = common_ips[common_ips > threshold*dev_count].index.values

                print(f"Common domains include: {common_domains}")
                print(f"Common IP include: {common_ips}")

                normal_devs = vp_flows[(vp_flows.short_domain.isin(common_domains)) | (vp_flows.remote_ip.isin(common_ips))].device_id.unique()
                outlier_devs = vp_flows[(~vp_flows.device_id.isin(normal_devs)) & (vp_flows.remote_port != 53) & (vp_flows.remote_port != 5353)].device_id.unique()
                outlier_flows = vp_flows[vp_flows.device_id.isin(outlier_devs)]

                if len(outlier_flows.index) != 0:
                    print(f"Found {outlier_flows.device_id.nunique()} outlying devices.")
                    outlier_dfs.append(outlier_flows)
                else:
                    print(f"Did not find any outlying devices.")

        print("\nFinished analyzing.")
        outliers_flows = pd.concat(outlier_dfs)
        print("saving files...")
        outliers_flows.to_parquet(out_fp)
    except Exception as e:
        print("Something goes wrong.")
        if len(outlier_dfs) > 0:
            outliers_flows = pd.concat(outlier_dfs)
            print("saving files...")
            outliers_flows.to_parquet(out_fp)
        else:
            print("There are no outliers!")

def analyze_outliers(flows):
    print(f"Found {flows.device_id.nunique()} devices from {flows.vendor_product.nunique()} products in total. ")

    vp_gorups = flows.groupby("vendor_product")

    for vp, vp_flows in vp_gorups:
        print(f"\n########### {vp} ###########")
        print(f"There are {vp_flows.device_id.nunique()} outlying devices in total.")

        dev_groups = vp_flows.groupby("device_id")

        for dev_id, dev_flows in dev_groups:
            print(f"\n====== {dev_id} ======")
            # print(dev_flows[["short_domain", "short_hostname"]].value_counts())
            print(dev_flows)

def remove_outliers(flows, outlier_flows, devs):
    outlier_dev_ids = outlier_flows.device_id.unique()
    flows = flows[~flows.device_id.isin(outlier_dev_ids)]

    devs = devs[~devs.device_id.isin(outlier_dev_ids)]
    outlier_devs = devs[devs.device_id.isin(outlier_dev_ids)]

    print("writing to file...")
    flows.to_parquet(constants.ANALYSIS_FLOWS_FP)
    devs.to_parquet(constants.ANALYSIS_DEVS_FP)
    outlier_devs.to_parquet(constants.OUTLIERS_DEVS_FP)

def dns_traffic(flows):
    dns_flows = flows[flows.remote_port == 53]

if __name__ == "__main__":
    print("reading files...")
    flows = pd.read_parquet(constants.FLOWS_FP)

    # detect_outliers(flows, constants.OUTLIERS_FLOWS_FP, threshold=.2)

    print("\n============================================================\n")

    outlier_flows = pd.read_parquet(constants.OUTLIERS_FLOWS_FP)
    analyze_outliers(outlier_flows)

    devs = pd.concat([pd.read_parquet(constants.DEVS_FP), pd.read_parquet(constants.OUTLIERS_DEVS_FP)])
    remove_outliers(flows, outlier_flows, devs)
    
    print("\ndone!")