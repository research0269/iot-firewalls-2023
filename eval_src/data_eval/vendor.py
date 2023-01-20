import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from util.plot import format_dev_type, get_top_20_products

def plot_vendor_trans_by_type(stats_fp, output_dir):
    MAIN_DEVTYPE = ['voice_assistant', 'camera', 'streaming', 'switch', 'speaker', 'light', 'network_device']
    
    trans_df = pd.read_parquet(stats_fp)
    trans_df = trans_df[trans_df.device_type.isin(MAIN_DEVTYPE)]
    top_vps = get_top_20_products()
    trans_df = trans_df[trans_df.vp.isin(top_vps)]

    trans_df.loc[:, "device_type"] = [format_dev_type(dev_type) for dev_type in trans_df.device_type]
    trans_df = trans_df[(trans_df["by"] == "short_domain") & (trans_df["thresh"] <= 5)]
    trans_df = trans_df[["by", "thresh", "device_num", "product_trans", "vendor_trans", "vp", "device_type"]]

    order = trans_df.groupby("device_type").vendor_trans.median().sort_values(ascending=False).index.tolist()
    trans_df = trans_df.melt(id_vars=["by", "thresh", "device_num", "vp", "device_type"], 
                             value_vars=['product_trans', 'vendor_trans'],
                             var_name="Types of MFAF", value_name="MFAF")
    trans_df.loc[:, "Types of MFAF"] = [
        "Transfer within Product" if k == "product_trans" else "Transfer within Vendor" for k in trans_df["Types of MFAF"]
    ]
    
    sns.set_style("whitegrid")
    ax = sns.boxplot(y="device_type", x="MFAF", hue="Types of MFAF", data=trans_df, order=order, width=.6)
    sns.despine(trim=True, left=True)

    ax.set(ylabel="", xlabel="MFAF (format = domain, thresholds <= 5)")
    ax.legend(ncol=2, loc="lower center", bbox_to_anchor=(.5, 1), frameon=False)

    plt.tight_layout()
    plt.savefig(f"{output_dir}/product_vendor_mfaf.png")
    plt.savefig(f"{output_dir}/product_vendor_mfaf.pdf")