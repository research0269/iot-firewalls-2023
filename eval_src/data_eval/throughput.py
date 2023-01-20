import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from util.general import print_log
from util.plot import format_vp, format_dev_type
import constants

MAIN_DEVTYPE = ['voice_assistant', 'camera', 'thermostat', 'tv', 'switch', 'streaming', 'light'] 

def clean_pkt_size_data(flow_fp):
    flows = pd.read_parquet(flow_fp, engine='pyarrow', columns=["device_id", "vendor_product", "device_type", "user_key", "ts", "in_byte_count", "internal_inbound_pkt_count", "out_byte_count", "internal_outbound_pkt_count", "remote_hostname"])
    flows = flows.dropna(subset=["internal_inbound_pkt_count", "internal_outbound_pkt_count"])
    flows.loc[:, "inbound_avg_pkt_size"] = flows.in_byte_count / flows.internal_inbound_pkt_count
    flows = flows[flows.inbound_avg_pkt_size <= 1500]
    flows.loc[:, "outbound_avg_pkt_size"] = flows.out_byte_count / flows.internal_outbound_pkt_count
    flows = flows[flows.outbound_avg_pkt_size <= 1500]
    return flows

def get_data(flows, feature, windows=['5min'], output_dir=None):
    grp_id = ["device_type", "vendor_product", "device_id"] if "vendor_product" in flows.columns else ["device_type", "device_id"]
    flows = flows.groupby(grp_id + ["ts"]).sum().reset_index()
    
    print_log("Sum up data")

    winsum_dfs = []
    for window_len in windows:
        winsum = flows.set_index("ts").groupby(grp_id)[feature].rolling(window_len).sum()
        winsum = winsum.rename(f"{feature}_{window_len}")
        winsum_dfs.append(winsum)
    
    df = pd.concat(winsum_dfs, axis="columns").reset_index()

    print_log("Finish the calculation!")
    print(df)

    if output_dir:
        df.to_parquet(f"{output_dir}/{feature}_winsum.parquet")

    print_log("Done!")

    return df

def fixed_boxplot(x, y, *args, label=None, **kwargs):
    sns.boxplot(x=x, y=y, *args, **kwargs, labels=[label])

def boxplot(df, x, x_label, y, y_label, hue, grp=None, output_dir=None, fn="", log=False):
    sns.set_style("whitegrid")

    if grp is None:
        df.loc[:, f"{y}_title"] = [f"{val}\n({df[df[y] == val].device_id.nunique()} Devices, {df[df[y] == val].vendor_product.nunique()} Products)" for val in df[y]]
        ax = sns.boxplot(y=f"{y}_title", x=x, hue=hue, fliersize=2, data=df, width=.85)
        ax.set(ylabel=y_label, xlabel=x_label)
        ax.legend(ncol=2, loc="lower center", bbox_to_anchor=(.5, 1), frameon=False)
        if log:
            ax.set_xscale("log", base=2)
            # ax.set_xlim(2**0, 2**28)
            plt.xticks([2**10, 2**15, 2**20, 2**25])
            ax.set_xticklabels(["1KB", "32KB", "1MB", "32MB"])
        sns.despine(trim=True, left=True, bottom=True)
    else:
        df.loc[:, f"{y}_title"] = [f"{val}\n(Devs={df[df[y] == val].device_id.nunique()})" for val in df[y]]
        h_ratios = df.groupby(grp)[f"{y}_title"].nunique().reindex(df[grp].unique()).tolist()
        g = sns.FacetGrid(df, row=grp, sharey=False, aspect=2, gridspec_kws={"height_ratios": h_ratios})
        g.map(fixed_boxplot, x, f"{y}_title", hue=hue, fliersize=2, palette="tab10", data=df, width=.85)
        g.set_axis_labels(x_label, y_label)
        g.set_titles(row_template="Device Type = {row_name}")
        g.axes[0][0].legend(ncol=2, loc="lower center", bbox_to_anchor=(.5, 1.1), frameon=False)
        g.despine(trim=True, left=True, bottom=True)
        if log:
            for ax in g.axes[0]:
                ax.set_xscale("log", base=2)
            plt.xticks([2**10, 2**15, 2**20])
            g.set_xticklabels(["1KB", "32KB", "1MB"])

    plt.tight_layout()
    if output_dir:
        if log:
            plt.savefig(f"{output_dir}/{fn}_log.png")
            plt.savefig(f"{output_dir}/{fn}_log.pdf")

        else:
            plt.savefig(f"{output_dir}/{fn}.png")
            plt.savefig(f"{output_dir}/{fn}.pdf")


def format_byte_winsum_df(df, feature_name, window_size):
    grp_id = ["device_type", "vendor_product", "device_id"] if "vendor_product" in flows.columns else ["device_type", "device_id"]
    df = df.groupby(grp_id)[f"{feature_name}_{window_size}"].max().reset_index()
    df.loc[:, "direction"] = "Inbound" if feature_name.startswith("in") else "Outbound"
    df = df.rename(columns={f"{feature_name}_{window_size}": "byte_count"})
    df = df[grp_id + ["byte_count", "direction"]]

    return df

def plot_throughput(byte_winsum, window_size, output_dir, log=True, method="box"):
    if method == "box":
        # Method 2: log scale boxplot
        boxplot(byte_winsum, 
             x="byte_count", x_label = f"Maximum Bytes Sent/Received in {window_size[:-3]} Minute by Device", 
             y="device_type", y_label = "",
             hue="direction",
             output_dir=output_dir,
             fn=f"throughput_{window_size}",
             log=log
        )
    elif method == "vp_box":
        boxplot(byte_winsum[byte_winsum.device_type.isin(["Switch", "Light"])], 
             x="byte_count", x_label = f"Maximum Bytes Sent/Received in {window_size[:-3]} Minute per Device", 
             y="vendor_product", y_label = "",
             hue="direction",
             grp="device_type", grp_order=byte_winsum.device_type.unique(),
             output_dir=output_dir,
             fn=f"throughput_vp_{window_size}",
             log=log
        )

def prepare_winsum_data(flows=None, output_dir=constants.THRESHOLDS_STATS_DIR, window_size="5min"):
    print_log("Read data...")

    if flows is None:
        flows = pd.read_parquet(
            constants.FLOWS_FP, 
            engine='pyarrow', 
            columns=["device_id", "vendor_product", "device_type", "in_byte_count", "out_byte_count", "ts"]
        )
    else:
        flows = flows[["device_id", "vendor_product", "device_type", "in_byte_count", "out_byte_count", "ts"]]

    duration = flows.groupby("device_id").ts.max() - flows.groupby("device_id").ts.min()
    duration = duration[duration > duration.quantile(.05)]
    included_devs = duration.reset_index().device_id.unique()
    flows = flows[flows.device_id.isin(included_devs)]
    print(flows.groupby("device_type").device_id.nunique().sort_values(ascending=False))
    print_log("Got data!")

    byte_count_dfs = []
    for feature in ["in_byte_count", "out_byte_count"]:
        print_log(f"Sum up by {feature}")
        df = get_data(flows[["device_id", "vendor_product", "device_type", feature, "ts"]], feature, windows=[window_size], output_dir=output_dir)
        df = format_byte_winsum_df(df, feature, window_size=window_size)
        byte_count_dfs.append(df)
    
    byte_winsum = pd.concat(byte_count_dfs, ignore_index=True)
    
    byte_winsum = byte_winsum[byte_winsum.device_type.isin(MAIN_DEVTYPE)]
    byte_winsum.loc[:, "vp_dev_count"] = [byte_winsum[byte_winsum.vendor_product == vp].device_id.nunique() for vp in byte_winsum.vendor_product]
    byte_winsum = byte_winsum[byte_winsum.vp_dev_count > 1]
    byte_winsum.loc[:, "device_type"] = [format_dev_type(devtype) for devtype in byte_winsum.device_type]
    byte_winsum.loc[:, "vendor_product"] = [format_vp(vp) for vp in byte_winsum.vendor_product]
    byte_winsum.loc[:, "device_count"] = [byte_winsum[byte_winsum.device_type == devtype].device_id.nunique() for devtype in byte_winsum.device_type]
    byte_winsum = byte_winsum.sort_values(by=["device_count", "vp_dev_count"], ascending=False)

    return byte_winsum

if __name__ == "__main__":
    WIN_SIZE = "1min"

    flows = clean_pkt_size_data()
    byte_winsum = prepare_winsum_data(flows, output_dir=constants.THRESHOLDS_STATS_DIR, window_size=WIN_SIZE)

    plot_throughput(byte_winsum, window_size=WIN_SIZE, log=True, method="box")

    for devtype in byte_winsum.device_type.unique():
        print(f"================ {devtype} ================")
        for direction in ["Inbound", "Outbound"]:
            print(f"| {direction} |")
        print()