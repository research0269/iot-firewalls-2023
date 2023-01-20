import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap

from util.general import ensure_dir_exists
from util.plot import format_vp, format_feature
import constants

def get_popular_devs_data(data_fp, top_n=20, columns=None):
    if columns is None:
        flows = pd.read_parquet(data_fp)
    else:
        if not "vendor_product" in columns:
            columns.append("vendor_product")
        if not "device_id" in columns:
            columns.append("device_id")
        flows = pd.read_parquet(data_fp, columns=columns)

    top_devs = flows.groupby("vendor_product").device_id.nunique().sort_values(ascending=False).reset_index().head(top_n).vendor_product.unique()

    flows = flows[flows.vendor_product.isin(top_devs)]

    return flows

def remove_outliers(flows):
    products_flows = flows.groupby("vendor_product")
    for name, grp in products_flows:
        print(name)
        port_usage = grp.groupby("device_id").remote_port.nunique().sort_values(ascending=False)
        gap = port_usage / port_usage.shift(-1)
        # print(gap)
        gap = gap[(gap >= 5)]
        if len(gap) > 0:
            gap_dev = gap.sort_values(ascending=False).index.values[0]
            thresh = port_usage[gap_dev]
            if thresh > 10:
                print(f"Threshold: {thresh}")
                devs_to_drop = port_usage[port_usage >= thresh].index.values
                if len(devs_to_drop) > 0:
                    print(f"To remove devices: {devs_to_drop}")
                    flows = flows[~flows.device_id.isin(devs_to_drop)]
        else:
            print("Nothing to exclude.")
        print()

    return flows

def stringify_port_count(count):
    if pd.isna(count):
        return "N/A"
    if count == 1:
        return "1 Port"
    elif count <= 5:
        return f"{count} Ports"
    else:
        return "5+ Ports"

def plot_port_dist(flows, out_dir):
    FEATURES = ["remote_ip", "short_hostname", "short_domain"]
    plot_dfs = []

    product_flows = flows.groupby("vendor_product")
    for name, grp in product_flows:
        dfs = []
        for feature in FEATURES:
            df = grp.groupby(feature).remote_port.nunique().reset_index() \
                    .rename(columns={"remote_port": "port_count", feature: "host_repr"})
            df.loc[:, "host_repr"] = format_feature(feature)
            df.loc[:, "port_count_str"] = [stringify_port_count(port_count) for port_count in df.port_count]
            dfs.append(df)

        df = pd.concat(dfs, ignore_index=True)
        df = df.groupby("host_repr").port_count_str.value_counts().rename("port_count_occ").reset_index()
        for f in FEATURES:
            formatted_f = format_feature(f)
            df.loc[df.host_repr == formatted_f, "port_count_perc"] = df.loc[df.host_repr == formatted_f, "port_count_occ"] / grp[f].nunique()
        df.loc[:, "vp"] = format_vp(name)

        plot_dfs.append(df)
    
    plot_df = pd.concat(plot_dfs)
    plot_df_dict = {}
    for f in FEATURES:
        plot_df_dict[f] = plot_df[plot_df.host_repr == format_feature(f)].pivot(index="vp", columns="port_count_str", values="port_count_perc").fillna(0)

    colors = [
        (66, 129, 164),
        (104, 153, 182),
        (172, 188, 195),
        (234, 210, 172),
        (230, 184, 156),
        (254, 147, 140)
    ]
    for i in range(len(colors)):
        colors[i] = (colors[i][0] / 255, colors[i][1] / 255, colors[i][2] / 255)
    cmap = ListedColormap(colors)

    fig, axes = plt.subplots(1, 3, sharey=True, sharex=True, figsize=(7,4.5))
    for f, ax in zip(FEATURES, axes):
        formatted_f = format_feature(f)
        plot_df_dict[f].plot.barh(stacked=True, colormap=cmap, ax=ax)
        ax.invert_yaxis()
        ax.title.set_text(formatted_f)
        ax.set_xlabel(f"% of Unique {formatted_f}")
        ax.set_ylabel("")
        ax.get_legend().set_visible(False)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_visible(False)

    axes[-1].legend(loc="center right", bbox_to_anchor=(2, .5), frameon=False)

    plt.tight_layout()
    plt.subplots_adjust(right=0.85)

    ensure_dir_exists(out_dir)
    plt.savefig(f"{out_dir}/port_count_dist_full.png")
    plt.savefig(f"{out_dir}/port_count_dist_full.pdf")

if __name__ == "__main__":
    ### Figure 2 ###
    flows = get_popular_devs_data(data_fp=constants.FLOWS_FP, top_n=8)
    plot_port_dist(flows, out_dir=constants.GRAPH_DIR)

    print("done!")