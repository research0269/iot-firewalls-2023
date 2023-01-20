import pandas as pd
import pathlib
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

from util.general import ensure_dir_exists
from util.plot import format_vp, format_dev_type
import constants

RULE_GEN_BY_OCC = ['remote_ip', 'short_domain', 'short_hostname']
RENAME_DICT = {
    'remote_ip': 'IP',
    'short_domain': 'Domain',
    'short_hostname': 'Hostname',
}
ABST_LEVELS = {
    # "device_vendor": "Vendor", 
    # "device_type": "Device Type", 
    "vendor_product": "Product"
}

def random_get_cdf_by(flows, devs, X, by, iter_n=100):
    total_flows = len(flows.index)
    total_unique_features = flows[by].nunique()
    # total_devs = len(devs.index)
    Y = []
    Y2 = []
    for x in X:
        temp, temp2 = 0, 0
        for i in range(iter_n):
            included_devs = devs.sample(n=x)
            included_features = flows[flows.device_id.isin(included_devs.values)][by].unique()
            included_flows = flows[flows[by].isin(included_features)]
            temp += len(included_flows.index) / total_flows
            temp2 += len(included_features) / total_unique_features
        Y.append(temp / iter_n)
        Y2.append(temp2 / iter_n)
    return Y, Y2

def get_selected_devs(devs, by, min_thresh=None, n=None):
    """
    Get selected devices from different abstraction.
    Only one of `min_thresh` and `n` should be set.
    """
    assert min_thresh is None or n is None, "`min_thresh` and `n` are mutually exclusive!"

    count = devs.groupby(by).device_id.nunique().sort_values(ascending=False)
    if min_thresh:
        selected = count[count > min_thresh]
    elif n:
        selected = count.head(n)
    else:
        selected = count
        
    return selected.index.values

def get_plot_data_by_abst(flows, devs, abst_key, n=10, out_dir="../data/variability_analysis", save_intermidate=False, save_final=True, enforce_update=False):
    selected_abst = get_selected_devs(devs, abst_key, n=n)
    data = {'X': [], 'Y_traffic': [], 'Y_feature': []}
    plot_dfs = []
    for abst_val in selected_abst:

        print(f"### {abst_val}")

        if not enforce_update and pathlib.Path(f"{out_dir}/{abst_key}/{abst_val}_cdf.parquet").is_file():
            # check if it has already been calculated
            print("...skip")
            df = pd.read_parquet(f"{out_dir}/{abst_key}/{abst_val}_cdf.parquet")
            plot_dfs.append(df)
            continue
        
        related_feature = ["device_id"]
        related_feature.extend(RULE_GEN_BY_OCC)
        selected_flows = flows.loc[flows[abst_key].values == abst_val, related_feature]
        selected_devs = pd.Series(selected_flows.device_id.unique(), name="device_id")
        data['X'] = [int(len(selected_devs) / 100 * i) for i in range(0, 101, 5)]
        dfs = []
        for feature in RULE_GEN_BY_OCC:
            print(f"[{datetime.now()}]...working on {feature}...")
            data['Y_traffic'], data['Y_feature'] = random_get_cdf_by(selected_flows[["device_id", feature]], selected_devs, data['X'], feature)
            df = pd.DataFrame(data=data)
            df.loc[:, 'feature'] = feature
            dfs.append(df)
        df = pd.concat(dfs)
        df.loc[:, 'abst_key'] = abst_key
        df.loc[:, 'abst_value'] = abst_val
        df.loc[:, 'dev_count'] = len(selected_devs.index)
        df.loc[:, 'X_perc'] = df.X / df.dev_count
        plot_dfs.append(df)
        if save_intermidate:
            ensure_dir_exists(f"{out_dir}/{abst_key}/")
            df.to_parquet(f"{out_dir}/{abst_key}/{abst_val}_cdf.parquet")
    
    plot_df = pd.concat(plot_dfs)
    if save_final:
        ensure_dir_exists(out_dir)
        plot_df.to_parquet(f"{out_dir}/{abst_key}_cdf.parquet")
    return plot_df

def get_data_by_abstraction(devs_fp, flows_fp, output_dir, n=10, enforce_update=False):
    devs = pd.read_parquet(devs_fp)
    flows = pd.read_parquet(flows_fp, columns=['device_id','device_vendor', 'device_type', 'vendor_product','remote_ip', 'short_domain', 'short_hostname'])
    
    # Abstractions:
    #   ["device_vendor", "device_type", "vendor_product"]:
    for abst in ABST_LEVELS.keys():
        print(f"# {abst}")
        get_plot_data_by_abst(flows, devs, n=n, out_dir=output_dir, abst_key=abst, save_intermidate=True, enforce_update=enforce_update)
        print()


def plot_multi_figs(df, out_dir=None, out_fn=None, by="traffic"):
    sns.set_theme(style="ticks", font_scale=1.3)
    
    grid = sns.FacetGrid(df, col="abst_value_display", hue="feature", col_wrap=10, height=3)
    grid.map(plt.plot, "X_perc", f"Y_{by}", marker="o")
    if by == "traffic":
        grid.set_axis_labels("% of Observed Devices", "% of Observed Traffic")
    else:
        grid.set_axis_labels("% of Observed Devices", "% of Observed Feature")

    for col_val, ax in grid.axes_dict.items():
        dev_counts = df[df.abst_value_display == col_val].dev_count.unique()
        n = dev_counts[0] if len(dev_counts) > 0 else 0
        ax.set_title(f"{col_val} | N={n}")
    
    for ax in grid.axes.flat:
        ax.axline((0, 0), slope=1, c=".2", ls="--", zorder=0)

    grid.fig.subplots_adjust(wspace=0.1, hspace=0.25)
    grid.fig.get_axes()[-1].legend(loc='lower right', fontsize=15)
    fig = grid.fig
    if out_fn:
        ensure_dir_exists(out_dir)
        if out_fn.endswith("png") or out_fn.endswith("pdf"):
            fig.savefig(f"{out_dir}/{out_fn}")
        else:
            fig.savefig(f"{out_dir}/{out_fn}.png")
            fig.savefig(f"{out_dir}/{out_fn}.pdf")
    return fig

def plot_by_abstraction(data_dir, output_dir, output_format="pdf"):
    dfs = []
    for abst in ABST_LEVELS:
        fp = f"{data_dir}/{abst}_cdf.parquet"
        tmp = pd.read_parquet(fp)
        
        # cleanning labels for plotting
        if abst == "vendor_product":
            tmp.loc[:, "abst_value_display"] = [format_vp(vp) for vp in tmp.abst_value]
            tmp.loc[:, "abst_value_display"] = tmp.abst_value_display.replace({"Google Chromecast": "Chromecast"})
        elif abst == "device_type":
            tmp.loc[:, "abst_value_display"] = [format_dev_type(dev_type) for dev_type in tmp.abst_value]
        else:
            tmp.loc[:, "abst_value_display"] = tmp.abst_value.str.title()
        
        tmp.replace({"remote_ip": "IP", "short_domain": "Domain", "short_hostname": "Hostname"}, inplace=True)

        tmp.loc[:, "abst"] = ABST_LEVELS[abst]

        print(tmp)
        dfs.append(tmp)

    df = pd.concat(dfs)
    df = df[df.feature.isin(list(RENAME_DICT.values()))]

    # change fraction to percentage
    if df["X_perc"].max() < 1.1:
        df.loc[:, "X_perc"] = df["X_perc"] * 100
    for by in ["traffic", "feature"]:
        if df[f"Y_{by}"].max() < 1.1:
            df.loc[:, f"Y_{by}"] = df[f"Y_{by}"] * 100
    
    # put features in order
    df = df.sort_values(by=["dev_count", "feature"], ascending=[False, False])

    summaries = []
    for product in df.abst_value.unique():
        print(f"\n### {product} ###")
        tmp = df.loc[(df.abst_value == product) & (df.Y_traffic >= 95), ["feature", "Y_traffic", "X_perc"]]
        tmp_by_feature = tmp.groupby("feature")
        for feature, data in tmp_by_feature:
            summary = data[data.X_perc == data.X_perc.min()]
            summaries.append(summary)
            print(summary)
    summary_df = pd.concat(summaries)
    print(summary_df.groupby("feature").X_perc.mean())

    plot_multi_figs(df, out_dir = output_dir, out_fn="measurements_lt_traffic", by="traffic")


def main():
    ### Figure 1 ###
    get_data_by_abstraction(
        devs_fp = constants.DEVS_FP,
        flows_fp = constants.FLOWS_FP,
        output_dir = constants.LONGTAILS_DATA_DIR,
        n=8,
        enforce_update=True
    )
    plot_by_abstraction(
        data_dir = constants.LONGTAILS_DATA_DIR,
        output_dir = constants.GRAPH_DIR
    )


if __name__ == "__main__":
    main()
    print("done!")