import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import numpy as np

import constants

############ PLOT FUNCTIONS

def prepare_work_data(fp):
    data = pd.read_csv(fp)[["device","functionality","thresh_hostname","thresh_pattern","thresh_domain"]]
    formats = ["hostname", "pattern", "domain"]
    for fmt in formats:
        data.loc[:, fmt] = ["Working" if dp != 0 else "Not Working" for dp in data[f"thresh_{fmt}"]]
    plot_data = data.melt(id_vars=["device", "functionality"], value_vars=formats, var_name="Host Repr.", value_name="Working")
    plot_data = plot_data.replace({"hostname": "Hostname", "domain": "Domain", "pattern": "Pattern"})

    return plot_data


def plot_working_func(fp):
    plot_data = prepare_work_data(fp)
    plot_data = plot_data.groupby("Host Repr.")["Working"].value_counts().rename("Result").reset_index().pivot(index="Host Repr.", columns="Working", values="Result").reindex(["Hostname", "Pattern", "Domain"])[["Working", "Not Working"]]
    
    print(plot_data)

    ax = plot_data.plot.barh(stacked=True, color=["royalblue", "gainsboro"], figsize=(5.5, 3))
    # src: https://stackoverflow.com/questions/41296313/stacked-bar-chart-with-centered-labels
    for col, c in zip(plot_data.columns, ax.containers):
        labels = [int(v.get_width()) if v.get_width() > 0 else '' for v in c]
        text_color = "white" if col == "Working" else "black"
        ax.bar_label(c, labels=labels, label_type='center', color=text_color)
    ax.set_xlim(0, 148)
    ax.set_xlabel("Number of Functionalities")
    ax.set_ylabel("Allowlist Type")
    ax.legend(ncol=2, bbox_to_anchor=(0.5, 1), loc='lower center')
    plt.tight_layout()
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/work.png")
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/work.pdf")

def plot_working_dev(fp):
    plot_data = prepare_work_data(fp)
    plot_data = plot_data[["device", "Host Repr.", "Working"]].drop_duplicates()
    partially_working = plot_data.groupby(["device", "Host Repr."])["Working"].nunique()
    partially_working = partially_working[partially_working > 1]
    plot_data = plot_data.join(partially_working, on=["device", "Host Repr."], rsuffix="_dev")
    plot_data.loc[:, "Working_dev"] = [orig_status if pd.isna(new_status) else "Partially Working" for orig_status, new_status in zip(plot_data["Working"], plot_data["Working_dev"])]
    plot_data = plot_data[["device", "Host Repr.", "Working_dev"]].drop_duplicates()
    plot_data = plot_data.groupby("Host Repr.")["Working_dev"].value_counts().rename("Result").reset_index().pivot(index="Host Repr.", columns="Working_dev", values="Result").reindex(["Hostname", "Pattern", "Domain"])[["Working", "Partially Working", "Not Working"]]

    print(plot_data)

    ax = plot_data.plot.barh(stacked=True, color=["royalblue", "#A2C8E0", "gainsboro"], figsize=(5.5, 3))
    # src: https://stackoverflow.com/questions/41296313/stacked-bar-chart-with-centered-labels
    for col, c in zip(plot_data.columns, ax.containers):
        labels = [int(v.get_width()) if v.get_width() > 0 else '' for v in c]
        text_color = "white" if col == "Working" else "black"
        ax.bar_label(c, labels=labels, label_type='center', color=text_color)
    ax.set_xlim(0, 24)
    ax.set_xlabel("Number of Devices")
    ax.set_ylabel("Allowlist Type")
    ax.legend(ncol=3, bbox_to_anchor=(0.5, 1), loc='lower center')
    plt.tight_layout()
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/work_dev.png")
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/work_dev.pdf")

def plot_work_combined(fp):
    data = prepare_work_data(fp)

    func_data = data.groupby("Host Repr.")["Working"].value_counts().rename("Result").reset_index().pivot(index="Host Repr.", columns="Working", values="Result").reindex(["Hostname", "Pattern", "Domain"])[["Working", "Not Working"]]

    dev_data = data[["device", "Host Repr.", "Working"]].drop_duplicates()
    partially_working = dev_data.groupby(["device", "Host Repr."])["Working"].nunique()
    partially_working = partially_working[partially_working > 1]
    dev_data = dev_data.join(partially_working, on=["device", "Host Repr."], rsuffix="_dev")
    dev_data.loc[:, "Working_dev"] = [orig_status if pd.isna(new_status) else "Partially Working" for orig_status, new_status in zip(dev_data["Working"], dev_data["Working_dev"])]
    dev_data = dev_data[["device", "Host Repr.", "Working_dev"]].drop_duplicates()
    dev_data = dev_data.groupby("Host Repr.")["Working_dev"].value_counts().rename("Result").reset_index().pivot(index="Host Repr.", columns="Working_dev", values="Result").reindex(["Hostname", "Pattern", "Domain"])[["Working", "Partially Working", "Not Working"]]

    print(func_data)
    print(dev_data)

    fig, axes = plt.subplots(nrows=2, ncols=1, figsize=(5.5, 6))
    dev_data.plot.barh(stacked=True, color=["royalblue", "#A2C8E0", "gainsboro"], figsize=(5.5, 4), ax=axes[0])
    func_data.plot.barh(stacked=True, color=["royalblue", "gainsboro"], figsize=(5.5, 4), ax=axes[1])
    for data, ax in zip([dev_data, func_data], axes):
        for col, c in zip(data.columns, ax.containers):
            labels = [int(v.get_width()) if v.get_width() > 0 else '' for v in c]
            text_color = "white" if col == "Working" else "black"
            ax.bar_label(c, labels=labels, label_type='center', color=text_color)
        ax.set_ylabel("Allowlist Type")
    axes[0].set_xlabel("Number of Devices")
    axes[0].set_xlim(0, 24)
    axes[0].legend(ncol=3, bbox_to_anchor=(0.5, 1), loc='lower center')
    axes[1].set_xlabel("Number of Functionality")
    axes[1].set_xlim(0, 148)
    # axes[1].legend(ncol=2, bbox_to_anchor=(0.5, 1), loc='lower center')
    axes[1].get_legend().set_visible(False)
    plt.tight_layout()
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/work_combined.png")
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/work_combined.pdf")


def plot_failures(input_fp, output_fn="failures", percent=False):
    fmts = ["hostname", "pattern", "domain"]
    if percent:
        plot_df = pd.concat([get_failures_by_func(input_fp, fmts, percent), get_failures_by_dev(input_fp, fmts, percent)], axis=1)
    else:
        plot_df = pd.concat([get_failures_by_func(input_fp, fmts), get_failures_by_dev(input_fp, fmts)], axis=1)
    
    total = {"Functionality": 0, "Devices": 0}
    total["Functionality"] = plot_df.total_funcs.unique()[0]
    total["Devices"] = plot_df.total_devs.unique()[0]

    fig, axes = plt.subplots(1, 2, sharey=True)
    for i, plot_by in enumerate(["Functionality", "Devices"]):
        cols = [f"{fmt}_func_count" for fmt in fmts] if plot_by == "Functionality" else [f"{fmt}_dev_count" for fmt in fmts]
        plot_grouped_barh(
            data=plot_df[cols],
            cols=cols,
            ax=axes[i],
            hue_labels=[fmt.capitalize() for fmt in fmts],
            y_title="Failure Reason" if i==0 else "",
            x_title=f"Percent of {plot_by} Affected\n(N={total[plot_by]})" if percent else f"Number of {plot_by} Affected\n(N={total[plot_by]})",
            grid=True,
            legend=i==1
        )
        axes[i].xaxis.set_major_formatter(mtick.PercentFormatter(1, decimals=0))
    axes[0].invert_yaxis()

    plt.tight_layout()
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/{output_fn}.png")
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/{output_fn}.pdf")

def plot_failures_by_func(fp):
    fmts = ["hostname", "pattern", "domain"]
    plot_df = get_failures_by_func(fp, fmts)

    fig, ax = plt.subplots()
    plot_grouped_barh(
        data=plot_df,
        cols=fmts,
        ax=ax,
        hue_labels=[fmt.capitalize() for fmt in fmts],
        output_dir=constants.REAL_WORLD_GRAPH_DIR,
        output_fn="failure_by_func",
        y_title="Failure Reason",
        x_title="Number of Functionality Affected",
        grid=True
    )

def plot_failures_by_dev(fp):
    fmts = ["hostname", "pattern", "domain"]
    plot_df = get_failures_by_dev(fp, fmts)

    fig, ax = plt.subplots()
    plot_grouped_barh(
        data=plot_df,
        cols=fmts,
        ax=ax,
        output_dir=constants.REAL_WORLD_GRAPH_DIR,
        output_fn="failure_by_dev",
        y_title="Failure Reason",
        x_title="Number of Devices Affected",
        grid=True
    )

def plot_grouped_barh(data, cols, ax, output_dir=None, output_fn=None, hue_labels=None, height=None, y_title="", x_title="", grid=False, legend=True):
    if hue_labels is None:
        hue_labels = cols

    # src: https://matplotlib.org/stable/gallery/lines_bars_and_markers/barchart.html
    y_labels = data.index

    y = np.arange(len(y_labels))  # the label locations
    height = 0.25 if height is None else height  # the height of the bars
    offsets = _get_offsets(len(hue_labels), height)

    for col, fmt, y_offset in zip(cols, hue_labels, offsets):
        ax.barh(y+y_offset, width=data[col], height=height, label=fmt.capitalize())
    
    ax.set_yticks(y, y_labels)
    ax.set_ylabel(y_title)
    ax.set_xlabel(x_title)
    if legend:
        ax.legend()
    if grid:
        ax.grid(True, axis="x")

    if not output_dir is None and not output_fn is None:
        plt.tight_layout()
        plt.savefig(f"{output_dir}/{output_fn}.png")
        plt.savefig(f"{output_dir}/{output_fn}.pdf")

############ GET DATA

def get_failures_by_func(fp, fmts, percent=False):
    data = pd.read_csv(fp)[["device","functionality","failure_hostname","failure_pattern","failure_domain"]]
    total_funcs = data.functionality.count()
    data = data.dropna(how="all", subset=["failure_hostname","failure_pattern","failure_domain"])
    data.loc[:, "failure_hostname"] = [format_reason(r) for r in data.failure_hostname]
    data.loc[:, "failure_pattern"] = [format_reason(r) for r in data.failure_pattern]
    data.loc[:, "failure_domain"] = [format_reason(r) for r in data.failure_domain]
    plot_df = pd.concat([data[f"failure_{fmt}"].value_counts().rename(f"{fmt}_func_count") for fmt in fmts], axis=1)
    plot_df = plot_df.fillna(0)
    plot_df = plot_df / total_funcs if percent else plot_df.astype(int)
    plot_df.loc[:, "total_funcs"] = total_funcs
    print(plot_df)
    return plot_df

def get_failures_by_dev(fp, fmts, percent=False):
    data = pd.read_csv(fp)[["device","functionality","failure_hostname","failure_pattern","failure_domain"]]
    total_devs = data.device.nunique()
    data = data.dropna(how="all", subset=["failure_hostname","failure_pattern","failure_domain"])
    data.loc[:, "failure_hostname"] = [format_reason(r) for r in data.failure_hostname]
    data.loc[:, "failure_pattern"] = [format_reason(r) for r in data.failure_pattern]
    data.loc[:, "failure_domain"] = [format_reason(r) for r in data.failure_domain]
    plot_df = pd.concat([data.groupby(f"failure_{fmt}").device.nunique().rename(f"{fmt}_dev_count") for fmt in fmts], axis=1)
    plot_df = plot_df.fillna(0)
    plot_df = plot_df / total_devs if percent else plot_df.astype(int)
    plot_df.loc[:, "total_devs"] = total_devs
    print(plot_df)
    return plot_df

############ HELPERS

def _get_offsets(n_cat, offset_unit):
    coefs = np.arange(n_cat) - (n_cat - 1) / 2
    return [n * offset_unit for n in coefs]

def format_reason(reason):
    return reason if pd.isna(reason) or reason != "Interaction Dependency" else "Interaction\nDependency"