import pandas as pd
import constants
import matplotlib.pyplot as plt

def get_lab_data(fp):
    data = pd.read_csv(fp).dropna(how="any")
    return data

def lab_data_summary(df):
    for fmt in ["domain", "pattern", "hostname", "ip"]:
        print(f"{fmt}:\n{df[fmt].value_counts()}")

def get_ordered_result_categories(cats):
    if "Fail to Connect" in cats:
        return ["Working", ]

def plot_geo_data(df, loc="lab"):
    data = df[["device", "functionality", "domain", "hostname", "pattern"]]
    formats = ["hostname", "pattern", "domain"]
    data = data.melt(id_vars=["device", "functionality"], value_vars=formats, var_name="Host Repr.", value_name="Working")
    possible_func_results = ["Working", "Not Working"]
    if data["Working"].dropna().nunique() > 2:
        possible_func_results.append("Fail to Connect")
    data = data.replace({"hostname": "Hostname", "domain": "Domain", "pattern": "Pattern"})

    func_data = data.groupby("Host Repr.")["Working"].value_counts().rename("Result").reset_index().pivot(index="Host Repr.", columns="Working", values="Result").reindex(["Hostname", "Pattern", "Domain"])[possible_func_results]

    dev_data = data[["device", "Host Repr.", "Working"]].drop_duplicates()
    partially_working = dev_data[dev_data.Working != "Fail to Connect"].groupby(["device", "Host Repr."])["Working"].nunique()
    partially_working = partially_working[partially_working > 1]
    dev_data = dev_data.join(partially_working, on=["device", "Host Repr."], rsuffix="_dev")
    dev_data.loc[:, "Working_dev"] = [orig_status if pd.isna(new_status) else "Partially Working" for orig_status, new_status in zip(dev_data["Working"], dev_data["Working_dev"])]
    dev_data = dev_data[["device", "Host Repr.", "Working_dev"]].drop_duplicates()
    possible_dev_results = ["Working", "Partially Working", "Not Working"]
    if dev_data["Working_dev"].dropna().nunique() > 3:
        possible_dev_results.append("Fail to Connect")
    dev_data = dev_data.groupby("Host Repr.")["Working_dev"].value_counts().rename("Result").reset_index().pivot(index="Host Repr.", columns="Working_dev", values="Result").reindex(["Hostname", "Pattern", "Domain"])[possible_dev_results]
    
    print(func_data)
    print(dev_data)

    fig, axes = plt.subplots(nrows=2, ncols=1, figsize=(5.5, 6))
    if len(possible_dev_results) > 3:
        dev_data.plot.barh(stacked=True, color=["royalblue", "#A2C8E0", "gainsboro", "darkgrey"], figsize=(5.5, 4), ax=axes[0])
    else:
        dev_data.plot.barh(stacked=True, color=["royalblue", "#A2C8E0", "gainsboro"], figsize=(5.5, 4), ax=axes[0])
    if len(possible_func_results) > 2:
        func_data.plot.barh(stacked=True, color=["royalblue", "gainsboro", "darkgrey"], figsize=(5.5, 4), ax=axes[1])
    else:
        func_data.plot.barh(stacked=True, color=["royalblue", "gainsboro"], figsize=(5.5, 4), ax=axes[1])
    for data, ax in zip([dev_data, func_data], axes):
        for col, c in zip(data.columns, ax.containers):
            labels = [int(v.get_width()) if v.get_width() > 0 else '' for v in c]
            text_color = "white" if col == "Working" else "black"
            ax.bar_label(c, labels=labels, label_type='center', color=text_color)
        ax.set_ylabel("Allowlist Type")
    axes[0].set_xlabel("Number of Devices")
    axes[0].set_xlim(0, 24)
    axes[0].legend(ncol=3 if len(possible_dev_results) == 3 else 2, bbox_to_anchor=(0.5, 1), loc='lower center')
    axes[1].set_xlabel("Number of Functionality")
    axes[1].set_xlim(0, 148)
    axes[1].get_legend().set_visible(False)
    plt.tight_layout()
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/work_{loc}_combined.png")
    plt.savefig(f"{constants.REAL_WORLD_GRAPH_DIR}/work_{loc}_combined.pdf")