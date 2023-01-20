import pandas as pd
import logging
from sklearn.model_selection import KFold
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import seaborn as sns

from util.general import setup_logger, log, ensure_dir_exists
from data_eval.base import get_sample_dict_by_levels, getRulesByPattern2, \
                           getRulesByOccurrence, getRuleDevCov
from util.plot import format_vp, get_top_20_products
import constants

RULE_GEN_LEVELS = [
    'product', 
    # 'vendor', 
    # 'type', 
    # 'others'
] # must contain 'product'

MIN_DEV = 50

def generateRules(devs, flows, store, features=[], levels=['product'], start_from=1, end_at=None, vps=None, step=5, min_dev=MIN_DEV, logger=None):
    assert 'product' in levels, "Missing level: product!"
    kf = KFold(n_splits=5, shuffle=True)
    
    if not vps is None:
        vp_list = vps
    elif end_at is None:
        vp_list = devs.vendor_product.unique()[start_from-1:]
    else:
        vp_list = devs.vendor_product.unique()[start_from-1:end_at]
    
    count = start_from
    total_vp = len(vp_list)
    dev_ids = devs.device_id.unique()
    
    for vp in vp_list:
        log(f"Processing {vp} ({count}/{total_vp})...", logging.INFO, logger=logger)
        
        # get data needed
        log(f"[{vp}] Getting devices...", logging.INFO, logger=logger)
        target_devs = devs[devs.vendor_product == vp]
        target_dev_ids = target_devs.device_id.unique()
        
        # skip products whose sample size is too small
        if len(target_dev_ids) < min_dev:
            count += 1
            continue
            
        devtype = target_devs.device_type.unique()[0]
        vendor, product = vp.split(':')
        
        log(f"[{vp}] Getting flows...", logging.INFO, logger=logger)
        flow_samples = get_sample_dict_by_levels(flows, levels=levels, vp=vp, vendor=vendor, devtype=devtype)
        
        median_data={"by":[], "thresh":[], "total_device_num":[], "sampled_devs_num": []}
        for level in levels:
            median_data["{}_trans".format(level)] = []

        for i in range(5):
            log(f'......Round {i+1}', logging.INFO, logger=logger)
            for by in features:
                log(f"[{vp}][{by}] Start analyzing {by}...", logging.INFO, logger=logger)
                use_pattern = by == 'hostname_pattern'
                
                # further shrink flows
                if use_pattern:
                    related_cols = ['short_hostname', 'device_id']
                else:
                    related_cols = [by, 'device_id']
                
                if 'remote_port' not in related_cols:
                    related_cols.append("remote_port")
                
                related_flow_samples = {}
                for level, sample in flow_samples.items():
                    related_flow_samples[level] = sample[related_cols]
                
                target_flows = related_flow_samples['product']
                
                for occ in [1]:
                    log(f"[{vp}][{by}] occurrence = {occ}", logging.INFO, logger=logger)
                    
                    stats_lists = {}
                    for level in levels:
                        stats_lists[level] = defaultdict(list)
                        
                    k_fold_count = 1
                    for train_dev_indice, test_dev_indice in kf.split(dev_ids):
                        log(f"[{vp}][{by}] occurrence = {occ} | k_fold = {k_fold_count} - getting rules...", logging.DEBUG, logger=logger)

                        train_all_dev_ids = list(dev_ids[train_dev_indice])
                        test_all_dev_ids = list(dev_ids[test_dev_indice])

                        train_devs = target_devs[target_devs["device_id"].isin(train_all_dev_ids)]

                        randomized_train_devs = train_devs.sample(n=len(train_devs.index))
                        train_len = len(randomized_train_devs.index)
                        cutoff = step
                        log(f"[{vp}][{by}] occurrence = {occ} | k_fold = {k_fold_count} - total device size: {train_len}", logging.DEBUG, logger=logger)
                        
                        while cutoff <= train_len:
                            if cutoff != train_len:
                                first_n_devs = randomized_train_devs.head(cutoff)
                            else:
                                first_n_devs = randomized_train_devs

                            log(f"[{vp}][{by}] occurrence = {occ} | k_fold = {k_fold_count} - using first {cutoff} devices for training...", logging.INFO, logger=logger)

                            sample_train_flows = target_flows[target_flows["device_id"].isin(first_n_devs.device_id.unique())]
                            
                            if use_pattern:
                                rules = getRulesByPattern2(sample_train_flows, thresh=occ)
                            else:
                                rules = getRulesByOccurrence(sample_train_flows, by, occ)
                            
                            if len(rules) != 0:
                                # calculate allowable traffic for each device
                                for level, sample_flows in related_flow_samples.items():
                                    log(f"[{vp}][{by}] occurrence = {occ} | k_fold = {k_fold_count} - getting rule coverage for {level}..", logging.DEBUG, logger=logger)
                                    
                                    # extract devices for test first to speed up flows selection
                                    test_flows = sample_flows[sample_flows["device_id"].isin(test_all_dev_ids)]

                                    stats_lists[level][cutoff].append(getRuleDevCov(rules, test_flows, by=by, include_dns=True))

                            if cutoff == train_len:
                                cutoff += step
                            elif cutoff + step > train_len:
                                cutoff = train_len
                            else:
                                cutoff += step

                        k_fold_count += 1
                        
                    if stats_lists['product'] == {}:
                        # if we didn't get any rules from the product
                        break

                    # allowable traffic for each device after cross validation
                    stats = {}
                    for n in stats_lists['product'].keys():
                        stats[n] = {}
                        median_data["by"].append(by)
                        median_data["thresh"].append(occ)
                        median_data["total_device_num"].append(len(target_dev_ids))
                        median_data["sampled_devs_num"].append(n)
                        for level in levels:
                            stats[n][level] = pd.concat(stats_lists[level][n], axis='index', sort=False)
                            median_data["{}_trans".format(level)].append(stats[n][level].median())
                        
            median_df = pd.DataFrame(data=median_data)
            ensure_dir_exists(f"{constants.EVAL_DIR}/sample_size/vp_data/")
            median_df.to_parquet(f"{constants.EVAL_DIR}/sample_size/vp_data/{vp}.parquet")
        try:
            orig_median_df = store.get('{}/{}/medians'.format(vendor, product))
        except KeyError:
            store.put('{}/{}/medians'.format(vendor, product), median_df)
        else:
            new_median_df = pd.concat([orig_median_df[~orig_median_df['by'].isin(features)], median_df], ignore_index=False)
            store.put('{}/{}/medians'.format(vendor, product), new_median_df)
        # store.put('{}/{}/medians'.format(vendor, product), median_df)

        count+=1

def get_trans_data(store, devs, feature=None, loops=1):
    medians_list = []
    vps = devs.vendor_product.unique()
    for vp in vps:
        vendor, product = vp.split(':')
        try:
            medians = store.get('/{}/{}/medians'.format(vendor, product))
        except KeyError:
            continue
        except ValueError:
            print(medians)
            raise
        if not feature is None:
            medians = medians[medians['by'] == feature]
        
        if not medians.empty:
            medians.loc[:, 'vp'] = vp
            medians.loc[:, "device_vendor"] = vendor
            medians.loc[:, 'device_type'] = devs[devs.vendor_product.values == vp].device_type.unique()[0]
            medians_list.append(medians)
    if len(medians_list) > 0:
        trans_df = pd.concat(medians_list, ignore_index=True)
        trans_df.loc[trans_df.device_type.isna(), 'device_type'] = "unknown"

        trans_df_size = trans_df.groupby(['vp', 'device_vendor', 'device_type', 'by', 'thresh', 'total_device_num', 'sampled_devs_num']).size()
        trans_df_mean = trans_df.groupby(['vp', 'device_vendor', 'device_type', 'by', 'thresh', 'total_device_num', 'sampled_devs_num']).mean()
        trans_df_mean.loc[:, 'loops'] = trans_df_size
        
        trans_df_mean = trans_df_mean[trans_df_mean['loops'] == loops]
        trans_df = trans_df_mean.reset_index()

        return trans_df
    else:
        return None
        
def eval_sample_size(flows_fp, devs_fp, store_fp, stats_dir, min_dev=MIN_DEV, rule_gen_by=None):
    if rule_gen_by is None:
        rule_gen_by = ['short_domain', 'short_hostname', 'hostname_pattern']

    logger = setup_logger(name="sample_size_logger", log_file="sample_size.log", level=logging.DEBUG)

    related_cols = [f if f != "hostname_pattern" else "short_hostname" for f in rule_gen_by]
    related_cols.extend(['device_id','device_vendor', 'device_type', 'vendor_product'])
    if 'remote_port' not in related_cols:
        related_cols.append('remote_port')

    related_cols = list(set(related_cols))

    # vps = ['amazon:echo', 'amazon:ring', 'amazon:fire', 'google:mini', 'google:nest', 'belkin:switch', 'wyze:camera', 'philips:bridge', 'samsung:hub', 'tplink:switch', 'google:chromecast']
    
    print("load flows...")
    flows = pd.read_parquet(flows_fp, engine='pyarrow', columns=related_cols)
    print("load devs...")
    devs = pd.read_parquet(devs_fp)
    
    ensure_dir_exists(f"{store_fp}", fp_type="file")
    with pd.HDFStore(store_fp) as store:
        for feature in rule_gen_by:
            generateRules(
                devs, 
                flows, 
                levels=RULE_GEN_LEVELS,
                store=store,
                features=[feature], 
                # start_from=394,
                # end_at=1,
                # vps = vps,
                min_dev=min_dev,
                logger=logger
            )

            trans_df = get_trans_data(store, devs, feature=feature, loops=5)
            if not trans_df is None:
                ensure_dir_exists(f"{stats_dir}")
                trans_df.to_parquet(f'{stats_dir}/stats_{feature}.parquet')

            print(trans_df)
           
    log("Done!", logging.INFO, logger=logger)

def clean_sample_size_data(stats_dir):
    stats = pd.read_parquet(f'{stats_dir}/stats.parquet')
    stats = stats[stats.sampled_devs_num % 5 == 0]
    stats.to_parquet(f'{stats_dir}/stats.parquet')

def combine_parquets(orig_df, features, stats_dir):
    dfs = [pd.read_parquet(f'{stats_dir}/stats_{f}.parquet') for f in features]
    if orig_df is not None:
        dfs.insert(0, orig_df)
    sample_size = pd.concat(dfs, ignore_index=True)
    sample_size.to_parquet(f'{stats_dir}/stats.parquet')
    print(sample_size)

def plot_heatmap(trans_df, fp, fn, vps=None, features=None, cmap='viridis'):
    if vps is not None:
        trans_df = trans_df[trans_df.vp.isin(vps)]
    if features is not None:
        trans_df = trans_df[trans_df.by.isin(features)]
    else:
        features = trans_df.by.unique()
    trans_df.loc[:, "vp"] = [format_vp(vp) for vp in trans_df.vp]
    plot_df = trans_df.replace({'by': constants.READABLE_FEATURES})
    plot_df = plot_df.rename(columns={'vp': 'Product', 'by': 'Feature', 'sampled_devs_num': 'Sample Size'})
    plot_df = plot_df[plot_df['Sample Size'].isin([5, 10, 20, 50, 100, 200])]

    print(plot_df)

    fig, axs = plt.subplots(1, len(features), figsize=(5, 6.3), sharey=True)
    cbar_ax = fig.add_axes([.31, .04, .63, .014])

    for i in range(len(features)):
        f = constants.READABLE_FEATURES[features[i]]
        print(f)
        axs[i].set_title(f)
        data = plot_df[plot_df["Feature"] == f]
        data = data[["Product", 'Sample Size', "product_trans"]]
        data = data.pivot("Product", 'Sample Size', "product_trans")
        sns.heatmap(data, cmap=cmap, square=True, ax=axs[i], vmin=0, vmax=1, cbar=i==0, cbar_ax=None if i else cbar_ax, cbar_kws={"orientation": "horizontal"})
        axs[i].set_ylabel("")
        axs[i].set_xlabel("Sample Size", position=(0.5, -0.02), horizontalalignment='center')

    plt.tight_layout()
    fig.subplots_adjust(bottom=0.15)
    plt.savefig(f"{fp}/{fn}.png")
    plt.savefig(f"{fp}/{fn}.pdf")

def sample_size_plot(data_fp, output_dir):
    sample_size_trans_df = pd.read_parquet(data_fp)
    vps = get_top_20_products()

    palette = ["#0E2E44", "#BFDDEE"]
    cmap = mcolors.LinearSegmentedColormap.from_list("my_colormap", tuple(palette))
    plot_heatmap(
        sample_size_trans_df, 
        vps=vps, 
        features=["hostname_pattern", "short_hostname"], 
        cmap=cmap, 
        fp=output_dir, 
        fn="sample_size"
    )

if __name__ == "__main__":
    eval_sample_size(
        flows_fp=constants.FLOWS_FP, 
        devs_fp=constants.DEVS_FP, 
        store_fp=constants.SAMPLE_SIZE_STORE_FP, 
        stats_dir=constants.SAMPLE_SIZE_DIR, 
        rule_gen_by=['short_hostname', 'hostname_pattern', 'short_domain']
    )
    clean_sample_size_data(stats_dir=constants.SAMPLE_SIZE_DIR)
    sample_size_plot(
        data_fp=f"{constants.SAMPLE_SIZE_DIR}/stats.parquet",
        output_dir=f"{constants.GRAPH_DIR}/sample_size"
    )