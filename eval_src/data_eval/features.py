import pandas as pd
import logging
from sklearn.model_selection import KFold

import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import seaborn as sns

from data_eval.base import get_product_pattern, get_sample_dict_by_levels, \
                           getRulesByOccurrence, getRulesByPattern, getRulesByPatternPort, \
                           getRuleDevCov, getThreshes
from util.general import setup_logger, log, ensure_dir_exists
from util.plot import format_vp
import constants

####################################################
#   DATA GENERATION 
####################################################

RULE_GEN_LEVELS = [
    'product', 
    'vendor', 
    'type', 
    'others'
] # must contain 'product'
MIN_DEV = 10

def generateRules(devs, flows, store, features=[], levels=['product'], start_from=1, end_at=None, vps=None, include_dns=False, min_dev=MIN_DEV, logger=None):
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
        dev_samples = {}
        target_devs = devs[devs.vendor_product.values == vp]
        target_dev_ids = target_devs.device_id.unique()
        
        # skip products whose sample size is too small
        if len(target_dev_ids) < min_dev:
            count += 1
            continue

        devtype = target_devs.device_type.unique()[0]
        vendor, product = vp.split(':')
        
        dev_samples = get_sample_dict_by_levels(devs, levels=levels, vp=vp, vendor=vendor, devtype=devtype)

        log(f"[{vp}] Getting flows...", logging.INFO, logger=logger)
        flow_samples = get_sample_dict_by_levels(flows, levels=levels, vp=vp, vendor=vendor, devtype=devtype)

        # allowable traffic fraction for each instance
        log(f"[{vp}] Getting thresholds...", logging.INFO, logger=logger)
        occ_thresh = getThreshes(len(target_dev_ids))
        store.put('{}/{}/occ_thresholds'.format(vendor, product), pd.Series(occ_thresh, name='thresh'))

        median_data={"by":[], "thresh":[], "device_num":[]}
        for level in levels:
            median_data["{}_trans".format(level)] = []
        
        for by in features:
            log(f"[{vp}][{by}] Start analyzing {by}...", logging.INFO, logger=logger)
            # check if we should use range or occurrence or pattern for rule-generation
            use_pattern = by == 'hostname_pattern'
            use_pattern_port = by == 'hostname_pattern_port'
            
            # further shrink flows
            if use_pattern:
                pattern_dict = get_product_pattern(vp, input_dir=constants.PATTERN_DIR, port=False)
                related_cols = ['short_hostname', 'device_id']
            elif use_pattern_port:
                pattern_dict = get_product_pattern(vp, input_dir=constants.PATTERN_DIR, port=True)
                related_cols = ['hostname_port', 'device_id']
            else:
                related_cols = [by, 'device_id']
            
            if include_dns and "remote_port" not in related_cols:
                related_cols.append("remote_port")
            
            related_flow_samples = {}
            for level, sample in flow_samples.items():
                related_flow_samples[level] = sample.loc[:, related_cols]
            
            target_flows = related_flow_samples['product']

            for occ in occ_thresh:
                log(f"[{vp}][{by}] occurrence = {occ}", logging.INFO, logger=logger)
                
                stats_lists = {}
                for level in levels:
                    stats_lists[level] = []
                    
                k_fold_count = 1
                for train_dev_indice, test_dev_indice in kf.split(dev_ids):
                    train_all_dev_ids = dev_ids[train_dev_indice]
                    train_devs = target_devs[target_devs.device_id.isin(train_all_dev_ids)]
                    train_flows = target_flows[target_flows.device_id.isin(train_devs.device_id.unique())]
                    
                    if use_pattern:
                        rules = getRulesByPattern(train_flows, pattern_map=pattern_dict, thresh=occ)
                    elif use_pattern_port:
                        rules = getRulesByPatternPort(train_flows, pattern_map=pattern_dict, thresh=occ)
                    else:
                        rules = getRulesByOccurrence(train_flows, by, occ)

                    if len(rules) == 0:
                        # if no rules can be generated, then move on to next round
                        break
                    
                    test_all_dev_ids = dev_ids[test_dev_indice]

                    # log(f"[{vp}][{by}] occurrence = {occ} | k_fold = {k_fold_count} - saving train set, test set, and rules..", logging.DEBUG, logger=logger)

                    # save training data
                    store.put('{}/{}/{}/occ_{}/k_{}/train_devs'.format(vendor, product, by, occ, k_fold_count), pd.Series(train_all_dev_ids, name='device_id'))
                    # save testing data
                    store.put('{}/{}/{}/occ_{}/k_{}/test_devs'.format(vendor, product, by, occ, k_fold_count), pd.Series(test_all_dev_ids, name='device_id'))
                    # save generated rules
                    if use_pattern:
                        store.put('{}/{}/{}/occ_{}/k_{}/rules'.format(vendor, product, by, occ, k_fold_count), pd.DataFrame.from_records([(host, pat) for host, pat in rules.items()], columns=["orig_hostname", "hostname_pattern"]))
                    elif use_pattern_port:
                        store.put('{}/{}/{}/occ_{}/k_{}/rules'.format(vendor, product, by, occ, k_fold_count), pd.DataFrame.from_records([(host, pat) for host, pat in rules.items()], columns=["orig_hostname_port", "hostname_pattern_port"]))
                    else:
                        store.put('{}/{}/{}/occ_{}/k_{}/rules'.format(vendor, product, by, occ, k_fold_count), pd.Series(rules, name='rule'))
                    
                    # calculate allowable traffic for each device
                    for level, sample_flows in related_flow_samples.items():
                        log(f"[{vp}][{by}] occurrence = {occ} | k_fold = {k_fold_count} - getting rule coverage for {level}..", logging.DEBUG, logger=logger)
                        sample_devs = dev_samples[level]
                        
                        # extract devices for test first to speed up flows selection
                        test_devs = sample_devs[sample_devs.device_id.isin(test_all_dev_ids)]
                        
                        test_flows = sample_flows[sample_flows.device_id.isin(test_devs.device_id.unique())]
                        stats_lists[level].append(getRuleDevCov(rules, test_flows, by=by, include_dns=include_dns, logger=logger))

                    k_fold_count += 1
                    
                if len(stats_lists['product']) == 0:
                    # if we didn't get any rules from the product
                    break

                # allowable traffic for each device after cross validation
                stats = {}
                for level in levels:
                    stats[level] = pd.concat(stats_lists[level], axis='index', sort=False)
                    store.put('{}/{}/{}/occ_{}/trans_stats/{}'.format(vendor, product, by, occ, level), stats[level])

                median_data["by"].append(by)
                median_data["thresh"].append(occ)
                median_data["device_num"].append(len(target_dev_ids))
                for level in levels:
                    median_data["{}_trans".format(level)].append(stats[level].median())
                    
            median_df = pd.DataFrame(data=median_data)
            ensure_dir_exists(f"{constants.EVAL_DIR}/feature_comparison/vp_data/")
            median_df.to_parquet(f"{constants.EVAL_DIR}/feature_comparison/vp_data/{vp}.parquet")
        try:
            orig_median_df = store.get('{}/{}/medians'.format(vendor, product))
        except KeyError:
            store.put('{}/{}/medians'.format(vendor, product), median_df)
        else:
            new_median_df = pd.concat([orig_median_df[~orig_median_df['by'].isin(features)], median_df], ignore_index=False)
            store.put('{}/{}/medians'.format(vendor, product), new_median_df)
        count+=1

def get_trans_data(devs, store, min_dev=MIN_DEV, conds=None):
    if conds is None:
        conds = {}
    medians_list = []
    for vp in devs.vendor_product.unique():
        if devs[devs.vendor_product == vp].device_id.nunique() < min_dev:
            continue
        vendor, product = vp.split(':')
        try:
            medians = store.get('/{}/{}/medians'.format(vendor, product))
            medians.loc[:, 'vp'] = vp
            medians.loc[:, 'device_vendor'] = vendor
            medians.loc[:, 'device_type'] = devs[devs.vendor_product.values == vp].device_type.unique()[0]
            for k, v in conds.items():
                medians = medians[medians[k] == v]
            medians_list.append(medians)
        except KeyError:
            continue
    trans_df = pd.concat(medians_list, ignore_index=True)
    return trans_df

def calculate_flows(devs, flows, store, features, levels=["product"], include_dns=True, vps=None, end_at=None, start_from=1, min_dev=MIN_DEV, logger=None):
    '''
    Similar to generateRules(), but only used when rules have already been created
    '''
    
    if not vps is None:
        vp_list = vps
    elif end_at is None:
        vp_list = devs.vendor_product.unique()[start_from-1:]
    else:
        vp_list = devs.vendor_product.unique()[start_from-1:end_at]
    
    count = start_from
    total_vp = len(vp_list)
    
    for vp in vp_list:
        log(f"Processing {vp} ({count}/{total_vp})...", logging.INFO, logger=logger)
        vendor, product = vp.split(':')
        target_devs = devs[devs.vendor_product.values == vp]
        target_dev_ids = target_devs.device_id.unique()

        if len(target_dev_ids) < min_dev:
            count += 1
            continue
        
        try:
            threshes = store.get('{}/{}/occ_thresholds'.format(vendor, product)).tolist()
        except KeyError:
            log(f"Cannot find `{vendor}/{product}/occ_thresholds`! Ignore the product.", logging.ERROR, logger=logger)
            continue

        devtype = target_devs.device_type.unique()[0]
        dev_samples = get_sample_dict_by_levels(devs, levels=levels, vp=vp, vendor=vendor, devtype=devtype)
        flow_samples = get_sample_dict_by_levels(flows, levels=levels, vp=vp, vendor=vendor, devtype=devtype)
        median_data={"by":[], "thresh":[], "device_num":[]}
        for level in levels:
            median_data["{}_trans".format(level)] = []

        for by in features:
            use_pattern = by == 'hostname_pattern'
            use_pattern_port = by == 'hostname_pattern_port'
            
            # further shrink flows
            if use_pattern:
                related_cols = ['short_hostname', 'device_id']
            elif use_pattern_port:
                related_cols = ['hostname_port', 'device_id']
            else:
                related_cols = [by, 'device_id']

            if include_dns and "remote_port" not in related_cols:
                related_cols.append("remote_port")
            
            related_flow_samples = {}
            for level, sample in flow_samples.items():
                related_flow_samples[level] = sample.loc[:, related_cols]

            for occ in threshes:
                stats_lists = {}
                for level in levels:
                    stats_lists[level] = []

                for k_fold_count in range(1, 6):
                    try:
                        if use_pattern or use_pattern_port:
                            rules = store.get('{}/{}/{}/occ_{}/k_{}/rules'.format(vendor, product, by, occ, k_fold_count))
                            rules = dict(rules.values)
                        else:
                            rules = store.get('{}/{}/{}/occ_{}/k_{}/rules'.format(vendor, product, by, occ, k_fold_count)).tolist()
                    except KeyError:
                        log(f"Cannot find `{vendor}/{product}/{by}/occ_{occ}/k_{k_fold_count}/rules`! Create one.", logging.WARNING, logger=logger)
                        continue
                    
                    try:
                        test_dev_ids = store.get('{}/{}/{}/occ_{}/k_{}/test_devs'.format(vendor, product, by, occ, k_fold_count)).tolist()
                    except KeyError:
                        log(f"Cannot find `{vendor}/{product}/{by}/occ_{occ}/k_{k_fold_count}/test_devs`! Skip the k-fold.", logging.WARNING, logger=logger)
                        continue

                    for level, sample_flows in related_flow_samples.items():
                        log(f"[{vp}][{by}] occurrence = {occ} | k_fold = {k_fold_count} - getting rule coverage for {level}..", logging.DEBUG, logger=logger)
                        sample_devs = dev_samples[level]
                        
                        # extract devices for test first to speed up flows selection
                        test_devs = sample_devs[sample_devs.device_id.isin(test_dev_ids)]
                        test_flows = sample_flows[sample_flows.device_id.isin(test_devs.device_id.unique())]

                        stats_lists[level].append(getRuleDevCov(rules, test_flows, by=by, include_dns=include_dns, logger=logger))

                if len(stats_lists['product']) == 0:
                    # if we didn't get any rules from the product
                    break

                # allowable traffic for each device after cross validation
                stats = {}
                for level in levels:
                    stats[level] = pd.concat(stats_lists[level], axis='index', sort=False)
                    store.put('{}/{}/{}/occ_{}/trans_stats/{}'.format(vendor, product, by, occ, level), stats[level])

                median_data["by"].append(by)
                median_data["thresh"].append(occ)
                median_data["device_num"].append(len(target_dev_ids))
                for level in levels:
                    median_data["{}_trans".format(level)].append(stats[level].median())

            median_df = pd.DataFrame(data=median_data)
            ensure_dir_exists(f"{constants.EVAL_DIR}/feature_comparison/vp_data/")
            median_df.to_parquet(f"{constants.EVAL_DIR}/feature_comparison/vp_data/{vp}.parquet")
        try:
            orig_median_df = store.get('{}/{}/medians'.format(vendor, product))
        except KeyError:
            store.put('{}/{}/medians'.format(vendor, product), median_df)
        else:
            new_median_df = pd.concat([orig_median_df[~orig_median_df['by'].isin(features)], median_df], ignore_index=False)
            store.put('{}/{}/medians'.format(vendor, product), new_median_df)
        count+=1


def feature_evaluation(flows_fp, devs_fp, store_fp, stats_fp, rule_gen_by=None, levels=None, min_dev=MIN_DEV):
    if rule_gen_by is None:
        rule_gen_by = ["remote_ip", "subnet_24", "network", "asn", 
                       "short_domain", "short_hostname", "hostname_pattern", 
                       "domain_port", "hostname_port", "hostname_pattern_port"
        ]
    if levels is None:
        levels = RULE_GEN_LEVELS

    logger = setup_logger(name="get_eval_figdata_logger", log_file="get_eval_figdata.log", level=logging.DEBUG)

    cols = []
    for f in rule_gen_by:
        if f == "hostname_pattern":
            cols.append("short_hostname")
        elif f == "hostname_pattern_port":
            cols.append("hostname_port")
        else:
            cols.append(f)
    related_cols = list(set(cols))
    related_cols.extend(['device_id','device_vendor', 'device_type', 'vendor_product'])
    if not "remote_port" in related_cols:
        related_cols.append('remote_port')
    
    log("Loading data...", logging.INFO, logger=logger)
    flows = pd.read_parquet(flows_fp, engine='pyarrow', columns=related_cols)
    devs = pd.read_parquet(devs_fp)
    # vps = devs.vendor_product.value_counts().head(20).index.tolist()

    ensure_dir_exists(store_fp, fp_type="file")
    with pd.HDFStore(store_fp) as store:
        generateRules(
            devs, 
            flows, 
            store, 
            features=rule_gen_by, 
            levels=levels, 
            include_dns=True, 
            # vps=vps, 
            # end_at=None, 
            # start_from=1, 
            min_dev=min_dev,
            logger=logger
        )

        trans_df = get_trans_data(
            devs=devs, 
            store=store,
            min_dev=min_dev,
        )
        print(trans_df)
        ensure_dir_exists(stats_fp, fp_type="file")
        trans_df.to_parquet(stats_fp)
    
    log("Done!", logging.INFO, logger=logger)



####################################################
#   PLOTS
####################################################

def plot_feature_heatmap(trans_df, features, thresholds, level, sort=True, metric='trans', cmap='viridis', output_dir=None, vps=None, fname="", display="combined", feature_rename=None):
    if vps is None:
        vps = []
    if feature_rename is None:
        feature_rename = {}

    plot_dfs = []
    data_col = "{}_{}".format(level, metric)
    cols = ['vp', data_col]
    if display == "devtype":
        cols.append('device_type')
    elif display == "vendor":
        cols.append('device_vendor')
    for t in thresholds:
        for feature in features:
            feature_plot = trans_df.loc[(trans_df['thresh'].values == t) & (trans_df['by'].values == feature), cols].set_index('vp')
            feature_plot = feature_plot.rename(columns={data_col: "{}:{}".format(feature, t)})
            plot_dfs.append(feature_plot)
    ordered_cols = []
    for feature in features:
        ordered_cols.extend(["{}:{}".format(feature, t) for t in thresholds])
    if display == "devtype":
        ordered_cols.append('device_type')
    elif display == "vendor":
        ordered_cols.append('device_vendor')
    plot_df = pd.concat(plot_dfs, axis=1)
    if len(vps) != 0:
        plot_df = plot_df.loc[plot_df.index.isin(vps), :]
    plot_df = plot_df[ordered_cols]
    plot_df.index = [format_vp(vp) for vp in plot_df.index]
    if sort:
        plot_df = plot_df.loc[:, ~plot_df.columns.duplicated()]
        plot_df = plot_df.sort_values(by=ordered_cols, ascending=False)
    print(plot_df)
    
    if display == "combined":
        plt.figure(figsize=(25,4))
        sns.heatmap(plot_df.T, cmap=cmap, square=True)
    elif display == "devtype":
        MAIN_DEVTYPE = plot_df.device_type.unique()
        # MAIN_DEVTYPE = ["voice_assistant", "thermostat", "switch", "streaming", "printer", "light", "garage_door_opener", "remote_controller", "speaker", "camera", "game", None, "storage"]
        plot_dev_df = plot_df[plot_df.device_type.isin(MAIN_DEVTYPE)]

        # insert empty rows
        plot_dev_dfs = []
        for devtype in MAIN_DEVTYPE:
            devtype_df = plot_dev_df[plot_dev_df.device_type.values == devtype]
            devtype_df = devtype_df.sort_index()
            if devtype != MAIN_DEVTYPE[-1]:
                devtype_df = devtype_df.append(pd.Series(name=""))
            print(devtype_df)
            plot_dev_dfs.append(devtype_df)
        plot_dev_df = pd.concat(plot_dev_dfs)
        print(plot_dev_df[[f"{f}:1" for f in features]])
        if len(features) > 1:
            feature_plot_dfs = []
            for feature in features:
                related_cols = ["{}:{}".format(feature, t) for t in thresholds]
                data = plot_dev_df.loc[:, related_cols]
                feature_plot_dfs.append(data)
            # fig, axs = plt.subplots(1, len(features), figsize=(5,12.5), sharey=True)
            fig, axs = plt.subplots(1, len(features), figsize=(5.5, 8), sharey=True)
            # cbar_ax = fig.add_axes([.135, .017, .85, .007]) # for full image
            # cbar_ax = fig.add_axes([.32, .017, .62, .007]) # for partial image
            cbar_ax = fig.add_axes([.31, .03, .64, .007]) # for 20 products
            empty_rows_mask = plot_dev_df.index.get_loc('')
            empty_rows = [i for i in range(len(empty_rows_mask)) if empty_rows_mask[i] ]
            print(empty_rows)
            for i in range(len(feature_plot_dfs)):
                if features[i] in feature_rename:
                    axs[i].set_title(feature_rename[features[i]])
                else:
                    axs[i].set_title(features[i])
                sns.heatmap(feature_plot_dfs[i], cmap=cmap, square=True, ax=axs[i], vmin=0, vmax=1, cbar=i==0, cbar_ax=None if i else cbar_ax, cbar_kws={"orientation": "horizontal"}, xticklabels=thresholds)
                if i == len(feature_plot_dfs) // 2:
                    if len(feature_plot_dfs) % 2 == 0:
                        axs[i].set_xlabel("Thresholds", position=(-0.5, -0.02), horizontalalignment='left')
                    else:
                        axs[i].set_xlabel("Thresholds")
                axs[i].set_ylabel("")
                yticks = axs[i].yaxis.get_major_ticks()
                for j in empty_rows:
                    yticks[j].set_visible(False)
    if output_dir:
        plt.tight_layout()
        ensure_dir_exists(output_dir)
        if display == "devtype":
            fig.subplots_adjust(bottom=0.1)
        elif display == "vendor":
            fig.subplots_adjust(bottom=0.12)
        else:
            fig.subplots_adjust(bottom=0.045)
        if fname == "":
            plt.savefig(f"{output_dir}/{metric}.png")
            plt.savefig(f"{output_dir}/{metric}.pdf")
        else:
            plt.savefig(f"{output_dir}/{fname}.png")
            plt.savefig(f"{output_dir}/{fname}.pdf")

def plot_feature_comparison(stats_fp, devs_fp, output_dir, features=None, levels=None):
    trans_df = pd.read_parquet(stats_fp)
    devs = pd.read_parquet(devs_fp)
    vps = devs.vendor_product.value_counts().head(20).index.tolist()

    # Possible features:
    if features is None:
        # full list of features
        features = [
            'remote_ip', 'subnet_24', "network", "asn", 
            'short_domain', 'hostname_pattern', 'short_hostname', 
            'ip_port', 'hostname_port', 'domain_port', 'hostname_pattern_port'
        ]
    if levels is None:
        levels = RULE_GEN_LEVELS

    palette = ["#0E2E44", "#BFDDEE"]
    cmap = mcolors.LinearSegmentedColormap.from_list("my_colormap", tuple(palette))
    
    ensure_dir_exists(output_dir)

    for level in levels:
        plot_feature_heatmap(
            trans_df, 
            features=features, 
            thresholds=[1,2,3,4,5], 
            level=level, 
            sort=True, 
            metric='trans',
            cmap=cmap,
            output_dir=output_dir,
            vps=vps,
            fname=f'{level}_mfaf',
            display='devtype',
            feature_rename=constants.READABLE_FEATURES
        )

def compare_pattern_hostname(stats_fp, output_dir):
    trans_df = pd.read_parquet(stats_fp)
    trans_df = trans_df[trans_df.by.isin(["hostname_pattern", "short_hostname"])]
    top_20_vp = trans_df[["vp", "device_num"]].drop_duplicates().sort_values(by="device_num", ascending=False).head(20).vp.unique()
    trans_df = trans_df[trans_df.vp.isin(top_20_vp)]
    trans_df = trans_df[["by", "thresh", "product_trans", "vp"]]
    trans_df = trans_df[trans_df.thresh <= 5]
    trans_df.loc[:, "vp"] = [format_vp(vp) for vp in trans_df.vp]

    pattern_df = trans_df[trans_df.by == "hostname_pattern"].set_index(["vp", "thresh"])
    hostname_df = trans_df[trans_df.by == "short_hostname"].set_index(["vp", "thresh"])
    diff = pattern_df.product_trans - hostname_df.product_trans
    low_vps = trans_df[(trans_df.by=="short_hostname") & (trans_df.thresh == 1) & (trans_df.product_trans <= 0.9)].vp.unique()

    print("Hostname")
    low_trans_hostname = trans_df[(trans_df.by == "short_hostname") & (trans_df.product_trans <= 0.9)]
    print("{} out of {} products achieve a transerfability < 0.9 when thresh = 1".format(
        low_trans_hostname[low_trans_hostname.thresh == 1].vp.nunique(),
        trans_df[(trans_df.thresh == 1) & (trans_df.by == "short_hostname")].vp.nunique()
    ))
    print("{} out of {} products achieve a transerfability < 0.9 when thresh = 5".format(
        low_trans_hostname[low_trans_hostname.thresh == 5].vp.nunique(),
        trans_df[(trans_df.thresh == 5) & (trans_df.by == "short_hostname")].vp.nunique()
    ))
    print("(thresh=1) Avg = {}".format(trans_df[(trans_df.thresh == 1) & (trans_df.by == "short_hostname")].product_trans.mean()))
    print("(thresh=5) Avg = {}".format(trans_df[(trans_df.thresh == 5) & (trans_df.by == "short_hostname")].product_trans.mean()))

    print("\nPattern")
    low_trans_pattern = trans_df[(trans_df.by == "hostname_pattern") & (trans_df.product_trans <= 0.9)]
    print("{} out of {} products achieve a transerfability <= 0.9 when thresh = 1".format(
        low_trans_pattern[low_trans_pattern.thresh == 1].vp.nunique(),
        trans_df[(trans_df.thresh == 1) & (trans_df.by == "hostname_pattern")].vp.nunique()
    ))
    print("{} out of {} products achieve a transerfability <= 0.9 when thresh = 5".format(
        low_trans_pattern[low_trans_pattern.thresh == 5].vp.nunique(),
        trans_df[(trans_df.thresh == 5) & (trans_df.by == "hostname_pattern")].vp.nunique()
    ))
    print("(thresh=1) Avg = {}".format(trans_df[(trans_df.thresh == 1) & (trans_df.by == "hostname_pattern")].product_trans.mean()))
    print("(thresh=5) Avg = {}".format(trans_df[(trans_df.thresh == 5) & (trans_df.by == "hostname_pattern")].product_trans.mean()))

    low_trans = trans_df[(trans_df.by == "short_hostname") & (trans_df.product_trans < 0.9)].join(trans_df[trans_df.by == "hostname_pattern"].set_index(["vp", "thresh"]), on=["vp", "thresh"], lsuffix="_hn", rsuffix="_pat")
    low_trans.loc[:, "pat_effect"] = low_trans.product_trans_pat - low_trans.product_trans_hn

    print(low_trans[low_trans.pat_effect > 0.5].sort_values(by=["pat_effect"], ascending=False))
    print(low_trans[low_trans.pat_effect > 0.5].vp.nunique())
    
    print(f"Effect > 0.1: {len(low_trans[low_trans.pat_effect > 0.1].index)} / {len(low_trans.index)}")


    low_vps = low_trans[low_trans.pat_effect > 0.1].vp.unique()
    plot_df = trans_df[(trans_df.vp.isin(low_vps)) & (trans_df.by.isin(["short_hostname", "hostname_pattern"]))]
    plot_df.rename(columns={"by": "Format", "thresh": "Threshold", "product_trans": "MFAF"}, inplace=True)
    plot_df.loc[:, "Format"] = plot_df["Format"].replace({"hostname_pattern": "Hostname Pattern", "short_hostname": "Hostname"})
    plot_df = plot_df.sort_values(by=["Format", "Threshold", "MFAF"], ascending=[True, True, False])
    plot_df["Threshold"] = plot_df["Threshold"].astype(int)
    g = sns.catplot(data=plot_df, x="Threshold", y="MFAF", 
                    hue="Format", hue_order=["Hostname Pattern", "Hostname"],
                    col="vp", height=2, kind="bar", col_wrap=3, legend=False)
    for col_val, ax in g.axes_dict.items():
        ax.set_title(f"{col_val}")

    g.fig.get_axes()[-2].legend(loc="lower center", bbox_to_anchor=(0.5, -0.65), ncol=2)
    g.savefig(f"{output_dir}/pat_name_diff.pdf", bbox_inches = "tight")
    g.savefig(f"{output_dir}/pat_name_diff.png", bbox_inches = "tight")

if __name__ == "__main__":
    feature_evaluation(
        flows_fp=constants.FLOWS_FP,
        devs_fp=constants.DEVS_FP,
        store_fp=constants.FEATURE_STORE_FP,
        stats_fp=constants.FEATURE_STATS_FP
    )