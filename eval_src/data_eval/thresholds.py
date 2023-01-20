import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import logging
from sklearn.model_selection import KFold

from data_eval.base import getRuleDevCov, get_sample_dict_by_levels, get_product_pattern, getRulesByPattern2, getRulesByOccurrence
from util.general import setup_logger, log
from util.plot import get_top_20_products, format_vp
import constants

def generateRules(devs, flows, store, features=[], levels=['product'], start_from=1, end_at=None, vps=None, include_dns=True, logger=None):
    assert 'product' in levels, "Missing level: product!"
    kf = KFold(n_splits=5, shuffle=True)
    MIN_DEV = 50
    
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
        vp_devs = devs[devs.vendor_product.values == vp]
        
        devtype = vp_devs.device_type.unique()[0]
            
        # allowable traffic fraction for each instance
        log(f"[{vp}] Getting thresholds...", logging.INFO, logger=logger)
        occ_thresh = [i for i in range(1, 40)]
        store.put(f'{vendor}/{product}/occ_thresholds', pd.Series(occ_thresh, name='thresh'))

        median_data={"by":[], "thresh":[], "device_num":[], "loop":[]}
        for level in levels:
            median_data[f"{level}_trans"] = []
                
        for loop in range(1,21):
            log(f'......Round {loop}', logging.INFO, logger=logger)

            # get data needed
            log(f"[{vp}][Round {loop}] Getting devices...", logging.INFO, logger=logger)
            dev_samples = {}

            target_devs = vp_devs.sample(50)
            target_dev_ids = target_devs.device_id.unique()
            
            # skip products whose sample size is too small
            if len(target_dev_ids) < MIN_DEV:
                count += 1
                continue

            dev_samples = get_sample_dict_by_levels(target_devs, levels=levels, vp=vp, vendor=vendor, devtype=devtype)

            log(f"[{vp}][Round {loop}] Getting flows...", logging.INFO, logger=logger)
            target_flows = flows[flows.device_id.isin(target_dev_ids)]
            flow_samples = get_sample_dict_by_levels(target_flows, levels=levels, vp=vp, vendor=vendor, devtype=devtype)

            for by in features:
                log(f"[{vp}][Round {loop}][{by}] Start analyzing {by}...", logging.INFO, logger=logger)
                # check if we should use range or occurrence or pattern for rule-generation
                use_pattern = by == 'hostname_pattern'
                
                # further shrink flows
                if use_pattern:
                    related_cols = ['short_hostname', 'device_id']
                else:
                    related_cols = [by, 'device_id']
                
                if include_dns and "remote_port" not in related_cols:
                    related_cols.append("remote_port")
                
                related_flow_samples = {}
                for level, sample in flow_samples.items():
                    related_flow_samples[level] = sample.loc[:, related_cols]
                
                target_flows = related_flow_samples['product']
                
                for occ in occ_thresh:
                    log(f"[{vp}][Round {loop}][{by}] occurrence = {occ}", logging.INFO, logger=logger)
                    
                    stats_lists = {}
                    for level in levels:
                        stats_lists[level] = []
                        
                    k_fold_count = 1
                    for train_dev_indice, test_dev_indice in kf.split(target_dev_ids):
                        # log(f"[{vp}][{by}] occurrence = {occ} | k_fold = {k_fold_count} - getting rules...", logging.DEBUG, logger=logger)
                        train_all_dev_ids = target_dev_ids[train_dev_indice]
                        train_devs = target_devs[target_devs.device_id.isin(train_all_dev_ids)]
                        train_flows = target_flows[target_flows.device_id.isin(train_devs.device_id.unique())]
                        
                        if use_pattern:
                            rules = getRulesByPattern2(train_flows, thresh=occ)
                        else:
                            rules = getRulesByOccurrence(train_flows, by, occ)

                        if len(rules) == 0:
                            # if no rules can be generated, then move on to next round
                            break
                        
                        test_all_dev_ids = target_dev_ids[test_dev_indice]

                        # save training data
                        store.put(f'{vendor}/{product}/{by}/loop_{loop}/occ_{occ}/k_{k_fold_count}/train_devs', pd.Series(train_all_dev_ids, name='device_id'))
                        # save testing data
                        store.put(f'{vendor}/{product}/{by}/loop_{loop}/occ_{occ}/k_{k_fold_count}/test_devs', pd.Series(test_all_dev_ids, name='device_id'))
                        # save generated rules
                        if use_pattern:
                            store.put(f'{vendor}/{product}/{by}/loop_{loop}/occ_{occ}/k_{k_fold_count}/rules', pd.DataFrame.from_records([(host, pat) for host, pat in rules.items()], columns=["orig_hostname", "hostname_pattern"]))
                        else:
                            store.put(f'{vendor}/{product}/{by}/loop_{loop}/occ_{occ}/k_{k_fold_count}/rules', pd.Series(rules, name='rule'))
                        
                        # calculate allowable traffic for each device
                        for level, sample_flows in related_flow_samples.items():
                            log(f"[{vp}][Round {loop}][{by}] occurrence = {occ} | k_fold = {k_fold_count} - getting rule coverage for {level}..", logging.DEBUG, logger=logger)
                            sample_devs = dev_samples[level]
                            
                            # extract devices for test first to speed up flows selection
                            test_devs = sample_devs[sample_devs.device_id.isin(test_all_dev_ids)]
                            
                            test_flows = sample_flows[sample_flows.device_id.isin(test_devs.device_id.unique())]
                            stats_lists[level].append(getRuleDevCov(rules, test_flows, by=by, include_dns=include_dns, include_cctld=False, logger=logger))

                        k_fold_count += 1
                        
                    if len(stats_lists['product']) == 0:
                        # if we didn't get any rules from the product
                        break

                    # allowable traffic for each device after cross validation
                    stats = {}
                    for level in levels:
                        stats[level] = pd.concat(stats_lists[level], axis='index', sort=False)
                        store.put(f'{vendor}/{product}/{by}/loop_{loop}/occ_{occ}/trans_stats/{level}', stats[level])

                    median_data["by"].append(by)
                    median_data["thresh"].append(occ)
                    median_data["device_num"].append(len(target_dev_ids))
                    median_data["loop"].append(loop)
                    for level in levels:
                        median_data[f"{level}_trans"].append(stats[level].median())
                        
        median_df = pd.DataFrame(data=median_data)
        try:
            orig_median_df = store.get(f'{vendor}/{product}/medians')
        except KeyError:
            store.put(f'{vendor}/{product}/medians', median_df)
        else:
            # add data in different loops
            new_median_df = pd.concat([orig_median_df, median_df[~median_df.loop.isin(orig_median_df.loop.unique())]], ignore_index=False)
            store.put(f'{vendor}/{product}/medians', new_median_df)
        count+=1


def merge_loop_stats(devs_fp, store_fp):
    devs = pd.read_parquet(devs_fp)

    top_vps = get_top_20_products()
    devs = devs[devs.vendor_product.isin(top_vps)]

    with pd.HDFStore(store_fp) as store:
        dfs = []
        for feature in ["short_hostname", "hostname_pattern"]:
            for vp in devs.vendor_product.unique():
                print(vp)
                vendor, product = vp.split(':')
                devtype = devs[devs.vendor_product == vp].device_type.unique()[0]
                for loop in range(1, 6):
                    median_df = pd.DataFrame(columns=["thresh", "product_trans"])
                    for occ in range(1, 40):
                        try:
                            median = store.get(f'{vendor}/{product}/{feature}/loop_{loop}/occ_{occ}/trans_stats/product').median()
                            median_df = median_df.append({"thresh": occ, "product_trans": median}, ignore_index=True)
                        except KeyError:
                            continue
                    if len(median_df.index) > 0:
                        median_df.loc[:, "loop"] = loop
                        median_df.loc[:, "vp"] = vp
                        median_df.loc[:, "device_vendor"] = vendor
                        median_df.loc[:, "device_type"] = devtype
                        median_df.loc[:, "by"] = feature
                    dfs.append(median_df)

    df = pd.concat(dfs, ignore_index=True)
    df.loc[df.device_type.isna(), "device_type"] = "NOTFOUND"
    df = df.groupby(["by", "vp", "device_vendor", "device_type", "thresh"]).product_trans.mean().reset_index()
    df.loc[df.device_type == "NOTFOUND", "device_type"] = None
    return df

def security_evaluation(flows_fp, devs_fp, store_fp):
    RULE_GEN_BY = ["short_hostname", "hostname_pattern"]
    logger = setup_logger(name="get_security_data_logger", log_file="get_security_data.log", level=logging.DEBUG)

    related_cols = list(set([f if f != "hostname_pattern" else "short_hostname" for f in RULE_GEN_BY]))
    related_cols.extend(['device_id','device_vendor', 'device_type', 'vendor_product'])
    related_cols.append('remote_port')
    
    log("Loading data...", logging.INFO, logger=logger)
    flows = pd.read_parquet(flows_fp, engine='pyarrow', columns=related_cols)
    devs = pd.read_parquet(devs_fp)

    top_vps = get_top_20_products()
    flows = flows[flows.vendor_product.isin(top_vps)]
    devs = devs[devs.vendor_product.isin(top_vps)]

    with pd.HDFStore(store_fp) as store:
        generateRules(
            devs, 
            flows, 
            store, 
            features=RULE_GEN_BY, 
            levels=["product"], 
            include_dns=True, 
            vps=top_vps, 
            # end_at=None, 
            # start_from=1, 
            logger=logger
        )

    log("Done!", logging.INFO, logger=logger)

def plot_sampled_devs(trans_df, output_dir):
    trans_df.loc[:, "vp"] = [format_vp(vp) for vp in trans_df.vp]
    trans_df = trans_df.replace({'by': constants.READABLE_FEATURES})
    trans_df = trans_df.rename(columns = {"by": "Format"})

    # adjust figure resolution to avoid potential fluctuation at the end
    trans_df = trans_df[trans_df.thresh % 5 == 1]

    format_order = ['Hostname', 'Pattern']
    trans_df = trans_df[trans_df["Format"].isin(format_order)]

    sns.set_context("notebook", font_scale=1.3)
    sns.set_style("whitegrid")
    g = sns.relplot(x="thresh", y="product_trans", hue="Format", col="vp", style="Format",
                    col_wrap=10, height=2.5, kind="line", linewidth=2, hue_order=format_order,
                    data=trans_df)
    g.set_axis_labels("Threshold", "MFAF")
    g.set_titles(col_template="{col_name}")
    plt.ylim(0, 1)
    plt.xlim(0, 40)
    sns.move_legend(g, "lower center", bbox_to_anchor=(0.5, -0.08), ncol=trans_df.vp.nunique(), title=None, frameon=False)

    g.savefig(f"{output_dir}/security.png")
    g.savefig(f"{output_dir}/security.pdf")