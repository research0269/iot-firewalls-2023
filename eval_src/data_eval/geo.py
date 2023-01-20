import pathlib, logging
import pandas as pd

from data_eval.base import get_product_pattern, getThreshes, getRulesByPattern, getRuleDevCov, getRulesByOccurrence
from util.general import log, setup_logger
import constants

def geo_to_parquet(flows, devs, loc, output_dir):
    geo_devs = devs[devs.tz_geo == loc]
    geo_flows = flows[flows.tz_geo == loc]

    pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)
    geo_flows.to_parquet(f"{output_dir}/{loc}_flows.parquet")
    geo_devs.to_parquet(f"{output_dir}/{loc}_devs.parquet")

def get_qualified_vps(geo_data):
    '''
    Find all the products that exist in all regions
    '''
    a_vps = set(geo_data["a"]["devs"].vendor_product.unique())
    eaa_vps = set(geo_data["eaa"]["devs"].vendor_product.unique())
    ara_vps = set(geo_data["ara"]["devs"].vendor_product.unique())
    return list(a_vps.intersection(eaa_vps, ara_vps))

def compare_geo(geo_data, store, features, vps=None, logger=None):
    if vps is None:
        vps = get_qualified_vps(geo_data)
    total_vp = len(vps)
    locs = ['a', 'eaa', 'ara']
    MIN_DEV = 10
    count = 1

    for vp in vps:
        vendor, product = vp.split(':')
        log(f'{vp} ({count}/{total_vp})', level=logging.INFO, logger=logger)

        sample_size = None
        for loc in locs:
            devs = geo_data[loc]['devs']
            if sample_size is None:
                sample_size = len(devs[devs.vendor_product.values == vp].index)
            else:
                sample_size = min(sample_size, len(devs[devs.vendor_product.values == vp].index))

        if sample_size < MIN_DEV:
            count += 1
            continue
        
        # minus 1 to avoid sample size == data size
        # sample_size -= 1
        train_size = MIN_DEV - 1

        pat_dict = get_product_pattern(vp)

        for i in range(len(locs)):
            # generate rules from a sample
            devs_i, flows_i = geo_data[locs[i]]['devs'], geo_data[locs[i]]['flows']

            for j in range(len(locs)):
                log(f'...FROM {locs[i]} TO {locs[j]}', level=logging.INFO, logger=logger)
                devs_j, flows_j = geo_data[locs[j]]['devs'], geo_data[locs[j]]['flows']
                
                vp_devs_i = devs_i[devs_i.vendor_product.values == vp]
                vp_devs_j = devs_j[devs_j.vendor_product.values == vp]
                
                vp_flows_i = flows_i[flows_i.vendor_product.values == vp]
                vp_flows_j = flows_j[flows_j.vendor_product.values == vp]

                occ_thresh = getThreshes(train_size)

                median_data={"by":[], "thresh":[], "device_num":[], "from": [], "to": [], "trans":[], "round": [], "train_flow_size": []}
                for k in range(30):
                    log(f"......ROUND {k}", level=logging.INFO, logger=logger)
                    sample_devs_i = vp_devs_i.sample(n=train_size)
                    sample_devs_j = vp_devs_j[~vp_devs_j.device_id.isin(sample_devs_i.device_id.unique())]

                    sample_flows_i = vp_flows_i[vp_flows_i.device_id.isin(sample_devs_i.device_id.unique())]
                    sample_flows_j = vp_flows_j[vp_flows_j.device_id.isin(sample_devs_j.device_id.unique())]

                    for by in features:
                        log(f".........by {by}", level=logging.INFO, logger=logger)
                        use_patterns = by == "hostname_pattern"

                        for occ in occ_thresh:
                            if use_patterns:
                                rules = getRulesByPattern(sample_flows_i, pat_dict, hostname_thresh=occ)
                                stats = getRuleDevCov(rules, sample_flows_j, by=by, include_dns=True, logger=logger)
                            else:
                                rules = getRulesByOccurrence(sample_flows_i, by, occ)
                                stats = getRuleDevCov(rules, sample_flows_j, by=by, include_dns=True, logger=logger)
                            store.put('{}/{}/from_{}/to_{}/{}/occ_{}/round_{}/trans_stats'.format(vendor, product, locs[i], locs[j], by, occ, k), stats)

                            median_data["by"].append(by)
                            median_data["thresh"].append(occ)
                            median_data["device_num"].append(train_size)
                            median_data["from"].append(locs[i])
                            median_data["to"].append(locs[j])
                            median_data["trans"].append(stats.median())
                            median_data["round"].append(k)
                            median_data["train_flow_size"].append(len(sample_flows_i.index))
                    
                median_df = pd.DataFrame(data=median_data)
                store.put('{}/{}/from_{}/to_{}/medians'.format(vendor, product, locs[i], locs[j]), median_df)

        count += 1

def prepare_geo_data(devs, flows):
    for loc in constants.TZ_DICT:
        print('Processing {}'.format(loc))
        geo_to_parquet(flows, devs, loc, constants.GEO_DATA_DIR)

def get_geo_stats(locs, features, vps):
    data_list = []
    with pd.HDFStore(constants.GEO_STORE_FP) as store:
        for locs_from in locs:
            for locs_to in locs:
                for f in features:
                    for vp in vps:
                        vendor, product = vp.split(':')
                        median_data = store.get('{}/{}/from_{}/to_{}/medians'.format(vendor, product, locs_from, locs_to))
                        for k in range(30):
                            data = store.get('{}/{}/from_{}/to_{}/{}/occ_{}/round_{}/trans_stats'.format(vendor, product, locs_from, locs_to, f, 1, k))
                            data = data.to_frame()
                            data = data.rename(columns={0: 'transferability'})
                            data.loc[:, 'product'] = vp
                            data.loc[:, 'train_region'] = locs_from
                            data.loc[:, 'test_region'] = locs_to
                            data.loc[:, 'is_same_region'] = locs_from == locs_to
                            data.loc[:, 'feature'] = f
                            data.loc[:, 'round'] = k
                            train_flow_sizes = median_data[(median_data['by'] == f) & (median_data['round'] == k)].train_flow_size.unique()
                            assert len(train_flow_sizes) == 1, train_flow_sizes
                            data.loc[:, 'train_flow_size'] = train_flow_sizes[0]
                            data = data.reset_index()
                            data_list.append(data)
                        
    all_data = pd.concat(data_list, ignore_index=True)
    output_path = constants.GEO_STATS_DIR
    for f in features:
        feature_data = all_data[all_data.feature == f]
        feature_data.to_csv(f'{output_path}/{f}.csv')

def prepare_geo_eval_data():
    RULE_GEN_BY = ["remote_ip", "subnet_24", "network", "asn", "short_hostname", "short_domain", "hostname_pattern"]
    logger = setup_logger(name="get_geo_eval_data_logger", log_file="get_geo_eval_data.log", level=logging.DEBUG)
    flows = pd.read_parquet(constants.FLOWS_FP)
    devs = pd.read_parquet(constants.DEVS_FP)

    prepare_geo_data(devs, flows)

    related_cols = list(set([f if f != "hostname_pattern" else "short_hostname" for f in RULE_GEN_BY]))
    related_cols.extend(['device_id','device_vendor', 'device_type', 'vendor_product'])

    related_cols.append('remote_port')

    geo_data = {
        'a': {},
        'eaa': {},
        'ara': {}
    }

    for loc in geo_data.keys():
        log(f'Read {loc} data...', level=logging.INFO, logger=logger)
        geo_data[loc]['flows'] = pd.read_parquet(f"{constants.GEO_DATA_DIR}/{loc}_flows.parquet", columns=related_cols)
        geo_data[loc]['devs'] = pd.read_parquet(f"{constants.GEO_DATA_DIR}/{loc}_devs.parquet")

    with pd.HDFStore(constants.GEO_STORE_FP) as store:
        compare_geo(
            geo_data,
            store=store,
            features=RULE_GEN_BY,
            logger=logger
        )
    
    get_geo_stats(
        locs=geo_data.keys(),
        features=RULE_GEN_BY,
        vps=get_qualified_vps(geo_data)
    )

    ### The rest of the analysis is done through R. 
    ### Please see geo.R

if __name__ == "__main__":
    prepare_geo_eval_data()
    print("Done!")