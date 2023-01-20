import tldextract, textdistance, re, logging, json
import numpy as np
import pandas as pd
from datetime import datetime
from collections import defaultdict, deque
from sklearn.cluster import DBSCAN
from suffix_trees import STree

from util.general import ensure_dir_exists, setup_logger, format_filename, print_log

def get_longest_substring(data):
    q = deque([(data, 0)]) # data and offset based on the first item
    result = []
    while q:
        s_list, offset = q.popleft()
        if not "" in s_list:
            st = STree.STree(s_list)
            lcs = st.lcs()
            pos_lcs = (offset + s_list[0].find(lcs), lcs)
            if len(lcs) >= 2 and not pos_lcs in result:
                # add current lcs
                result.append(pos_lcs)
                # add the remaining part to the queue
                # left part
                left_s_list = [s_list[i][:s_list[i].find(lcs)] for i in range(len(s_list))]
                q.append((left_s_list, offset))
                # right part
                right_s_list = [s_list[i][s_list[i].find(lcs)+len(lcs):] for i in range(len(s_list))]
                q.append((right_s_list, offset + s_list[0].find(lcs)+len(lcs)))

    result = sorted(result)

    # if there is some unique prefix or suffix
    if result[0][0] != 0:
        result = [(0, "")] + result
    if result[-1][0] + len(result[-1][1]) < len(data[0]):
        result.append((result[-1][0] + len(result[-1][1]), ""))

    result = [subs for pos, subs in result]
    
    return result

def concat_hostname_pat(end_sd_pat, middle_sd, d):
    d = re.sub(r"\.", '\.', d)
    middle_sd = re.sub(r"\.", '\.', middle_sd)

    if end_sd_pat == "" and middle_sd == "":
        return d
    
    if middle_sd == "":
        return end_sd_pat + "\." + d
    
    if end_sd_pat == "":
        return middle_sd + "\." + d

    hostname = "\.".join([end_sd_pat, middle_sd, d])

    if hostname == "(mdns)":
        hostname = "\(mdns\)"
    
    return hostname

def lev_distance(x, y):
    return 1-textdistance.levenshtein.normalized_similarity(x, y)

def lcs2pattern(lcs, cluster, threshold, total_size, enable_options=False, logger=None, verbose=True):
    '''
    Convert the list of longest common substrings (LCS) to a pattern that can be used to match similar strings.
    The process is as follows:
        - If there are only several options can be inserted between two adjacent LCS, then insert the options
        - If there are too many variations can be inserted between two adjacent LCS, then insert `.*`
    ---
    INPUT:
        lcs:        (list) all the longest substrings
        cluster:    (list) a cluster of similar strings
        threshold:  (float) the threshold the separate case 1 (limited options) and case 2 (too many options)
        total_size: (int) the size of the whole end_subdomain cluster (not the patterns)
        enable_options: (bool) whether to match by options (i.e., case 1 above)
        logger:     (logger) the logger that logs everything. If None is specified, it will print out the logs to the stdout.
        verbose:    (bool) whether to print out the process
    ---
    Return: (str) the pattern that will match all the strings in the cluster
    '''
    if not enable_options:
        return ".*".join(lcs)
    
    escaped_lcs = [re.escape(s) for s in lcs]
    pat = re.compile("(.*)".join(escaped_lcs))
    total_pos = len(lcs) - 1
    cols = [str(i) for i in range(1, total_pos+1)]
    variations = []
    for item in cluster:
        m = pat.match(item)
        if m:
            if logger:
                logger.debug(list(m.groups()))
            elif verbose:
                print(list(m.groups()))
            variations.append(list(m.groups()))
            
    df = pd.DataFrame(np.array(variations), columns=cols)
    final_pat = lcs[0]
    for i in range(len(cols)):
        if df[cols[i]].nunique() == 1:
            new_pat = df[cols[i]].unique()[0]
        else:
            frac = df[cols[i]].nunique() / total_size
            if frac < threshold and df[cols[i]].nunique() < 10:
                # if the options are limited
                new_pat = "(" + "|".join(df[cols[i]].unique()) + ")"
            else:
                new_pat = ".*"
        final_pat = final_pat + new_pat + lcs[i+1]
    return final_pat


def combine_similar_hostnames(rules, logger=None, eps_thresh=0.25, verbose=True):
    '''
    Combining similar hostnames as patterns
    ---
    INPUT:
        rules:  (list) a list of rules (expected to be hostnames)
        logger: (logger) the logger that logs everything. If None is specified, it will print out the logs to the stdout.
        eps_thresh: (float) the `eps` parameter for DBSCAN
        verbose:    (bool) whether to print out the process
    ---
    RETURN:
        (dataframe) A dataframe that contains two columns: "orig_hostname" and "hostname_pat".
    '''
    # group hostname with same domains (enforced)
    hn_grp = {"domain": [], "subdomain": [], "orig_hostname": []}
    for r in rules:
        if ":" in r:
            hostname, port = r.split(":")
        else:
            hostname = r
            port = None
        subdomain, sld, tld = tldextract.extract(hostname)
        domain = sld + '.' + tld if tld != "" else sld
        if not port is None:
            domain = domain + ":" + port
        hn_grp["domain"].append(domain)
        hn_grp["subdomain"].append(subdomain)
        hn_grp["orig_hostname"].append(r)
    df = pd.DataFrame(data=hn_grp)
    
    # group hostnames by longest common subdomains
    df.loc[:, "end_subdomain"] = [sd.split(".")[0] if sd != "" else "" for sd in df.subdomain]
    df.loc[:, "end_sd_pat"] = [re.sub(r"[0-9]+", '[0-9]+', sd) for sd in df.end_subdomain]
    df.loc[:, "middle_subdomain"] = [".".join(sd.split(".")[1:]) if sd != "" and "." in sd else "" for sd in df.subdomain] # currently not used

    hn = df.groupby(["domain", "middle_subdomain"]).end_subdomain.nunique()
    combinable_hn = hn[hn > 1].reset_index()
    combinable_hn_grpby = df[(df.domain.isin(combinable_hn.domain.unique())) & (df.middle_subdomain.isin(combinable_hn.middle_subdomain.unique()))].groupby(["domain", "middle_subdomain"])

    for name, grp in combinable_hn_grpby:
        domain, middle_subdomain = name
        if middle_subdomain != "":
            if logger:
                logger.info(f"### {middle_subdomain}.{domain} ###")
        else:
            if logger:
                logger.info(f"### {domain} ###")
        end_subdomains = np.array(grp.end_sd_pat.unique())
        if logger:
            logger.debug(end_subdomains)
        distance_mat = np.array([[lev_distance(sd1, sd2) for sd1 in end_subdomains] for sd2 in end_subdomains])

        # cluster using DBSCAN
        # src: https://scikit-learn.org/stable/auto_examples/cluster/plot_dbscan.html#sphx-glr-auto-examples-cluster-plot-dbscan-py
        #      https://stackoverflow.com/questions/38720283/python-string-clustering-with-scikit-learns-dbscan-using-levenshtein-distance

        db = DBSCAN(eps=eps_thresh, min_samples=2, metric='precomputed').fit(distance_mat)

        labels = db.labels_
        clusters = defaultdict(list)
        for i in range(len(labels)):
            clusters[labels[i]].append(end_subdomains[i])
        
        if logger:
            logger.debug(clusters)

        for i, cluster in clusters.items():
            if i != -1:
                lcs = get_longest_substring(cluster)
                common_hostname = lcs2pattern(lcs, cluster, 0.5, len(grp.index), enable_options=True, logger=logger, verbose=verbose)
                if logger:
                    logger.info(common_hostname)
                elif verbose:
                    print(f"{common_hostname} (totoa size: {len(grp.index)})")
                df.loc[(df.domain == domain) & (df.middle_subdomain == middle_subdomain) & (df.end_sd_pat.isin(cluster)), "end_sd_pat"] = common_hostname

        # Number of clusters in labels, ignoring noise if present.
        n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
        n_noise_ = list(labels).count(-1)
        if logger:
            logger.info('Estimated number of clusters: %d' % n_clusters_)
            logger.info('Estimated number of noise points: %d' % n_noise_)
        
            logger.info("")
    
    df.loc[:, "hostname_pattern"] = [concat_hostname_pat(end_sd_pat, middle_sd, d) for end_sd_pat, middle_sd, d in zip(df.end_sd_pat, df.middle_subdomain, df.domain)]

    return df[["orig_hostname", "hostname_pattern"]]

def jsonify_patterns(pat_df, output_fp=None):
    pat_dict = dict(zip(pat_df.orig_hostname, pat_df.hostname_pattern))
    if not output_fp is None:
        with open(output_fp, "w") as f:
            json.dump(pat_dict, f, indent=4)

def get_rules(flows, vp, rule_type):
    return flows[flows.vendor_product == vp][rule_type].dropna().unique()

def extract_patterns(pat_gen_by, flows_fp, devs_fp, pattern_dir, top_n=None):
    ensure_dir_exists(pattern_dir)
    related_cols = pat_gen_by + ['device_id', 'vendor_product']

    flows = pd.read_parquet(flows_fp, engine='pyarrow', columns=related_cols)
    devs = pd.read_parquet(devs_fp)
    if top_n is None:
        vps = devs.vendor_product.unique()
    else:
        vps = devs.vendor_product.value_counts().head(top_n).index.tolist()

    logger = setup_logger(name="pattern_extract", log_file="pattern_extract.log", level=logging.DEBUG)

    for by in pat_gen_by:
        print(f"[{datetime.now()}] ==================== {by} ====================")
        for vp in vps:
            print_log(f"processing {vp}...")
            rules = get_rules(flows, vp, by)
            df = combine_similar_hostnames(rules, logger)
            output_fn = format_filename(f"{vp}-port-pattern-map.json" if by == "hostname_port" else f"{vp}-pattern-map.json")
            output_fp = f"{pattern_dir}/{output_fn}"
            print_log(f"Output to {output_fp}")
            jsonify_patterns(df, output_fp)
