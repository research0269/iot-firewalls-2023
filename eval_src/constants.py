import pyasn

DATA_DIR = "./data"
LONGTAILS_DATA_DIR = f"{DATA_DIR}/variability_analysis"
PATTERN_DIR = f"{DATA_DIR}/patterns"
EVAL_DIR = f"{DATA_DIR}/eval"
GEO_DATA_DIR = f"{DATA_DIR}/geo_data"
GEO_STATS_DIR = f"{DATA_DIR}/geo_eval"
THRESHOLDS_STATS_DIR = f"{EVAL_DIR}/thresholds"
REAL_WORLD_DATA_DIR = f"{DATA_DIR}/real_world"
GRAPH_DIR = "./graphs"
REAL_WORLD_GRAPH_DIR = f"{GRAPH_DIR}/real_world"
LAB_EXPR_ALLOWLISTS_DIR = "../firewalls_src/data/allowlists"

DEVS_CSV_FP = f"{DATA_DIR}/raw_data/sample.devices.csv"             # > Data provided by IoT Inspector
FLOWS_CSV_FP = f"{DATA_DIR}/raw_data/sample.flows.csv"              # > Data provided by IoT Inspector
CLEANED_DEVS_CSV_FP = f"{DATA_DIR}/raw_data/cleaned_dev_name.csv"   # > Data provided by IoT Inspector
DEVTYPE_CSV_FP = f"{DATA_DIR}/raw_data/dev_types.csv"               # > Manually labelled device type for each product in the dataset.
                                                                    #   The labels are created by two researchers independently and then converged.
ALL_FLOWS_FP = f"{DATA_DIR}/flows.parquet"                          # > Preprocessed traffic data that contains all the packets aggregated in 5-second window
DEVS_FP = f"{DATA_DIR}/devs.parquet"                                # > Preprocessed devices data
FLOWS_FP = f"{DATA_DIR}/flows.only.parquet"                         # > Preprocessed traffic data that only contains flows.
                                                                    #   A flow is identified by (device id, local port, remote ip, remote port, protocol) within 24 hrs
                                                                    #   This is the traffic data that is used for analysis
FEATURE_STATS_FP = f"{EVAL_DIR}/feature_comparison/stats.parquet"   # > The MFAF data
FEATURE_STORE_FP = f"{EVAL_DIR}/feature_comparison/eval_data.h5"    # > Stores all the intermediate data
SAMPLE_SIZE_DIR = f"{EVAL_DIR}/sample_size"
SAMPLE_SIZE_STORE_FP = f"{EVAL_DIR}/sample_size/eval_data.h5"
GEO_STORE_FP = f"{GEO_STATS_DIR}/geo_data.h5"
THRESHOLDS_STORE_FP = f"{EVAL_DIR}/thresholds/thresholds.h5"

TZ_DICT = {
    'a': ['UTC-02:30', 'UTC-03:00', 'UTC-04:00', 'UTC-05:00', 'UTC-06:00', 'UTC-07:00', 'UTC-08:00', 'UTC-10:00'], # north america, south america
    'eaa': ['UTC+01:00', 'UTC+02:00', 'UTC+03:00', 'UTC+04:00'], # europe, africa, arab
    'ara': ['UTC+05:30', 'UTC+07:00', 'UTC+08:00', 'UTC+09:00', 'UTC+09:30', 'UTC+10:00', 'UTC+11:00', 'UTC+12:00'] # asia, russia, australia
}

ASNDB = pyasn.pyasn(f'{DATA_DIR}/raw_data/ipasn_20200821.dat')

READABLE_FEATURES = {
    'remote_ip': 'IP',
    'subnet_24': 'Subnet/24',
    'network': 'BGP Prefix',
    'asn': 'ASN',
    'short_domain': 'Domain',
    'short_hostname': 'Hostname',
    'hostname_pattern': 'Pattern',
    'ip_port': 'IP:Port',
    'hostname_port': 'Hostname:Port',
    'domain_port': 'Domain:Port',
    'hostname_pattern_port': 'Pattern:Port',
}