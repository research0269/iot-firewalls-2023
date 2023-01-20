from data_cleaning.outlier_analysis import detect_outliers
from variability_analysis.plot_cdf import get_data_by_abstraction, plot_by_abstraction
from variability_analysis.plot_port import get_popular_devs_data, plot_port_dist
from rule_creation.extract_patterns import extract_patterns
from data_eval.features import feature_evaluation, plot_feature_comparison, compare_pattern_hostname
from data_eval.sample_size import eval_sample_size, clean_sample_size_data, sample_size_plot
from data_eval.thresholds import security_evaluation, merge_loop_stats, plot_sampled_devs
from data_eval.vendor import plot_vendor_trans_by_type
from data_eval.throughput import clean_pkt_size_data, prepare_winsum_data, plot_throughput
from data_eval.geo import prepare_geo_eval_data
from rule_creation.create_rules import create_rules
from real_world.failures import plot_failures, plot_failures_by_dev, plot_failures_by_func, plot_working_func, plot_working_dev, plot_work_combined
from real_world.attacks import get_public_endpoints, calculate_attack_surface, get_public_endpoints_test, plot_attack_surface
from real_world.geo_affect import get_lab_data, lab_data_summary, plot_geo_data

import constants

def figure_1():
    get_data_by_abstraction(
        devs_fp = constants.DEVS_FP,
        flows_fp = constants.FLOWS_FP,
        output_dir = constants.LONGTAILS_DATA_DIR,
        n=8,
        enforce_update=True
    )
    plot_by_abstraction(
        data_dir = constants.LONGTAILS_DATA_DIR,
        output_dir = f"{constants.GRAPH_DIR}/variability_analysis"
    )

def figure_2():
    flows = get_popular_devs_data(data_fp=constants.FLOWS_FP, top_n=8)
    plot_port_dist(flows, out_dir=f"{constants.GRAPH_DIR}/variability_analysis")

def prepare_for_eval():
    extract_patterns(
        pat_gen_by=["short_hostname", "hostname_port"], 
        flows_fp=constants.FLOWS_FP, 
        devs_fp=constants.DEVS_FP, 
        pattern_dir=constants.PATTERN_DIR
    )
    feature_evaluation(
        flows_fp=constants.FLOWS_FP,
        devs_fp=constants.DEVS_FP,
        store_fp=constants.FEATURE_STORE_FP,
        stats_fp=constants.FEATURE_STATS_FP,
        min_dev=1
    )

def figure_3():
    plot_feature_comparison(
        stats_fp=constants.FEATURE_STATS_FP, 
        devs_fp=constants.DEVS_FP, 
        output_dir=f"{constants.GRAPH_DIR}/feature_comparison", 
        features=["short_hostname", "hostname_pattern", "short_domain"], 
        levels=["product"]
    )

def figure_4():
    compare_pattern_hostname(
        stats_fp=constants.FEATURE_STATS_FP,
        output_dir=f"{constants.GRAPH_DIR}/feature_comparison"
    )

def figure_5():
    eval_sample_size(
        flows_fp=constants.FLOWS_FP, 
        devs_fp=constants.DEVS_FP, 
        store_fp=constants.SAMPLE_SIZE_STORE_FP, 
        stats_dir=constants.SAMPLE_SIZE_DIR, 
        rule_gen_by=['short_hostname', 'hostname_pattern', 'short_domain'],
    )
    clean_sample_size_data(stats_dir=constants.SAMPLE_SIZE_DIR)
    sample_size_plot(
        data_fp=f"{constants.SAMPLE_SIZE_DIR}/stats.parquet",
        output_dir=f"{constants.GRAPH_DIR}/sample_size"
    )

def figure_6():
    security_evaluation(
        flows_fp=constants.FLOWS_FP, 
        devs_fp=constants.DEVS_FP, 
        store_fp=constants.THRESHOLDS_STORE_FP
    )
    mfaf_df = merge_loop_stats(
        devs_fp=constants.DEVS_FP, 
        store_fp=constants.THRESHOLDS_STORE_FP
    )
    plot_sampled_devs(
        trans_df=mfaf_df, 
        output_dir=f"{constants.GRAPH_DIR}/thresholds"
    )

def figure_7():
    plot_feature_comparison(
        stats_fp=constants.FEATURE_STATS_FP, 
        devs_fp=constants.DEVS_FP, 
        output_dir=f"{constants.GRAPH_DIR}/vendor", 
        features=["short_domain", "hostname_pattern", "short_hostname"], 
        levels=["vendor"]
    )

def figure_8():
    plot_vendor_trans_by_type(
        stats_fp=constants.FEATURE_STATS_FP,
        output_dir=f"{constants.GRAPH_DIR}/vendor"
    )

def figure_9():
    plot_work_combined(f"{constants.REAL_WORLD_DATA_DIR}/real_world_thresh.csv")


def figure_10():
    plot_failures(f"{constants.REAL_WORLD_DATA_DIR}/real_world_thresh.csv", output_fn="failures_perc", percent=True)

def figure_11():
    df = calculate_attack_surface(f"{constants.REAL_WORLD_DATA_DIR}/real_world_thresh.csv")
    plot_attack_surface(df)

def figure_12():
    plot_geo_data(get_lab_data(f"{constants.REAL_WORLD_DATA_DIR}/lab-results.csv"))

def figure_13():
    plot_geo_data(get_lab_data(f"{constants.REAL_WORLD_DATA_DIR}/europe-results.csv"), loc="europe")

def figure_14():
    WIN_SIZE = "1min"

    flows = clean_pkt_size_data(flow_fp=constants.FLOWS_FP)
    byte_winsum = prepare_winsum_data(flows, output_dir=constants.THRESHOLDS_STATS_DIR, window_size=WIN_SIZE)

    plot_throughput(
        byte_winsum, 
        window_size=WIN_SIZE, 
        output_dir=f"{constants.GRAPH_DIR}/throughput",
        log=True, 
        method="box"
    )

    for devtype in byte_winsum.device_type.unique():
        print(f"================ {devtype} ================")
        for direction in ["Inbound", "Outbound"]:
            print(f"| {direction} |")
        print()

def main():
    # Variability
    # figure_1()
    # figure_2()

    # # Rule Creation
    # prepare_for_eval()
    # figure_3()
    # figure_4()
    # figure_5()
    # figure_6()
    # figure_7()
    # figure_8()
    # figure_9()

    # # Table 12
    # prepare_geo_eval_data()
    # The rest of the analysis is done in R --- data_eval/geo.R

    # Prepare for the real-world experiments:
    #   populate the data dir in firewalls_src
    create_rules(
        flow_fp=constants.FLOWS_FP, 
        devs_fp=constants.DEVS_FP, 
        features=["short_hostname", "hostname_pattern", "short_domain"], 
        output_dir=constants.LAB_EXPR_ALLOWLISTS_DIR
    )

    # Lab Tests
    figure_9()
    figure_10()
    figure_11()
    figure_12()
    figure_13()

    # Appendix
    figure_14()

if __name__ == "__main__":
    detect_outliers(pd.read_parquet(constants.FLOWS_FP), f"{constants.DATA_DIR}/outliers.parquet", threshold=0.2)
    main()
    print("done!")