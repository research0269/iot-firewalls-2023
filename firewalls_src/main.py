import logging, argparse, pathlib, glob
import sniffer, device, constants

def create_device(dev_config):
    dev = device.Device(
        mac=dev_config["mac"],
        ip=dev_config["ip"],
        product=dev_config["product"],
        name=dev_config["name"],
        feature=dev_config["feature"],
        thresh=dev_config["thresh"],
        pattern_enabled=dev_config["pattern"],
        local_allowlist=dev_config["local"],
        tailscale=dev_config["tailscale"]
    )
    return dev

def start_sniffer(queue_num, log_fp, dev_name, feature, thresh, capability, pattern_enabled, local_allowlist, tailscale):
    # create log filepath if not specified
    if log_fp == "":
        # make sure that we can create the log
        if pattern_enabled and feature != "none":
            output_dir = f"{constants.LOG_DIR}/{dev_name}/patterns/"
        else:
            output_dir = f"{constants.LOG_DIR}/{dev_name}/{feature}/"
        pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        if tailscale:
            log_fp_pattern = "{}/tailscale_{}.t{}.*.log".format(output_dir, capability, thresh)
        else:
            log_fp_pattern = "{}/{}.t{}.*.log".format(output_dir, capability, thresh)
        fps = glob.glob(log_fp_pattern)
        fnum = len(fps) + 1
        if tailscale:
            log_fp = "{}/tailscale_{}.t{}.{}.log".format(output_dir, capability, thresh, fnum)
        else:
            log_fp = "{}/{}.t{}.{}.log".format(output_dir, capability, thresh, fnum)
    else:
        output_dir = log_fp.rsplit('/', 1)[0]
        pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)

    # set up logger
    logging.basicConfig(
        filename=log_fp, 
        format='%(asctime)s - [%(name)s][%(levelname)s]: %(message)s', 
        level=logging.DEBUG
    )
    # set up logging in console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - [%(name)s][%(levelname)s]: %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    # logger for this module
    logger = logging.getLogger(__name__)

    dev_conf = constants.DEVICE_CONFIGS[dev_name]
    dev_conf['feature'] = feature
    dev_conf['thresh'] = thresh
    dev_conf['pattern'] = pattern_enabled
    dev_conf['local'] = local_allowlist
    dev_conf['tailscale'] = tailscale
    dev = create_device(dev_conf)
    logger.info("Device created: %s (%s, %s)", dev.name, dev.ip, dev.mac)
    logger.debug(f"Deivce configuration: {dev_conf}")

    if tailscale:
        sniff = sniffer.Sniffer(
            input_iface="eth0",         # the interface to the device
            output_iface="tailscale0",  # the interface to the Internet
            device=dev,
            # iptables_backup='iptables.bak',
            queue_num=queue_num,
            tailscale=tailscale
        )
    else:
        sniff = sniffer.Sniffer(
            input_iface="eth0",     # the interface to the device
            output_iface="wlan0",   # the interface to the Internet
            device=dev,
            # iptables_backup='iptables.bak',
            queue_num=queue_num
        )
    logger.info("Sniffer created.")
    sniff.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A simple firewall implementation based on iptables.')
    parser.add_argument('device', type=str, help="The name of the device that we want to collect data from.")
    parser.add_argument('-n', '--qnum', type=int, default=0, help="The queue_num parameter of iptables (default to be 0).")
    # parser.add_argument('-b', '--backup', help="The path to the backup file of original iptables.")
    parser.add_argument('-o', '--output', type=str, default="", help="The name of the log file.")
    parser.add_argument('-f', '--filter', type=str, default="hostname", help="Which filter to use? It must be one of the following: ip, hostname, domain, none")
    parser.add_argument('-t', '--thresh', type=int, default=1, help="What should the threshold be?")
    parser.add_argument('-c', '--capability', type=str, default="", help="The capability that should be tested.")
    parser.add_argument('--pattern', default=False, action='store_true')
    parser.add_argument('--local', default=False, action='store_true')
    parser.add_argument('--tailscale', default=False, action='store_true')
    args = parser.parse_args()

    if not args.device in constants.DEVICE_CONFIGS:
        print("We don't have information about that device. Check `constants.py` and fill in device information.")
    elif not isinstance(args.qnum, int):
        print("`-n` or `--qnum` must be an integer!")
    elif not isinstance(args.thresh, int):
        print("`-t` or `--thresh` must be an integer!")
    elif args.thresh <= 0 and args.filter != "none":
        print("`-t` or `--thresh` must at least be 1, unless `-c` or `--capability` is set to 'none'.")
    elif not args.filter.lower() in ['ip', 'domain', 'hostname', 'none']:
        print("`-f` or `--filter` only accepts one of the following feature: ip, hostname, domain, or none.")
    elif args.output == "" and args.capability == "":
        print("When capability is not specified, please manually provide output filepath.")
    elif args.pattern and (args.filter != "hostname" and args.filter != "none"):
        print("`--pattern` only works with hostnames or none.")
    elif args.tailscale and args.local:
        print("`--tailscale` and `local` cannot be used at the same time")
    else:
        start_sniffer(
            queue_num=args.qnum, 
            log_fp=args.output, 
            dev_name=args.device, 
            feature=args.filter, 
            thresh=args.thresh,
            capability=args.capability,
            pattern_enabled=args.pattern,
            local_allowlist=args.local,
            tailscale=args.tailscale
        )
    # Example CMD: 
    # sudo ../venv/bin/python main.py amazon_echo_dot -n 0 -f none -t 0 -c entertainment --pattern