# the list of device configs are from our own lab
# one should change it accordingly for their devices

DEVICE_CONFIGS = {
    'wyze_cam': {
        "mac": "2c:aa:8e:9a:64:b7", 
        "ip": "192.168.143.252", 
        "name": "Wyze Cam", 
        "product": "wyze_cam", 
        "feature": "hostname", 
        "thresh": 1
    },
    'belkin_switch': {
        "mac": "c4:41:1e:5b:18:a5", 
        "ip": "192.168.143.251", 
        "name": "Belkin Switch", 
        "product": "belkin_switch", 
        "feature": "hostname", 
        "thresh": 1
    },
    'ring_cam': {
        "mac": "54:e0:19:3c:7c:14", 
        "ip": "192.168.143.253", 
        "name": "Ring Cam", 
        "product": "ring_cam", 
        "feature": "hostname", 
        "thresh": 1
    },
    'philips_hue': {
        "mac": "00:17:88:72:7b:50", 
        "ip": "192.168.143.249", 
        "name": "Philips Hue Lightbulb", 
        "product": "philips_hue", 
        "feature": "hostname", 
        "thresh": 1
    },
    'sonos_one': {
        "mac": "48:a6:b8:fb:b1:66", 
        "ip": "192.168.143.239", 
        "name": "Sonos One", 
        "product": "sonos_one", 
        "feature": "hostname", 
        "thresh": 1
    },
    'amazon_echo_dot': {
        "mac": "1c:4d:66:fc:13:79",
        "ip": "192.168.143.250",
        "name": "Amazon Echo Dot",
        "product": "amazon_echo_dot",
        "feature": "hostname",
        "thresh": 1
    },
    'tplink_switch': {
        "mac": "50:c7:bf:09:f3:4c",
        "ip": "192.168.143.80",
        "name": "TP-Link Kasa Smart WiFi Plug",
        "product": "tplink_switch",
        "feature": "hostname",
        "thresh": 1
    },
    'amazon_fire': {
        "mac": "f0:f0:a4:f8:e5:fc",
        "ip": "192.168.143.118",
        "name": "Amazon Fire TV Stick",
        "product": "amazon_fire",
        "feature": "hostname",
        "thresh": 1
    },
    'google_home': {
        "mac": "a4:77:33:2f:e0:6e",
        "ip": "192.168.143.20",
        "name": "Google Home Assistant",
        "product": "google_home",
        "feature": "hostname",
        "thresh": 1
    },
    'google_chromecast': {
        "mac": "f0:72:ea:e3:88:c2",
        "ip": "192.168.143.123",
        "name": "Google Chromecast TV",
        "product": "google_chromecast",
        "feature": "hostname",
        "thresh": 1
    },
    'lifx_light': {
        "mac": "d0:73:d5:10:de:e5",
        "ip": "192.168.143.243",
        "name": "Lifx Lightbulb",
        "product": "lifx_light",
        "feature": "hostname",
        "thresh": 1
    },
    'nintendo_switch': {
        "mac": "cc:5b:31:ea:14:9b",
        "ip": "192.168.143.236",
        "name": "Nintendo Switch",
        "product": "nintendo_switch",
        "feature": "hostname",
        "thresh": 1
    },
    'chamberlain_garage': {
        "mac": "cc:6a:10:49:73:81",
        "ip": "192.168.143.244",
        "name": "Chamberlain Garage Door",
        "product": "chamberlain_garage",
        "feature": "hostname",
        "thresh": 1
    },
    'dlink_camera': {
        "mac": "b0:c5:54:61:bf:a4",
        "ip": "192.168.143.227",
        "name": "DLink Camera",
        "product": "dlink_camera",
        "feature": "hostname",
        "thresh": 1
    },
    'xiaomi_vacuum': {
        "mac": "24:18:c6:e2:2d:eb",
        "ip": "192.168.143.173",
        "name": "Xiaomi Vacuum",
        "product": "xiaomi_vacuum",
        "feature": "hostname",
        "thresh": 1
    },
    'sony_console': {
        "mac": "40:99:22:89:98:6d",
        "ip": "192.168.143.175",
        "name": "Sony Console",
        "product": "sony_console",
        "feature": "hostname",
        "thresh": 1
    },
    'logitech_harmony': {
        "mac": "00:04:20:f2:93:2e",
        "ip": "192.168.143.228",
        "name": "Logitech Harmony",
        "product": "logitech_harmony",
        "feature": "hostname",
        "thresh": 1
    },
    'roku_streamer': {
        "mac": "bc:d7:d4:6b:2c:a3",
        "ip": "192.168.143.229",
        "name": "Roku Streamer",
        "product": "roku_streamer",
        "feature": "hostname",
        "thresh": 1
    },
    'google_nest': {
        "mac": "20:1f:3b:81:5f:ac",
        "ip": "192.168.143.209",
        "name": "Google Nest",
        "product": "google_nest",
        "feature": "hostname",
        "thresh": 1
    },
    'idevice_switch': {
        "mac": "d4:81:ca:64:68:56",
        "ip": "192.168.143.91",
        "name": "iDevice Switch",
        "product": "idevice_switch",
        "feature": "hostname",
        "thresh": 1
    },
    'lutron_bridge': {
        "mac": "b0:d5:cc:51:f5:c5",
        "ip": "192.168.143.171",
        "name": "Lutron Bridge",
        "product": "lutron_bridge",
        "feature": "hostname",
        "thresh": 1
    },
    'honeywell_thermostat': {
        "mac": "48:a2:e6:82:5f:76",
        "ip": "192.168.143.204",
        "name": "Honeywell Thermostat",
        "product": "honeywell_thermostat",
        "feature": "hostname",
        "thresh": 1
    },
    'ecobee_thermostat': {
        "mac": "44:61:32:D3:01:42",
        "ip": "192.168.143.83",
        "name": "Ecobee Thermostat",
        "product": "ecobee_thermostat",
        "feature": "hostname",
        "thresh": 1
    },
    'ihome_switch': {
        "mac": "50:8a:06:a5:9f:c3",
        "ip": "192.168.143.195",
        "name": "iHome Switch",
        "product": "ihome_switch",
        "feature": "hostname",
        "thresh": 1
    }
}

ALLOWLIST_DIR = "./data/allowlists"
LOCAL_ALLOWLIST_DIR = "./data/allowlists_local"
LOG_DIR = "./data/logs"