"""
CTU-13 Dataset ground truth and scenario metadata.

Each scenario maps to:
  - botnet family name
  - list of known infected IP addresses (from README files)
  - PCAP filename (botnet-only capture, publicly available)
  - binetflow filename (labelled netflow, used ONLY for label matching)

Labels are assigned by matching flows from PCAP to infected IPs.
A flow is labelled BOTNET if src_ip is in the infected set for that scenario.
(We only see forward direction, so src_ip is the originator as seen by the sensor.)
"""

# Scenario metadata extracted verbatim from CTU-13 README files
SCENARIOS = {
    1: {
        "family": "Neris",
        "infected_ips": ["147.32.84.165"],
        "pcap": "botnet-capture-20110810-neris.pcap",
        "binetflow": "capture20110810.binetflow",
        "duration_hours": 6.15,
    },
    2: {
        "family": "Neris",
        "infected_ips": ["147.32.84.165"],
        "pcap": "botnet-capture-20110811-neris.pcap",
        "binetflow": "capture20110811.binetflow",
        "duration_hours": 14.18,
    },
    3: {
        "family": "Rbot",
        "infected_ips": ["147.32.84.165"],
        "pcap": "botnet-capture-20110812-rbot.pcap",
        "binetflow": "capture20110812.binetflow",
        "duration_hours": 66.85,
    },
    4: {
        "family": "Rbot",
        "infected_ips": ["147.32.84.165"],
        "pcap": "botnet-capture-20110815-rbot-dos.pcap",
        "binetflow": "capture20110815.binetflow",
        "duration_hours": 4.21,
    },
    5: {
        "family": "Virut",
        "infected_ips": ["147.32.84.165"],
        "pcap": "botnet-capture-20110815-fast-flux.pcap",
        "binetflow": "capture20110815-2.binetflow",
        "duration_hours": 11.63,
    },
    6: {
        "family": "Menti",
        "infected_ips": ["147.32.84.165"],
        "pcap": "botnet-capture-20110816-donbot.pcap",
        "binetflow": "capture20110816.binetflow",
        "duration_hours": 2.18,
    },
    7: {
        "family": "Sogou",
        "infected_ips": ["147.32.84.165"],
        "pcap": "botnet-capture-20110816-sogou.pcap",
        "binetflow": "capture20110816-2.binetflow",
        "duration_hours": 0.38,
    },
    8: {
        "family": "Murlo",
        "infected_ips": ["147.32.84.165"],
        "pcap": "botnet-capture-20110816-qvod.pcap",
        "binetflow": "capture20110816-3.binetflow",
        "duration_hours": 19.5,
    },
    9: {
        "family": "Neris",
        "infected_ips": [
            "147.32.84.165", "147.32.84.191", "147.32.84.192",
            "147.32.84.193", "147.32.84.204", "147.32.84.205",
            "147.32.84.206", "147.32.84.207", "147.32.84.208",
            "147.32.84.209",
        ],
        "pcap": "botnet-capture-20110817-bot.pcap",
        "binetflow": "capture20110817.binetflow",
        "duration_hours": 5.18,
    },
    10: {
        "family": "Rbot",
        "infected_ips": [
            "147.32.84.165", "147.32.84.191", "147.32.84.192",
            "147.32.84.193", "147.32.84.204", "147.32.84.205",
            "147.32.84.206", "147.32.84.207", "147.32.84.208",
            "147.32.84.209",
        ],
        "pcap": "botnet-capture-20110818-bot.pcap",
        "binetflow": "capture20110818.binetflow",
        "duration_hours": 4.75,
    },
    11: {
        "family": "Rbot",
        "infected_ips": [
            "147.32.84.165", "147.32.84.191", "147.32.84.192",
        ],
        "pcap": "botnet-capture-20110818-bot-2.pcap",
        "binetflow": "capture20110818-2.binetflow",
        "duration_hours": 0.26,
    },
    12: {
        "family": "NSIS.ay",
        "infected_ips": [
            "147.32.84.165", "147.32.84.191", "147.32.84.192",
        ],
        "pcap": "botnet-capture-20110819-bot.pcap",
        "binetflow": "capture20110819.binetflow",
        "duration_hours": 1.21,
    },
    13: {
        "family": "Virut",
        "infected_ips": ["147.32.84.165"],
        "pcap": "botnet-capture-20110815-fast-flux-2.pcap",
        "binetflow": "capture20110815-3.binetflow",
        "duration_hours": 16.36,
    },
}

# Known normal/legitimate IPs from CTU-13 (co-workers' machines verified clean)
# These are used only for label matching, never as model inputs.
KNOWN_NORMAL_IPS = [
    "147.32.84.170",   # Common across scenarios
    "147.32.84.134",
    "147.32.84.164",
    "147.32.87.36",
    "147.32.80.9",     # DNS server
    "147.32.84.59",
]

# Botnet family groupings for leave-one-family-out experiments
FAMILY_SCENARIOS = {
    "Neris": [1, 2, 9],
    "Rbot": [3, 4, 10, 11],
    "Virut": [5, 13],
    "Menti": [6],
    "Sogou": [7],
    "Murlo": [8],
    "NSIS.ay": [12],
}

def get_infected_ips(scenario_id: int) -> set:
    """Return the set of known infected IPs for a given scenario."""
    return set(SCENARIOS[scenario_id]["infected_ips"])

def get_family(scenario_id: int) -> str:
    """Return the botnet family name for a given scenario."""
    return SCENARIOS[scenario_id]["family"]

def get_all_infected_ips() -> set:
    """Return the union of all infected IPs across all scenarios."""
    ips = set()
    for s in SCENARIOS.values():
        ips.update(s["infected_ips"])
    return ips
