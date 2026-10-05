"""UniGuard Preprocessing: 1D-CNN Beacon Detector"""

import numpy as np

def preprocess_beacon_cnn(flows: list[dict]) -> np.ndarray:
    """
    Preprocess raw flow dicts into the (B, 32, 7) tensor for the 1D-CNN.
    Expects flow dicts to contain:
    - pkt_sizes: list of forward packet sizes (bytes)
    - pkt_iats: list of forward inter-arrival times (microseconds)
    - pkt_flags: list of forward TCP flags (integers)
    """
    if not flows:
        return np.zeros((0, 32, 7), dtype=np.float32)
        
    B = len(flows)
    X = np.zeros((B, 32, 7), dtype=np.float32)
    
    # Constants from meta.json
    PKT_SIZE_LOG_SCALE = 0.09090909090909091
    IAT_LOG_SCALE = 0.054288816503800214
    IAT_CLIP_US = 100000000.0
    
    for i, flow in enumerate(flows):
        sizes = flow.get("pkt_sizes", [])
        iats = flow.get("pkt_iats", [])
        flags = flow.get("pkt_flags", [])
        
        # Take up to 32 packets
        n_pkts = min(32, len(sizes))
        if n_pkts == 0:
            continue
            
        # Ensure lists are long enough for n_pkts
        sizes = sizes[:n_pkts]
        iats = iats[:n_pkts]
        flags = flags[:n_pkts]
        
        # Channel 0: log1p(pkt_size_bytes) * pkt_size_log_scale
        sizes_arr = np.array(sizes, dtype=np.float32)
        X[i, :n_pkts, 0] = np.log1p(sizes_arr) * PKT_SIZE_LOG_SCALE
        
        # Channel 1: log1p(clamp(IAT_microseconds, 0, 1e8)) * iat_log_scale
        iats_arr = np.array(iats, dtype=np.float32)
        iats_arr = np.clip(iats_arr, 0.0, IAT_CLIP_US)
        X[i, :n_pkts, 1] = np.log1p(iats_arr) * IAT_LOG_SCALE
        
        # Channel 2: padding mask (1.0 for real packets)
        X[i, :n_pkts, 2] = 1.0
        
        # TCP Flags
        flags_arr = np.array(flags, dtype=np.int32)
        # Channel 3: SYN (0x02)
        X[i, :n_pkts, 3] = (flags_arr & 0x02 > 0).astype(np.float32)
        # Channel 4: FIN (0x01)
        X[i, :n_pkts, 4] = (flags_arr & 0x01 > 0).astype(np.float32)
        # Channel 5: RST (0x04)
        X[i, :n_pkts, 5] = (flags_arr & 0x04 > 0).astype(np.float32)
        # Channel 6: PSH (0x08)
        X[i, :n_pkts, 6] = (flags_arr & 0x08 > 0).astype(np.float32)
        
    return X
