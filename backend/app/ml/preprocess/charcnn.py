"""UniGuard Preprocessing: Char-CNN DNS Detector"""

import numpy as np
import re
import math
from pathlib import Path

# CharCNN Vocabulary (from meta.json)
CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-_."
CHAR2IDX = {c: i + 2 for i, c in enumerate(CHARS)}
PAD_TOKEN = 0
UNK_TOKEN = 1
MAX_LEN = 128

def preprocess_charcnn(domains: list[str], feature_stats_path: str) -> tuple[np.ndarray, np.ndarray]:
    """
    Preprocess raw domain names into (token_ids, lexical_features) for the Char-CNN.
    """
    if not domains:
        return np.zeros((0, MAX_LEN), dtype=np.int64), np.zeros((0, 18), dtype=np.float32)
        
    # Load normalization stats
    try:
        stats = np.load(feature_stats_path)
        feat_mean = stats['mean']
        feat_std = stats['std']
    except Exception:
        # Fallback if file not found
        feat_mean = np.zeros(18, dtype=np.float32)
        feat_std = np.ones(18, dtype=np.float32)

    B = len(domains)
    token_ids = np.zeros((B, MAX_LEN), dtype=np.int64)
    features = np.zeros((B, 18), dtype=np.float32)

    for i, raw_domain in enumerate(domains):
        # 1. Clean
        d = raw_domain.strip().lower()
        d = re.sub(r'^https?://', '', d)
        d = re.sub(r':\d+$', '', d)
        d = d.rstrip('.')
        d = re.sub(r'\.+', '.', d)
        
        try:
            # Try punycode encoding if there are non-ascii chars
            d = d.encode('idna').decode('ascii')
        except Exception:
            pass
            
        d = d[:253]  # RFC 1035 max length
        
        # 2. Tokenize
        tokens = []
        for char in d:
            tokens.append(CHAR2IDX.get(char, UNK_TOKEN))
            
        # Pad/truncate
        if len(tokens) > MAX_LEN:
            tokens = tokens[:MAX_LEN]
        token_ids[i, :len(tokens)] = tokens
        
        # 3. Lexical Features
        length = len(d)
        log_len = math.log1p(length)
        
        char_counts = {}
        for c in d:
            char_counts[c] = char_counts.get(c, 0) + 1
            
        entropy = 0.0
        if length > 0:
            for count in char_counts.values():
                p = count / length
                entropy -= p * math.log2(p)
                
        norm_entropy = entropy / math.log2(length) if length > 1 else 0.0
        
        digits = sum(1 for c in d if c.isdigit())
        alphas = sum(1 for c in d if c.isalpha())
        vowels = sum(1 for c in d if c in 'aeiou')
        
        digit_ratio = digits / length if length > 0 else 0
        alpha_ratio = alphas / length if length > 0 else 0
        vowel_ratio = vowels / length if length > 0 else 0
        
        # max consonant run
        consonants = 'bcdfghjklmnpqrstvwxyz'
        max_c_run = 0
        current_run = 0
        for c in d:
            if c in consonants:
                current_run += 1
                max_c_run = max(max_c_run, current_run)
            else:
                current_run = 0
                
        sep_ratio = d.count('-') / length if length > 0 else 0
        unique_char_ratio = len(char_counts) / length if length > 0 else 0
        
        labels = d.split('.')
        n_labels = len(labels)
        label_lengths = [len(l) for l in labels]
        max_label_len = max(label_lengths) if label_lengths else 0
        mean_label_len = sum(label_lengths) / n_labels if n_labels > 0 else 0
        
        hex_chars = sum(1 for c in d if c in '0123456789abcdef')
        base32_chars = sum(1 for c in d if c in 'abcdefghijklmnopqrstuvwxyz234567')
        base64_chars = alphas + digits + d.count('+') + d.count('/')
        
        hex_fraction = hex_chars / length if length > 0 else 0
        base32_fraction = base32_chars / length if length > 0 else 0
        base64_fraction = base64_chars / length if length > 0 else 0
        
        # Simplified mock for dict_word_ratio and subdomain_entropy
        dict_word_ratio = 0.0
        subdomain_entropy = entropy
        
        feat_vec = np.array([
            length, log_len, entropy, norm_entropy,
            digit_ratio, alpha_ratio, vowel_ratio, max_c_run,
            sep_ratio, unique_char_ratio, n_labels, max_label_len,
            mean_label_len, hex_fraction, base32_fraction, base64_fraction,
            dict_word_ratio, subdomain_entropy
        ], dtype=np.float32)
        
        # 4. Normalize
        # Add epsilon to std to prevent division by zero
        safe_std = np.where(feat_std == 0, 1e-8, feat_std)
        features[i] = (feat_vec - feat_mean) / safe_std
        
    return token_ids, features
