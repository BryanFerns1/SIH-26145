"""
Evidence Features Module
========================
Extracts comprehensive statistical, lexical, and structural features from DNS query names (FQDNs).
Used for:
  - Baseline classifiers (Logistic Regression, LightGBM)
  - Feature fusion in Char-CNN
  - Interpretability and shortcut diagnostics
"""

import math
import re
from collections import Counter
from typing import List, Dict, Any, Optional
import numpy as np

_VOWELS = set("aeiou")
_CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
_HEX_CHARS = set("0123456789abcdef")
_BASE32_CHARS = set("abcdefghijklmnopqrstuvwxyz234567")
_BASE64_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=")

# Common top English word list for dictionary coverage (top 500 common syllables/words)
COMMON_WORDS = set([
    "about", "above", "after", "again", "air", "all", "almost", "along", "also", "always",
    "america", "an", "and", "animal", "another", "answer", "any", "are", "around", "as",
    "ask", "at", "away", "back", "be", "because", "been", "before", "began", "begin",
    "being", "below", "between", "big", "book", "both", "boy", "build", "built", "but",
    "by", "call", "came", "can", "car", "care", "carry", "center", "city", "cloud",
    "come", "country", "day", "did", "different", "do", "does", "don't", "down", "each",
    "earth", "east", "eat", "end", "even", "every", "example", "eye", "face", "family",
    "far", "fast", "few", "find", "first", "follow", "food", "for", "form", "found",
    "four", "from", "get", "give", "go", "good", "great", "group", "grow", "had",
    "hand", "hard", "has", "have", "he", "head", "hear", "help", "her", "here",
    "high", "him", "his", "home", "house", "how", "idea", "if", "important", "in",
    "into", "is", "it", "its", "just", "keep", "kind", "know", "land", "large",
    "last", "late", "learn", "leave", "left", "let", "letter", "life", "light", "like",
    "line", "list", "little", "live", "long", "look", "made", "mail", "make", "man",
    "many", "may", "me", "mean", "men", "might", "mile", "miss", "more", "most",
    "mother", "mountain", "move", "much", "must", "my", "name", "near", "need", "never",
    "new", "next", "night", "no", "not", "now", "number", "of", "off", "often",
    "oil", "old", "on", "once", "one", "only", "open", "or", "other", "our",
    "out", "over", "own", "page", "paper", "part", "people", "picture", "place", "plant",
    "play", "point", "port", "read", "real", "red", "right", "river", "run", "said",
    "same", "saw", "say", "school", "sea", "second", "see", "seem", "sentence", "set",
    "she", "show", "side", "small", "so", "some", "something", "sometimes", "song", "soon",
    "sound", "south", "spell", "start", "state", "still", "stop", "story", "study", "such",
    "sun", "system", "take", "talk", "tell", "than", "that", "the", "their", "them",
    "then", "there", "these", "they", "thing", "think", "this", "those", "thought", "three",
    "through", "time", "to", "together", "too", "took", "tree", "try", "turn", "two",
    "under", "until", "up", "us", "use", "very", "voice", "walk", "want", "war",
    "watch", "water", "way", "we", "well", "went", "were", "what", "when", "where",
    "which", "while", "white", "who", "why", "will", "with", "without", "word", "work",
    "world", "would", "write", "year", "you", "young", "your", "zone", "net", "web",
    "app", "tech", "site", "online", "shop", "store", "news", "blog", "data", "info",
    "host", "server", "mail", "auth", "login", "admin", "secure", "portal", "cloud", "static",
    "media", "img", "cdn", "user", "file", "api", "dev", "test", "stage", "prod"
])


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _max_consonant_run(s: str) -> int:
    """Longest contiguous run of consonants."""
    max_run, cur = 0, 0
    for ch in s:
        if ch in _CONSONANTS:
            cur += 1
            if cur > max_run:
                max_run = cur
        else:
            cur = 0
    return max_run


def _longest_dictionary_word_len(s: str) -> int:
    """Length of the longest matched common dictionary word substring."""
    s_clean = re.sub(r"[^a-z]", "", s.lower())
    if not s_clean:
        return 0
    max_w = 0
    for w in COMMON_WORDS:
        if len(w) > max_w and w in s_clean:
            max_w = len(w)
    return max_w


class BigramRarityScorer:
    """
    Computes bigram frequency distribution from a reference benign corpus,
    and scores test domains on mean log rarity of character bigrams.
    """
    def __init__(self):
        self.bigram_counts = Counter()
        self.total_bigrams = 0
        self.default_log_prob = -10.0

    def fit(self, domains: List[str]):
        self.bigram_counts.clear()
        self.total_bigrams = 0
        for d in domains:
            d_clean = re.sub(r"[^a-z0-9]", "", d.lower())
            for i in range(len(d_clean) - 1):
                bg = d_clean[i:i+2]
                self.bigram_counts[bg] += 1
                self.total_bigrams += 1

        if self.total_bigrams == 0:
            self.total_bigrams = 1

    def score(self, domain: str) -> float:
        """Returns mean negative log probability of bigrams (higher = more rare/anomalous)."""
        d_clean = re.sub(r"[^a-z0-9]", "", domain.lower())
        if len(d_clean) < 2:
            return 0.0
        scores = []
        for i in range(len(d_clean) - 1):
            bg = d_clean[i:i+2]
            cnt = self.bigram_counts.get(bg, 0)
            if cnt > 0:
                prob = cnt / self.total_bigrams
                scores.append(-math.log2(prob))
            else:
                scores.append(15.0)  # penalty for unseen bigram
        return float(np.mean(scores)) if scores else 0.0


FEATURE_NAMES_EXTENDED = [
    "length",               # 0: raw character length
    "log_len",              # 1: log1p(length)
    "entropy",              # 2: Shannon entropy over entire domain
    "norm_entropy",         # 3: entropy normalised by log2(unique_chars)
    "digit_ratio",          # 4: ratio of digits
    "alpha_ratio",          # 5: ratio of letters
    "vowel_ratio",          # 6: ratio of vowels over letters
    "max_consonant_run",    # 7: longest consecutive consonant substring
    "sep_ratio",            # 8: ratio of separator chars (. - _)
    "unique_char_ratio",    # 9: unique characters / length
    "n_labels",             # 10: number of dot-separated labels
    "max_label_len",        # 11: maximum length among labels
    "mean_label_len",       # 12: mean length across labels
    "hex_fraction",         # 13: ratio of valid hex characters
    "base32_fraction",      # 14: ratio of valid base32 characters
    "base64_fraction",      # 15: ratio of valid base64 characters
    "dict_word_ratio",      # 16: length of longest common word / length
    "subdomain_entropy",    # 17: entropy of subdomains (excluding SLD+TLD)
]


def extract_features_vector(
    domain: str,
    rarity_scorer: Optional[BigramRarityScorer] = None,
) -> np.ndarray:
    """
    Extract 18 lexical and statistical features for a single domain string.
    """
    d = domain.strip().lower().rstrip(".")
    length = max(len(d), 1)

    log_len = math.log1p(length)
    entropy = _shannon_entropy(d)
    
    unique_chars = len(set(d))
    norm_entropy = entropy / math.log2(max(unique_chars, 2))

    digit_count = sum(ch.isdigit() for ch in d)
    digit_ratio = digit_count / length

    alpha_count = sum(ch.isalpha() for ch in d)
    alpha_ratio = alpha_count / length

    vowel_count = sum(ch in _VOWELS for ch in d)
    vowel_ratio = vowel_count / max(alpha_count, 1)

    max_cons = _max_consonant_run(d)

    sep_count = sum(ch in ".-_" for ch in d)
    sep_ratio = sep_count / length

    unique_char_ratio = unique_chars / length

    # Label-level features
    labels = d.split(".")
    n_labels = len(labels)
    label_lens = [len(lbl) for lbl in labels]
    max_lbl = max(label_lens) if label_lens else 0
    mean_lbl = float(np.mean(label_lens)) if label_lens else 0.0

    # Encoding character fractions
    hex_count = sum(ch in _HEX_CHARS for ch in d)
    hex_fraction = hex_count / length

    b32_count = sum(ch in _BASE32_CHARS for ch in d)
    b32_fraction = b32_count / length

    b64_count = sum(ch in _BASE64_CHARS for ch in d)
    b64_fraction = b64_count / length

    # Dictionary word ratio
    longest_word_len = _longest_dictionary_word_len(d)
    dict_word_ratio = longest_word_len / length

    # Subdomain entropy (excluding the last two labels if >= 3 labels)
    if n_labels >= 3:
        subdomain_part = ".".join(labels[:-2])
        sub_entropy = _shannon_entropy(subdomain_part)
    elif n_labels == 2:
        sub_entropy = _shannon_entropy(labels[0])
    else:
        sub_entropy = 0.0

    vec = [
        float(length),
        log_len,
        entropy,
        norm_entropy,
        digit_ratio,
        alpha_ratio,
        vowel_ratio,
        float(max_cons),
        sep_ratio,
        unique_char_ratio,
        float(n_labels),
        float(max_lbl),
        mean_lbl,
        hex_fraction,
        b32_fraction,
        b64_fraction,
        dict_word_ratio,
        sub_entropy,
    ]

    return np.array(vec, dtype=np.float32)
