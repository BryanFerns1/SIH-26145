"""
Central split configuration for UniGuard 1D CNN.

ALL stages must import splits from here. This is the single source of truth.

Scenarios available in extracted_flows/all_flows.pkl:
  1, 2, 3, 4, 5, 6, 7, 8, 12, 13
  (9, 10, 11 were NOT extracted -- PCAPs not available locally)

Split design rationale:
  - test = [8, 12]: Murlo + NSIS.ay -- unseen families, decent size
  - val = [6, 7]: Menti + Sogou -- used for early stopping / model selection
  - cal = [13]: Virut -- held out for threshold calibration ONLY
  - train = [1, 2, 3, 4, 5]: Neris + Rbot + Virut -- all remaining
    (Scenario 5 = Virut stays in train so that Virut is not absent from training,
     even though 13 = Virut is in cal. This is acceptable because 5 and 13 are
     different captures with different network contexts.)

Families represented in train: Neris (1,2), Rbot (3,4), Virut (5)
Families NOT in train: Menti (val), Sogou (val), Murlo (test), NSIS.ay (test)
"""

# Scenario assignments -- MUST be pairwise disjoint
TRAIN_SCENARIOS = [1, 2, 3, 4, 5]
VAL_SCENARIOS = [6, 7]
CAL_SCENARIOS = [13]
TEST_SCENARIOS = [8, 12]

# All scenarios that should be present in the pickle
ALL_SCENARIOS = sorted(TRAIN_SCENARIOS + VAL_SCENARIOS + CAL_SCENARIOS + TEST_SCENARIOS)

# Scenarios that were NOT extracted (PCAPs unavailable)
MISSING_SCENARIOS = [9, 10, 11]


def validate_splits():
    """Assert pairwise disjoint and complete."""
    sets = {
        'train': set(TRAIN_SCENARIOS),
        'val': set(VAL_SCENARIOS),
        'cal': set(CAL_SCENARIOS),
        'test': set(TEST_SCENARIOS),
    }
    names = list(sets.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            overlap = sets[names[i]] & sets[names[j]]
            assert not overlap, (
                f"SPLIT LEAKAGE: {names[i]} and {names[j]} share scenarios {overlap}"
            )
    return True


def validate_pickle_scenarios(flows: list):
    """Assert that every scenario in ALL_SCENARIOS actually exists in the data."""
    present = set(f['scenario_id'] for f in flows)
    missing = set(ALL_SCENARIOS) - present
    assert not missing, (
        f"Scenarios {missing} are in the split config but NOT in the pickle! "
        f"Present: {sorted(present)}"
    )
    return True


def split_flows(flows: list) -> tuple:
    """
    Split flows into (train, val, cal, test) using the canonical config.

    Returns: (train_flows, val_flows, cal_flows, test_flows)
    """
    validate_splits()
    validate_pickle_scenarios(flows)

    train_set = set(TRAIN_SCENARIOS)
    val_set = set(VAL_SCENARIOS)
    cal_set = set(CAL_SCENARIOS)
    test_set = set(TEST_SCENARIOS)

    train, val, cal, test = [], [], [], []
    for f in flows:
        sid = f['scenario_id']
        if sid in train_set:
            train.append(f)
        elif sid in val_set:
            val.append(f)
        elif sid in cal_set:
            cal.append(f)
        elif sid in test_set:
            test.append(f)
        # else: skip (should not happen after validation)

    return train, val, cal, test


def get_split_table() -> str:
    """Return a human-readable split table."""
    from ctu13_ground_truth import SCENARIOS
    lines = []
    lines.append(f"{'Scenario':>8} | {'Role':>8} | {'Family':<10}")
    lines.append("-" * 35)
    for role, sids in [('train', TRAIN_SCENARIOS), ('val', VAL_SCENARIOS),
                       ('cal', CAL_SCENARIOS), ('test', TEST_SCENARIOS)]:
        for sid in sids:
            family = SCENARIOS.get(sid, {}).get('family', '?')
            lines.append(f"{sid:>8} | {role:>8} | {family:<10}")
    return "\n".join(lines)


if __name__ == "__main__":
    validate_splits()
    print("Splits are valid (pairwise disjoint).")
    print()
    print(get_split_table())
