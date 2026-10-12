"""
1D CNN model for UniGuard botnet C2 / beaconing detection.

Architecture: small 1D CNN with 3 conv blocks, BatchNorm, GlobalAvgPooling.
Target: < 1M parameters, CPU-only inference >= 5000 flows/s.

Two model variants:
  A) Packet-sequence input: (N=32, 7)
  B) Beacon-series input:   (K=32, 3)
  A+B) Combined model with shared output head

Loss: Focal loss (handles class imbalance better than class weights alone
      because it down-weights easy examples regardless of class).
"""

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppress TF warnings

import numpy as np


def build_model_a(N: int = 32, C: int = 7, name: str = "beacon_cnn_a"):
    """
    Variant A: Packet-sequence 1D CNN.

    Input: (batch, N, C) where C = 7 (size, iat, mask, syn, fin, rst, psh)
    Output: sigmoid probability of botnet

    Architecture:
      Conv1D(32, 3) -> BN -> ReLU -> Conv1D(64, 3) -> BN -> ReLU ->
      Conv1D(64, 3) -> BN -> ReLU -> GlobalAvgPool -> Dropout(0.3) ->
      Dense(32) -> ReLU -> Dropout(0.2) -> Dense(1, sigmoid)
    """
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers

    inp = keras.Input(shape=(N, C), name="packet_seq")

    x = layers.Conv1D(32, 3, padding='same', name='conv1')(inp)
    x = layers.BatchNormalization(name='bn1')(x)
    x = layers.ReLU(name='relu1')(x)

    x = layers.Conv1D(64, 3, padding='same', name='conv2')(x)
    x = layers.BatchNormalization(name='bn2')(x)
    x = layers.ReLU(name='relu2')(x)

    x = layers.Conv1D(64, 3, padding='same', name='conv3')(x)
    x = layers.BatchNormalization(name='bn3')(x)
    x = layers.ReLU(name='relu3')(x)

    x = layers.GlobalAveragePooling1D(name='gap')(x)
    x = layers.Dropout(0.3, name='drop1')(x)
    x = layers.Dense(32, activation='relu', name='fc1')(x)
    x = layers.Dropout(0.2, name='drop2')(x)
    x = layers.Dense(1, activation='sigmoid', name='output')(x)

    model = keras.Model(inputs=inp, outputs=x, name=name)
    return model


def build_model_b(K: int = 32, name: str = "beacon_cnn_b"):
    """
    Variant B: Beacon-series 1D CNN.

    Input: (batch, K, 3) where 3 = (gap, bytes, packets)
    Output: sigmoid probability of botnet
    """
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers

    inp = keras.Input(shape=(K, 3), name="beacon_seq")

    x = layers.Conv1D(32, 3, padding='same', name='conv1')(inp)
    x = layers.BatchNormalization(name='bn1')(x)
    x = layers.ReLU(name='relu1')(x)

    x = layers.Conv1D(64, 3, padding='same', name='conv2')(x)
    x = layers.BatchNormalization(name='bn2')(x)
    x = layers.ReLU(name='relu2')(x)

    x = layers.Conv1D(64, 3, padding='same', name='conv3')(x)
    x = layers.BatchNormalization(name='bn3')(x)
    x = layers.ReLU(name='relu3')(x)

    x = layers.GlobalAveragePooling1D(name='gap')(x)
    x = layers.Dropout(0.3, name='drop1')(x)
    x = layers.Dense(32, activation='relu', name='fc1')(x)
    x = layers.Dropout(0.2, name='drop2')(x)
    x = layers.Dense(1, activation='sigmoid', name='output')(x)

    model = keras.Model(inputs=inp, outputs=x, name=name)
    return model


def build_model_ab(N: int = 32, C_a: int = 7, K: int = 32,
                    use_ls_score: bool = False,
                    name: str = "beacon_cnn_ab"):
    """
    Combined model: Variant A + Variant B (optionally + Lomb-Scargle scalar).

    Two-branch architecture with shared dense head.
    """
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers

    # Branch A: Packet-sequence
    inp_a = keras.Input(shape=(N, C_a), name="packet_seq")
    a = layers.Conv1D(32, 3, padding='same', name='a_conv1')(inp_a)
    a = layers.BatchNormalization(name='a_bn1')(a)
    a = layers.ReLU(name='a_relu1')(a)
    a = layers.Conv1D(64, 3, padding='same', name='a_conv2')(a)
    a = layers.BatchNormalization(name='a_bn2')(a)
    a = layers.ReLU(name='a_relu2')(a)
    a = layers.GlobalAveragePooling1D(name='a_gap')(a)

    # Branch B: Beacon-series
    inp_b = keras.Input(shape=(K, 3), name="beacon_seq")
    b = layers.Conv1D(32, 3, padding='same', name='b_conv1')(inp_b)
    b = layers.BatchNormalization(name='b_bn1')(b)
    b = layers.ReLU(name='b_relu1')(b)
    b = layers.Conv1D(64, 3, padding='same', name='b_conv2')(b)
    b = layers.BatchNormalization(name='b_bn2')(b)
    b = layers.ReLU(name='b_relu2')(b)
    b = layers.GlobalAveragePooling1D(name='b_gap')(b)

    # Concatenate branches
    inputs = [inp_a, inp_b]
    concat_list = [a, b]

    if use_ls_score:
        inp_ls = keras.Input(shape=(1,), name="ls_score")
        inputs.append(inp_ls)
        concat_list.append(inp_ls)

    merged = layers.Concatenate(name='concat')(concat_list)
    x = layers.Dropout(0.3, name='drop1')(merged)
    x = layers.Dense(64, activation='relu', name='fc1')(x)
    x = layers.Dropout(0.2, name='drop2')(x)
    x = layers.Dense(32, activation='relu', name='fc2')(x)
    x = layers.Dense(1, activation='sigmoid', name='output')(x)

    model = keras.Model(inputs=inputs, outputs=x, name=name)
    return model


# ---------------------------------------------------------------------------
# Focal Loss
# ---------------------------------------------------------------------------

def focal_loss(gamma=2.0, alpha=0.25):
    """
    Focal loss for binary classification.

    Why focal loss over class weights:
      - Class weights uniformly upweight the minority class, which can
        amplify noisy labels.
      - Focal loss down-weights EASY examples (both classes) while
        focusing on hard examples, which is more robust to the
        easy-benign / hard-botnet imbalance in network traffic.

    gamma: focusing parameter (higher = more focus on hard examples)
    alpha: weight for positive class (botnet)
    """
    import tensorflow as tf

    def _focal_loss(y_true, y_pred):
        y_true = tf.cast(y_true, tf.float32)
        y_pred = tf.clip_by_value(y_pred, 1e-7, 1.0 - 1e-7)

        # Binary cross entropy components
        bce_pos = -y_true * tf.math.log(y_pred)
        bce_neg = -(1.0 - y_true) * tf.math.log(1.0 - y_pred)

        # Focal modulation
        p_t = y_true * y_pred + (1.0 - y_true) * (1.0 - y_pred)
        focal_weight = tf.pow(1.0 - p_t, gamma)

        # Alpha weighting
        alpha_weight = y_true * alpha + (1.0 - y_true) * (1.0 - alpha)

        loss = focal_weight * alpha_weight * (bce_pos + bce_neg)
        return tf.reduce_mean(loss)

    return _focal_loss


def count_params(model) -> int:
    """Count total trainable parameters."""
    return int(sum(p.numpy().size for p in model.trainable_weights))


def print_model_summary(model):
    """Print model summary and parameter count."""
    model.summary()
    n_params = count_params(model)
    print(f"\nTotal trainable parameters: {n_params:,}")
    if n_params > 1_000_000:
        print("WARNING: Model exceeds 1M parameter target!")
    else:
        print(f"Within 1M target ({n_params/1_000_000:.1%} of budget)")
