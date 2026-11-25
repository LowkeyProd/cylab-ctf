#!/usr/bin/env python3
"""
Solve script for PowerAnalysis: Part 2 (#365)
Category: Cryptography
Methodology: Correlation Power Analysis (CPA) with noise filtering on AES-128 S-Box outputs.
"""
import glob
from pathlib import Path
import numpy as np

# Standard AES S-Box table
AES_SBOX = np.array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
], dtype=np.uint8)

# Hamming Weight lookup table for 0..255
HW = np.array([bin(i).count('1') for i in range(256)], dtype=np.float64)


def load_traces(trace_dir: Path):
    file_list = sorted(glob.glob(str(trace_dir / "trace*.txt")))
    print(f"[*] Found {len(file_list)} trace files in {trace_dir}", flush=True)

    plaintexts = []
    traces = []
    for fpath in file_list:
        with open(fpath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            pt_hex = lines[0].split(": ")[1].strip()
            plaintexts.append(bytes.fromhex(pt_hex))
            trace_data = eval(lines[1].split(": ")[1].strip())
            traces.append(trace_data)

    pts_arr = np.array([[b for b in pt] for pt in plaintexts], dtype=np.uint8)
    traces_arr = np.array(traces, dtype=np.float64)
    return pts_arr, traces_arr


def perform_cpa(plaintexts: np.ndarray, traces: np.ndarray, filter_window: int = 3):
    """
    Applies moving average filter to suppress measurement noise,
    then calculates Pearson correlation for all 256 key candidates per byte.
    """
    if filter_window > 1:
        print(f"[*] Applying moving-average noise filter (window={filter_window})...", flush=True)
        filtered_traces = np.apply_along_axis(
            lambda m: np.convolve(m, np.ones(filter_window) / filter_window, mode="valid"),
            axis=1,
            arr=traces
        )
    else:
        filtered_traces = traces

    # Mean-center and normalize trace columns
    trace_centered = filtered_traces - np.mean(filtered_traces, axis=0)
    trace_norm = np.linalg.norm(trace_centered, axis=0)
    trace_norm[trace_norm == 0] = 1e-12
    trace_normalized = trace_centered / trace_norm

    recovered_key_bytes = []
    candidates = np.arange(256, dtype=np.uint8)

    print("[*] Running Correlation Power Analysis across 16 key bytes...", flush=True)
    for byte_idx in range(16):
        # Hypothetical intermediate values: S-Box(plaintext ^ candidate_key)
        # pts shape: (num_traces, 1), candidates shape: (256,) -> intermediate shape: (num_traces, 256)
        intermediate = AES_SBOX[plaintexts[:, byte_idx:byte_idx + 1] ^ candidates]
        hyp_hw = HW[intermediate]

        # Mean-center and normalize hypothetical power consumption
        hyp_centered = hyp_hw - np.mean(hyp_hw, axis=0)
        hyp_norm = np.linalg.norm(hyp_centered, axis=0)
        hyp_norm[hyp_norm == 0] = 1e-12
        hyp_normalized = hyp_centered / hyp_norm

        # Correlation matrix: (256, trace_samples)
        corr_matrix = np.abs(hyp_normalized.T @ trace_normalized)
        max_corrs = np.max(corr_matrix, axis=1)

        sorted_candidates = np.argsort(max_corrs)[::-1]
        best_cand = sorted_candidates[0]
        runner_up = sorted_candidates[1]

        recovered_key_bytes.append(best_cand)
        print(
            f"  Byte {byte_idx:2d}: best=0x{best_cand:02x} (corr={max_corrs[best_cand]:.4f}), "
            f"runner_up=0x{runner_up:02x} (corr={max_corrs[runner_up]:.4f}), "
            f"gap={max_corrs[best_cand] - max_corrs[runner_up]:.4f}",
            flush=True
        )

    key_hex = bytes(recovered_key_bytes).hex()
    return key_hex


def solve():
    print("[*] Solving PowerAnalysis: Part 2...", flush=True)
    base_dir = Path(__file__).resolve().parent
    traces_dir = base_dir / "traces"

    pts, traces = load_traces(traces_dir)
    print(f"[*] Loaded {pts.shape[0]} traces of length {traces.shape[1]} samples.", flush=True)

    key_hex = perform_cpa(pts, traces, filter_window=3)
    print(f"[*] Recovered AES Key: {key_hex}", flush=True)

    flag = f"academy{{{key_hex}}}"
    print(f"[+] Flag found: {flag}", flush=True)

    # Save to flag.txt
    flag_path = base_dir / "flag.txt"
    flag_path.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Flag written to {flag_path}", flush=True)

    return flag


if __name__ == "__main__":
    solve()
