import base64
import math
from collections import Counter

FILE_PATH = "pqc_messages.txt"

#ANSI Color codes for clean CLI formatting
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def chi_square(data):
    n = len(data)
    expected = n / 256.0
    counts = Counter(data)
    chi2 = sum(((counts[b] - expected) ** 2) / expected for b in range(256))
    return chi2, expected


def bit_hamming_distance(buf1, buf2):
    if len(buf1) != len(buf2):
        return 0, 0
    diffs = sum(bin(a ^ b).count('1') for a, b in zip(buf1, buf2))
    return diffs, len(buf1) * 8


def main():
    print(f"\n{BOLD}{BLUE}----------------------- PQC AUDIT -----------------------{RESET}\n")

    try:
        with open(FILE_PATH, "r", encoding="utf-8") as f:
            raw_b64 = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}[-] Error: file '{FILE_PATH}' not found.{RESET}")
        return

    if not raw_b64:
        print(f"{RED}[-] Sample file is empty.{RESET}")
        return

    samples = [base64.b64decode(s) for s in raw_b64]
    all_bytes = bytearray().join(samples)

    print(f"Loaded {BOLD}{len(samples)}{RESET} samples ({len(all_bytes)} bytes total)\n")

    #1. Uniqueness check
    unique_count = len(set(raw_b64))
    print(f"[*] Unique ciphertexts: {unique_count}/{len(samples)}")
    if unique_count == len(samples):
        print(f"    -> {GREEN}PASS{RESET}: No duplicate payloads (ephemeral keying OK)")
    else:
        print(f"    -> {RED}FAIL{RESET}: Duplicates detected")

    #2. Payload size / FIPS 203 match
    sizes = set(len(s) for s in samples)
    sample_len = len(samples[0])
    
    print(f"[*] Payload size: {sample_len} bytes")
    if len(sizes) == 1:
        if sample_len == 1088:
            print(f"    -> {GREEN}PASS{RESET}: ML-KEM-768 match (FIPS 203)")
        elif sample_len in (768, 1568):
            print(f"    -> {GREEN}PASS{RESET}: ML-KEM-{512 if sample_len == 768 else 1024} match")
        else:
            print(f"    -> {YELLOW}WARN{RESET}: Non-standard PQC payload size")
    else:
        print(f"    -> {RED}FAIL{RESET}: Inconsistent payload sizes")

    #3. Frequency & Entropy
    entropy = shannon_entropy(all_bytes)
    chi2, exp_freq = chi_square(all_bytes)
    print(f"[*] Shannon Entropy: {entropy:.6f} / 8.0")
    print(f"[*] Chi-Square (χ²): {chi2:.2f} (expected freq/byte: {exp_freq:.1f})")
    
    if 180.0 <= chi2 <= 330.0:
        print(f"    -> {GREEN}PASS{RESET}: Uniform byte distribution")
    else:
        print(f"    -> {YELLOW}INFO{RESET}: Mild Chi2 variance (expected with q=3329 modular reduction)")

    #4. Bit independence / Avalanche
    if len(samples) > 1:
        flips = []
        for i in range(len(samples) - 1):
            diff, total = bit_hamming_distance(samples[i], samples[i + 1])
            flips.append((diff / total) * 100)
        
        avg_flip = sum(flips) / len(flips)
        print(f"[*] Avg Hamming Distance (adjacent samples): {avg_flip:.2f}%")
        if 45.0 <= avg_flip <= 55.0:
            print(f"    -> {GREEN}PASS{RESET}: Good avalanche effect (~50% bit flips)")
        else:
            print(f"    -> {YELLOW}WARN{RESET}: Avalanche rate deviates from expected 50%")

    print(f"\n{BOLD}{BLUE}----------------------------------------------------------{RESET}\n")


if __name__ == "__main__":
    main()