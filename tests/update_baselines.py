import sys
import os
# Add parent dir to path so we can import scalpel_racer
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scalpel_racer import analyze_results, ScanResult

# Hashes for consistency
HASH_BODY1 = "a930708296f3049c81101773566458d9f0765b03c2311c979f43396060399b13"
HASH_BODY2 = "8312c64d5771c1a3c56c8b455485dd9507687133b3af5182c440e1b10b0626f1"
HASH_SUCCESS = "a51199a18f94874e709778760b606371c8d0070046ae197770433705606c0e74"
HASH_ERROR = "e1c9c0e004111791308115140c4e251853085e3300414f1578f85164943117d9"

class Capturer:
    def __init__(self):
        self.output = []
    def write(self, text):
        self.output.append(text)
    def flush(self): pass
    def get(self): return "".join(self.output).strip()

def regenerate(filename, results):
    print(f"[*] Regenerating {filename}...")
    cap = Capturer()
    old_stdout = sys.stdout
    sys.stdout = cap
    try:
        analyze_results(results)
    finally:
        sys.stdout = old_stdout
    
    path = os.path.join("tests", "baselines", filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(cap.get())

def main():
    # 1. Identical
    results = [
        ScanResult(0, 200, 100.0, HASH_BODY1, "body1"),
        ScanResult(1, 200, 110.0, HASH_BODY1, "body1"),
    ]
    regenerate("analyze_results_identical.txt", results)

    # 2. Different Bodies
    results = [
        ScanResult(0, 200, 100.0, HASH_BODY1, "body1"),
        ScanResult(1, 200, 110.0, HASH_BODY2, "body2"),
    ]
    regenerate("analyze_results_different_bodies.txt", results)

    # 3. Mixed Status
    results = [
        ScanResult(0, 200, 100.0, HASH_SUCCESS, "success"),
        ScanResult(1, 500, 50.0, HASH_ERROR, "error"),
    ]
    regenerate("analyze_results_mixed_status.txt", results)

    # 4. Histogram
    results = [ScanResult(i, 200, 100.0 + (i%5)*5, HASH_BODY1, "body1") for i in range(20)]
    regenerate("analyze_results_histogram.txt", results)

    print("[+] All baselines updated to match current code logic.")

if __name__ == "__main__":
    main()
