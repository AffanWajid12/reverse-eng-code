import re
import os
from collections import Counter

class DecompilerAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.content = ""
        self.report = {
            "qt_classes": Counter(),
            "unsafe_functions": [],
            "hardcoded_files": [],
            "interesting_strings": [],
            "custom_functions": [],
            "potential_flaws": []
        }

    def load_file(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.content = f.read()
            return True
        except FileNotFoundError:
            print(f"Error: Could not find file '{self.file_path}'")
            return False

    def analyze(self):
        # 1. Architecture: Identify Qt Framework Components
        # Pattern: Words starting with Q followed by a capital letter (Qt convention)
        qt_pattern = r"\b(Q[A-Z][a-zA-Z0-9]+)\b"
        self.report["qt_classes"] = Counter(re.findall(qt_pattern, self.content))

        # 2. Logic: Identify Custom "FUN_" Functions
        # Pattern: The generic naming convention used by Ghidra/IDA
        func_pattern = r"\b(FUN_[0-9a-fA-F]+)\b"
        self.report["custom_functions"] = list(set(re.findall(func_pattern, self.content)))

        # 3. Flaws: Check for Hardcoded File Paths and Resources
        # Pattern: Strings that look like file paths or qrc resources
        file_pattern = r'"([a-zA-Z0-9_:/\\.]+\.(?:txt|wav|mp3|png|ini|dat))"'
        qrc_pattern = r'"(qrc:[^"]+)"'
        
        self.report["hardcoded_files"].extend(re.findall(file_pattern, self.content))
        self.report["hardcoded_files"].extend(re.findall(qrc_pattern, self.content))

        # 4. Functionality: Extract Human-Readable Strings (UI Text)
        # Pattern: Strings that are likely UI messages (ignoring single chars or gibberish)
        string_pattern = r'"([A-Za-z0-9\s\.,!?:]{3,})"'
        all_strings = re.findall(string_pattern, self.content)
        # Filter out common noise
        self.report["interesting_strings"] = [
            s for s in all_strings 
            if s not in self.report["hardcoded_files"] and "default" not in s
        ]

        # 5. Security: Scan for Unsafe C Functions (CWE-120 Buffer Overflows)
        unsafe_patterns = [
            "strcpy", "strcat", "sprintf", "gets", "memcpy", "system"
        ]
        for func in unsafe_patterns:
            if re.search(rf"\b{func}\b", self.content):
                self.report["unsafe_functions"].append(func)
                self.report["potential_flaws"].append(f"Use of unsafe function '{func}' detected (Risk: Buffer Overflow)")

        # 6. Flaw Check: Insecure File IO
        if "QFile" in self.content and ("QDataStream" in self.content or "write" in self.content):
             self.report["potential_flaws"].append(
                 "Local File Persistence detected (QFile/QDataStream). "
                 "If this saves scores, it is likely insecure/unencrypted."
             )

    def print_report(self):
        print("="*60)
        print(f" STATIC ANALYSIS REPORT: {self.file_path}")
        print("="*60)

        print(f"\n[+] ARCHITECTURE: Qt Framework Detection")
        print(f"    - Qt Classes Found: {len(self.report['qt_classes'])}")
        # Print top 5 used classes to show what the app focuses on (e.g., Media vs GUI)
        for cls, count in self.report['qt_classes'].most_common(8):
            print(f"      * {cls}: {count} occurrences")

        print(f"\n[+] FUNCTIONALITY: Key String Artifacts")
        print(f"    (These reveal what the application does)")
        for s in set(self.report["interesting_strings"]):
            print(f"      * \"{s}\"")

        print(f"\n[+] RESOURCES: Hardcoded Assets")
        print(f"    (Files compiled into the exe or loaded locally)")
        for f in set(self.report["hardcoded_files"]):
            print(f"      * {f}")

        print(f"\n[+] SECURITY & FLAWS: Vulnerability Scan")
        if not self.report["potential_flaws"]:
            print("      - No obvious flaws detected by heuristic scan.")
        else:
            for flaw in self.report["potential_flaws"]:
                print(f"      [!] {flaw}")

        if self.report["unsafe_functions"]:
            print(f"      [!] Unsafe C Library calls: {', '.join(self.report['unsafe_functions'])}")

        print(f"\n[+] CODE METRICS")
        print(f"    - Total Custom Functions (FUN_...): {len(self.report['custom_functions'])}")
        print("="*60)

# --- HOW TO RUN ---
# 1. Create a file named 'decompiled_code.c'
# 2. Paste your Ghidra/IDA code into it.
# 3. Run this script.

if __name__ == "__main__":
    # Create a dummy file if it doesn't exist for testing
    target_file = "SnakeGame.exe.c"
    
    # Run analysis
    analyzer = DecompilerAnalyzer(target_file)
    if analyzer.load_file():
        analyzer.analyze()
        analyzer.print_report()