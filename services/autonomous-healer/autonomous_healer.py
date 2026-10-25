#!/usr/bin/env python3
"""
scripts/autonomous_healer.py — Closed-Loop Self-Debugging & Auto-Repair Supervisor
Tier 2 Autonomous Resilience Loop: converges test regressions to exit code 0.
"""
import re
import subprocess
import sys
from pathlib import Path

MAX_HEAL_ITERATIONS = 6

def run_verification_step(step_name: str, cmd: list) -> tuple[int, str, str]:
    """Execute a verification command and capture output."""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr

def apply_deterministic_repair(stage_name: str, stdout: str, stderr: str) -> bool:
    """Applies AST or regex autofixes for known regression signatures."""
    combined = f"{stdout}\n{stderr}"
    
    # Repair: Blocked native alert/confirm dialogs
    if "BLOCKED_DIALOG" in combined or "alert(" in combined:
        for target in Path("public").glob("*.html"):
            src = target.read_text(encoding="utf-8")
            if "alert(" in src:
                patched = re.sub(r"\balert\(([^)]+)\)", r"showToast('System Notice', \1)", src)
                target.write_text(patched, encoding="utf-8")
                return True
                
    # Repair: Window handler export missing
    match_mod = re.search(r"MODULE_HANDLER.*calls (\w+)\(\)", combined)
    if match_mod:
        fn_name = match_mod.group(1)
        for target in Path("public").glob("*.html"):
            src = target.read_text(encoding="utf-8")
            if fn_name in src and f"window.{fn_name}" not in src:
                patched = src.replace("</script>", f"window.{fn_name} = {fn_name};\n</script>")
                target.write_text(patched, encoding="utf-8")
                return True
                
    return False

def run_autonomous_loop() -> int:
    """Runs closed loop self-healing until 0 errors or MAX_HEAL_ITERATIONS."""
    print("=== [AUTONOMOUS HEALER] STARTING PRIVAINDIA VERIFICATION SUPERVISOR ===")
    
    pipeline = [
        ("Python DPDP Compliance Tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"]),
    ]
    
    for iteration in range(1, MAX_HEAL_ITERATIONS + 1):
        print(f"--> [ITERATION {iteration}/{MAX_HEAL_ITERATIONS}] Running validation pipeline...")
        all_passed = True
        
        for stage_name, cmd in pipeline:
            retcode, stdout, stderr = run_verification_step(stage_name, cmd)
            if retcode != 0:
                print(f"[FAULT DETECTED] Stage '{stage_name}' failed with code {retcode}.")
                print(f"STDERR: {stderr[:300]}")
                repaired = apply_deterministic_repair(stage_name, stdout, stderr)
                print(f"[REPAIR ACTION] Stage '{stage_name}' patched: {repaired}")
                all_passed = False
                break
                
        if all_passed:
            print(f"=== [CONVERGED] All checks passed with 0 errors on iteration {iteration} ===")
            return 0
            
    print("[ERROR] Max healing iterations reached without full convergence.")
    return 1

if __name__ == "__main__":
    sys.exit(run_autonomous_loop())
