#!/usr/bin/env bash
set -euo pipefail

KERNEL_DIR="${1:-.}"
BUILD_LOG="${2:-}"
FAIL=0

echo "=== N0Kernel r2 ABI & Hook Gate (${KERNEL_DIR}) ==="
fail() { echo "[FAIL] $*" >&2; FAIL=1; }
pass() { echo "[PASS] $*"; }

cd "${KERNEL_DIR}"

grep -Eq '^\s*ksu_handle_setresuid\s*\(' kernel/sys.c && pass "Check 1: ksu_handle_setresuid in kernel/sys.c" || fail "Check 1: ksu_handle_setresuid MISSING in kernel/sys.c"
grep -Eq '^\s*ksu_handle_sys_reboot\s*\(' kernel/reboot.c && pass "Check 2: ksu_handle_sys_reboot in kernel/reboot.c" || fail "Check 2: ksu_handle_sys_reboot MISSING in kernel/reboot.c"

python3 - << 'PYEOF' || FAIL=1
import os, re, sys
su_files = [p for p in ["drivers/kernelsu/sucompat.c", "drivers/kernelsu/sucompat.h", "KernelSU-Next/kernel/sucompat.c", "KernelSU-Next/kernel/sucompat.h"] if os.path.isfile(p)]
if not su_files:
    print("[FAIL] Check 3: sucompat.c/h not found", file=sys.stderr); sys.exit(1)
su_text = "\n".join(open(p, errors="ignore").read() for p in su_files)
def arg2_kind(txt, fn):
    kinds = set()
    for m in re.finditer(r'\b' + re.escape(fn) + r'\s*\(\s*[^,]+,\s*([^,\)]+)', txt):
        a = re.sub(r'\s+', ' ', m.group(1)).strip()
        if a.startswith('&') or a == 'filename': continue
        if 'struct filename' in a: kinds.add('struct_filename_ptrptr')
        elif re.search(r'char\s+(?:__user\s+)?\*\*', a): kinds.add('const_char_user_ptrptr')
    return kinds
ok = True
for fn, path in [("ksu_handle_faccessat", "fs/open.c"), ("ksu_handle_stat", "fs/stat.c")]:
    ct = open(path, errors="ignore").read()
    ck, sk = arg2_kind(ct, fn), arg2_kind(su_text, fn)
    if not ck or not sk or ck != sk:
        print(f"[FAIL] Check 3: ABI mismatch {fn}: {path}={ck} vs sucompat={sk}", file=sys.stderr); ok = False
    else:
        print(f"[PASS] Check 3: ABI match {fn} ({sorted(sk)[0]})")
    if not re.search(r'\b' + re.escape(fn) + r'\s*\(\s*&', ct):
        print(f"[FAIL] Check 3: call site {fn} missing in {path}", file=sys.stderr); ok = False
sys.exit(0 if ok else 1)
PYEOF

[[ -f fs/susfs.c && -f include/linux/susfs.h ]] && pass "Check 4a: fs/susfs.c & include/linux/susfs.h present" || fail "Check 4a: SUSFS core files missing"
for f in fs/namei.c fs/namespace.c fs/stat.c fs/proc/task_mmu.c; do
  grep -q 'CONFIG_KSU_SUSFS' "$f" && pass "Check 4b: SUSFS in $f" || fail "Check 4b: SUSFS missing in $f"
done
grep -Rq 'CONFIG_KSU_SUSFS' drivers/kernelsu/ KernelSU-Next/kernel/ 2>/dev/null && pass "Check 4c: SUSFS in KSUN" || fail "Check 4c: SUSFS missing in KSUN"
REJS="$(find . -maxdepth 5 -name '*.rej' -not -path './out*' 2>/dev/null || true)"
[[ -z "$REJS" ]] && pass "Check 4d: Zero .rej files" || fail "Check 4d: .rej files found: $REJS"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  TOUCHED="$(git status --porcelain | awk '{print $NF}' | grep -Ev '^(KernelSU-Next/|drivers/kernelsu/|out|scripts/ksu_abi_gate\.sh)' || true)"
  OP_HITS=""
  [[ -n "$TOUCHED" ]] && OP_HITS="$(git diff -- $TOUCHED 2>/dev/null | grep -E '^\+' | grep -Ev '^\+\+\+' | grep -iE '\b(oneplus|kebab|instantnoodle|hotdog|lemonade|oplus)\b' || true)"
  [[ -z "$OP_HITS" ]] && pass "Check 5: Zero OnePlus identifiers" || fail "Check 5: OnePlus identifier found: $OP_HITS"
fi

if [[ -n "$BUILD_LOG" ]]; then
  ERRS="$(grep -E '(^| )error:' "$BUILD_LOG" || true)"
  WARNS="$(grep -E '(drivers/kernelsu|KernelSU-Next|fs/susfs\.c|include/linux/susfs).*warning:' "$BUILD_LOG" || true)"
  [[ -z "$ERRS" ]] && pass "Check 6a: Zero errors in $BUILD_LOG" || fail "Check 6a: Errors in $BUILD_LOG"
  [[ -z "$WARNS" ]] && pass "Check 6b: Zero KSU/SUSFS warnings in $BUILD_LOG" || fail "Check 6b: Warnings in $BUILD_LOG: $(echo "$WARNS" | head -n 5)"
fi

[[ "$FAIL" -eq 0 ]] && echo "GATE RESULT: PASSED" || { echo "GATE RESULT: FAILED"; exit 1; }
