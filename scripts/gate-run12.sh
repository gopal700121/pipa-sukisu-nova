#!/usr/bin/env bash
# gate-run12.sh — SUSFS symbol coverage gate.
# Catches both failure classes this project has already hit:
#   Run #8:  call sites whose declarations are missing from the tree's headers (compile error)
#   Run #11: calls that compile (extern self-carried in the .c file / merged headers) but
#            whose definitions do not exist in the tree's core — vmlinux LINK error
# Usage: bash gate-run12.sh   (from the kernel tree root, before launching the build)
set -u
H=(include/linux/susfs_def.h include/linux/susfs.h)
CORE=fs/susfs.c
HOOKS=(drivers/kernelsu/*.c fs/stat.c fs/exec.c fs/open.c fs/namespace.c fs/read_write.c \
       fs/readdir.c fs/statfs.c fs/namei.c fs/super.c fs/proc/base.c fs/proc/cmdline.c \
       fs/proc/fd.c fs/proc/task_mmu.c fs/proc_namespace.c fs/notify/fdinfo.c \
       block/ioprio.c mm/memory.c kernel/sys.c kernel/kallsyms.c security/selinux/avc.c)
fail=0

echo "[gate] SUSFS symbol coverage over drivers/kernelsu/*.c + the 4.19 hook files"

for s in $(grep -hoE '\b(susfs_[A-Za-z_0-9]+|STATX_SUS_[A-Z_]+)\b' "${HOOKS[@]}" 2>/dev/null | sort -u); do
    [ "$s" = "susfs_def" ] && continue
    grep -rqF -- "$s" "${H[@]}" "$CORE" drivers/kernelsu/ 2>/dev/null \
        || { echo "MISSING DECLARATION: $s"; fail=1; }
done

for s in $(grep -hoE '\bsusfs_[a-z_0-9]+\(' "${HOOKS[@]}" 2>/dev/null | tr -d '(' | sort -u); do
    if ! grep -qE "^[A-Za-z_].*\b$s\b[[:space:]]*\(" "$CORE" 2>/dev/null \
       && ! grep -qE "static[[:space:]]+inline.*\b$s\b" "${H[@]}" 2>/dev/null; then
        echo "MISSING DEFINITION (link risk): $s — not defined in $CORE nor inlined in headers"
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "GATE PASS — every SUSFS symbol used by the hooks is declared and defined in the v2.1.0 layer"
fi
exit "$fail"
