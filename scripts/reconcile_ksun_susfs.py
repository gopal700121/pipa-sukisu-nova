import glob
import os
import re
import sys

# 1. Reconcile include/linux/sched.h.rej (SUSFS task_struct fields) if present
if os.path.exists("include/linux/sched.h.rej"):
    rej_txt = open("include/linux/sched.h.rej").read()
    print(">>> Reconciling include/linux/sched.h.rej:")
    print(rej_txt)
    added = [line[1:] for line in rej_txt.splitlines() if line.startswith("+") and not line.startswith("+++")]
    if added and any("SUSFS" in l or "susfs" in l for l in added):
        sched = open("include/linux/sched.h").read()
        block = "\n".join(added) + "\n"
        anchor = "\trandomized_struct_fields_end"
        if anchor not in sched:
            anchor = "\t/* CPU-specific state of this task: */"
        assert anchor in sched, "No anchor in include/linux/sched.h"
        sched = sched.replace(anchor, block + anchor, 1)
        open("include/linux/sched.h", "w").write(sched)
        os.remove("include/linux/sched.h.rej")
        print(">>> Resolved include/linux/sched.h.rej cleanly")

# 2. Reconcile fs/proc/task_mmu.c.rej (5-arg walk_page_range backport) if present
if os.path.exists("fs/proc/task_mmu.c.rej"):
    print(">>> Reconciling fs/proc/task_mmu.c.rej")
    print(open("fs/proc/task_mmu.c.rej").read())
    txt = open("fs/proc/task_mmu.c").read()
    if "#include <linux/susfs_def.h>" not in txt:
        txt = "#include <linux/susfs_def.h>\n" + txt
    if "AS_FLAGS_SUS_MAP" in txt:
        sus_cond = "unlikely(test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags)) && susfs_is_current_proc_umounted()"
    elif "BIT_SUS_MAP" in txt:
        sus_cond = "unlikely(inode->i_mapping->flags & BIT_SUS_MAP) && susfs_is_current_proc_umounted()"
    else:
        sus_cond = "0"
    target = "ret = walk_page_range(mm, start_vaddr, end, &pagemap_ops, &pm);"
    if target in txt:
        replacement = (
            "#ifdef CONFIG_KSU_SUSFS_SUS_MAP\n"
            "\t\t\t{\n"
            "\t\t\t\tstruct vm_area_struct *vma = find_vma(mm, start_vaddr);\n"
            "\t\t\t\tif (vma && vma->vm_file) {\n"
            "\t\t\t\t\tstruct inode *inode = file_inode(vma->vm_file);\n"
            f"\t\t\t\t\tif ({sus_cond}) {{\n"
            "\t\t\t\t\t\tmemset(pm.buffer, 0, sizeof(pagemap_entry_t) * pm.len);\n"
            "\t\t\t\t\t\tpm.pos = pm.len;\n"
            "\t\t\t\t\t\tret = 0;\n"
            "\t\t\t\t\t} else {\n"
            "\t\t\t\t\t\tret = walk_page_range(mm, start_vaddr, end, &pagemap_ops, &pm);\n"
            "\t\t\t\t\t}\n"
            "\t\t\t\t} else {\n"
            "\t\t\t\t\tret = walk_page_range(mm, start_vaddr, end, &pagemap_ops, &pm);\n"
            "\t\t\t\t}\n"
            "\t\t\t}\n"
            "#else\n"
            "\t\t\tret = walk_page_range(mm, start_vaddr, end, &pagemap_ops, &pm);\n"
            "#endif"
        )
        txt = txt.replace(target, replacement, 1)
        open("fs/proc/task_mmu.c", "w").write(txt)
        os.remove("fs/proc/task_mmu.c.rej")
        print(">>> Resolved fs/proc/task_mmu.c.rej cleanly")

# 3. Ensure fs/stat.c uses exact wagamy v2.1.0 susfs_generic_fillattr_spoofer wiring
if os.path.exists("fs/stat.c.rej"):
    os.remove("fs/stat.c.rej")
stat_c = open("fs/stat.c").read()
if "susfs_generic_fillattr_spoofer" not in stat_c:
    inc_block = (
        "#ifdef CONFIG_KSU_SUSFS\n"
        "#include <linux/susfs_def.h>\n"
        "#include <linux/version.h>\n"
        "#endif\n\n"
        "#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT\n"
        "extern void susfs_generic_fillattr_spoofer(struct inode *inode, struct kstat *stat);\n"
        "#endif\n"
    )
    stat_c = stat_c.replace("#include <linux/uaccess.h>\n", "#include <linux/uaccess.h>\n\n" + inc_block, 1)
    # Tail of generic_fillattr()
    stat_c = stat_c.replace(
        "\tstat->blocks = inode->i_blocks;\n}",
        "\tstat->blocks = inode->i_blocks;\n#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT\n\tsusfs_generic_fillattr_spoofer(inode, stat);\n#endif\n}",
        1,
    )
    # vfs_getattr_nosec()
    old_ga = "\tif (inode->i_op->getattr)\n\t\treturn inode->i_op->getattr(path, stat, request_mask,\n\t\t\t\t\t    query_flags);"
    new_ga = (
        "\tif (inode->i_op->getattr) {\n"
        "\t\tint err = inode->i_op->getattr(path, stat, request_mask,\n"
        "\t\t\t\t\t    query_flags);\n"
        "#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT\n"
        "\t\tif (!err)\n"
        "\t\t\tsusfs_generic_fillattr_spoofer(inode, stat);\n"
        "#endif\n"
        "\t\treturn err;\n"
        "\t}"
    )
    if old_ga in stat_c:
        stat_c = stat_c.replace(old_ga, new_ga, 1)
    open("fs/stat.c", "w").write(stat_c)
    print(">>> Wired wagamy v2.1.0 susfs_generic_fillattr_spoofer in fs/stat.c")

# 4. Ensure fs/Makefile builds susfs.o
fsmk = open("fs/Makefile").read()
if "susfs.o" not in fsmk:
    fsmk += "\nobj-$(CONFIG_KSU_SUSFS) += susfs.o\n"
    open("fs/Makefile", "w").write(fsmk)
    print(">>> Added obj-$(CONFIG_KSU_SUSFS) += susfs.o to fs/Makefile")

# 5. Report and fail on any remaining .rej files
rejs = glob.glob("**/*.rej", recursive=True)
if rejs:
    print("ERROR: Unresolved .rej files:", rejs, file=sys.stderr)
    for r in rejs:
        print(f"=== {r} ===")
        print(open(r).read())
    sys.exit(1)

# 6. Wire ksu_handle_sys_reboot in kernel/reboot.c
reb = open("kernel/reboot.c").read()
if "ksu_handle_sys_reboot" not in reb:
    anchor = "SYSCALL_DEFINE4(reboot,"
    cap_anchor = "\tif (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))"
    assert anchor in reb and cap_anchor in reb, "kernel/reboot.c anchors missing"
    decl = (
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n"
        "#endif\n\n"
    )
    reb = reb.replace(anchor, decl + anchor, 1)
    hook = (
        "#ifdef CONFIG_KSU\n"
        "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
        "#endif\n"
    )
    reb = reb.replace(cap_anchor, hook + cap_anchor, 1)
    open("kernel/reboot.c", "w").write(reb)
    print(">>> Wired ksu_handle_sys_reboot in kernel/reboot.c")

# 7. Wire ksu_handle_setresuid in kernel/sys.c
sysc = open("kernel/sys.c").read()
if "ksu_handle_setresuid" not in sysc:
    fn_anchor = "long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)"
    sec_anchor = "\tretval = security_task_fix_setuid(new, old, LSM_SETID_RES);"
    assert fn_anchor in sysc and sec_anchor in sysc, "kernel/sys.c anchors missing"
    decl = (
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\n"
        "#endif\n\n"
    )
    sysc = sysc.replace(fn_anchor, decl + fn_anchor, 1)
    hook = (
        "#ifdef CONFIG_KSU\n"
        "\tksu_handle_setresuid(ruid, euid, suid);\n"
        "#endif\n"
    )
    sysc = sysc.replace(sec_anchor, hook + sec_anchor, 1)
    open("kernel/sys.c", "w").write(sysc)
    print(">>> Wired ksu_handle_setresuid in kernel/sys.c")

# 8. Relax init/Kconfig KALLSYMS_ALL dependency
ik = open("init/Kconfig").read()
ik2 = re.sub(
    r'(config KALLSYMS_ALL\n\s+bool "Include all symbols in kallsyms"\n\s+)depends on DEBUG_KERNEL && KALLSYMS',
    r"\1depends on KALLSYMS",
    ik,
)
if ik2 != ik:
    open("init/Kconfig", "w").write(ik2)
    print(">>> Relaxed init/Kconfig KALLSYMS_ALL dependency")

# 9. Update arch/arm64/configs/vendor/pipa_defconfig with wagamy's exact trio + KALLSYMS
defcfg_path = "arch/arm64/configs/vendor/pipa_defconfig"
defcfg = open(defcfg_path).read()
required_opts = [
    "CONFIG_KSU=y",
    "CONFIG_KSU_MANUAL_HOOK=y",
    "CONFIG_KSU_SUSFS=y",
    "CONFIG_KALLSYMS=y",
    "CONFIG_KALLSYMS_ALL=y",
]
for opt in required_opts:
    key = opt.split("=")[0].replace("# ", "").replace(" is not set", "")
    if re.search(rf"^(# )?{re.escape(key)}[= ]", defcfg, re.M):
        defcfg = re.sub(rf"^(# )?{re.escape(key)}[= ].*$", opt, defcfg, flags=re.M)
    else:
        defcfg += f"\n{opt}\n"
open(defcfg_path, "w").write(defcfg)
print(">>> Updated vendor/pipa_defconfig with:", required_opts)
