#include <linux/proc_fs.h> 
#include <linux/cdev.h>    
#include <linux/device.h>  

#include "hwBreakpointProc_module.h"
#include "proc_pid.h"
#include "api_proxy.h"
#include "anti_ptrace_detection.h"

#pragma pack(push,1)
struct ioctl_request {
    char     cmd;        
    uint64_t param1;     
    uint64_t param2;     
    uint64_t param3;     
    uint64_t buf_size;   
};
#pragma pack(pop)
//////////////////////////////////////////////////////////////////

// ⭐ 专属定制：游戏偏移地址硬编码
#define OFF_SKIP     0x2639fd8
#define OFF_SKIP_JMP 0x53709a0
#define OFF_MAXHP    0x33b2ffc

// 指令定义
#define CMD_SET_GAME_BASE 22
static atomic64_t g_game_base = ATOMIC64_INIT(0);

static atomic64_t g_hook_pc;
static struct mutex g_hwbp_handle_info_mutex;
static cvector g_hwbp_handle_info_arr = NULL;

static dev_t g_devno;
static struct cdev g_cdev;
static struct class *g_class = NULL;

static void record_hit_details(struct HWBP_HANDLE_INFO *info, struct pt_regs *regs) {
    struct HWBP_HIT_ITEM hit_item = {0};
	if (!info || !regs) return;
	hit_item.task_id = info->task_id;
    hit_item.hit_addr = regs->pc;
	hit_item.hit_time = ktime_get_real_seconds();
    memcpy(&hit_item.regs_info.regs, regs->regs, sizeof(hit_item.regs_info.regs));
    hit_item.regs_info.sp = regs->sp;
    hit_item.regs_info.pc = regs->pc;
    hit_item.regs_info.pstate = regs->pstate;
    hit_item.regs_info.orig_x0 = regs->orig_x0;
    hit_item.regs_info.syscallno = regs->syscallno;
    if (info->hit_item_arr) {
		if(cvector_length(info->hit_item_arr) < MIN_LEN) { 
			cvector_pushback(info->hit_item_arr, &hit_item);
		}
    }
}

#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
static bool arm64_move_bp_to_next_instruction(struct perf_event *bp, uint64_t next_instruction_addr, struct perf_event_attr *original_attr, struct perf_event_attr * next_instruction_attr) {
    int result;
	if (!bp || !original_attr || !next_instruction_attr || !next_instruction_addr) return false;
	memcpy(next_instruction_attr, original_attr, sizeof(struct perf_event_attr));
	next_instruction_attr->bp_addr = next_instruction_addr;
	next_instruction_attr->bp_len = HW_BREAKPOINT_LEN_4;
	next_instruction_attr->bp_type = HW_BREAKPOINT_X;
	next_instruction_attr->disabled = 0;
	result = x_modify_user_hw_breakpoint(bp, next_instruction_attr);
	if(result) {
		next_instruction_attr->bp_addr = 0;
		return false;
	}
	return true;
}

static bool arm64_recovery_bp_to_original(struct perf_event *bp, struct perf_event_attr *original_attr, struct perf_event_attr * next_instruction_attr) {
    int result;
	if (!bp || !original_attr || !next_instruction_attr) return false;
	result = x_modify_user_hw_breakpoint(bp, original_attr);
	if(result) return false;
	next_instruction_attr->bp_addr = 0;
	return true;
}
#endif

static void hwbp_hit_user_info_callback(struct perf_event *bp,
	struct perf_sample_data *data,
	struct pt_regs *regs, struct HWBP_HANDLE_INFO * hwbp_handle_info) {
	hwbp_handle_info->hit_total_count++;
	record_hit_details(hwbp_handle_info, regs);
}

// ==========================================
// ⭐ 上帝视角 Handler：强制匹配，无视 PC 偏移！
// ==========================================
static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
	citerator iter;
	uint64_t hook_pc;
	uint64_t base = atomic64_read(&g_game_base);
	
	// ⭐ 获取当前触发断点【真正绑定的地址】，而不是漂移的 PC
	uint64_t bp_bound_addr = bp->attr.bp_addr; 

	// ⭐ 打印雷达日志，使用 dmesg | grep HWBP-BOSS 查看
	printk_debug(KERN_INFO "[HWBP-BOSS] HIT! PC: 0x%llx | BoundAddr: 0x%llx | LR: 0x%llx\n", 
		regs->pc, bp_bound_addr, regs->regs[30]);

	// 【强制拦截判定】
	if (base != 0) {
		// 1. 秒过功能判断
		if (bp_bound_addr == base + OFF_SKIP) {
			printk_debug(KERN_INFO "[HWBP-BOSS] Executing SKIP logic (PC -> OFF_SKIP_JMP)\n");
			regs->pc = base + OFF_SKIP_JMP;
			return; // 截断原生处理
		}

		// 2. 秒杀/最大血量判断
		if (bp_bound_addr == base + OFF_MAXHP) {
			printk_debug(KERN_INFO "[HWBP-BOSS] Executing MAXHP logic (X0=1, Ret)\n");
			regs->regs[0] = 1;
			regs->pc = regs->regs[30]; // 跳回 LR
			return; 
		}
	}

	hook_pc = atomic64_read(&g_hook_pc);
	if(hook_pc) {
		regs->pc = hook_pc;
		return;
	}

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if (hwbp_handle_info->sample_hbp != bp) continue;
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
		if(hwbp_handle_info->next_instruction_attr.bp_addr != regs->pc) {
			bool should_toggle = true;
			hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
			if(!hwbp_handle_info->is_32bit_task) {
				if(arm64_move_bp_to_next_instruction(bp, regs->pc + 4, &hwbp_handle_info->original_attr, &hwbp_handle_info->next_instruction_attr)) {
					should_toggle = false;
				}
			}
			if(should_toggle) toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
		} else {
			if(!arm64_recovery_bp_to_original(bp, &hwbp_handle_info->original_attr, &hwbp_handle_info->next_instruction_attr)) {
				toggle_bp_registers_directly(&hwbp_handle_info->next_instruction_attr, hwbp_handle_info->is_32bit_task, 0);
			}
		}
#else
		hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
		toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
#endif
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
}

// ==========================================
// 常规 IOCTL 与 设备操作
// ==========================================

static ssize_t OnCmdOpenProcess(struct ioctl_request *hdr, char __user* buf) {
	uint64_t pid = hdr->param1, handle = 0;
	struct pid * proc_pid_struct = get_proc_pid_struct(pid);
	if (!proc_pid_struct) return -EINVAL;
	handle = (uint64_t)proc_pid_struct;
	if (!!x_copy_to_user((void*)buf, (void*)&handle, sizeof(handle))) return -EINVAL;
	return 0;
}

static ssize_t OnCmdCloseProcess(struct ioctl_request *hdr, char __user* buf) {
	release_proc_pid_struct((struct pid *)hdr->param1);
	return 0;
}

static ssize_t OnCmdGetCpuNumBrps(struct ioctl_request *hdr, char __user* buf) { return getCpuNumBrps(); }
static ssize_t OnCmdGetCpuNumWrps(struct ioctl_request *hdr, char __user* buf) { return getCpuNumWrps(); }

static ssize_t OnCmdInstProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	uint64_t proc_virt_addr = hdr->param2;
	char hwbp_len  =  hdr->param3 & 0xFF;
	char hwbp_type = (hdr->param3 >> 8) & 0xFF;

	pid_t pid_val = pid_nr(proc_pid_struct);
	if (!pid_val) return -EINVAL;

	struct task_struct *task = pid_task(proc_pid_struct, PIDTYPE_PID);
	if (!task) return -EINVAL;
	
	struct HWBP_HANDLE_INFO hwbp_handle_info = { 0 };
	hwbp_handle_info.task_id = pid_val;
	hwbp_handle_info.is_32bit_task = is_compat_thread(task_thread_info(task));
	ptrace_breakpoint_init(&hwbp_handle_info.original_attr);
	hwbp_handle_info.original_attr.bp_addr = proc_virt_addr;
	hwbp_handle_info.original_attr.bp_len = hwbp_len;
	hwbp_handle_info.original_attr.bp_type = hwbp_type;
	hwbp_handle_info.original_attr.disabled = 0;

	hwbp_handle_info.sample_hbp = x_register_user_hw_breakpoint(&hwbp_handle_info.original_attr, hwbp_handler, NULL, task);
	if (IS_ERR((void __force *)hwbp_handle_info.sample_hbp)) return PTR_ERR((void __force *)hwbp_handle_info.sample_hbp);
	
	hwbp_handle_info.hit_item_arr = cvector_create(sizeof(struct HWBP_HIT_ITEM));
	mutex_lock(&g_hwbp_handle_info_mutex);
	cvector_pushback(g_hwbp_handle_info_arr, &hwbp_handle_info);
	mutex_unlock(&g_hwbp_handle_info_mutex);

	if (x_copy_to_user((void*)buf, &hwbp_handle_info.sample_hbp, sizeof(uint64_t))) return -EINVAL;
	return 0;
}

static ssize_t OnCmdUninstProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
	struct perf_event * sample_hbp = (struct perf_event *)hdr->param1;
	citerator iter;
	bool found = false;
	if(!sample_hbp) return -EFAULT;

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->sample_hbp == sample_hbp) {
			if(hwbp_handle_info->hit_item_arr) {
				cvector_destroy(hwbp_handle_info->hit_item_arr);
				hwbp_handle_info->hit_item_arr = NULL;
			}
			cvector_rm(g_hwbp_handle_info_arr, iter);
			found = true;
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	if(found) x_unregister_hw_breakpoint(sample_hbp);
	return 0;
}

static ssize_t OnCmdSuspendProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
	struct perf_event * sample_hbp = (struct perf_event *)hdr->param1;
	struct perf_event_attr new_instruction_attr;
	citerator iter;
	bool found = false;
	if(!sample_hbp) return -EFAULT;

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->sample_hbp == sample_hbp) {
			hwbp_handle_info->original_attr.disabled = 1;
			memcpy(&new_instruction_attr, &hwbp_handle_info->original_attr, sizeof(struct perf_event_attr));
			found = true;
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	if(found && !x_modify_user_hw_breakpoint(sample_hbp, &new_instruction_attr)) return 0;
	return -EFAULT;
}

static ssize_t OnCmdResumeProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
	struct perf_event * sample_hbp = (struct perf_event *)hdr->param1;
	struct perf_event_attr new_instruction_attr;
	citerator iter;
	bool found = false;
	if(!sample_hbp) return -EFAULT;

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->sample_hbp == sample_hbp) {
			hwbp_handle_info->original_attr.disabled = 0;
			memcpy(&new_instruction_attr, &hwbp_handle_info->original_attr, sizeof(struct perf_event_attr));
			found = true;
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	if(found && !x_modify_user_hw_breakpoint(sample_hbp, &new_instruction_attr)) return 0;
	return -EFAULT;
}

static ssize_t OnCmdGetHwbpHitCount(struct ioctl_request *hdr, char __user* buf) {
	#pragma pack(1)
	struct buf_layout {
		uint64_t hit_total_count;
		uint64_t hit_item_arr_count;
	};
	#pragma pack()
	struct perf_event *sample_hbp = (struct perf_event *)hdr->param1;
	struct buf_layout user_data = {0};
	citerator iter;

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if (hwbp_handle_info->sample_hbp == sample_hbp && hwbp_handle_info->hit_item_arr) {
			user_data.hit_total_count = hwbp_handle_info->hit_total_count;
			user_data.hit_item_arr_count = cvector_length(hwbp_handle_info->hit_item_arr);
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	
	if (x_copy_to_user((void*)buf, &user_data, sizeof(user_data))) return -EINVAL;
	return 0;
}

static ssize_t OnCmdGetHwbpHitDetail(struct ioctl_request *hdr, char __user* buf) {
	struct perf_event *sample_hbp = (struct perf_event *)hdr->param1;
	size_t size = hdr->buf_size;
	ssize_t count = 0;
	size_t copy_pos = (size_t)buf;
	size_t end_pos = (size_t)((size_t)buf + size);
	citerator iter;

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if (hwbp_handle_info->sample_hbp == sample_hbp && hwbp_handle_info->hit_item_arr) {
			citerator child;
			for (child = cvector_begin(hwbp_handle_info->hit_item_arr); child != cvector_end(hwbp_handle_info->hit_item_arr); child = cvector_next(hwbp_handle_info->hit_item_arr, child)) {
				struct HWBP_HIT_ITEM * hit_item = (struct HWBP_HIT_ITEM *)child;
				if (copy_pos >= end_pos) break;
				if (x_copy_to_user((void*)copy_pos, hit_item, sizeof(struct HWBP_HIT_ITEM))) break;
				copy_pos += sizeof(struct HWBP_HIT_ITEM);
				count++;
			}
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return count;
}

static ssize_t OnCmdSetHookPc(struct ioctl_request *hdr, char __user* buf) {
	atomic64_set(&g_hook_pc, hdr->param1);
	return 0;
}

static ssize_t OnCmdHideKernelModule(struct ioctl_request *hdr, char __user* buf) {
	if (g_hwBreakpointProc_devp && g_hwBreakpointProc_devp->is_hidden_module == false) {
		g_hwBreakpointProc_devp->is_hidden_module = true; 
		list_del_init(&__this_module.list);
		kobject_del(&THIS_MODULE->mkobj.kobj);
	}
	return 0;
}

// ⭐ 处理基址接收
static ssize_t OnCmdSetGameBase(struct ioctl_request *hdr, char __user* buf) {
	atomic64_set(&g_game_base, hdr->param1);
	return 0;
}

static inline ssize_t DispatchCommand(struct ioctl_request *hdr, char __user* buf) {
	switch (hdr->cmd) {
	case CMD_OPEN_PROCESS: return OnCmdOpenProcess(hdr, buf);
	case CMD_CLOSE_PROCESS: return OnCmdCloseProcess(hdr, buf);
	case CMD_GET_NUM_BRPS: return OnCmdGetCpuNumBrps(hdr, buf);
	case CMD_GET_NUM_WRPS: return OnCmdGetCpuNumWrps(hdr, buf);
	case CMD_INST_PROCESS_HWBP: return OnCmdInstProcessHwbp(hdr, buf);
	case CMD_UNINST_PROCESS_HWBP: return OnCmdUninstProcessHwbp(hdr, buf);
	case CMD_SUSPEND_PROCESS_HWBP: return OnCmdSuspendProcessHwbp(hdr, buf);
	case CMD_RESUME_PROCESS_HWBP: return OnCmdResumeProcessHwbp(hdr, buf);
	case CMD_GET_HWBP_HIT_COUNT: return OnCmdGetHwbpHitCount(hdr, buf);
	case CMD_GET_HWBP_HIT_DETAIL: return OnCmdGetHwbpHitDetail(hdr, buf);
	case CMD_SET_HOOK_PC: return OnCmdSetHookPc(hdr, buf);
	case CMD_HIDE_KERNEL_MODULE: return OnCmdHideKernelModule(hdr, buf);
	case CMD_SET_GAME_BASE: return OnCmdSetGameBase(hdr, buf); 
	default: return -EINVAL;
	}
}

static ssize_t hwBreakpointProc_read(struct file* filp, char __user* buf, size_t size, loff_t* ppos) {
    struct ioctl_request hdr = {0};
    size_t header_size = sizeof(hdr);
    if (size < header_size) return -EINVAL;
    if (x_copy_from_user(&hdr, buf, header_size)) return -EFAULT;
    if (size < header_size + hdr.buf_size) return -EINVAL;
    return DispatchCommand(&hdr, buf + header_size);
}

static long hwbp_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) { return -EINVAL; }

static void clean_hwbp(void) {
	citerator iter;
	cvector wait_unregister_bp_arr = cvector_create(sizeof(struct perf_event *));
	if(!wait_unregister_bp_arr || !g_hwbp_handle_info_arr) return;

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->sample_hbp) {
			cvector_pushback(wait_unregister_bp_arr, &hwbp_handle_info->sample_hbp);
			hwbp_handle_info->sample_hbp = NULL;
		}
		if(hwbp_handle_info->hit_item_arr) {
			cvector_destroy(hwbp_handle_info->hit_item_arr);
			hwbp_handle_info->hit_item_arr = NULL;
		}
	}
	cvector_destroy(g_hwbp_handle_info_arr);
	g_hwbp_handle_info_arr = NULL;
	mutex_unlock(&g_hwbp_handle_info_mutex);
	
	for (iter = cvector_begin(wait_unregister_bp_arr); iter != cvector_end(wait_unregister_bp_arr); iter = cvector_next(wait_unregister_bp_arr, iter)) {
	  struct perf_event * bp = *(struct perf_event **)iter;
	  x_unregister_hw_breakpoint(bp);
	}
	cvector_destroy(wait_unregister_bp_arr);
}

static int hwBreakpointProc_release(struct inode *inode, struct file *filp) {
	clean_hwbp();
	mutex_lock(&g_hwbp_handle_info_mutex);
	g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO));
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return 0;
}

static const struct file_operations hwbp_dev_fops = {
	.owner = THIS_MODULE,
	.read = hwBreakpointProc_read,
	.release = hwBreakpointProc_release,
	.unlocked_ioctl = hwbp_dev_ioctl,
	.compat_ioctl = hwbp_dev_ioctl,
};

static int hwBreakpointProc_dev_init(void) {
#ifdef CONFIG_KALLSYMS_LOOKUP_NAME
	if(!init_kallsyms_lookup()) return -EBADF;
#endif

	g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO));
	mutex_init(&g_hwbp_handle_info_mutex);

#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
	start_anti_ptrace_detection(&g_hwbp_handle_info_mutex, &g_hwbp_handle_info_arr);
#endif

	g_hwBreakpointProc_devp = x_kmalloc(sizeof(struct hwBreakpointProcDev), GFP_KERNEL);
	memset(g_hwBreakpointProc_devp, 0, sizeof(struct hwBreakpointProcDev));

	if (alloc_chrdev_region(&g_devno, 0, 1, "hwBreakpointProcMod") == 0) {
		cdev_init(&g_cdev, &hwbp_dev_fops);
		g_cdev.owner = THIS_MODULE;
		if (cdev_add(&g_cdev, g_devno, 1) == 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
			g_class = class_create("hwBreakpointProcMod");
#else
			g_class = class_create(THIS_MODULE, "hwBreakpointProcMod");
#endif
			if (g_class) device_create(g_class, NULL, g_devno, NULL, "hwBreakpointProcMod");
		}
	}

#ifdef CONFIG_USE_PROC_FILE_NODE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	static const struct proc_ops hwBreakpointProc_proc_ops = {
		.proc_read    = hwBreakpointProc_read,
		.proc_release = hwBreakpointProc_release,
	};
#else
	static const struct file_operations hwBreakpointProc_proc_ops = {
		.read    = hwBreakpointProc_read,
		.release = hwBreakpointProc_release,
	};
#endif
	g_hwBreakpointProc_devp->proc_parent = proc_mkdir(CONFIG_PROC_NODE_AUTH_KEY, NULL);
	if(g_hwBreakpointProc_devp->proc_parent) {
		g_hwBreakpointProc_devp->proc_entry = proc_create(CONFIG_PROC_NODE_AUTH_KEY, S_IRUGO | S_IWUGO, g_hwBreakpointProc_devp->proc_parent, &hwBreakpointProc_proc_ops);
		start_hide_procfs_dir(CONFIG_PROC_NODE_AUTH_KEY);
	}
#endif

	printk(KERN_EMERG "Hello hwBreakpointProc init done\n");
	return 0;
}

static void hwBreakpointProc_dev_exit(void) {
#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
	stop_anti_ptrace_detection();
#endif

	clean_hwbp();
	mutex_destroy(&g_hwbp_handle_info_mutex);

	if (g_class) {
		device_destroy(g_class, g_devno);
		class_destroy(g_class);
	}
	cdev_del(&g_cdev);
	unregister_chrdev_region(g_devno, 1);
	
#ifdef CONFIG_USE_PROC_FILE_NODE
	if(g_hwBreakpointProc_devp->proc_entry) {
		proc_remove(g_hwBreakpointProc_devp->proc_entry);
		g_hwBreakpointProc_devp->proc_entry = NULL;
	}
	if(g_hwBreakpointProc_devp->proc_parent) {
		proc_remove(g_hwBreakpointProc_devp->proc_parent);
		g_hwBreakpointProc_devp->proc_parent = NULL;
	}
	stop_hide_procfs_dir();
#endif
	kfree(g_hwBreakpointProc_devp);
	printk(KERN_EMERG "Goodbye\n");
}

int __init init_module(void) { return hwBreakpointProc_dev_init(); }
void __exit cleanup_module(void) { hwBreakpointProc_dev_exit(); }

#ifndef CONFIG_MODULE_GUIDE_ENTRY
unsigned char* __check_(unsigned char* result, void *ptr, void *diag) { return result; }
unsigned char * __check_fail_(unsigned char *result) { return result; }
#endif

unsigned long __stack_chk_guard;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux");
MODULE_DESCRIPTION("Hardware Breakpoint God Mode Driver");
