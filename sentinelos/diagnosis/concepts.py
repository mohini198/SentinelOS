"""Plain-language OS concept notes shown next to each incident. Static text, no AI."""

CONCEPTS = {
    "fd_exhaustion": {
        "concept": "File descriptors and per-process limits (RLIMIT_NOFILE)",
        "kernel": "Each open file or socket is an integer entry in the process's fd table, visible as /proc/<pid>/fd. The kernel refuses new opens with EMFILE once the limit is reached.",
        "why": "The program opens files or sockets and never calls close(), so the table fills up.",
        "fix": "Raising the limit (prlimit) only buys time. SIGTERM ends the process and the kernel closes all its descriptors.",
    },
    "memory_pressure": {
        "concept": "Virtual memory, page cache, swap and the OOM killer",
        "kernel": "/proc/meminfo MemAvailable counts free RAM plus reclaimable page cache. /proc/pressure/memory (PSI) shows how long tasks stalled waiting for memory.",
        "why": "A process (often a leak) keeps growing until the kernel must reclaim aggressively, swap, or kill something using oom_score.",
        "fix": "drop_caches frees clean cache only. SIGTERM on the biggest consumer returns its pages to the kernel before the OOM killer picks a victim itself.",
    },
    "cpu_exhaustion": {
        "concept": "CPU scheduling, load average and priorities (nice)",
        "kernel": "/proc/stat holds cumulative jiffies per CPU state. Two samples give a usage percentage. /proc/loadavg counts runnable plus uninterruptible tasks.",
        "why": "One or more runnable processes use every time slice, so other tasks wait in the run queue.",
        "fix": "renice lowers the process priority so the scheduler favours others. SIGTERM removes a true runaway. A cgroup cpu.max quota can cap it.",
    },
    "zombie_processes": {
        "concept": "Process lifecycle: fork, exit, wait",
        "kernel": "A finished child stays in the process table in state Z until its parent calls wait(), so the kernel can hand over the exit status.",
        "why": "The parent never calls wait(). A zombie is already dead, so signals to it do nothing.",
        "fix": "Act on the parent. When the parent exits, init adopts and reaps the zombies.",
    },
    "dstate_processes": {
        "concept": "Uninterruptible sleep (D state) and I/O waits",
        "kernel": "State D in /proc/<pid>/stat means the task is blocked inside the kernel, usually waiting for disk or network storage. Signals are delivered only after it wakes.",
        "why": "Slow or stuck storage, NFS hangs or failing disks.",
        "fix": "Killing does not help until I/O returns. Check disk health and mounts first.",
    },
    "disk_full": {
        "concept": "File systems, block usage and log rotation",
        "kernel": "statvfs reports total and available blocks per mount. At 100% writes fail with ENOSPC, even for root-owned services.",
        "why": "Logs, caches or temp files grow without rotation.",
        "fix": "Vacuum or rotate logs, which frees blocks without touching application data.",
    },
    "inode_exhaustion": {
        "concept": "Inodes",
        "kernel": "Every file needs an inode. statvfs also reports inode counts, which can run out while free space remains.",
        "why": "Millions of tiny files such as sessions, caches or mail queues.",
        "fix": "Find the directory with the huge file count and clean it. Freeing space alone does not help.",
    },
}