# Fault injection scripts (implemented in Step 4)
# Each script simulates one failure class for testing:
#   mem_leak.py      — allocates memory until OOM
#   cpu_hog.py       — spins all cores
#   disk_fill.py     — writes a large file to /tmp
#   fd_leak.py       — opens files without closing
#   crash_loop.py    — repeatedly exits with error
#   zombie_maker.py  — forks without waiting (creates zombies)
