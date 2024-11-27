# Future Work

- **TEST PRESTAZIONI** 
1) struttura più performante (es: hash tables)
2) USE READ/WRITE SPINLOCKS -> provare test di concorrenza (fare le stesse operazioni scalando i thread 1/2/4/8)

- **USE CASE nell'articolo** -> far vedere come sia semplice gestire uno specifico USE CASE (backups... / VMs...)

- **Resolve full pathname until root in log** (see dpath usage when i print list of protected paths -> that actually solves it !!!! OKKKK, try to find similar way for other probes that use dentry_path_raw)

- **SingleFS for log file -> IOCTL or ProcFS (see if possible in kernel module?)**
OPPURE: quando chiamo open -> filp_open -> setup struttura di sessione (struct file collegata all'array dei puntatori dei file aperti  e ritorna descrittore del file. Ma nel kernel su work queue che ci scrivo ci arrivo direttaente col pointer per una sessione di I/O associata alla struct file aperta al montaggio del fs -> i thread nel kernel vanno read write)

- **Replace syscall hacking with IOCTL**

- **RCU_READ or RW_LOCK instead of spinlock/unlock**
