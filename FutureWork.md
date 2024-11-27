# Future Work

- **TEST PRESTAZIONI** -> overhead della protezione. 
RW è regolare sul resto dei files, mentre sui file protetti avrei regolarmente la read ma non ha senso dato che non triggerano il controllo
(read sui protetti / Read write sul resto dei file --> vedo solo overhead sui checks)
Si può fare a fs montato stabilmente (aprendo e chiudendo lo stesso set di files -> se apro e richiudo il page cache mi carica tutto in memoria -> lightweight)

test sulle varie operazioni intercettate al variare della grandezza del set (0(baseline), 10 / 100 / 1000 elementi) -> vedere come cresce il delay (se è eccessivo valutare di cambiare la lista con un hash-table)

ADDITIONAL TEST: momento in cui faccio una open ho bisogno di una sessione. Voglio vedere cosa succede se cerco di aprire una directory invece di file regolari. in modalità update non posso -> CREATE di un file nella directory protetta

0) 
1) struttura più performante (es: hash tables)
2) test di concorrenza se con i lock ok. (fare le stesse operazioni scalando i thread 1/2/4/8)

- **USE CASE nell'articolo** -> far vedere come sia semplice gestire uno specifico USE CASE (backups... / VMs...)

- **Resolve full pathname until root in log** (see dpath usage when i print list of protected paths -> that actually solves it !!!! OKKKK, try to find similar way for other probes that use dentry_path_raw)

- **SingleFS for log file -> IOCTL or ProcFS (see if possible in kernel module?)**
OPPURE: quando chiamo open -> filp_open -> setup struttura di sessione (struct file collegata all'array dei puntatori dei file aperti  e ritorna descrittore del file. Ma nel kernel su work queue che ci scrivo ci arrivo direttaente col pointer per una sessione di I/O associata alla struct file aperta al montaggio del fs -> i thread nel kernel vanno read write)

- **Replace syscall hacking with IOCTL**

- **RCU_READ or RW_LOCK instead of spinlock/unlock**
