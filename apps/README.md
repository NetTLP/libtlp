
## Example Applications


### dma_read

### dma_write


### pmem

### process-list

- ./process-list -r 192.168.10.1 -R 130.69.250.234 -s System.map

Linux has a task_struct for the first process, called swapper.  The
address of the swapper process is noted in System.map.  process-list
finds all task_struct from the task_struct of the swapper process.

```shell-session
% ./process-list -r 192.168.10.1 -R 130.69.250.234 -s System.map       
PhyAddr             PID STAT COMMAND
0x00000003411740      0 R    swapper/0
0x0000087c330000      1 S    systemd
0x0000086a411dc0    647 S    systemd-journal
0x0000086ba50000    655 S    lvmetad
0x0000086c4cd940    662 S    systemd-udevd
0x0000086d363b80    848 S    systemd-timesyn
0x0000086d361dc0   1017 S    systemd-network
0x0000086d2c3b80   1037 S    systemd-resolve
0x0000086cc35940   1134 S    rsyslogd
0x0000086d319dc0   1140 S    atd
0x0000086ba51dc0   1147 S    snapd
0x0000086ba55940   1150 S    cron
0x0000086cc28000   1154 S    lxcfs
0x0000086cc2d940   1155 S    irqbalance
0x0000086a413b80   1161 S    systemd-logind
0x0000086a410000   1162 S    dbus-daemon
0x0000087a838000   1193 S    accounts-daemon
0x00000876309dc0   1203 S    networkd-dispat
0x0000087630d940   1247 S    sshd
0x00000746ffd940  12768 S    sshd
0x000008718cd940  12885 S    sshd
0x00000874f10000  12886 S    zsh
0x000008719b8000  13040 T    view
0x0000086d315940   1251 S    polkitd
0x0000086d2bbb80   1292 S    agetty
0x000008695c1dc0   1510 S    unattended-upgr
0x00000879658000  12770 S    systemd
0x00000879293b80  12771 S    (sd-pam)
0x0000087c331dc0      2 S    kthreadd
0x0000087c333b80      3 D    rcu_gp
0x0000087c335940      4 D    rcu_par_gp
0x0000087c350000      6 D    kworker/0:0H
0x0000087c353b80      8 D    mm_percpu_wq
0x0000087c399dc0      9 S    ksoftirqd/0
0x0000087c39bb80     10 D    rcu_sched
0x0000087c39d940     11 S    migration/0
0x0000087be8d940     13 S    cpuhp/0
0x0000087bea5940     14 S    cpuhp/1
0x0000087bea0000     15 S    migration/1
0x0000087bea1dc0     16 S    ksoftirqd/1
0x0000087bea3b80     17 D    kworker/1:0
0x0000087bead940     18 D    kworker/1:0H
0x0000087bea8000     19 S    cpuhp/2
0x0000087bea9dc0     20 S    migration/2
0x0000087beabb80     21 S    ksoftirqd/2
0x0000087bf03b80     22 D    kworker/2:0
0x0000087bf05940     23 D    kworker/2:0H
0x0000087bf00000     24 S    cpuhp/3
0x0000087bf01dc0     25 S    migration/3
0x0000087bf19dc0     26 S    ksoftirqd/3
0x0000087bf1d940     28 D    kworker/3:0H
0x0000087bf18000     29 S    cpuhp/4
0x0000087bf78000     30 S    migration/4
0x0000087bf79dc0     31 S    ksoftirqd/4
0x0000087bf7d940     33 D    kworker/4:0H
0x0000087bf98000     34 S    cpuhp/5
0x0000087bf99dc0     35 S    migration/5
0x0000087bf9bb80     36 S    ksoftirqd/5
0x0000087bfa5940     38 D    kworker/5:0H
0x0000087bfa0000     39 S    cpuhp/6
0x0000087bfa1dc0     40 S    migration/6
0x0000087bfa3b80     41 S    ksoftirqd/6
0x0000087bff8000     43 D    kworker/6:0H
0x0000087bff9dc0     44 S    cpuhp/7
0x0000087bffbb80     45 S    migration/7
0x0000087b821dc0     46 S    ksoftirqd/7
0x0000087b825940     48 D    kworker/7:0H
0x0000087b820000     49 S    cpuhp/8
0x0000087b87d940     50 S    migration/8
0x0000087b878000     51 S    ksoftirqd/8
0x0000087b87bb80     53 D    kworker/8:0H
0x0000087b898000     54 S    cpuhp/9
0x0000087b899dc0     55 S    migration/9
0x0000087b89bb80     56 S    ksoftirqd/9
0x0000087b8a9dc0     58 D    kworker/9:0H
0x0000087b8abb80     59 S    cpuhp/10
0x0000087b8ad940     60 S    migration/10
0x0000087b8a8000     61 S    ksoftirqd/10
0x0000087b903b80     63 D    kworker/10:0H
0x0000087b905940     64 S    cpuhp/11
0x0000087b900000     65 S    migration/11
0x0000087b958000     66 S    ksoftirqd/11
0x0000087b95bb80     68 D    kworker/11:0H
0x0000087b95d940     69 S    cpuhp/12
0x0000087b9bbb80     70 S    migration/12
0x0000087b9bd940     71 S    ksoftirqd/12
0x0000087b9b8000     72 D    kworker/12:0
0x0000087b9b9dc0     73 D    kworker/12:0H
0x0000087b9e0000     74 S    cpuhp/13
0x0000087b9e1dc0     75 S    migration/13
0x0000087b9e3b80     76 S    ksoftirqd/13
0x0000087b9e5940     77 D    kworker/13:0
0x0000087b9e8000     78 D    kworker/13:0H
0x0000087b9e9dc0     79 S    cpuhp/14
0x0000087b9ebb80     80 S    migration/14
0x0000087b9ed940     81 S    ksoftirqd/14
0x0000087ba40000     83 D    kworker/14:0H
0x0000087ba41dc0     84 S    cpuhp/15
0x0000087ba43b80     85 S    migration/15
0x0000087ba5d940     86 S    ksoftirqd/15
0x0000087ba59dc0     88 D    kworker/15:0H
0x0000087ba5bb80     89 S    cpuhp/16
0x0000087ba85940     90 S    migration/16
0x0000087ba80000     91 S    ksoftirqd/16
0x0000087ba81dc0     92 D    kworker/16:0
0x0000087ba83b80     93 D    kworker/16:0H
0x0000087bad8000     94 S    cpuhp/17
0x0000087bad9dc0     95 S    migration/17
0x0000087badbb80     96 S    ksoftirqd/17
0x0000087bae1dc0     98 D    kworker/17:0H
0x0000087bae3b80     99 S    cpuhp/18
0x0000087bae5940    100 S    migration/18
0x0000087bae0000    101 S    ksoftirqd/18
0x0000087baf8000    103 D    kworker/18:0H
0x0000087baf9dc0    104 S    cpuhp/19
0x0000087bafbb80    105 S    migration/19
0x0000087bb65940    106 S    ksoftirqd/19
0x0000087bb61dc0    108 D    kworker/19:0H
0x0000087bbad940    109 S    kdevtmpfs
0x0000087b56bb80    110 D    netns
0x0000087b56d940    111 S    rcu_tasks_kthre
0x0000087b568000    112 S    kauditd
0x0000087b711dc0    115 S    khungtaskd
0x0000087bb63b80    116 S    oom_reaper
0x0000087b783b80    117 D    writeback
0x0000087b785940    118 S    kcompactd0
0x0000087b780000    119 S    ksmd
0x0000087b781dc0    120 S    khugepaged
0x0000087b7dbb80    121 D    crypto
0x0000087b7dd940    122 D    kintegrityd
0x0000087b7d8000    123 D    kblockd
0x0000087b1c9dc0    126 D    tpm_dev_wq
0x0000087b1cbb80    127 D    ata_sff
0x0000087b1cd940    128 D    md
0x0000087a835940    129 D    edac-poller
0x0000087a831dc0    131 D    devfreq_wq
0x0000087a833b80    132 D    kworker/13:1
0x0000087a909dc0    133 S    watchdogd
0x0000087a90bb80    134 D    kworker/15:1
0x0000087a908000    136 D    kworker/8:1
0x0000087630bb80    137 D    kworker/18:1
0x0000087b713b80    138 D    kworker/4:1
0x0000087b715940    139 D    kworker/3:1
0x00000871ccbb80    141 D    kworker/7:1
0x00000871ccd940    142 D    kworker/9:1
0x00000871cc8000    143 D    kworker/11:1
0x00000871cd0000    144 D    kworker/10:1
0x00000871cd1dc0    145 D    kworker/14:1
0x00000871cd3b80    146 D    kworker/16:1
0x00000871cd5940    147 D    kworker/17:1
0x00000871ce5940    148 D    kworker/19:1
0x00000871ce1dc0    151 S    kswapd0
0x00000871ce3b80    152 D    kworker/u41:0
0x0000086d198000    153 S    ecryptfs-kthrea
0x0000086cc49dc0    242 D    kthrotld
0x0000086cc4bb80    243 D    acpi_thermal_pm
0x0000086d36d940    246 D    kworker/0:4
0x0000086d369dc0    248 D    kworker/0:6
0x0000086d2c5940    251 D    ipv6_addrconf
0x0000086d2a1dc0    262 D    kstrp
0x0000086ca9bb80    281 D    charger_manager
0x0000086a518000    368 D    nvme-wq
0x0000086a519dc0    369 D    nvme-reset-wq
0x0000086a51bb80    370 D    nvme-delete-wq
0x0000086d370000    419 S    scsi_eh_0
0x0000086d371dc0    420 D    scsi_tmf_0
0x0000086d373b80    421 S    scsi_eh_1
0x0000086d375940    422 D    scsi_tmf_1
0x0000086c2e1dc0    423 S    scsi_eh_2
0x0000086c2e3b80    424 D    scsi_tmf_2
0x0000086c2e5940    425 S    scsi_eh_3
0x0000086c2e0000    426 D    scsi_tmf_3
0x00000869b1bb80    427 S    scsi_eh_4
0x00000869b1d940    428 D    scsi_tmf_4
0x00000869b18000    429 S    scsi_eh_5
0x00000869b19dc0    430 D    scsi_tmf_5
0x0000086d309dc0    431 S    scsi_eh_6
0x0000086d30bb80    432 D    scsi_tmf_6
0x0000086d30d940    433 S    scsi_eh_7
0x0000086d308000    434 D    scsi_tmf_7
0x0000086d299dc0    516 D    raid5wq
0x0000086cb75940    563 S    jbd2/nvme0n1p2-
0x0000086cb70000    564 D    ext4-rsv-conver
0x0000086cb73b80    613 D    kworker/18:1H
0x0000086cb71dc0    625 D    kworker/5:2
0x0000086cdd5940    649 D    kworker/9:1H
0x0000086cdd0000    650 D    iscsi_eh
0x0000086cdd1dc0    654 D    kworker/7:1H
0x0000086cdd3b80    658 D    ib-comp-wq
0x0000086c490000    659 D    ib-comp-unb-wq
0x0000086c283b80    660 D    ib_mcast
0x0000086c285940    661 D    ib_nl_sa_wq
0x0000086c280000    663 D    rdma_cm
0x0000086957bb80    718 S    loop0
0x0000086957d940    720 D    kworker/5:1H
0x00000876308000    721 S    irq/82-mei_me
0x0000086c281dc0    723 D    kworker/16:1H
0x0000086d2c1dc0    724 D    kworker/14:1H
0x0000086af45940    727 D    kworker/6:1H
0x0000086af41dc0    729 D    kworker/17:1H
0x0000086af43b80    732 D    kworker/11:1H
0x0000086d25bb80    733 D    kworker/10:1H
0x0000086d25d940    735 D    kworker/3:1H
0x0000087bba9dc0    736 D    kworker/13:1H
0x0000086c4c8000    737 S    loop1
0x0000087a83bb80    739 D    led_workqueue
0x0000086d313b80    759 D    nfit
0x0000086d310000    779 D    kworker/15:1H
0x0000086d311dc0    780 D    kworker/4:1H
0x0000086cc30000    781 D    kworker/8:1H
0x0000086cc31dc0    782 D    kworker/12:1H
0x0000086d259dc0    955 D    kworker/17:2
0x0000086d258000   1068 D    kworker/2:1H
0x0000086ac01dc0   1117 D    kworker/0:1H
0x0000086d2bd940   1273 D    kworker/19:1H
0x00000871b11dc0   1418 D    kworker/19:2
0x00000871b15940   1424 D    kworker/1:1H
0x0000086c4cbb80   2413 D    kworker/7:2
0x0000086caf0000   4041 D    kworker/9:0
0x0000086969d940   5312 D    kworker/12:1
0x0000086d2c0000   5818 D    kworker/1:2
0x0000086d36bb80   6049 D    kworker/11:2
0x0000086d1b3b80   8640 D    kworker/10:0
0x00000871b13b80   9860 D    kworker/14:0
0x0000086d31d940  10166 D    kworker/8:2
0x0000086d1b1dc0  10342 D    kworker/2:1
0x0000087bffd940  10849 D    kworker/6:0
0x0000087bbabb80  11035 D    kworker/5:1
0x00000869b38000  12540 D    kworker/15:0
0x0000087b959dc0  12682 D    kworker/3:2
0x0000086d31bb80  12699 D    kworker/u40:0
0x0000087b7d9dc0  12742 D    kworker/4:2
0x0000087c355940  12887 D    kworker/u40:1
0x0000087c351dc0  12906 D    kworker/6:1
0x0000086d2b8000  12912 D    kworker/18:0
%
```


### codedump

- ./codedump -r 192.168.10.1 -b 1b:00 -s ./System.map-4.20.2-tsukumo1-nopti -p 17022 -o demo.dump

demo.dump can be reassembled by objdump -M intel -m i386:x86-64 -b binary -D demo.dump

```shell-session
tsukumo1:/home/upa/work/nettlp/libtlp/apps % ./codedump -r 192.168.10.1 -b 1b:00 -s System.map -p 20286 -o code.dump
code area: 0x85a48b000-0x85a48bdb0
dump complete
tsukumo1:/home/upa/work/nettlp/libtlp/apps % file code.dump             <18:08>
code.dump: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, missing section headers
```

```shell-session
tsukumo1:/home/upa/work/nettlp/libtlp/apps % ./codedump -r 192.168.10.1 -b 1b:00 -s System.map -p 20286 -o test.dump
cod area: 0x85a48b000-0x85a48bdb0
dump complete
tsukumo1:/home/upa/work/nettlp/libtlp/apps % objdump -M intel -m i386:x86-64 -b binary -D test.dump

test.dump:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
   0:	7f 45                	jg     0x47
   2:	4c                   	rex.WR
   3:	46 02 01             	rex.RX add r8b,BYTE PTR [rcx]
   6:	01 00                	add    DWORD PTR [rax],eax
	...
  10:	03 00                	add    eax,DWORD PTR [rax]
  12:	3e 00 01             	add    BYTE PTR ds:[rcx],al
  15:	00 00                	add    BYTE PTR [rax],al
  17:	00 40 08             	add    BYTE PTR [rax+0x8],al
  1a:	00 00                	add    BYTE PTR [rax],al
  1c:	00 00                	add    BYTE PTR [rax],al
  1e:	00 00                	add    BYTE PTR [rax],al
  20:	40 00 00             	add    BYTE PTR [rax],al
  23:	00 00                	add    BYTE PTR [rax],al
  25:	00 00                	add    BYTE PTR [rax],al
  27:	00 10                	add    BYTE PTR [rax],dl
  29:	2b 00                	sub    eax,DWORD PTR [rax]
	...
  33:	00 40 00             	add    BYTE PTR [rax+0x0],al
  36:	38 00                	cmp    BYTE PTR [rax],al
  38:	09 00                	or     DWORD PTR [rax],eax
  3a:	40 00 1d 00 1c 00 06 	add    BYTE PTR [rip+0x6001c00],bl        # 0x6001c41
  41:	00 00                	add    BYTE PTR [rax],al
  43:	00 04 00             	add    BYTE PTR [rax+rax*1],al
  46:	00 00                	add    BYTE PTR [rax],al
  48:	40 00 00             	add    BYTE PTR [rax],al
  4b:	00 00                	add    BYTE PTR [rax],al
  4d:	00 00                	add    BYTE PTR [rax],al
  4f:	00 40 00             	add    BYTE PTR [rax+0x0],al
  52:	00 00                	add    BYTE PTR [rax],al
  54:	00 00                	add    BYTE PTR [rax],al
  56:	00 00                	add    BYTE PTR [rax],al
  58:	40 00 00             	add    BYTE PTR [rax],al
  5b:	00 00                	add    BYTE PTR [rax],al
  5d:	00 00                	add    BYTE PTR [rax],al
  5f:	00 f8                	add    al,bh
  61:	01 00                	add    DWORD PTR [rax],eax
  63:	00 00                	add    BYTE PTR [rax],al
  65:	00 00                	add    BYTE PTR [rax],al
  67:	00 f8                	add    al,bh
  69:	01 00                	add    DWORD PTR [rax],eax
  6b:	00 00                	add    BYTE PTR [rax],al
  6d:	00 00                	add    BYTE PTR [rax],al
  6f:	00 08                	add    BYTE PTR [rax],cl
  71:	00 00                	add    BYTE PTR [rax],al
  73:	00 00                	add    BYTE PTR [rax],al
  75:	00 00                	add    BYTE PTR [rax],al
  77:	00 03                	add    BYTE PTR [rbx],al
  79:	00 00                	add    BYTE PTR [rax],al
  7b:	00 04 00             	add    BYTE PTR [rax+rax*1],al
  7e:	00 00                	add    BYTE PTR [rax],al
  80:	38 02                	cmp    BYTE PTR [rdx],al
  82:	00 00                	add    BYTE PTR [rax],al
  84:	00 00                	add    BYTE PTR [rax],al
  86:	00 00                	add    BYTE PTR [rax],al
  88:	38 02                	cmp    BYTE PTR [rdx],al
  8a:	00 00                	add    BYTE PTR [rax],al
  8c:	00 00                	add    BYTE PTR [rax],al
  8e:	00 00                	add    BYTE PTR [rax],al
  90:	38 02                	cmp    BYTE PTR [rdx],al
  92:	00 00                	add    BYTE PTR [rax],al
  94:	00 00                	add    BYTE PTR [rax],al
  96:	00 00                	add    BYTE PTR [rax],al
  98:	1c 00                	sbb    al,0x0
  9a:	00 00                	add    BYTE PTR [rax],al
  9c:	00 00                	add    BYTE PTR [rax],al
  9e:	00 00                	add    BYTE PTR [rax],al
  a0:	1c 00                	sbb    al,0x0
  a2:	00 00                	add    BYTE PTR [rax],al
  a4:	00 00                	add    BYTE PTR [rax],al
  a6:	00 00                	add    BYTE PTR [rax],al
  a8:	01 00                	add    DWORD PTR [rax],eax
  aa:	00 00                	add    BYTE PTR [rax],al
  ac:	00 00                	add    BYTE PTR [rax],al
  ae:	00 00                	add    BYTE PTR [rax],al
  b0:	01 00                	add    DWORD PTR [rax],eax
  b2:	00 00                	add    BYTE PTR [rax],al
  b4:	05 00 00 00 00       	add    eax,0x0
	...
  cd:	00 00                	add    BYTE PTR [rax],al
  cf:	00 b0 0d 00 00 00    	add    BYTE PTR [rax+0xd],dh
  d5:	00 00                	add    BYTE PTR [rax],al
  d7:	00 b0 0d 00 00 00    	add    BYTE PTR [rax+0xd],dh
  dd:	00 00                	add    BYTE PTR [rax],al
  df:	00 00                	add    BYTE PTR [rax],al
  e1:	00 20                	add    BYTE PTR [rax],ah
  e3:	00 00                	add    BYTE PTR [rax],al
  e5:	00 00                	add    BYTE PTR [rax],al
  e7:	00 01                	add    BYTE PTR [rcx],al
  e9:	00 00                	add    BYTE PTR [rax],al
  eb:	00 06                	add    BYTE PTR [rsi],al
  ed:	00 00                	add    BYTE PTR [rax],al
  ef:	00 68 1d             	add    BYTE PTR [rax+0x1d],ch
  f2:	00 00                	add    BYTE PTR [rax],al
  f4:	00 00                	add    BYTE PTR [rax],al
  f6:	00 00                	add    BYTE PTR [rax],al
  f8:	68 1d 20 00 00       	push   0x201d
  fd:	00 00                	add    BYTE PTR [rax],al
```
