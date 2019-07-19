
## Example Applications


### dma_read

### dma_write


### pmem

### process-list

### codedump

./codedump -r 192.168.10.1 -b 1b:00 -s ./System.map-4.20.2-tsukumo1-nopti -p 17022 -o demo.dump

demo.dump can be reassembled by objdump -M intel -m i386:x86-64 -b binary -D demo.dump