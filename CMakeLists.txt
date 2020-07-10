cmake_minimum_required(VERSION 3.1)

project(tlp)

set(CMAKE_C_FLAGS "-Wall -O -g")

# libtlp
add_library(tlp STATIC lib/libtlp.c)
target_include_directories(tlp PUBLIC include)
install(TARGETS tlp DESTINATION /usr/local/lib)
install(FILES include/libtlp.h include/tlp.h DESTINATION /usr/local/include)

# test
add_executable(test_dma_read test/test_dma_read.c)
target_link_libraries(test_dma_read tlp)

add_executable(test_dma_write test/test_dma_write.c)
target_link_libraries(test_dma_write tlp)

add_executable(test_msg_bar4 test/test_msg_bar4.c)
target_link_libraries(test_msg_bar4 tlp)

add_executable(test_msg_msix test/test_msg_msix.c)
target_link_libraries(test_msg_msix tlp)

add_executable(test_msg_devid test/test_msg_devid.c)
target_link_libraries(test_msg_devid tlp)

# apps
add_executable(example apps/example.c)
target_link_libraries(example tlp)

add_executable(dma_read apps/dma_read.c)
target_link_libraries(dma_read tlp)

add_executable(dma_write apps/dma_write.c)
target_link_libraries(dma_write tlp)

add_executable(psmem apps/psmem.c)
target_link_libraries(psmem tlp pthread)

add_executable(process-list apps/process-list.c)
target_link_libraries(process-list tlp)

add_executable(pgd-walk apps/pgd-walk.c)
target_link_libraries(pgd-walk tlp)

add_executable(codedump apps/codedump.c)
target_link_libraries(codedump tlp)

add_executable(tlpperf apps/tlpperf.c)
target_link_libraries(tlpperf tlp pthread)

add_executable(pcie_cfg_read apps/pcie_cfg_read.c)
target_link_libraries(pcie_cfg_read tlp)

add_executable(pcie_cfg_write apps/pcie_cfg_write.c)
target_link_libraries(pcie_cfg_write tlp)

# unittest
enable_testing()
add_executable(unittest test.c picotest/picotest.c)
target_link_libraries(unittest tlp)
add_test(
	NAME unittest
	COMMAND unittest
)
