# Bare-metal build for Raspberry Pi 5 (BCM2712 / Cortex-A76, AArch64)
#
# Platform selection (x86-vfio-port, see ~/.claude/plans/x86-vfio-port.md):
#   PLATFORM=rpi5      (default) -- bare-metal Pi 5 image (kernel_2712.img/payload).
#   PLATFORM=x86-linux           -- VFIO/x86-64 port. Phase 3 links a minimal
#                                   target (HAL + crc32c + timer) that boots to a
#                                   console self-test; mlx5/nvme/rdma core join in
#                                   Phase 4/5.
#
# Objects are classified into an arch-independent CORE set (the mlx5 driver +
# RoCEv2/NVMe-oF + TCP/IP stack + job/timestamp/crc32c/stateprof/rxcopy + command
# dispatch) shared by every platform, and a per-platform set (the bare-metal
# seam: boot/MMU/exception vectors, PL011 UART, ARM generic timer, PSCI SMP, RP1
# GEM, BCM2712 PCIe bring-up, fwupdate/xmodem/ftpd/telnet transport, ...; or the
# x86 VFIO HAL). Only the platform set and the toolchain differ across platforms.
# The HAL contract those platform files implement lives in include/platform.h
# (DMA) + src/{mmio,cache,timer,smp}.h (MMIO / cache / timer / SMP).
#
# The rpi5 link list below is kept VERBATIM and UNREORDERED so kernel_2712.img /
# payload_2712.img stay byte-identical; the CORE_OBJS/*_PLATFORM_OBJS groups are
# the authoritative core-vs-platform classification (kept honest against the link
# list by the drift check inside the rpi5 branch).
PLATFORM ?= rpi5

# --- Core: arch-independent, shared by rpi5 / x86-linux / vxworks(future). ---
CORE_OBJS := command net_buf netctx job arp ip icmp tcp \
             test bench err nvme_tcp nvme nvmet_tcp nvmet timestamp \
             crc32c mlx5 mlx5_net mlx5_qp rdma_cm nvme_rdma nvmet_rdma \
             stateprof rxcopy

# --- Platform (rpi5): bare-metal seam (boot/MMU/vectors, PL011, ARM timer,
#     PSCI SMP, RP1 Cadence GEM, BCM2712 PCIe, fwupdate/xmodem/ftpd/telnet). ---
RPI5_PLATFORM_OBJS := boot main pl011 vectors exceptions xmodem fwupdate \
             pcie pcie1 platform_init fan pcidump uart_shim mmu eth iperf3 \
             telnet ftpd psci smp timer dma_rpi5 string_min

# --- Platform (x86-linux): VFIO HAL. Sources live in src/platform/x86-linux/. ---
X86_PLATFORM_OBJS := console hal_timer hal_smp hal_dma vfio main

SRC_DIR   := src
BUILD_DIR := build
BOOT_DIR  := boot

ifeq ($(PLATFORM),rpi5)

CROSS   ?= aarch64-linux-gnu-
CC      := $(CROSS)gcc
LD      := $(CROSS)ld
OBJCOPY := $(CROSS)objcopy

ARCH_FLAGS := -mcpu=cortex-a76
# -fno-pie/-fno-pic: this distro's gcc defaults to PIE, which makes some
# extern-symbol accesses go through a GOT entry instead of a direct PC-relative
# (adrp+add) computation. A GOT entry holds the address as a plain link-time
# constant that only a dynamic linker would fix up -- we have none (bare
# metal), so it's silently wrong whenever this image runs somewhere other
# than its linked base (e.g. chainloaded by fwupdate at LOAD_ADDR). See
# boot.S's primary_core comment for the same issue in hand-written asm.
CFLAGS  := $(ARCH_FLAGS) -Wall -Wextra -O2 -ffreestanding -fno-stack-protector -fno-pie -fno-pic -nostdlib -nostartfiles -MMD -MP -Iinclude
ASFLAGS := $(ARCH_FLAGS)
LDFLAGS := -nostdlib -no-pie -static

# rpi5 link list -- VERBATIM and UNREORDERED (see header note: link order ==
# input-section order == symbol placement == byte-identical images). Do NOT
# reorder or derive from the *_OBJS groups.
OBJS := $(BUILD_DIR)/boot.o $(BUILD_DIR)/main.o $(BUILD_DIR)/pl011.o \
        $(BUILD_DIR)/vectors.o $(BUILD_DIR)/exceptions.o $(BUILD_DIR)/xmodem.o \
        $(BUILD_DIR)/command.o $(BUILD_DIR)/fwupdate.o $(BUILD_DIR)/pcie.o \
        $(BUILD_DIR)/pcie1.o $(BUILD_DIR)/platform_init.o \
        $(BUILD_DIR)/fan.o $(BUILD_DIR)/pcidump.o \
        $(BUILD_DIR)/uart_shim.o $(BUILD_DIR)/mmu.o \
        $(BUILD_DIR)/net_buf.o $(BUILD_DIR)/eth.o $(BUILD_DIR)/netctx.o \
        $(BUILD_DIR)/job.o \
        $(BUILD_DIR)/arp.o $(BUILD_DIR)/ip.o $(BUILD_DIR)/icmp.o $(BUILD_DIR)/tcp.o \
        $(BUILD_DIR)/test.o $(BUILD_DIR)/bench.o $(BUILD_DIR)/err.o \
        $(BUILD_DIR)/nvme_tcp.o $(BUILD_DIR)/nvme.o \
        $(BUILD_DIR)/nvmet_tcp.o $(BUILD_DIR)/nvmet.o \
        $(BUILD_DIR)/timestamp.o $(BUILD_DIR)/iperf3.o \
        $(BUILD_DIR)/crc32c.o $(BUILD_DIR)/mlx5.o $(BUILD_DIR)/mlx5_net.o \
        $(BUILD_DIR)/mlx5_qp.o $(BUILD_DIR)/rdma_cm.o \
        $(BUILD_DIR)/nvme_rdma.o $(BUILD_DIR)/nvmet_rdma.o \
        $(BUILD_DIR)/telnet.o $(BUILD_DIR)/ftpd.o \
        $(BUILD_DIR)/psci.o $(BUILD_DIR)/smp.o \
        $(BUILD_DIR)/stateprof.o $(BUILD_DIR)/timer.o $(BUILD_DIR)/rxcopy.o \
        $(BUILD_DIR)/dma_rpi5.o $(BUILD_DIR)/string_min.o

# Sanity (parse-time): the CORE_OBJS + RPI5_PLATFORM_OBJS classification must
# name exactly the objects in the rpi5 link list above -- no more, no less. This
# keeps the HAL seam / Makefile groups honest as objects are added, without
# touching the (order-sensitive) link. Errors if the two views ever diverge.
_RPI5_OBJ_NAMES := $(patsubst $(BUILD_DIR)/%.o,%,$(OBJS))
_OBJS_DRIFT := $(filter-out $(CORE_OBJS) $(RPI5_PLATFORM_OBJS),$(_RPI5_OBJ_NAMES)) \
               $(filter-out $(_RPI5_OBJ_NAMES),$(CORE_OBJS) $(RPI5_PLATFORM_OBJS))
ifneq ($(strip $(_OBJS_DRIFT)),)
$(error core/platform object classification drift vs rpi5 link list: $(_OBJS_DRIFT))
endif

# Firmware on the Pi 5 looks for kernel_2712.img before falling back to kernel8.img
KERNEL_IMG := $(BOOT_DIR)/kernel_2712.img
KERNEL_ELF := $(BUILD_DIR)/kernel.elf

# "Payload" build: identical sources, linked at LOAD_ADDR (src/board.h) via
# linker_payload.ld instead of the primary 0x80000 boot address. Send THIS
# file via fwupdate/xmodemsend, not kernel_2712.img -- a kernel_2712.img
# jumped to at LOAD_ADDR silently misbehaves, because static data containing
# pointers (e.g. command.c's COMMANDS[] table) bakes in absolute addresses
# at link time that nothing here relocates at runtime. kernel_2712.img is
# only correct when it runs at the address it was linked for (0x80000, where
# firmware actually loads it).
PAYLOAD_IMG := $(BOOT_DIR)/payload_2712.img
PAYLOAD_ELF := $(BUILD_DIR)/payload.elf

.PHONY: all clean payload

all: $(KERNEL_IMG) $(PAYLOAD_IMG)

payload: $(PAYLOAD_IMG)

# mlx5.cは-O0固定(理由はファイル冒頭のコメント参照 -- -O2だとENABLE_HCA直後の
# QUERY_ISSIが実機で毎回失敗する未解明の問題があり、-O0では確実に成功する)。
$(BUILD_DIR)/mlx5.o: $(SRC_DIR)/mlx5.c | $(BUILD_DIR)
	$(CC) $(filter-out -O2,$(CFLAGS)) -O0 -c $< -o $@

$(KERNEL_ELF): $(OBJS) linker.ld
	$(LD) -T linker.ld $(LDFLAGS) -o $@ $(OBJS)

$(KERNEL_IMG): $(KERNEL_ELF)
	$(OBJCOPY) $< -O binary $@

$(PAYLOAD_ELF): $(OBJS) linker_payload.ld
	$(LD) -T linker_payload.ld $(LDFLAGS) -o $@ $(OBJS)

$(PAYLOAD_IMG): $(PAYLOAD_ELF)
	$(OBJCOPY) $< -O binary $@

else ifeq ($(PLATFORM),x86-linux)

# Native x86-64 toolchain (Ubuntu). Unlike rpi5 this is a hosted target: it
# links against libc/pthread (no -ffreestanding/-nostdlib). -msse4.2 enables the
# hardware CRC32C (Castagnoli) backend in crc32c.c; -D_GNU_SOURCE unlocks
# pthread_setaffinity_np / MAP_HUGETLB / pread etc.
CC      := gcc

# board.h は純粋な #define 定数群(arch 非依存)なので x86 でも src/board.h を
# そのまま使う(シャドウ不要)。-ffunction-sections/-fdata-sections +
# --gc-sections で、hca_bringup から到達しない RPi5 固有グルー(mlx5.c の
# pcie1 bring-up や nvmet/rdma コマンドラッパ等)を素通ししてリンクから落とす
# -- これにより pcie1/eth/telnet 等の RPi5 platform シンボルを x86 で用意
# せずに済む。mlx5.o は RPi5 と同様 -O0(下の専用ルール、Makefile 冒頭の
# mlx5 コメント参照)。
CFLAGS  := -Wall -Wextra -O2 -ffunction-sections -fdata-sections -MMD -MP -Iinclude -Isrc -msse4.2 -pthread -D_GNU_SOURCE
LDFLAGS := -pthread -Wl,--gc-sections

# Phase 4 core: mlx5 HCA bring-up の到達集合。crc32c/timer は自己テスト用、
# mlx5 が bring-up 本体、timestamp は ts_log。--gc-sections が未到達関数を
# 落とすので、依存の閉包(net_buf/netctx/job/mlx5_qp/rdma_cm/nvme_rdma/
# nvmet_rdma 等)は「実際に到達して未定義になったものだけ」追加する方針。
X86_CORE_OBJS := crc32c timer mlx5 mlx5_qp timestamp netctx net_buf \
                 job rdma_cm nvme_rdma nvmet_rdma \
                 mlx5_net rxcopy tcp ip arp icmp test eth \
                 nvmet nvme nvmet_tcp nvme_tcp stateprof

OBJS := $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(X86_PLATFORM_OBJS) $(X86_CORE_OBJS)))

TARGET := $(BUILD_DIR)/rpi5-x86

.PHONY: all clean

all: $(TARGET)

# x86 platform sources live in a subdir; give them their own pattern rule.
$(BUILD_DIR)/%.o: $(SRC_DIR)/platform/x86-linux/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# mlx5.o は RPi5 同様 -O0(Makefile 冒頭 mlx5 コメント参照)。explicit rule は
# generic pattern rule に優先する。
$(BUILD_DIR)/mlx5.o: $(SRC_DIR)/mlx5.c | $(BUILD_DIR)
	$(CC) $(filter-out -O2,$(CFLAGS)) -O0 -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

else

$(error Unknown PLATFORM '$(PLATFORM)' -- use 'rpi5' (default) or 'x86-linux'.)

endif

# --- Shared across platforms: build dir, generic src/ compile rules, clean. ---
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.S | $(BUILD_DIR)
	$(CC) $(ASFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(KERNEL_IMG) $(PAYLOAD_IMG)

-include $(OBJS:.o=.d)
