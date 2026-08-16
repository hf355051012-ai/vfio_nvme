# vfio_nvme -- x86-64 Linux ユーザ空間 + VFIO で ConnectX-4 を直接駆動し、
# NVMe-oF (RoCEv2) / NVMe/TCP のターゲットとイニシエータを同一プロセスに立てる。
#
# hosted target なので libc/pthread にリンクする(-ffreestanding/-nostdlib 無し)。
#   -msse4.2      crc32c.c のハードウェア CRC32C (Castagnoli) バックエンド
#   -D_GNU_SOURCE pthread_setaffinity_np / MAP_HUGETLB / pread など
#   --gc-sections 到達しない関数をリンクから落とす

CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -ffunction-sections -fdata-sections -MMD -MP \
           -Iinclude -Isrc -msse4.2 -pthread -D_GNU_SOURCE
LDFLAGS := -pthread -Wl,--gc-sections

SRC_DIR   := src
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/vfio_nvme

# VFIO HAL(コンソール / タイマ / SMP / DMA / VFIO / エントリ)。
PLATFORM_OBJS := console hal_timer hal_smp hal_dma vfio main

# アーキ非依存コア: mlx5 ドライバ + RoCEv2/NVMe-oF + TCP/IP + 計測基盤。
CORE_OBJS := crc32c timer mlx5 mlx5_qp timestamp netif net_buf \
             job rdma_cm nvme_rdma nvmet_rdma \
             mlx5_net rxcopy tcp ip arp icmp \
             nvmet nvme nvmet_tcp nvme_tcp stateprof

OBJS := $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(PLATFORM_OBJS) $(CORE_OBJS)))

.PHONY: all clean

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# platform ソースは専用サブディレクトリにあるので、先に評価される専用ルールを置く。
$(BUILD_DIR)/%.o: $(SRC_DIR)/platform/x86-linux/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# mlx5.c は -O0 固定。-O2 だと ENABLE_HCA 直後の QUERY_ISSI が実機で毎回失敗する
# 未解明の問題があり、-O0 では確実に成功する。explicit rule が pattern rule に優先する。
$(BUILD_DIR)/mlx5.o: $(SRC_DIR)/mlx5.c | $(BUILD_DIR)
	$(CC) $(filter-out -O2,$(CFLAGS)) -O0 -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

clean:
	rm -rf $(BUILD_DIR)

-include $(OBJS:.o=.d)
