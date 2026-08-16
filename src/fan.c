// Pi 5純正ファン(GPIO45/FAN_PWM -> RP1 PWM1チャンネル3)。

#include "fan.h"
#include "board.h"
#include "mmio.h"
#include "pl011.h"
#include "pcie.h"

extern pl011_t debug_uart; // main.cで定義

#define RP1_REG(off) (PCIE_OUTBOUND_CPU_BASE + (off))

#define RP1_GPIO_BASE  RP1_REG(0xd0000)
#define RP1_PADS_BASE  RP1_REG(0xf0000)
#define RP1_PWM1_BASE  RP1_REG(0x9c000)

// GPIO45はbank 2(GPIO34-53をカバー)、bank内オフセット j = 45-34 = 11。
#define GPIO45_BANK_GPIO_OFFSET 0x8000u
#define GPIO45_BANK_PADS_OFFSET 0x8004u
#define GPIO45_J                11u

#define GPIO45_CTRL_REG (RP1_GPIO_BASE + GPIO45_BANK_GPIO_OFFSET + GPIO45_J * 8 + 0x4)
#define GPIO45_PAD_REG  (RP1_PADS_BASE + GPIO45_BANK_PADS_OFFSET + GPIO45_J * 4)

#define GPIO_CTRL_FUNCSEL_MASK 0x0000001fu // RP1_FSEL_ALT0 = 0でGPIO45に"pwm1"を選択
#define GPIO_CTRL_OUTOVER_MASK 0x00003000u
#define GPIO_CTRL_OEOVER_MASK  0x0000c000u

#define PAD_IN_ENABLE_BIT    0x00000040u
#define PAD_OUT_DISABLE_BIT  0x00000080u

#define PWM_GLOBAL_CTRL      0x000u
#define PWM_CHANNEL_CTRL(x)  (0x014u + (x) * 16u)
#define PWM_RANGE(x)         (0x018u + (x) * 16u)
#define PWM_DUTY(x)          (0x020u + (x) * 16u)

#define PWM_CHANNEL_DEFAULT  0x101u // bit8: FIFO未使用, bit0: trailing-edge M/Sモード
#define PWM_POLARITY_BIT     0x8u
#define PWM_CHANNEL_ENABLE(x) (1u << (x))
#define PWM_SET_UPDATE        0x80000000u

#define FAN_PWM_CHANNEL 3u
#define FAN_PWM_RANGE   2078u // PWM1の50MHzクロックで約24kHz

// RP1のクロックジェネレータ(BAR1オフセット0x18000)。PWM1のクロックは
// ファームウェアが有効化しないまま残っているため、ここで自前で有効化する。
#define RP1_CLOCKS_BASE       RP1_REG(0x18000)
#define CLK_PWM1_CTRL         (RP1_CLOCKS_BASE + 0x084)

#define CLK_CTRL_ENABLE       0x00000800u // bit11
#define CLK_CTRL_AUXSRC_MASK  0x000003e0u
#define CLK_CTRL_AUXSRC_SHIFT 5u
#define CLK_PWM1_AUXSRC_XOSC  2u // xosc, 50MHz -- DIV_INT/DIV_FRACはデフォルトの1:1のままでよい

static void log_str(const char *s) {
    pl011_puts(&debug_uart, s);
}

// PWM1のクロックをxosc(50MHz、DIV 1:1)、有効化して供給する。
static void pwm1_clock_enable(void) {
    uint32_t ctrl = mmio_read32(CLK_PWM1_CTRL);
    ctrl &= ~CLK_CTRL_AUXSRC_MASK;
    ctrl |= (CLK_PWM1_AUXSRC_XOSC << CLK_CTRL_AUXSRC_SHIFT) & CLK_CTRL_AUXSRC_MASK;
    ctrl |= CLK_CTRL_ENABLE;
    mmio_write32(CLK_PWM1_CTRL, ctrl);
}

// GPIO45をPWM1にピンマックスし、チャンネル3をduty_percentのデューティで駆動する。
int fan_set_speed(uint32_t duty_percent) {
    if (duty_percent > 100u) {
        duty_percent = 100u;
    }
    uint32_t duty_ticks = (FAN_PWM_RANGE * duty_percent) / 100u;

    pwm1_clock_enable();

    log_str("fan: pin-muxing GPIO45 to PWM1 (alt0)\n");
    uint32_t pad = mmio_read32(GPIO45_PAD_REG);
    pad = (pad & ~PAD_OUT_DISABLE_BIT) | PAD_IN_ENABLE_BIT;
    mmio_write32(GPIO45_PAD_REG, pad);

    uint32_t ctrl = mmio_read32(GPIO45_CTRL_REG);
    ctrl &= ~(GPIO_CTRL_OUTOVER_MASK | GPIO_CTRL_OEOVER_MASK | GPIO_CTRL_FUNCSEL_MASK);
    mmio_write32(GPIO45_CTRL_REG, ctrl);

    // 稼働中のチャンネルはRANGE/DUTYの変更を正しくラッチしないことがある
    // ので、書き換え前に一旦無効化する。
    uint32_t gctrl = mmio_read32(RP1_PWM1_BASE + PWM_GLOBAL_CTRL);
    gctrl &= ~PWM_CHANNEL_ENABLE(FAN_PWM_CHANNEL);
    mmio_write32(RP1_PWM1_BASE + PWM_GLOBAL_CTRL, gctrl);

    log_str("fan: driving PWM1 channel 3 to ");
    pl011_udec64(&debug_uart, duty_percent);
    log_str("% duty\n");
    mmio_write32(RP1_PWM1_BASE + PWM_RANGE(FAN_PWM_CHANNEL), FAN_PWM_RANGE);
    mmio_write32(RP1_PWM1_BASE + PWM_DUTY(FAN_PWM_CHANNEL), duty_ticks);
    mmio_write32(RP1_PWM1_BASE + PWM_CHANNEL_CTRL(FAN_PWM_CHANNEL),
                 PWM_CHANNEL_DEFAULT | PWM_POLARITY_BIT);

    // 無効化した状態から改めて有効化し、SET_UPDATEを0->1に遷移させて
    // 新しいRANGE/DUTYをラッチする。
    gctrl &= ~PWM_SET_UPDATE;
    gctrl |= PWM_CHANNEL_ENABLE(FAN_PWM_CHANNEL);
    mmio_write32(RP1_PWM1_BASE + PWM_GLOBAL_CTRL, gctrl);

    gctrl |= PWM_SET_UPDATE;
    mmio_write32(RP1_PWM1_BASE + PWM_GLOBAL_CTRL, gctrl);

    log_str("fan: done\n");
    return 0;
}
