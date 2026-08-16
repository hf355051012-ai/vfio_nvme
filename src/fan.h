#ifndef FAN_H
#define FAN_H

#include <stdint.h>

// ケースファンをduty_percent(0-100、範囲外はクランプ)で駆動する
// (pcie_rc_init()呼び出し後に使うこと)。
int fan_set_speed(uint32_t duty_percent);

#endif
