// RUN: llvm-mc -triple x86_64-unknown-unknown -mcpu=knl -mattr=+avx512vnni --show-encoding < %s | FileCheck %s

// CHECK: vpdpbusd %zmm3, %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x50,0xcb]
          vpdpbusd %zmm3, %zmm2, %zmm1

// CHECK: vpdpbusds %zmm3, %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x51,0xcb]
          vpdpbusds %zmm3, %zmm2, %zmm1

// CHECK: vpdpwssd %zmm3, %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x52,0xcb]
          vpdpwssd %zmm3, %zmm2, %zmm1

// CHECK: vpdpwssds %zmm3, %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x53,0xcb]
          vpdpwssds %zmm3, %zmm2, %zmm1

// CHECK: vpdpbusd %zmm23, %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x50,0xef]
          vpdpbusd %zmm23, %zmm22, %zmm21

// CHECK: vpdpbusds %zmm23, %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x51,0xef]
          vpdpbusds %zmm23, %zmm22, %zmm21

// CHECK: vpdpwssd %zmm23, %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x52,0xef]
          vpdpwssd %zmm23, %zmm22, %zmm21

// CHECK: vpdpwssds %zmm23, %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x53,0xef]
          vpdpwssds %zmm23, %zmm22, %zmm21

// CHECK: vpdpbusd %zmm3, %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x50,0xcb]
          vpdpbusd %zmm3, %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusds %zmm3, %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x51,0xcb]
          vpdpbusds %zmm3, %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssd %zmm3, %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x52,0xcb]
          vpdpwssd %zmm3, %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssds %zmm3, %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x53,0xcb]
          vpdpwssds %zmm3, %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusd %zmm23, %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x50,0xef]
          vpdpbusd %zmm23, %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusds %zmm23, %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x51,0xef]
          vpdpbusds %zmm23, %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssd %zmm23, %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x52,0xef]
          vpdpwssd %zmm23, %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssds %zmm23, %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x53,0xef]
          vpdpwssds %zmm23, %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusd  (%rcx), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x50,0x09]
          vpdpbusd  (%rcx), %zmm2, %zmm1

// CHECK: vpdpbusd  -256(%rsp), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x50,0x4c,0x24,0xfc]
          vpdpbusd  -256(%rsp), %zmm2, %zmm1

// CHECK: vpdpbusd  256(%rsp), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x50,0x4c,0x24,0x04]
          vpdpbusd  256(%rsp), %zmm2, %zmm1

// CHECK: vpdpbusd  268435456(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x50,0x8c,0xf1,0x00,0x00,0x00,0x10]
          vpdpbusd  268435456(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpbusd  -536870912(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x50,0x8c,0xf1,0x00,0x00,0x00,0xe0]
          vpdpbusd  -536870912(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpbusd  -536870910(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x50,0x8c,0xf1,0x02,0x00,0x00,0xe0]
          vpdpbusd  -536870910(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpbusds  (%rcx), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x51,0x09]
          vpdpbusds  (%rcx), %zmm2, %zmm1

// CHECK: vpdpbusds  -256(%rsp), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x51,0x4c,0x24,0xfc]
          vpdpbusds  -256(%rsp), %zmm2, %zmm1

// CHECK: vpdpbusds  256(%rsp), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x51,0x4c,0x24,0x04]
          vpdpbusds  256(%rsp), %zmm2, %zmm1

// CHECK: vpdpbusds  268435456(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x51,0x8c,0xf1,0x00,0x00,0x00,0x10]
          vpdpbusds  268435456(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpbusds  -536870912(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x51,0x8c,0xf1,0x00,0x00,0x00,0xe0]
          vpdpbusds  -536870912(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpbusds  -536870910(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x51,0x8c,0xf1,0x02,0x00,0x00,0xe0]
          vpdpbusds  -536870910(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpwssd  (%rcx), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x52,0x09]
          vpdpwssd  (%rcx), %zmm2, %zmm1

// CHECK: vpdpwssd  -256(%rsp), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x52,0x4c,0x24,0xfc]
          vpdpwssd  -256(%rsp), %zmm2, %zmm1

// CHECK: vpdpwssd  256(%rsp), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x52,0x4c,0x24,0x04]
          vpdpwssd  256(%rsp), %zmm2, %zmm1

// CHECK: vpdpwssd  268435456(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x52,0x8c,0xf1,0x00,0x00,0x00,0x10]
          vpdpwssd  268435456(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpwssd  -536870912(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x52,0x8c,0xf1,0x00,0x00,0x00,0xe0]
          vpdpwssd  -536870912(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpwssd  -536870910(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x52,0x8c,0xf1,0x02,0x00,0x00,0xe0]
          vpdpwssd  -536870910(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpwssds  (%rcx), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x53,0x09]
          vpdpwssds  (%rcx), %zmm2, %zmm1

// CHECK: vpdpwssds  -256(%rsp), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x53,0x4c,0x24,0xfc]
          vpdpwssds  -256(%rsp), %zmm2, %zmm1

// CHECK: vpdpwssds  256(%rsp), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xf2,0x6d,0x48,0x53,0x4c,0x24,0x04]
          vpdpwssds  256(%rsp), %zmm2, %zmm1

// CHECK: vpdpwssds  268435456(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x53,0x8c,0xf1,0x00,0x00,0x00,0x10]
          vpdpwssds  268435456(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpwssds  -536870912(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x53,0x8c,0xf1,0x00,0x00,0x00,0xe0]
          vpdpwssds  -536870912(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpwssds  -536870910(%rcx,%r14,8), %zmm2, %zmm1
// CHECK: encoding: [0x62,0xb2,0x6d,0x48,0x53,0x8c,0xf1,0x02,0x00,0x00,0xe0]
          vpdpwssds  -536870910(%rcx,%r14,8), %zmm2, %zmm1

// CHECK: vpdpbusd  (%rcx), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x50,0x29]
          vpdpbusd  (%rcx), %zmm22, %zmm21

// CHECK: vpdpbusd  -256(%rsp), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x50,0x6c,0x24,0xfc]
          vpdpbusd  -256(%rsp), %zmm22, %zmm21

// CHECK: vpdpbusd  256(%rsp), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x50,0x6c,0x24,0x04]
          vpdpbusd  256(%rsp), %zmm22, %zmm21

// CHECK: vpdpbusd  268435456(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x50,0xac,0xf1,0x00,0x00,0x00,0x10]
          vpdpbusd  268435456(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpbusd  -536870912(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x50,0xac,0xf1,0x00,0x00,0x00,0xe0]
          vpdpbusd  -536870912(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpbusd  -536870910(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x50,0xac,0xf1,0x02,0x00,0x00,0xe0]
          vpdpbusd  -536870910(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpbusds  (%rcx), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x51,0x29]
          vpdpbusds  (%rcx), %zmm22, %zmm21

// CHECK: vpdpbusds  -256(%rsp), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x51,0x6c,0x24,0xfc]
          vpdpbusds  -256(%rsp), %zmm22, %zmm21

// CHECK: vpdpbusds  256(%rsp), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x51,0x6c,0x24,0x04]
          vpdpbusds  256(%rsp), %zmm22, %zmm21

// CHECK: vpdpbusds  268435456(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x51,0xac,0xf1,0x00,0x00,0x00,0x10]
          vpdpbusds  268435456(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpbusds  -536870912(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x51,0xac,0xf1,0x00,0x00,0x00,0xe0]
          vpdpbusds  -536870912(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpbusds  -536870910(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x51,0xac,0xf1,0x02,0x00,0x00,0xe0]
          vpdpbusds  -536870910(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpwssd  (%rcx), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x52,0x29]
          vpdpwssd  (%rcx), %zmm22, %zmm21

// CHECK: vpdpwssd  -256(%rsp), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x52,0x6c,0x24,0xfc]
          vpdpwssd  -256(%rsp), %zmm22, %zmm21

// CHECK: vpdpwssd  256(%rsp), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x52,0x6c,0x24,0x04]
          vpdpwssd  256(%rsp), %zmm22, %zmm21

// CHECK: vpdpwssd  268435456(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x52,0xac,0xf1,0x00,0x00,0x00,0x10]
          vpdpwssd  268435456(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpwssd  -536870912(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x52,0xac,0xf1,0x00,0x00,0x00,0xe0]
          vpdpwssd  -536870912(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpwssd  -536870910(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x52,0xac,0xf1,0x02,0x00,0x00,0xe0]
          vpdpwssd  -536870910(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpwssds  (%rcx), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x53,0x29]
          vpdpwssds  (%rcx), %zmm22, %zmm21

// CHECK: vpdpwssds  -256(%rsp), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x53,0x6c,0x24,0xfc]
          vpdpwssds  -256(%rsp), %zmm22, %zmm21

// CHECK: vpdpwssds  256(%rsp), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xe2,0x4d,0x40,0x53,0x6c,0x24,0x04]
          vpdpwssds  256(%rsp), %zmm22, %zmm21

// CHECK: vpdpwssds  268435456(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x53,0xac,0xf1,0x00,0x00,0x00,0x10]
          vpdpwssds  268435456(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpwssds  -536870912(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x53,0xac,0xf1,0x00,0x00,0x00,0xe0]
          vpdpwssds  -536870912(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpwssds  -536870910(%rcx,%r14,8), %zmm22, %zmm21
// CHECK: encoding: [0x62,0xa2,0x4d,0x40,0x53,0xac,0xf1,0x02,0x00,0x00,0xe0]
          vpdpwssds  -536870910(%rcx,%r14,8), %zmm22, %zmm21

// CHECK: vpdpbusd  (%rcx), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x50,0x09]
          vpdpbusd  (%rcx), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusd  -256(%rsp), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x50,0x4c,0x24,0xfc]
          vpdpbusd  -256(%rsp), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusd  256(%rsp), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x50,0x4c,0x24,0x04]
          vpdpbusd  256(%rsp), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusd  268435456(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x50,0x8c,0xf1,0x00,0x00,0x00,0x10]
          vpdpbusd  268435456(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusd  -536870912(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x50,0x8c,0xf1,0x00,0x00,0x00,0xe0]
          vpdpbusd  -536870912(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusd  -536870910(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x50,0x8c,0xf1,0x02,0x00,0x00,0xe0]
          vpdpbusd  -536870910(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusds  (%rcx), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x51,0x09]
          vpdpbusds  (%rcx), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusds  -256(%rsp), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x51,0x4c,0x24,0xfc]
          vpdpbusds  -256(%rsp), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusds  256(%rsp), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x51,0x4c,0x24,0x04]
          vpdpbusds  256(%rsp), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusds  268435456(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x51,0x8c,0xf1,0x00,0x00,0x00,0x10]
          vpdpbusds  268435456(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusds  -536870912(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x51,0x8c,0xf1,0x00,0x00,0x00,0xe0]
          vpdpbusds  -536870912(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusds  -536870910(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x51,0x8c,0xf1,0x02,0x00,0x00,0xe0]
          vpdpbusds  -536870910(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssd  (%rcx), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x52,0x09]
          vpdpwssd  (%rcx), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssd  -256(%rsp), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x52,0x4c,0x24,0xfc]
          vpdpwssd  -256(%rsp), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssd  256(%rsp), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x52,0x4c,0x24,0x04]
          vpdpwssd  256(%rsp), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssd  268435456(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x52,0x8c,0xf1,0x00,0x00,0x00,0x10]
          vpdpwssd  268435456(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssd  -536870912(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x52,0x8c,0xf1,0x00,0x00,0x00,0xe0]
          vpdpwssd  -536870912(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssd  -536870910(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x52,0x8c,0xf1,0x02,0x00,0x00,0xe0]
          vpdpwssd  -536870910(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssds  (%rcx), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x53,0x09]
          vpdpwssds  (%rcx), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssds  -256(%rsp), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x53,0x4c,0x24,0xfc]
          vpdpwssds  -256(%rsp), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssds  256(%rsp), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xf2,0x6d,0x4a,0x53,0x4c,0x24,0x04]
          vpdpwssds  256(%rsp), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssds  268435456(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x53,0x8c,0xf1,0x00,0x00,0x00,0x10]
          vpdpwssds  268435456(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssds  -536870912(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x53,0x8c,0xf1,0x00,0x00,0x00,0xe0]
          vpdpwssds  -536870912(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpwssds  -536870910(%rcx,%r14,8), %zmm2, %zmm1 {%k2}
// CHECK: encoding: [0x62,0xb2,0x6d,0x4a,0x53,0x8c,0xf1,0x02,0x00,0x00,0xe0]
          vpdpwssds  -536870910(%rcx,%r14,8), %zmm2, %zmm1 {%k2}

// CHECK: vpdpbusd  (%rcx), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x50,0x29]
          vpdpbusd  (%rcx), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusd  -256(%rsp), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x50,0x6c,0x24,0xfc]
          vpdpbusd  -256(%rsp), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusd  256(%rsp), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x50,0x6c,0x24,0x04]
          vpdpbusd  256(%rsp), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusd  268435456(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x50,0xac,0xf1,0x00,0x00,0x00,0x10]
          vpdpbusd  268435456(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusd  -536870912(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x50,0xac,0xf1,0x00,0x00,0x00,0xe0]
          vpdpbusd  -536870912(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusd  -536870910(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x50,0xac,0xf1,0x02,0x00,0x00,0xe0]
          vpdpbusd  -536870910(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusds  (%rcx), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x51,0x29]
          vpdpbusds  (%rcx), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusds  -256(%rsp), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x51,0x6c,0x24,0xfc]
          vpdpbusds  -256(%rsp), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusds  256(%rsp), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x51,0x6c,0x24,0x04]
          vpdpbusds  256(%rsp), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusds  268435456(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x51,0xac,0xf1,0x00,0x00,0x00,0x10]
          vpdpbusds  268435456(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusds  -536870912(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x51,0xac,0xf1,0x00,0x00,0x00,0xe0]
          vpdpbusds  -536870912(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpbusds  -536870910(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x51,0xac,0xf1,0x02,0x00,0x00,0xe0]
          vpdpbusds  -536870910(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssd  (%rcx), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x52,0x29]
          vpdpwssd  (%rcx), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssd  -256(%rsp), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x52,0x6c,0x24,0xfc]
          vpdpwssd  -256(%rsp), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssd  256(%rsp), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x52,0x6c,0x24,0x04]
          vpdpwssd  256(%rsp), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssd  268435456(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x52,0xac,0xf1,0x00,0x00,0x00,0x10]
          vpdpwssd  268435456(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssd  -536870912(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x52,0xac,0xf1,0x00,0x00,0x00,0xe0]
          vpdpwssd  -536870912(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssd  -536870910(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x52,0xac,0xf1,0x02,0x00,0x00,0xe0]
          vpdpwssd  -536870910(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssds  (%rcx), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x53,0x29]
          vpdpwssds  (%rcx), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssds  -256(%rsp), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x53,0x6c,0x24,0xfc]
          vpdpwssds  -256(%rsp), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssds  256(%rsp), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xe2,0x4d,0x42,0x53,0x6c,0x24,0x04]
          vpdpwssds  256(%rsp), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssds  268435456(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x53,0xac,0xf1,0x00,0x00,0x00,0x10]
          vpdpwssds  268435456(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssds  -536870912(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x53,0xac,0xf1,0x00,0x00,0x00,0xe0]
          vpdpwssds  -536870912(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

// CHECK: vpdpwssds  -536870910(%rcx,%r14,8), %zmm22, %zmm21 {%k2}
// CHECK: encoding: [0x62,0xa2,0x4d,0x42,0x53,0xac,0xf1,0x02,0x00,0x00,0xe0]
          vpdpwssds  -536870910(%rcx,%r14,8), %zmm22, %zmm21 {%k2}

