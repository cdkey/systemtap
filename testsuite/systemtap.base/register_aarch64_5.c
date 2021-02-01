void foo(void) {
    asm volatile("movz x29, 0xdead;"
        "movk x29, 0xbeef, lsl 16;"
        "movk x29, 0x1234, lsl 32;"
        "movk x29, 0x5678, lsl 48;");
    return;
}

int main(void) {
    foo();
    return 0;
}
