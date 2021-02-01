void foo(void) {
    asm volatile("movz x3, 0xdead;"
        "movk x3, 0xbeef, lsl 16;"
        "movk x3, 0x1234, lsl 32;"
        "movk x3, 0x5678, lsl 48;");
    return;
}

int main(void) {
    foo();
    return 0;
}
