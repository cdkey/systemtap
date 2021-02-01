void foo(void) {
    asm volatile("movz x2, 0xdead;"
        "movk x2, 0xbeef, lsl 16;"
        "movk x2, 0x1234, lsl 32;"
        "movk x2, 0x5678, lsl 48;");
    return;
}

int main(void) {
    foo();
    return 0;
}
