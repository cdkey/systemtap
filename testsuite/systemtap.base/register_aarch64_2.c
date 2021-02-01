void foo(void) {
    asm volatile("movz x1, 0xdead;"
        "movk x1, 0xbeef, lsl 16;"
        "movk x1, 0x1234, lsl 32;"
        "movk x1, 0x5678, lsl 48;");
    return;
}

int main(void) {
    foo();
    return 0;
}
