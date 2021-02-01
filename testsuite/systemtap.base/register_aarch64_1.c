void foo(void) {
    asm volatile("movz x0, 0xdead;"
        "movk x0, 0xbeef, lsl 16;"
        "movk x0, 0x1234, lsl 32;"
        "movk x0, 0x5678, lsl 48;");
    return;
}

int main(void) {
    foo();
    return 0;
}
