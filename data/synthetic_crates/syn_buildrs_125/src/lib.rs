pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xe222c6a6 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xd77d5a0 as *mut u32;
        *ptr = 1;
    }
}
