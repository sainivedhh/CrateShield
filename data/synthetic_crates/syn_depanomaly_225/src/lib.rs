pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x1bfae73 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x42c2e2eb as *mut u32;
        *ptr = 1;
    }
}
