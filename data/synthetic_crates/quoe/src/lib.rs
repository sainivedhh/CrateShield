pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x787525b9 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xdbdd5da as *mut u32;
        *ptr = 1;
    }
}
