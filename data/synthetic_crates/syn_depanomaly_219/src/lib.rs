pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x153a221 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xf6eac3a0 as *mut u32;
        *ptr = 1;
    }
}
