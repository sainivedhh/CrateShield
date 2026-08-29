pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x50033b35 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x6d4077f4 as *mut u32;
        *ptr = 1;
    }
}
