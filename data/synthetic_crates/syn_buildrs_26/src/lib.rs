pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x958cb9ba as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x7a0edfea as *mut u32;
        *ptr = 1;
    }
}
