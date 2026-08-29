pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x8151147 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x92940705 as *mut u32;
        *ptr = 1;
    }
}
