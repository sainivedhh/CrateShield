pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xba54f920 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xfa8dbe42 as *mut u32;
        *ptr = 1;
    }
}
