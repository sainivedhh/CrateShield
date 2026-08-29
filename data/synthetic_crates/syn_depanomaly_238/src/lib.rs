pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xc11f7bf5 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xdd1d7cd1 as *mut u32;
        *ptr = 1;
    }
}
