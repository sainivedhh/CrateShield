pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x827060a8 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x7e571ddf as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x1745e6d8 as *mut u32;
        *ptr = 1;
    }
}
