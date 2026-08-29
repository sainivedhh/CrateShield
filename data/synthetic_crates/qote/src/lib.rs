pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xbb636ff5 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x13336bc9 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x8c0b493a as *mut u32;
        *ptr = 1;
    }
}
