pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xbdacec5e as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x423711f1 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xb9a5e4d0 as *mut u32;
        *ptr = 1;
    }
}
