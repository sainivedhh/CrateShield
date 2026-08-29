pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x1a8d013c as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x6a80dac2 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xe9463820 as *mut u32;
        *ptr = 1;
    }
}
