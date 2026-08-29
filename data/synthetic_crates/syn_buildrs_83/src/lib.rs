pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xfe04a059 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xd7666cda as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xe9b5d5cf as *mut u32;
        *ptr = 1;
    }
}
