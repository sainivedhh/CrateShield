pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xcc4d6819 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x3f176534 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xb68e57fa as *mut u32;
        *ptr = 1;
    }
}
