pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xa2a9e4d8 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xd2e83f38 as *mut u32;
        *ptr = 1;
    }
}
