pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xa85c7e4a as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xde8eee0b as *mut u32;
        *ptr = 1;
    }
}
