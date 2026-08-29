pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x7aa071e9 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x506e60c7 as *mut u32;
        *ptr = 1;
    }
}
