pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x6e54bc6d as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x72e77b51 as *mut u32;
        *ptr = 1;
    }
}
