pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x9f0fea8d as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x2702978b as *mut u32;
        *ptr = 1;
    }
}
