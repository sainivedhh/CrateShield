pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xcf0400c8 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xfdd50f21 as *mut u32;
        *ptr = 1;
    }
}
