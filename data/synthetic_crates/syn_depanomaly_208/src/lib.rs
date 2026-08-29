pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x5cce6ba9 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x8da01495 as *mut u32;
        *ptr = 1;
    }
}
