pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xc40d5874 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xa43b0b7a as *mut u32;
        *ptr = 1;
    }
}
