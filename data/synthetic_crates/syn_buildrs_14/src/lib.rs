pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x1ca36cfb as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xedd97831 as *mut u32;
        *ptr = 1;
    }
}
