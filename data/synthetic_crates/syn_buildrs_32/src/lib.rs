pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xbe0f151b as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x8da02097 as *mut u32;
        *ptr = 1;
    }
}
