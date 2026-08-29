pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x77e4a0c7 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xf6803cdb as *mut u32;
        *ptr = 1;
    }
}
