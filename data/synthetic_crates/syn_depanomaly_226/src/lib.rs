pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x77243041 as *mut u32;
        *ptr = 1;
    }
}
