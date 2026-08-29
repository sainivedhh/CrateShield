pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x93cd2291 as *mut u32;
        *ptr = 1;
    }
}
