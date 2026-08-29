pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x8a89c0f0 as *mut u32;
        *ptr = 1;
    }
}
