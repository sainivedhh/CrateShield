pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x302b8831 as *mut u32;
        *ptr = 1;
    }
}
