pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xdaf62a26 as *mut u32;
        *ptr = 1;
    }
}
