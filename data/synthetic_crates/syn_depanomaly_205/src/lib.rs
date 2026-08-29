pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xcf487ef as *mut u32;
        *ptr = 1;
    }
}
