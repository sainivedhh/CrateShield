pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xb98f6dbe as *mut u32;
        *ptr = 1;
    }
}
