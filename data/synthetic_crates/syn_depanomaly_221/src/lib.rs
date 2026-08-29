pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xedaf4766 as *mut u32;
        *ptr = 1;
    }
}
