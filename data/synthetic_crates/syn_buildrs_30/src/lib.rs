pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x12c146e0 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x89a2788b as *mut u32;
        *ptr = 1;
    }
}
