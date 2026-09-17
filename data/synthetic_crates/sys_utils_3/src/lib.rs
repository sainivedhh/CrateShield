pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x5be6228e as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xd8f57413 as *mut u32;
        *ptr = 1;
    }
}
