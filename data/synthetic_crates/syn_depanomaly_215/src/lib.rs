pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x476d068c as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x8eded44d as *mut u32;
        *ptr = 1;
    }
}
