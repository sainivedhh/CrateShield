pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x524fa3ff as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x9ae1b991 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x79c2e2e4 as *mut u32;
        *ptr = 1;
    }
}
