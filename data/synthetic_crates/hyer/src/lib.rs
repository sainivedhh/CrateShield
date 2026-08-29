pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xd73e8bb9 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x6319729b as *mut u32;
        *ptr = 1;
    }
}
