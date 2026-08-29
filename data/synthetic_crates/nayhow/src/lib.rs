pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x48fa5e98 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x7070ec2 as *mut u32;
        *ptr = 1;
    }
}
