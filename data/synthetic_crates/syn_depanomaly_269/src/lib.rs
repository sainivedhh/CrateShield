pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x979c40cf as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xff4cd10f as *mut u32;
        *ptr = 1;
    }
}
