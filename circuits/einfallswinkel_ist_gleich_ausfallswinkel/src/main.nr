fn main(einfallswinkel: u64, ausfallswinkel: u64) {
    assert(einfallswinkel < 360);
    assert(ausfallswinkel < 360);
    assert(einfallswinkel == ausfallswinkel);
}
