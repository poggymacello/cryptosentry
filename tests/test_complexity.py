from cryptosentry.complexity import gnfs_operations, shor_operations


def test_both_complexity_curves_increase_with_key_size():
    for fn in (gnfs_operations, shor_operations):
        values = [fn(bits) for bits in (64, 128, 256, 512, 1024)]
        assert all(values[i] < values[i + 1] for i in range(len(values) - 1))


def test_shor_grows_slower_than_gnfs_at_large_key_sizes():
    # the whole point of the comparison: at real-world key sizes, the
    # quantum estimate should be dramatically smaller than the classical one
    bits = 2048
    assert shor_operations(bits) < gnfs_operations(bits)
