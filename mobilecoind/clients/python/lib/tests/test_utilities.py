#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from unittest import TestCase

import mobilecoin


class TestDisplayAsMOB(TestCase):
    def test_display_as_MOB(self):
        nMOB = 1e3
        μMOB = 1e6
        MOB = 1e12
        kMOB = 1e15
        MMOB = 1e18

        test_pairs = [
            # negative values
            (-9999.05 * kMOB, "-9999.05 kMOB"),
            (-1, "-0.001 nMOB"),
            # zero
            (0, "0.000 MOB"),
            # nano
            (0.001 * nMOB, "0.001 nMOB"),
            (0.012 * nMOB, "0.012 nMOB"),
            (0.123 * nMOB, "0.123 nMOB"),
            (0.500 * nMOB, "0.500 nMOB"),
            (0.999 * nMOB, "0.999 nMOB"),
            (0.9991 * nMOB, "0.999 nMOB"),
            (0.9995 * nMOB, "0.001 μMOB"),
            # micro
            (0.001 * μMOB, "0.001 μMOB"),
            (0.012 * μMOB, "0.012 μMOB"),
            (0.123 * μMOB, "0.123 μMOB"),
            (0.5 * μMOB, "0.500 μMOB"),
            (0.999 * μMOB, "0.999 μMOB"),
            (0.9991 * μMOB, "0.999 μMOB"),
            (0.9995 * μMOB, "0.000001 MOB"),
            (1 * μMOB, "0.000001 MOB"),
            (12 * μMOB, "0.000012 MOB"),
            (123 * μMOB, "0.000123 MOB"),
            (500 * μMOB, "0.000500 MOB"),
            # base precision 6
            (0.000099 * MOB, "0.000099 MOB"),
            (0.000090 * MOB, "0.000090 MOB"),
            (0.0009991 * MOB, "0.000999 MOB"),
            (0.0009995 * MOB, "0.001 MOB"),
            # base precision 3
            (0.0009999 * MOB, "0.001 MOB"),
            (0.0015 * MOB, "0.002 MOB"),
            (0.0030005 * MOB, "0.003 MOB"),
            (0.999 * MOB, "0.999 MOB"),
            (0.9991 * MOB, "0.999 MOB"),
            (0.9995 * MOB, "1.000 MOB"),
            (1 * MOB, "1.000 MOB"),
            (12 * MOB, "12.000 MOB"),
            (123 * MOB, "123.000 MOB"),
            (0.012 * MOB, "0.012 MOB"),
            (0.1 * MOB, "0.100 MOB"),
            (0.25 * MOB, "0.250 MOB"),
            (0.22342 * MOB, "0.223 MOB"),
            (1.2349 * MOB, "1.235 MOB"),
            (34.5 * MOB, "34.500 MOB"),
            (1234.234323 * MOB, "1234.234 MOB"),
            (9999.999 * MOB, "9999.999 MOB"),
            (9999.9991 * MOB, "9999.999 MOB"),
            (9999.9995 * MOB, "10.00 kMOB"),
            # kilo
            (9.9999994 * kMOB, "9999.999 MOB"),
            (9.9999995 * kMOB, "10.00 kMOB"),
            (12 * kMOB, "12.00 kMOB"),
            (123.02 * kMOB, "123.02 kMOB"),
            (500 * kMOB, "500.00 kMOB"),
            (9999.05 * kMOB, "9999.05 kMOB"),
            (9999.994 * kMOB, "9999.99 kMOB"),
            (9999.995 * kMOB, "10.00 MMOB"),
            # mega
            (9.999994 * MMOB, "9999.99 kMOB"),
            (9.999995 * MMOB, "10.00 MMOB"),
            (10 * MMOB, "10.00 MMOB"),
            (123.02 * MMOB, "123.02 MMOB"),
            (200.01 * MMOB, "200.01 MMOB"),
            (250 * MMOB, "250.00 MMOB"),
            (250.000_000_000_001 * MMOB, "overflow"),
        ]

        for (picoMOB, expected_str) in test_pairs:
            str = mobilecoin.display_as_MOB(picoMOB)
            print(str, expected_str)
            self.assertTrue(str == expected_str)
