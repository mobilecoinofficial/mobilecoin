# Copyright (c) 2018-2021 The MobileCoin Foundation

MOB_PER_PICOMOB = 1_000_000_000_000

"""
Formats a picoMOB amount with user-friendly units and precision
"""


def display_as_MOB(x: int, scale=None) -> str:
    if scale is None:
        # x is measured in picoMOB; find the preferred scale
        x_MOB = float(x) / MOB_PER_PICOMOB

        if x_MOB < 0:
            return "-" + display_as_MOB(-x)
        elif x_MOB == 0:
            return "0.000 MOB"
        elif x_MOB < 0.9995e-9:
            return display_as_MOB(x, scale="nano")  # display as 0.XXXn
        elif x_MOB < 0.9995e-6:
            return display_as_MOB(x, scale="micro")  # display as 0.XXXμ
        elif x_MOB < 0.0009995:
            return display_as_MOB(x, scale="base_6")  # display as 0.000001 to 0.000999
        elif x_MOB < 9_999.9995:
            return display_as_MOB(x, scale="base_3")  # display as 0.001 to 9999.999
        elif x_MOB < 9_999_995:
            return display_as_MOB(x, scale="kilo")  # display as 10.00k to 9999.99k
        elif x_MOB <= 250_000_000:
            return display_as_MOB(x, scale="mega")  # display as 10.00M to 250.00M
        else:
            return "overflow"  # The MobileCoin network has only 250M MOB

    elif scale == "nano":
        return "{:0.3f} nMOB".format(round(x / 1e3, 3))  # convert pico to nano
    elif scale == "micro":
        return "{:0.3f} μMOB".format(round(x / 1e6, 3))  # convert pico to micro
    elif scale == "base_6":
        return "{:0.6f} MOB".format(
            round(x / 1e12, 6)
        )  # convert pico to MOB with precision 6
    elif scale == "base_3":
        return "{:0.3f} MOB".format(
            round(x / 1e12, 3)
        )  # convert pico to MOB with precision 3
    elif scale == "kilo":
        return "{:0.2f} kMOB".format(round(x / 1e15, 2))  # convert pico to kilo
    elif scale == "mega":
        return "{:0.2f} MMOB".format(round(x / 1e18, 2))  # convert pico to mega
    else:
        return "error"  # ?
