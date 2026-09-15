import sys


def int2string(number):
    """
    Converts an integer to a string.
    """
    string = ""
    while number:
        string = chr(number & 0xFF) + string
        number >>= 8
    return string


if __name__ == "__main__":
    # Check if command line argument is provided
    if len(sys.argv) > 1:
        input_number = int(sys.argv[1])
        result = int2string(input_number)
        print(result)
    else:
        print("Please provide an integer as a command line argument.")
