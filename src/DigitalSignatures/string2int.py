import sys


def string2int(string):
    """
    Converts a string to its corresponding integer number.
    """
    result = 0
    for char in string:
        result = (result << 8) + ord(char)
    return result


if __name__ == "__main__":
    # Check if command line argument is  provided
    if len(sys.argv) > 1:
        input_string = sys.argv[1]
        result = string2int(input_string)
        print(result)
    else:
        print("Please provide a string as a command line argument.")
