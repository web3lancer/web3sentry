import argparse
import logging
import sys

from web3sentry import __version__

__author__ = "nathfavour"
__copyright__ = "nathfavour"
__license__ = "MIT"

_logger = logging.getLogger(__name__)


# ---- Python API ----
# The functions defined in this section can be imported by users in their
# Python scripts/interactive interpreter, e.g. via
# `from web3sentry.skeleton import fib`,
# when using this Python module as a library.


def fib(n):
    """Fibonacci example function
    
    This calculates the nth Fibonacci number using an iterative approach.
    Remember that Fibonacci sequence starts with 1, 1, 2, 3, 5, 8, 13...
    where each number is the sum of the two preceding ones.

    Args:
      n (int): The position in the Fibonacci sequence (must be positive)

    Returns:
      int: The n-th Fibonacci number
    
    Raises:
      AssertionError: If n is not a positive integer
    """
    # Hey, make sure n is positive or this won't work!
    assert n > 0, "n must be greater than 0"
    
    # Starting with the first two Fibonacci numbers
    a, b = 1, 1
    
    # For n=1, we just return a=1 without any iteration
    # For n>1, we need to iterate n-1 times
    for _i in range(n - 1):
        # The classic Fibonacci calculation - each new number is the sum of the previous two
        a, b = b, a + b
    
    return a


# ---- CLI ----
# The functions defined in this section are wrappers around the main Python
# API allowing them to be called directly from the terminal as a CLI
# executable/script.


def parse_args(args):
    """Parse command line parameters

    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--help"]``).

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(description="Just a Fibonacci demonstration")
    parser.add_argument(
        "--version",
        action="version",
        version=f"web3sentry {__version__}",
    )
    parser.add_argument(dest="n", help="n-th Fibonacci number", type=int, metavar="INT")
    parser.add_argument(
        "-v",
        "--verbose",
        dest="loglevel",
        help="set loglevel to INFO",
        action="store_const",
        const=logging.INFO,
    )
    parser.add_argument(
        "-vv",
        "--very-verbose",
        dest="loglevel",
        help="set loglevel to DEBUG",
        action="store_const",
        const=logging.DEBUG,
    )
    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging
    
    This configures our logging system - how verbose we want to be and
    what format we want our log messages in.

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    # Define a nice format for our log messages with timestamps
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    
    # Set up the basic configuration for logging
    # We'll print to stdout with our custom format and timestamp
    logging.basicConfig(
        level=loglevel, stream=sys.stdout, format=logformat, datefmt="%Y-%m-%d %H:%M:%S"
    )


def main(args):
    """Wrapper allowing :func:`fib` to be called with string arguments in a CLI fashion

    Instead of returning the value from :func:`fib`, it prints the result to the
    ``stdout`` in a nicely formatted message.

    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--verbose", "42"]``).
    """
    # Parse those command line arguments - gotta know what the user wants!
    args = parse_args(args)
    
    # Set up our logging based on how chatty the user wants us to be
    setup_logging(args.loglevel)
    
    # Let's get this party started!
    _logger.debug("Starting crazy calculations...")
    
    # Calculate and show the Fibonacci number to the user
    print(f"The {args.n}-th Fibonacci number is {fib(args.n)}")
    
    # We're all done here
    _logger.info("Script ends here - thanks for using our Fibonacci calculator!")


def run():
    """Calls :func:`main` passing the CLI arguments extracted from :obj:`sys.argv`

    This function can be used as entry point to create console scripts with setuptools.
    It's basically just a convenient way to call our main function with the
    command line arguments.
    """
    # Grab everything after the script name and send it to main()
    main(sys.argv[1:])


if __name__ == "__main__":
    # ^  This is a guard statement that will prevent the following code from
    #    being executed in the case someone imports this file instead of
    #    executing it as a script.
    #    https://docs.python.org/3/library/__main__.html

    # After installing your project with pip, users can also run your Python
    # modules as scripts via the ``-m`` flag, as defined in PEP 338::
    #
    #     python -m web3sentry.skeleton 42
    #
    # Let's fire up our script!
    run()
