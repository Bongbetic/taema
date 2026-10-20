import sys

argv = sys.argv[1:]


def _dispatch(arguments):
    from .cli.framework import main

    return main(arguments)


if argv == ["--version"]:
    from . import __version__

    print("taema " + __version__)
    sys.exit(0)
if argv == ["--help"]:
    from .cli.fast import main

    sys.exit(main())

sys.exit(_dispatch(argv))
