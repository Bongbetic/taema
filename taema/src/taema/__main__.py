import sys
from .cli.commands import main

sys.exit(main(sys.argv[1:]))
